import {
  Controller,
  Post,
  Get,
  Query,
  Body,
  HttpException,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiSecurity } from '@nestjs/swagger';
import { HybridAuthGuard } from '../../auth/hybrid-auth.guard';
import { PermissionGuard } from '../../auth/permission.guard';
import { RequirePermission } from '../../auth/require-permission.decorator';
import { OrganizationId } from '../../auth/auth-context.decorator';
import { db } from '@db';
import { ConnectionRepository } from '../repositories/connection.repository';
import { CredentialVaultService } from '../services/credential-vault.service';
import { OAuthCredentialsService } from '../services/oauth-credentials.service';
import { RampRoleMappingService } from '../services/ramp-role-mapping.service';
import { IntegrationSyncLoggerService } from '../services/integration-sync-logger.service';
import {
  getManifest,
  type RampUser,
  type RampUsersResponse,
  type RoleMappingEntry,
} from '@trycompai/integration-platform';

@Controller({ path: 'integrations/sync/ramp', version: '1' })
@ApiTags('Integrations')
@UseGuards(HybridAuthGuard, PermissionGuard)
@ApiSecurity('apikey')
export class RampRoleMappingController {
  constructor(
    private readonly connectionRepository: ConnectionRepository,
    private readonly credentialVaultService: CredentialVaultService,
    private readonly oauthCredentialsService: OAuthCredentialsService,
    private readonly roleMappingService: RampRoleMappingService,
    private readonly syncLoggerService: IntegrationSyncLoggerService,
  ) {}

  @Post('discover-roles')
  @RequirePermission('integration', 'update')
  async discoverRoles(
    @OrganizationId() organizationId: string,
    @Query('connectionId') connectionId: string,
    @Query('refresh') refresh?: string,
  ) {
    if (!connectionId) {
      throw new HttpException('connectionId is required', HttpStatus.BAD_REQUEST);
    }

    const shouldRefresh = refresh === 'true';
    let discoveredRoles: Array<{ role: string; userCount: number }>;

    // Use cached roles unless refresh is requested
    const cachedRoles = shouldRefresh
      ? null
      : await this.roleMappingService.getCachedDiscoveredRoles(connectionId);

    if (cachedRoles) {
      discoveredRoles = cachedRoles;
    } else {
      const logId = await this.syncLoggerService.startLog({
        connectionId,
        organizationId,
        provider: 'ramp',
        eventType: 'role_discovery',
        triggeredBy: 'manual',
      });

      try {
        const accessToken = await this.getAccessToken(connectionId, organizationId);
        const users = await this.fetchAllRampUsers(accessToken);

        const roleCounts = new Map<string, number>();
        for (const user of users) {
          const role = user.role ?? 'UNKNOWN';
          roleCounts.set(role, (roleCounts.get(role) ?? 0) + 1);
        }

        discoveredRoles = Array.from(roleCounts.entries())
          .map(([role, userCount]) => ({ role, userCount }))
          .sort((a, b) => b.userCount - a.userCount);

        // Cache the discovered roles
        const existingMapping = await this.roleMappingService.getSavedMapping(connectionId);
        await this.roleMappingService.saveMapping(
          connectionId,
          existingMapping ?? [],
          discoveredRoles,
        );

        await this.syncLoggerService.completeLog(logId, {
          rolesDiscovered: discoveredRoles.length,
          totalUsers: users.length,
        });
      } catch (error) {
        await this.syncLoggerService.failLog(
          logId,
          error instanceof Error ? error.message : String(error),
        );
        throw error;
      }
    }

    const rampRoleNames = discoveredRoles.map((r) => r.role);
    const defaultMapping = this.roleMappingService.getDefaultMapping(rampRoleNames);
    const existingMapping = await this.roleMappingService.getSavedMapping(connectionId);

    // Fetch existing custom roles for this org with their permissions
    const customRoles = await db.organizationRole.findMany({
      where: { organizationId },
      select: { name: true, permissions: true, obligations: true },
      orderBy: { name: 'asc' },
    });

    const existingCustomRoles = customRoles.map((r) => ({
      name: r.name,
      permissions: JSON.parse(r.permissions) as Record<string, string[]>,
      obligations: JSON.parse(r.obligations) as Record<string, boolean>,
    }));

    return { discoveredRoles, defaultMapping, existingMapping, existingCustomRoles };
  }

  @Post('role-mapping')
  @RequirePermission('integration', 'update')
  async saveRoleMapping(
    @OrganizationId() organizationId: string,
    @Body() body: { connectionId: string; mapping: RoleMappingEntry[] },
  ) {
    const { connectionId, mapping } = body;

    if (!connectionId || !Array.isArray(mapping)) {
      throw new HttpException(
        'connectionId and mapping are required',
        HttpStatus.BAD_REQUEST,
      );
    }

    const connection = await this.connectionRepository.findById(connectionId);
    if (!connection || connection.organizationId !== organizationId) {
      throw new HttpException('Connection not found', HttpStatus.NOT_FOUND);
    }

    const logId = await this.syncLoggerService.startLog({
      connectionId,
      organizationId,
      provider: 'ramp',
      eventType: 'role_mapping_save',
      triggeredBy: 'manual',
    });

    try {
      // Create custom roles in the database
      await this.roleMappingService.ensureCustomRolesExist(organizationId, mapping);

      // Save mapping to connection variables (preserve existing discovered roles)
      await this.roleMappingService.saveMapping(connectionId, mapping);

      await this.syncLoggerService.completeLog(logId, {
        mappingCount: mapping.length,
      });

      return { success: true, mapping };
    } catch (error) {
      await this.syncLoggerService.failLog(
        logId,
        error instanceof Error ? error.message : String(error),
      );
      throw error;
    }
  }

  @Get('role-mapping')
  @RequirePermission('integration', 'read')
  async getRoleMapping(
    @Query('connectionId') connectionId: string,
  ) {
    if (!connectionId) {
      throw new HttpException('connectionId is required', HttpStatus.BAD_REQUEST);
    }

    const mapping = await this.roleMappingService.getSavedMapping(connectionId);
    return { mapping };
  }

  private async getAccessToken(
    connectionId: string,
    organizationId: string,
  ): Promise<string> {
    let credentials =
      await this.credentialVaultService.getDecryptedCredentials(connectionId);

    if (!credentials?.access_token) {
      throw new HttpException(
        'No valid credentials. Please reconnect.',
        HttpStatus.UNAUTHORIZED,
      );
    }

    const manifest = getManifest('ramp');
    const oauthConfig =
      manifest?.auth.type === 'oauth2' ? manifest.auth.config : null;

    if (oauthConfig?.supportsRefreshToken && credentials.refresh_token) {
      try {
        const oauthCreds = await this.oauthCredentialsService.getCredentials(
          'ramp',
          organizationId,
        );
        if (oauthCreds) {
          const newToken = await this.credentialVaultService.refreshOAuthTokens(
            connectionId,
            {
              tokenUrl: oauthConfig.tokenUrl,
              refreshUrl: oauthConfig.refreshUrl,
              clientId: oauthCreds.clientId,
              clientSecret: oauthCreds.clientSecret,
              clientAuthMethod: oauthConfig.clientAuthMethod,
            },
          );
          if (newToken) {
            credentials =
              await this.credentialVaultService.getDecryptedCredentials(connectionId);
          }
        }
      } catch {
        // Try with existing token
      }
    }

    if (!credentials?.access_token) {
      throw new HttpException(
        'No valid credentials. Please reconnect.',
        HttpStatus.UNAUTHORIZED,
      );
    }

    const token = credentials.access_token;
    return Array.isArray(token) ? token[0] : token;
  }

  private async fetchAllRampUsers(accessToken: string): Promise<RampUser[]> {
    const users: RampUser[] = [];
    let nextUrl: string | null = null;

    do {
      const url = nextUrl
        ? new URL(nextUrl)
        : new URL('https://demo-api.ramp.com/developer/v1/users');
      if (!nextUrl) {
        url.searchParams.set('page_size', '100');
      }

      const response = await fetch(url.toString(), {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new HttpException(
          'Failed to fetch users from Ramp',
          HttpStatus.BAD_GATEWAY,
        );
      }

      const data: RampUsersResponse = await response.json();
      if (data.data?.length) {
        users.push(...data.data);
      }
      nextUrl = data.page?.next ?? null;
    } while (nextUrl);

    return users;
  }
}
