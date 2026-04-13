/**
 * Two-Factor Authentication Check
 * Verifies that all organization members have 2FA enabled.
 *
 * Uses GET /orgs/{org}/members?filter=2fa_disabled to find members
 * without 2FA. The filter is only available to organization owners.
 *
 * @see https://docs.github.com/en/rest/orgs/members#list-organization-members
 */

import { TASK_TEMPLATES } from '../../../task-mappings';
import type { IntegrationCheck } from '../../../types';
import type { GitHubOrg } from '../types';

interface GitHubOrgMember {
  login: string;
  id: number;
  html_url: string;
}

const MAX_USERNAMES_IN_DESCRIPTION = 20;
const MAX_USERNAMES_IN_EVIDENCE = 100;

const isOwnerPermissionError = (errorMsg: string): boolean => {
  const lower = errorMsg.toLowerCase();

  if (lower.includes('403') || lower.includes('forbidden')) return true;
  if (lower.includes('must be an organization owner') || lower.includes('organization owners')) {
    return true;
  }

  // GitHub documents 422 for this endpoint when filter constraints fail.
  if (lower.includes('422') || lower.includes('unprocessable') || lower.includes('validation failed')) {
    return true;
  }

  return false;
};

const formatUsernamesPreview = (members: GitHubOrgMember[]): string => {
  const preview = members.slice(0, MAX_USERNAMES_IN_DESCRIPTION).map((member) => `@${member.login}`);
  const remaining = members.length - preview.length;

  if (remaining > 0) {
    return `${preview.join(', ')} and ${remaining} more`;
  }
  return preview.join(', ');
};

export const twoFactorAuthCheck: IntegrationCheck = {
  id: 'two_factor_auth',
  name: '2FA Enforcement',
  description:
    'Verify that all GitHub organization members have two-factor authentication enabled',
  service: 'code-security',
  taskMapping: TASK_TEMPLATES.twoFactorAuth,
  defaultSeverity: 'high',

  run: async (ctx) => {
    // Step 1: Get all orgs the authenticated user belongs to
    let orgs: GitHubOrg[];
    try {
      orgs = await ctx.fetchAllPages<GitHubOrg>('/user/orgs');
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      ctx.error(`Failed to fetch organizations: ${errorMsg}`);
      ctx.fail({
        title: 'Cannot fetch GitHub organizations',
        description: `Failed to list organizations: ${errorMsg}`,
        resourceType: 'organization',
        resourceId: 'github',
        severity: 'medium',
        remediation:
          'Ensure the GitHub integration has the read:org scope. You may need to reconnect the integration.',
      });
      return;
    }

    if (orgs.length === 0) {
      ctx.fail({
        title: 'No GitHub organizations found',
        description:
          'The connected GitHub account is not a member of any organizations. 2FA enforcement is an organization-level setting.',
        resourceType: 'organization',
        resourceId: 'github',
        severity: 'low',
        remediation:
          'Connect a GitHub account that belongs to at least one organization.',
      });
      return;
    }

    ctx.log(`Found ${orgs.length} organization(s). Checking 2FA status...`);

    // Step 2: For each org, check for members without 2FA
    for (const org of orgs) {
      ctx.log(`Checking 2FA for organization: ${org.login}`);
      const orgSlug = encodeURIComponent(org.login);
      const checkedAt = new Date().toISOString();

      let membersWithout2FA: GitHubOrgMember[];
      try {
        membersWithout2FA = await ctx.fetchAllPages<GitHubOrgMember>(
          `/orgs/${orgSlug}/members?filter=2fa_disabled`,
        );
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);

        // GitHub returns 422 when the caller is not an org owner for 2fa_* filters.
        if (isOwnerPermissionError(errorMsg)) {
          ctx.warn(
            `Cannot check 2FA for ${org.login}: the account must be an organization owner to use the 2FA filter.`,
          );
          ctx.fail({
            title: `Cannot verify 2FA for ${org.login}`,
            description:
              'Insufficient permissions to check 2FA status. The `filter=2fa_disabled` parameter is only available to organization owners on GitHub.',
            resourceType: 'organization',
            resourceId: org.login,
            severity: 'medium',
            remediation:
              'Reconnect the GitHub integration with an account that is an owner of this organization.',
          });
          continue;
        }

        ctx.error(`Failed to check 2FA for ${org.login}: ${errorMsg}`);
        ctx.fail({
          title: `Error checking 2FA for ${org.login}`,
          description: `Failed to query members without 2FA: ${errorMsg}`,
          resourceType: 'organization',
          resourceId: org.login,
          severity: 'medium',
          remediation: 'Check the integration connection and try again.',
        });
        continue;
      }

      // Step 3: Also fetch total member count for context
      let totalCount: number | null = null;
      try {
        const totalMembers = await ctx.fetchAllPages<GitHubOrgMember>(`/orgs/${orgSlug}/members`);
        totalCount = totalMembers.length;
      } catch (error) {
        // Non-critical: we can still report 2FA findings without total count
        const errorMsg = error instanceof Error ? error.message : String(error);
        ctx.warn(`Could not fetch total member count for ${org.login}: ${errorMsg}`);
      }

      const without2FACount = membersWithout2FA.length;

      if (without2FACount === 0) {
        ctx.pass({
          title: `All members have 2FA enabled in ${org.login}`,
          description:
            typeof totalCount === 'number' && totalCount > 0
              ? `All ${totalCount} members of the ${org.login} organization have two-factor authentication enabled.`
              : `No members without 2FA were returned for ${org.login}.`,
          resourceType: 'organization',
          resourceId: org.login,
          evidence: {
            organization: org.login,
            totalMembers: totalCount,
            membersWithout2FA: 0,
            checkedAt,
          },
        });
      } else {
        // List each member without 2FA as a separate finding
        for (const member of membersWithout2FA) {
          ctx.fail({
            title: `2FA not enabled: ${member.login}`,
            description: `GitHub user @${member.login} in the ${org.login} organization does not have two-factor authentication enabled.`,
            resourceType: 'user',
            resourceId: `${org.login}/${member.login}`,
            severity: 'high',
            remediation: `Ask @${member.login} to enable 2FA in their GitHub account settings (Settings > Password and authentication > Two-factor authentication). Alternatively, enforce 2FA at the organization level in ${org.login}'s settings.`,
            evidence: {
              organization: org.login,
              username: member.login,
              userId: member.id,
              profileUrl: member.html_url,
              checkedAt,
            },
          });
        }

        // Also emit a summary
        ctx.fail({
          title: `${without2FACount} member(s) without 2FA in ${org.login}`,
          description: `${without2FACount} out of ${totalCount ?? 'unknown'} members in the ${org.login} organization do not have two-factor authentication enabled: ${formatUsernamesPreview(membersWithout2FA)}`,
          resourceType: 'organization',
          resourceId: `${org.login}/2fa-summary`,
          severity: 'high',
          remediation: `1. Go to https://github.com/organizations/${org.login}/settings/security\n2. Under "Authentication security", check "Require two-factor authentication for everyone"\n3. This will require all existing and future members to enable 2FA`,
          evidence: {
            organization: org.login,
            totalMembers: totalCount,
            membersWithout2FA: without2FACount,
            sampleUsernames: membersWithout2FA
              .slice(0, MAX_USERNAMES_IN_EVIDENCE)
              .map((member) => member.login),
            usernamesTruncated: membersWithout2FA.length > MAX_USERNAMES_IN_EVIDENCE,
            checkedAt,
          },
        });
      }
    }
  },
};
