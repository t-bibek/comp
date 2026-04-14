import { Injectable, Logger } from '@nestjs/common';
import type { SecurityFinding } from '../cloud-security.service';
import { parseGcpPermissionError } from '../remediation-error.utils';

/** Full SCC finding structure with all useful fields. */
interface SCCFinding {
  name: string;
  category: string;
  severity: string;
  state: string;
  resourceName: string;
  description?: string;
  createTime: string;
  eventTime: string;
  externalUri?: string;
  nextSteps?: string;
  sourceProperties?: Record<string, unknown>;
  findingClass?: string;
  compliances?: Array<{
    standard: string;
    version: string;
    ids: string[];
  }>;
  parentDisplayName?: string;
}

interface SCCFindingResult {
  finding: SCCFinding;
  resource?: {
    name: string;
    projectDisplayName?: string;
    type?: string;
    displayName?: string;
  };
}

/** Map SCC category → our serviceId for grouping in the UI. */
const CATEGORY_TO_SERVICE: Record<string, string> = {
  // Cloud Storage
  PUBLIC_BUCKET_ACL: 'cloud-storage',
  BUCKET_POLICY_ONLY_DISABLED: 'cloud-storage',
  BUCKET_LOGGING_DISABLED: 'cloud-storage',
  BUCKET_LOCK_DISABLED: 'cloud-storage',
  BUCKET_CMEK_DISABLED: 'cloud-storage',
  // Compute / VPC
  OPEN_FIREWALL: 'vpc-network',
  OPEN_SSH_PORT: 'vpc-network',
  OPEN_RDP_PORT: 'vpc-network',
  FIREWALL_RULE_LOGGING_DISABLED: 'vpc-network',
  FLOW_LOGS_DISABLED: 'vpc-network',
  DEFAULT_SERVICE_ACCOUNT_USED: 'compute-engine',
  COMPUTE_SECURE_BOOT_DISABLED: 'compute-engine',
  OS_LOGIN_DISABLED: 'compute-engine',
  PUBLIC_IP_ADDRESS: 'compute-engine',
  IP_FORWARDING_ENABLED: 'compute-engine',
  SERIAL_PORT_ENABLED: 'compute-engine',
  FULL_API_ACCESS: 'compute-engine',
  SHIELDED_VM_DISABLED: 'compute-engine',
  // IAM
  ADMIN_SERVICE_ACCOUNT: 'iam',
  MFA_NOT_ENFORCED: 'iam',
  OVER_PRIVILEGED_SERVICE_ACCOUNT_USER: 'iam',
  SERVICE_ACCOUNT_KEY_NOT_ROTATED: 'iam',
  USER_MANAGED_SERVICE_ACCOUNT_KEY: 'iam',
  NON_ORG_IAM_MEMBER: 'iam',
  OVER_PRIVILEGED_ACCOUNT: 'iam',
  PRIMITIVE_ROLES_USED: 'iam',
  KMS_ROLE_SEPARATION: 'iam',
  // Cloud SQL
  SQL_PUBLIC_IP: 'cloud-sql',
  SQL_NO_ROOT_PASSWORD: 'cloud-sql',
  SQL_CROSS_DB_OWNERSHIP_CHAINING: 'cloud-sql',
  SQL_LOCAL_INFILE: 'cloud-sql',
  SSL_NOT_ENFORCED: 'cloud-sql',
  AUTO_BACKUP_DISABLED: 'cloud-sql',
  SQL_CONTAINED_DATABASE_AUTHENTICATION: 'cloud-sql',
  SQL_LOG_DISCONNECTIONS_DISABLED: 'cloud-sql',
  SQL_LOG_CONNECTIONS_DISABLED: 'cloud-sql',
  SQL_LOG_ERROR_VERBOSITY: 'cloud-sql',
  SQL_LOG_MIN_MESSAGES: 'cloud-sql',
  SQL_LOG_MIN_DURATION_STATEMENT_ENABLED: 'cloud-sql',
  // GKE
  CLUSTER_PRIVATE_GOOGLE_ACCESS_DISABLED: 'gke',
  CLUSTER_SHIELDED_NODES_DISABLED: 'gke',
  LEGACY_AUTHORIZATION_ENABLED: 'gke',
  MASTER_AUTHORIZED_NETWORKS_DISABLED: 'gke',
  NETWORK_POLICY_DISABLED: 'gke',
  POD_SECURITY_POLICY_DISABLED: 'gke',
  PRIVATE_CLUSTER_DISABLED: 'gke',
  RELEASE_CHANNEL_DISABLED: 'gke',
  WEB_UI_ENABLED: 'gke',
  WORKLOAD_IDENTITY_DISABLED: 'gke',
  // KMS
  KMS_KEY_NOT_ROTATED: 'cloud-kms',
  KMS_PROJECT_HAS_OWNER: 'cloud-kms',
  // Logging / Monitoring
  AUDIT_LOGGING_DISABLED: 'cloud-logging',
  LOG_NOT_EXPORTED: 'cloud-logging',
  LOCKED_RETENTION_POLICY_NOT_SET: 'cloud-logging',
  AUDIT_CONFIG_NOT_MONITORED: 'cloud-monitoring',
  CUSTOM_ROLE_NOT_MONITORED: 'cloud-monitoring',
  FIREWALL_NOT_MONITORED: 'cloud-monitoring',
  NETWORK_NOT_MONITORED: 'cloud-monitoring',
  ROUTE_NOT_MONITORED: 'cloud-monitoring',
  SQL_INSTANCE_NOT_MONITORED: 'cloud-monitoring',
  // DNS
  DNSSEC_DISABLED: 'cloud-dns',
  RSASHA1_FOR_SIGNING: 'cloud-dns',
  // BigQuery
  DATASET_CMEK_DISABLED: 'bigquery',
  PUBLIC_DATASET: 'bigquery',
  // Pub/Sub
  PUBSUB_CMEK_DISABLED: 'pubsub',
  // Cloud Armor / Load Balancing
  SSL_POLICY_WEAK: 'cloud-armor',
};

/** Human-readable service names for UI grouping. */
const SERVICE_NAMES: Record<string, string> = {
  'cloud-storage': 'Cloud Storage',
  'vpc-network': 'VPC Network',
  'compute-engine': 'Compute Engine',
  'iam': 'IAM',
  'cloud-sql': 'Cloud SQL',
  'gke': 'GKE',
  'cloud-kms': 'Cloud KMS',
  'cloud-logging': 'Cloud Logging',
  'cloud-monitoring': 'Cloud Monitoring',
  'cloud-dns': 'Cloud DNS',
  'bigquery': 'BigQuery',
  'pubsub': 'Pub/Sub',
  'cloud-armor': 'Cloud Armor',
  'security-command-center': 'Security Command Center',
};

/** Map GCP API service names → our service category IDs. */
const GCP_API_TO_SERVICE: Record<string, string[]> = {
  'storage.googleapis.com': ['cloud-storage'],
  'storage-component.googleapis.com': ['cloud-storage'],
  'compute.googleapis.com': ['compute-engine', 'vpc-network'],
  'securitycenter.googleapis.com': ['security-command-center'],
  'sqladmin.googleapis.com': ['cloud-sql'],
  'container.googleapis.com': ['gke'],
  'cloudkms.googleapis.com': ['cloud-kms'],
  'logging.googleapis.com': ['cloud-logging'],
  'monitoring.googleapis.com': ['cloud-monitoring'],
  'dns.googleapis.com': ['cloud-dns'],
  'bigquery.googleapis.com': ['bigquery'],
  'bigquerystorage.googleapis.com': ['bigquery'],
  'pubsub.googleapis.com': ['pubsub'],
  'networksecurity.googleapis.com': ['cloud-armor'],
  'iam.googleapis.com': ['iam'],
  'iamcredentials.googleapis.com': ['iam'],
};

export type GcpSetupStepId =
  | 'enable_security_command_center_api'
  | 'enable_cloud_resource_manager_api'
  | 'enable_service_usage_api'
  | 'grant_findings_viewer_role';

export type GcpSetupAdminAction =
  | { kind: 'link'; label: string; url: string }
  | { kind: 'command'; label: string; command: string };

export type GcpSetupResolveAction = {
  label: string;
  method: 'POST';
  endpoint: string;
  body: { stepId: GcpSetupStepId };
};

export type GcpSetupStep = {
  id: GcpSetupStepId;
  name: string;
  success: boolean;
  error?: string;
  actionUrl?: string;
  actionText?: string;
  requiredForScan: boolean;
  resolveAction?: GcpSetupResolveAction;
  adminActions?: GcpSetupAdminAction[];
};

const REQUIRED_GCP_API_STEPS: Array<{
  id: GcpSetupStepId;
  api: string;
  name: string;
  actionUrl: string;
  actionText: string;
  requiredForScan: boolean;
}> = [
  {
    id: 'enable_security_command_center_api',
    api: 'securitycenter.googleapis.com',
    name: 'Enable Security Command Center API',
    actionUrl:
      'https://console.cloud.google.com/apis/library/securitycenter.googleapis.com',
    actionText: 'Open API',
    requiredForScan: true,
  },
  {
    id: 'enable_cloud_resource_manager_api',
    api: 'cloudresourcemanager.googleapis.com',
    name: 'Enable Cloud Resource Manager API',
    actionUrl:
      'https://console.cloud.google.com/apis/library/cloudresourcemanager.googleapis.com',
    actionText: 'Open API',
    requiredForScan: false,
  },
  {
    id: 'enable_service_usage_api',
    api: 'serviceusage.googleapis.com',
    name: 'Enable Service Usage API',
    actionUrl:
      'https://console.cloud.google.com/apis/library/serviceusage.googleapis.com',
    actionText: 'Open API',
    requiredForScan: false,
  },
];

const FINDINGS_VIEWER_ACTION = {
  actionUrl: 'https://console.cloud.google.com/iam-admin/iam',
  actionText: 'Open IAM',
  requiredForScan: true,
};

@Injectable()
export class GCPSecurityService {
  private readonly logger = new Logger(GCPSecurityService.name);

  /**
   * One-click GCP setup: enable required APIs, detect user email,
   * and grant the Findings Viewer role at the organization level.
   * Returns status of each step so the frontend can show what succeeded/failed.
   */
  async autoSetup(params: {
    accessToken: string;
    organizationId: string;
    projectId: string;
  }): Promise<{
    email: string | null;
    steps: GcpSetupStep[];
  }> {
    const { accessToken, organizationId, projectId } = params;
    const steps: GcpSetupStep[] = [];
    const email = await this.detectEmail(accessToken);

    for (const stepDef of REQUIRED_GCP_API_STEPS) {
      steps.push(
        await this.runEnableApiSetupStep({
          stepDef,
          accessToken,
          projectId,
        }),
      );
    }

    steps.push(
      await this.runGrantFindingsViewerSetupStep({
        accessToken,
        organizationId,
        email,
      }),
    );

    this.logger.log(
      `GCP auto-setup: ${steps.filter((s) => s.success).length}/${steps.length} steps succeeded`,
    );
    return { email, steps };
  }

  async resolveSetupStep(params: {
    stepId: GcpSetupStepId;
    accessToken: string;
    organizationId: string;
    projectId: string;
    email?: string | null;
  }): Promise<{ email: string | null; step: GcpSetupStep }> {
    const { stepId, accessToken, organizationId, projectId } = params;
    const email = params.email ?? (await this.detectEmail(accessToken));

    if (stepId === 'grant_findings_viewer_role') {
      return {
        email,
        step: await this.runGrantFindingsViewerSetupStep({
          accessToken,
          organizationId,
          email,
        }),
      };
    }

    const stepDef = REQUIRED_GCP_API_STEPS.find((s) => s.id === stepId);
    if (!stepDef) {
      throw new Error(`Unsupported GCP setup step: ${stepId}`);
    }

    return {
      email,
      step: await this.runEnableApiSetupStep({
        stepDef,
        accessToken,
        projectId,
      }),
    };
  }

  private async detectEmail(accessToken: string): Promise<string | null> {
    try {
      const resp = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (resp.ok) {
        const info = (await resp.json()) as { email?: string };
        return info.email ?? null;
      }
    } catch {
      this.logger.warn('Could not fetch user email');
    }
    return null;
  }

  private async runEnableApiSetupStep(params: {
    stepDef: (typeof REQUIRED_GCP_API_STEPS)[number];
    accessToken: string;
    projectId: string;
  }): Promise<GcpSetupStep> {
    const { stepDef, accessToken, projectId } = params;
    const actionUrl = this.getApiConsoleUrl(stepDef.api, projectId);

    try {
      const resp = await fetch(
        `https://serviceusage.googleapis.com/v1/projects/${projectId}/services/${stepDef.api}:enable`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: '{}',
        },
      );

      if (resp.ok || resp.status === 409) {
        return {
          id: stepDef.id,
          name: stepDef.name,
          success: true,
          actionUrl,
          actionText: stepDef.actionText,
          requiredForScan: stepDef.requiredForScan,
        };
      }

      const rawError = await resp.text();
      const message = this.getEnableApiErrorMessage(stepDef.api, rawError);
      const isPermissionError = /permission denied|does not have permission|forbidden|PERMISSION_DENIED/i.test(
        message,
      );

      if (isPermissionError) {
        const alreadyEnabled = await this.isApiAlreadyEnabled(
          accessToken,
          projectId,
          stepDef.api,
        );
        if (alreadyEnabled) {
          return {
            id: stepDef.id,
            name: stepDef.name,
            success: true,
            actionUrl,
            actionText: stepDef.actionText,
            requiredForScan: stepDef.requiredForScan,
          };
        }
      }

      return {
        id: stepDef.id,
        name: stepDef.name,
        success: false,
        error: message,
        actionUrl,
        actionText: stepDef.actionText,
        requiredForScan: stepDef.requiredForScan,
        adminActions: this.buildEnableApiAdminActions(stepDef, projectId, rawError, actionUrl),
      };
    } catch (err) {
      const rawError = err instanceof Error ? err.message : String(err);
      return {
        id: stepDef.id,
        name: stepDef.name,
        success: false,
        error: this.getEnableApiErrorMessage(stepDef.api, rawError),
        actionUrl,
        actionText: stepDef.actionText,
        requiredForScan: stepDef.requiredForScan,
        adminActions: this.buildEnableApiAdminActions(stepDef, projectId, rawError, actionUrl),
      };
    }
  }

  private async runGrantFindingsViewerSetupStep(params: {
    accessToken: string;
    organizationId: string;
    email: string | null;
  }): Promise<GcpSetupStep> {
    const { accessToken, organizationId, email } = params;

    if (!email) {
      return {
        id: 'grant_findings_viewer_role',
        name: 'Grant Findings Viewer role',
        success: false,
        error:
          'Could not identify your Google account email. Reconnect GCP and approve profile/email access.',
        ...FINDINGS_VIEWER_ACTION,
      };
    }

    if (!organizationId) {
      return {
        id: 'grant_findings_viewer_role',
        name: 'Grant Findings Viewer role',
        success: false,
        error: 'Organization ID not detected yet.',
        ...FINDINGS_VIEWER_ACTION,
      };
    }

    const adminActions = this.buildFindingsViewerAdminActions({
      organizationId,
      email,
    });

    try {
      const getPolicyResp = await fetch(
        `https://cloudresourcemanager.googleapis.com/v3/organizations/${organizationId}:getIamPolicy`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ options: { requestedPolicyVersion: 3 } }),
        },
      );

      if (!getPolicyResp.ok) {
        const rawError = await getPolicyResp.text();
        return {
          id: 'grant_findings_viewer_role',
          name: 'Grant Findings Viewer role',
          success: false,
          error: this.getFindingsViewerErrorMessage(rawError),
          ...FINDINGS_VIEWER_ACTION,
          adminActions,
        };
      }

      const policy = (await getPolicyResp.json()) as {
        version?: number;
        bindings?: Array<{ role: string; members: string[] }>;
        etag?: string;
      };

      const role = 'roles/securitycenter.findingsViewer';
      const member = `user:${email}`;
      const bindings = policy.bindings ?? [];
      const existing = bindings.find((b) => b.role === role);

      if (existing && existing.members.includes(member)) {
        return {
          id: 'grant_findings_viewer_role',
          name: 'Grant Findings Viewer role',
          success: true,
          ...FINDINGS_VIEWER_ACTION,
        };
      }

      if (existing) {
        existing.members.push(member);
      } else {
        bindings.push({ role, members: [member] });
      }

      const setPolicyResp = await fetch(
        `https://cloudresourcemanager.googleapis.com/v3/organizations/${organizationId}:setIamPolicy`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            policy: {
              version: policy.version ?? 3,
              bindings,
              ...(policy.etag ? { etag: policy.etag } : {}),
            },
            updateMask: 'bindings',
          }),
        },
      );

      if (setPolicyResp.ok) {
        return {
          id: 'grant_findings_viewer_role',
          name: 'Grant Findings Viewer role',
          success: true,
          ...FINDINGS_VIEWER_ACTION,
        };
      }

      const rawError = await setPolicyResp.text();
      return {
        id: 'grant_findings_viewer_role',
        name: 'Grant Findings Viewer role',
        success: false,
        error: this.getFindingsViewerErrorMessage(rawError),
        ...FINDINGS_VIEWER_ACTION,
        adminActions,
      };
    } catch (err) {
      const rawError = err instanceof Error ? err.message : String(err);
      return {
        id: 'grant_findings_viewer_role',
        name: 'Grant Findings Viewer role',
        success: false,
        error: this.getFindingsViewerErrorMessage(rawError),
        ...FINDINGS_VIEWER_ACTION,
        adminActions,
      };
    }
  }

  private buildEnableApiAdminActions(
    stepDef: (typeof REQUIRED_GCP_API_STEPS)[number],
    projectId: string,
    rawError?: string,
    actionUrl?: string,
  ): GcpSetupAdminAction[] {
    const actions: GcpSetupAdminAction[] = [
      {
        kind: 'link',
        label: stepDef.actionText,
        url: actionUrl ?? this.getApiConsoleUrl(stepDef.api, projectId),
      },
      {
        kind: 'command',
        label: `Copy: enable ${stepDef.api}`,
        command: `gcloud services enable ${stepDef.api} --project=${projectId}`,
      },
    ];

    if (rawError) {
      const permInfo = parseGcpPermissionError(rawError, projectId);
      if (permInfo.fixScript) {
        actions.push({
          kind: 'command',
          label: 'Copy: grant required project role',
          command: permInfo.fixScript,
        });
      }
    }

    return actions;
  }

  private getApiConsoleUrl(apiName: string, projectId: string): string {
    return `https://console.cloud.google.com/apis/library/${apiName}?project=${encodeURIComponent(projectId)}`;
  }

  private async isApiAlreadyEnabled(
    accessToken: string,
    projectId: string,
    apiName: string,
  ): Promise<boolean> {
    try {
      const resp = await fetch(
        `https://serviceusage.googleapis.com/v1/projects/${projectId}/services/${apiName}`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
        },
      );

      if (!resp.ok) return false;

      const data = (await resp.json()) as { state?: string };
      return data.state === 'ENABLED';
    } catch {
      return false;
    }
  }

  private buildFindingsViewerAdminActions(params: {
    organizationId: string;
    email: string;
  }): GcpSetupAdminAction[] {
    const { organizationId, email } = params;
    return [
      {
        kind: 'link',
        label: FINDINGS_VIEWER_ACTION.actionText,
        url: FINDINGS_VIEWER_ACTION.actionUrl,
      },
      {
        kind: 'command',
        label: 'Copy: grant Findings Viewer role',
        command: [
          `gcloud organizations add-iam-policy-binding ${organizationId}`,
          `  --member='user:${email}'`,
          "  --role='roles/securitycenter.findingsViewer'",
        ].join(' \\\n'),
      },
    ];
  }

  private extractGcpError(raw: string): string {
    let message = raw;
    try {
      const parsed = JSON.parse(raw) as { error?: { message?: string } };
      message = parsed.error?.message ?? raw;
    } catch {
      message = raw;
    }
    return message
      .replace(/\s*Help Token:\s*[\w-]+/gi, '')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 240);
  }

  private getEnableApiErrorMessage(apiName: string, raw: string): string {
    const message = this.extractGcpError(raw);

    if (
      /permission denied|does not have permission|forbidden|PERMISSION_DENIED/i.test(
        message,
      )
    ) {
      return `Your account cannot enable ${apiName}. Ask a project owner/editor to enable it.`;
    }

    return message || `Failed to enable ${apiName}.`;
  }

  private getFindingsViewerErrorMessage(raw: string): string {
    const message = this.extractGcpError(raw);

    if (/getIamPolicy|resourcemanager\.organizations\.getIamPolicy/i.test(message)) {
      return 'Your account cannot read organization IAM policy. Ask a GCP organization admin to grant roles/securitycenter.findingsViewer.';
    }

    if (
      /setIamPolicy|resourcemanager\.organizations\.setIamPolicy/i.test(message)
    ) {
      return 'Your account cannot grant org IAM roles. Ask a GCP organization admin to grant roles/securitycenter.findingsViewer.';
    }

    if (/permission denied|does not have permission|forbidden|PERMISSION_DENIED/i.test(message)) {
      return 'Your account does not have organization IAM permissions required for auto-setup. Ask a GCP organization admin to grant roles/securitycenter.findingsViewer.';
    }

    return (
      message ||
      'Unable to grant Findings Viewer role automatically. Ask a GCP organization admin to grant roles/securitycenter.findingsViewer.'
    );
  }

  /**
   * Auto-detect GCP organizations accessible by the OAuth token.
   */
  async detectOrganizations(
    accessToken: string,
  ): Promise<Array<{ id: string; displayName: string }>> {
    // v3 search API — works for listing all orgs the user has access to
    const response = await fetch(
      'https://cloudresourcemanager.googleapis.com/v3/organizations:search',
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
      },
    );

    if (!response.ok) {
      const errorText = await response.text();
      this.logger.warn(`Failed to search GCP organizations: ${errorText}`);
      return [];
    }

    const data = await response.json();
    const orgs = (data.organizations ?? []) as Array<{
      name: string;
      displayName?: string;
      state?: string;
    }>;

    return orgs
      .filter((o) => o.state === 'ACTIVE')
      .map((o) => ({
        // name is "organizations/123456"
        id: o.name.replace('organizations/', ''),
        displayName: o.displayName ?? o.name,
      }));
  }

  /**
   * Auto-detect active GCP projects accessible by the OAuth token.
   */
  async detectProjects(
    accessToken: string,
  ): Promise<Array<{ id: string; name: string; number: string }>> {
    const response = await fetch(
      'https://cloudresourcemanager.googleapis.com/v1/projects?filter=lifecycleState:ACTIVE&pageSize=50',
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
      },
    );

    if (!response.ok) {
      this.logger.warn(`Failed to list GCP projects`);
      return [];
    }

    const data = await response.json();
    return ((data.projects ?? []) as Array<{
      projectId: string;
      name: string;
      projectNumber: string;
    }>).map((p) => ({
      id: p.projectId,
      name: p.name,
      number: p.projectNumber,
    }));
  }

  /**
   * Detect which GCP services the customer actually uses by querying
   * the Service Usage API for each project. Maps GCP API names to
   * our service category IDs.
   */
  async detectServices(
    accessToken: string,
    projects: Array<{ id: string }>,
  ): Promise<string[]> {
    const detected = new Set<string>();

    for (const project of projects.slice(0, 5)) {
      try {
        const response = await fetch(
          `https://serviceusage.googleapis.com/v1/projects/${project.id}/services?filter=state:ENABLED&pageSize=200`,
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
              'Content-Type': 'application/json',
            },
          },
        );

        if (!response.ok) {
          this.logger.warn(`Failed to list services for project ${project.id}`);
          continue;
        }

        const data = await response.json();
        const services = (data.services ?? []) as Array<{
          name: string;
          config?: { name: string };
        }>;

        for (const svc of services) {
          const apiName = svc.config?.name ?? svc.name.split('/').pop() ?? '';
          const mapped = GCP_API_TO_SERVICE[apiName];
          if (mapped) {
            for (const id of mapped) detected.add(id);
          }
        }
      } catch (err) {
        this.logger.warn(
          `Service detection failed for ${project.id}: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    this.logger.log(`Detected ${detected.size} GCP service categories: ${[...detected].join(', ')}`);
    return [...detected];
  }

  /**
   * Scan GCP Security Command Center for all active findings.
   * Pulls rich data: description, remediation steps, compliance mappings, service grouping.
   */
  async scanSecurityFindings(
    credentials: Record<string, unknown>,
    variables: Record<string, unknown>,
    enabledServices?: string[],
  ): Promise<SecurityFinding[]> {
    const accessToken = credentials.access_token as string;
    const organizationId = variables.organization_id as string;

    if (!accessToken) {
      throw new Error('Access token is required');
    }
    if (!organizationId) {
      this.logger.warn('GCP Organization ID not configured');
      throw new Error(
        'GCP_ORG_MISSING: Organization ID not detected. Go to the GCP integration settings to auto-detect your organization.',
      );
    }

    this.logger.log(`Scanning GCP SCC for org ${organizationId}`);

    const allFindings: SecurityFinding[] = [];
    const enabledServiceSet = enabledServices ? new Set(enabledServices) : null;
    let pageToken: string | undefined;

    do {
      const response = await this.fetchFindings(accessToken, organizationId, pageToken);

      for (const result of response.findings) {
        const f = result.finding;
        const serviceId = CATEGORY_TO_SERVICE[f.category] ?? 'security-command-center';
        if (enabledServiceSet && !enabledServiceSet.has(serviceId)) {
          continue;
        }
        const findingKey = `gcp-${serviceId}-${f.category.toLowerCase().replace(/_/g, '-')}`;

        // Build remediation text from SCC's nextSteps + our AI guidance hint
        const remediation = this.buildRemediation(f);

        allFindings.push({
          id: f.name,
          title: this.formatTitle(f.category),
          description: f.description || `Security finding: ${f.category}`,
          severity: this.mapSeverity(f.severity),
          resourceType: result.resource?.type ?? 'gcp-resource',
          resourceId: f.resourceName,
          remediation,
          evidence: {
            findingKey,
            serviceId,
            serviceName: SERVICE_NAMES[serviceId] ?? serviceId,
            category: f.category,
            state: f.state,
            resourceName: f.resourceName,
            severity: f.severity,
            eventTime: f.eventTime,
            externalUri: f.externalUri,
            findingClass: f.findingClass,
            compliances: f.compliances,
            sourceProperties: f.sourceProperties,
            projectDisplayName: result.resource?.projectDisplayName,
            resourceDisplayName: result.resource?.displayName,
          },
          createdAt: f.createTime,
        });
      }

      pageToken = response.nextPageToken;
    } while (pageToken);

    this.logger.log(`Found ${allFindings.length} GCP security findings`);
    return allFindings;
  }

  private async fetchFindings(
    accessToken: string,
    organizationId: string,
    pageToken?: string,
  ): Promise<{ findings: SCCFindingResult[]; nextPageToken?: string }> {
    const url = new URL(
      `https://securitycenter.googleapis.com/v2/organizations/${organizationId}/sources/-/findings`,
    );
    url.searchParams.set('pageSize', '500');
    url.searchParams.set('filter', 'state="ACTIVE"');

    if (pageToken) {
      url.searchParams.set('pageToken', pageToken);
    }

    const response = await fetch(url.toString(), {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      this.logger.error(`GCP SCC API error: ${errorText}`);

      if (errorText.includes('ACCESS_TOKEN_SCOPE_INSUFFICIENT')) {
        throw new Error('OAuth scopes insufficient. Reconnect the GCP integration.');
      }
      if (
        errorText.includes('SERVICE_DISABLED') ||
        errorText.includes('has not been used') ||
        errorText.includes('Security Command Center API')
      ) {
        throw new Error(
          'SCC_NOT_ACTIVATED: Security Command Center is not activated on your GCP organization. ' +
          'Enable it at https://console.cloud.google.com/security/command-center — the Standard tier is free.',
        );
      }
      if (errorText.includes('PERMISSION_DENIED') || errorText.includes('403')) {
        throw new Error(
          'Permission denied. Grant "Security Center Findings Viewer" role at the organization level.',
        );
      }

      if (errorText.includes('Security Command Center Legacy')) {
        throw new Error(
          'Security Command Center Legacy has been disabled by Google. ' +
            'Please activate the Standard or Premium tier in your GCP console: ' +
            'Security > Security Command Center > Settings.',
        );
      }

      if (errorText.includes('Security Command Center API has not been used')) {
        throw new Error(
          'The Security Command Center API is not enabled for this project. ' +
            'Enable it in the GCP console: APIs & Services > Enable APIs > Security Command Center API.',
        );
      }

      throw new Error(`GCP API error (${response.status}): ${errorText}`);
    }

    const data = await response.json();
    return {
      findings: data.listFindingsResults ?? [],
      nextPageToken: data.nextPageToken,
    };
  }

  /** Build remediation text from SCC's nextSteps + API context for AI auto-fix. */
  private buildRemediation(f: SCCFinding): string {
    const parts: string[] = [];

    if (f.nextSteps) {
      parts.push(f.nextSteps);
    }

    if (f.externalUri) {
      parts.push(`More info: ${f.externalUri}`);
    }

    if (f.compliances?.length) {
      const standards = f.compliances.map((c) => `${c.standard} ${c.version} (${c.ids.join(', ')})`);
      parts.push(`Compliance: ${standards.join('; ')}`);
    }

    return parts.join('\n\n') || `Review and remediate this ${f.category} finding in GCP Console.`;
  }

  /** Convert SCC SCREAMING_SNAKE_CASE category to readable title. */
  private formatTitle(category: string): string {
    return category
      .split('_')
      .map((w) => w.charAt(0) + w.slice(1).toLowerCase())
      .join(' ');
  }

  private mapSeverity(gcpSeverity: string): SecurityFinding['severity'] {
    const map: Record<string, SecurityFinding['severity']> = {
      CRITICAL: 'critical',
      HIGH: 'high',
      MEDIUM: 'medium',
      LOW: 'low',
    };
    return map[gcpSeverity] ?? 'medium';
  }
}
