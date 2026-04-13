import { render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi, beforeEach } from 'vitest';

const mockPost = vi.fn();

vi.mock('@/hooks/use-api', () => ({
  useApi: () => ({
    post: mockPost,
  }),
}));

vi.mock('sonner', () => ({
  toast: {
    error: vi.fn(),
    success: vi.fn(),
    message: vi.fn(),
  },
}));

import { GcpSetupGuide } from './GcpSetupGuide';

describe('GcpSetupGuide', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders actionable failed setup steps from API response', async () => {
    mockPost.mockResolvedValue({
      data: {
        email: 'user@example.com',
        organizationId: '123456789',
        steps: [
          {
            id: 'enable_security_command_center_api',
            name: 'Enable Security Command Center API',
            success: false,
            error: 'Permission denied',
            actionUrl:
              'https://console.cloud.google.com/apis/library/securitycenter.googleapis.com',
            actionText: 'Open API',
          },
          {
            id: 'grant_findings_viewer_role',
            name: 'Grant Findings Viewer role',
            success: false,
            error: 'Need org admin role',
            actionUrl: 'https://console.cloud.google.com/iam-admin/iam',
            actionText: 'Open IAM',
          },
        ],
      },
    });

    render(
      <GcpSetupGuide
        connectionId="conn_1"
        hasOrgId={false}
        onRunScan={vi.fn()}
        isScanning={false}
      />,
    );

    await waitFor(() =>
      expect(screen.getByText('Some steps need manual setup:')).toBeInTheDocument(),
    );

    expect(
      screen.getAllByText('Enable Security Command Center API').length,
    ).toBeGreaterThan(0);
    expect(screen.getAllByText('Grant Findings Viewer role').length).toBeGreaterThan(0);
    expect(screen.getByRole('link', { name: /Open API/i })).toHaveAttribute(
      'href',
      'https://console.cloud.google.com/apis/library/securitycenter.googleapis.com',
    );
    expect(screen.getByRole('link', { name: /Open IAM/i })).toHaveAttribute(
      'href',
      'https://console.cloud.google.com/iam-admin/iam',
    );
    expect(screen.getByRole('button', { name: 'Retry setup' })).toBeInTheDocument();
  });
});
