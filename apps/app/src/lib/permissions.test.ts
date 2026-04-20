import { describe, expect, it } from 'vitest';
import {
  canAccessApp,
  canAccessCompliance,
  canAccessRoute,
  getDefaultRoute,
  hasPermission,
  mergePermissions,
  resolveBuiltInPermissions,
  type UserPermissions,
} from './permissions';

describe('canAccessApp', () => {
  it('returns true for users with explicit app:read', () => {
    const permissions: UserPermissions = { app: ['read'] };
    expect(canAccessApp(permissions)).toBe(true);
  });

  it('returns true for users with pentest permissions (custom role)', () => {
    const permissions: UserPermissions = { pentest: ['create', 'read', 'delete'] };
    expect(canAccessApp(permissions)).toBe(true);
  });

  it('returns true for users with any app-implying resource', () => {
    const permissions: UserPermissions = { control: ['read'] };
    expect(canAccessApp(permissions)).toBe(true);
  });

  it('returns false for portal-only users (employee: policy + compliance only)', () => {
    const permissions: UserPermissions = {
      policy: ['read'],
      compliance: ['required'],
    };
    expect(canAccessApp(permissions)).toBe(false);
  });

  it('returns false for empty permissions', () => {
    expect(canAccessApp({})).toBe(false);
  });

  it('returns false for users with only compliance:required', () => {
    const permissions: UserPermissions = { compliance: ['required'] };
    expect(canAccessApp(permissions)).toBe(false);
  });

  it('returns false for users with only policy:read', () => {
    const permissions: UserPermissions = { policy: ['read'] };
    expect(canAccessApp(permissions)).toBe(false);
  });
});

describe('canAccessRoute', () => {
  it('allows access to penetration-tests with pentest:read', () => {
    const permissions: UserPermissions = { pentest: ['read'] };
    expect(canAccessRoute(permissions, 'penetration-tests')).toBe(true);
  });

  it('denies access to penetration-tests without pentest:read', () => {
    const permissions: UserPermissions = { control: ['read'] };
    expect(canAccessRoute(permissions, 'penetration-tests')).toBe(false);
  });

  it('allows access to unknown routes by default', () => {
    const permissions: UserPermissions = {};
    expect(canAccessRoute(permissions, 'nonexistent-route')).toBe(true);
  });

});

describe('getDefaultRoute', () => {
  it('returns penetration-tests for pentest-only users', () => {
    const permissions: UserPermissions = { pentest: ['create', 'read', 'delete'] };
    const route = getDefaultRoute(permissions, 'org_123');
    expect(route).toBe('/org_123/security/penetration-tests');
  });

  it('returns frameworks as first route for full-access users', () => {
    const permissions: UserPermissions = {
      app: ['read'],
      framework: ['read'],
      control: ['read'],
      pentest: ['read'],
    };
    const route = getDefaultRoute(permissions, 'org_123');
    expect(route).toBe('/org_123/frameworks');
  });

  it('returns null for users with no permissions at all', () => {
    const permissions: UserPermissions = {};
    const route = getDefaultRoute(permissions, 'org_123');
    expect(route).toBeNull();
  });
});

describe('canAccessCompliance', () => {
  it('returns true when user has framework:read', () => {
    const permissions: UserPermissions = { framework: ['read'] };
    expect(canAccessCompliance(permissions)).toBe(true);
  });

  it('returns true when user has policy:read only', () => {
    const permissions: UserPermissions = { policy: ['read'] };
    expect(canAccessCompliance(permissions)).toBe(true);
  });

  it('returns true when user has control:read', () => {
    const permissions: UserPermissions = { control: ['read'] };
    expect(canAccessCompliance(permissions)).toBe(true);
  });

  it('returns false when user has only pentest permissions', () => {
    const permissions: UserPermissions = { pentest: ['create', 'read', 'delete'] };
    expect(canAccessCompliance(permissions)).toBe(false);
  });

  it('returns false for empty permissions', () => {
    expect(canAccessCompliance({})).toBe(false);
  });
});

describe('hasPermission', () => {
  it('returns true when permission exists', () => {
    const permissions: UserPermissions = { pentest: ['create', 'read'] };
    expect(hasPermission(permissions, 'pentest', 'read')).toBe(true);
  });

  it('returns false when resource is missing', () => {
    const permissions: UserPermissions = {};
    expect(hasPermission(permissions, 'pentest', 'read')).toBe(false);
  });

  it('returns false when action is not in the list', () => {
    const permissions: UserPermissions = { pentest: ['read'] };
    expect(hasPermission(permissions, 'pentest', 'create')).toBe(false);
  });
});

// CS-189: Auditor View is gated by `audit:read` (see ROUTE_PERMISSIONS.auditor).
// Owners/admins intentionally do NOT have audit:read in their built-in role
// definitions (packages/auth/src/permissions.ts) — that permission is reserved
// for the built-in `auditor` role or for custom org roles that explicitly
// opt in. This test exercises the full resolution path the app uses.
describe('Auditor View visibility (audit:read gating)', () => {
  const resolve = (
    roleString: string,
    customRolePerms: UserPermissions = {},
  ): UserPermissions => {
    const { permissions } = resolveBuiltInPermissions(roleString);
    mergePermissions(permissions, customRolePerms);
    return permissions;
  };

  it('shows for the built-in auditor role', () => {
    expect(canAccessRoute(resolve('auditor'), 'auditor')).toBe(true);
  });

  it('shows when auditor is one of several roles (e.g. owner,auditor)', () => {
    expect(canAccessRoute(resolve('owner,auditor'), 'auditor')).toBe(true);
    expect(canAccessRoute(resolve('admin, auditor'), 'auditor')).toBe(true);
  });

  it('hides for owner alone (no audit:read on owner role)', () => {
    expect(canAccessRoute(resolve('owner'), 'auditor')).toBe(false);
  });

  it('hides for admin alone (no audit:read on admin role)', () => {
    expect(canAccessRoute(resolve('admin'), 'auditor')).toBe(false);
  });

  it('hides for employee / contractor', () => {
    expect(canAccessRoute(resolve('employee'), 'auditor')).toBe(false);
    expect(canAccessRoute(resolve('contractor'), 'auditor')).toBe(false);
  });

  it('shows when a custom role explicitly grants audit:read', () => {
    expect(
      canAccessRoute(resolve('CompAI', { audit: ['read'] }), 'auditor'),
    ).toBe(true);
  });

  it('shows when owner is combined with a custom role that grants audit:read', () => {
    expect(
      canAccessRoute(resolve('owner,CompAI', { audit: ['read'] }), 'auditor'),
    ).toBe(true);
  });

  it('hides when owner has a custom role that does NOT grant audit:read', () => {
    expect(
      canAccessRoute(
        resolve('owner,ReadOnlyViewer', { evidence: ['read'] }),
        'auditor',
      ),
    ).toBe(false);
  });

  it('hides when role string is empty', () => {
    expect(canAccessRoute(resolve(''), 'auditor')).toBe(false);
  });
});
