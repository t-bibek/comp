'use server';

import { authActionClientWithoutOrg } from '@/actions/safe-action';
import { auth } from '@/utils/auth';
import { db } from '@db/server';
import { headers } from 'next/headers';
import { z } from 'zod';

const cancelSchema = z.object({
  organizationId: z.string().min(1),
});

export const cancelOnboarding = authActionClientWithoutOrg
  .inputSchema(cancelSchema)
  .metadata({
    name: 'cancel-onboarding',
    track: {
      event: 'cancel-onboarding',
      channel: 'server',
    },
  })
  .action(async ({ parsedInput, ctx }) => {
    const session = await auth.api.getSession({
      headers: await headers(),
    });

    if (!session) {
      return { success: false, error: 'Not authorized.' };
    }

    // Verify the user owns this org and it's still incomplete
    const member = await db.member.findFirst({
      where: {
        userId: session.user.id,
        organizationId: parsedInput.organizationId,
        role: { contains: 'owner' },
      },
      include: { organization: { select: { onboardingCompleted: true } } },
    });

    if (!member) {
      return { success: false, error: 'Only the owner can cancel onboarding.' };
    }

    if (member.organization.onboardingCompleted) {
      return { success: false, error: 'Cannot cancel a completed organization.' };
    }

    // Find a fallback org to switch to BEFORE deleting
    const fallbackOrg = await db.member.findFirst({
      where: {
        userId: session.user.id,
        organizationId: { not: parsedInput.organizationId },
        deactivated: false,
        organization: {
          onboardingCompleted: true,
          hasAccess: true,
        },
      },
      select: { organizationId: true },
      orderBy: { createdAt: 'desc' },
    });

    // Switch active org BEFORE deletion so the session never
    // references a deleted org (even if the client redirect is slow).
    if (fallbackOrg) {
      try {
        await auth.api.setActiveOrganization({
          headers: await headers(),
          body: { organizationId: fallbackOrg.organizationId },
        });
      } catch (error) {
        console.error('Failed to switch to fallback org:', error);
        return { success: false, error: 'Failed to switch organization.' };
      }
    }

    // Delete the incomplete org (cascade handles related records)
    try {
      await db.organization.delete({
        where: { id: parsedInput.organizationId },
      });
    } catch (error) {
      console.error('Failed to delete organization:', error);
      return { success: false, error: 'Failed to cancel onboarding.' };
    }

    return {
      success: true,
      fallbackOrgId: fallbackOrg?.organizationId ?? null,
    };
  });
