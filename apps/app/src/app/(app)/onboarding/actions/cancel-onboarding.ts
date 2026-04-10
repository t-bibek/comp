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

    // Verify the user owns this org
    const member = await db.member.findFirst({
      where: {
        userId: session.user.id,
        organizationId: parsedInput.organizationId,
        role: { contains: 'owner' },
      },
    });

    if (!member) {
      return { success: false, error: 'Only the owner can cancel onboarding.' };
    }

    // Find a fallback org to switch to (completed, with access)
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

    // Delete the incomplete org (cascade handles related records)
    try {
      await db.organization.delete({
        where: { id: parsedInput.organizationId },
      });
    } catch (error) {
      console.error('Failed to delete organization:', error);
      return { success: false, error: 'Failed to cancel onboarding.' };
    }

    // Switch to fallback org if available
    if (fallbackOrg) {
      try {
        await auth.api.setActiveOrganization({
          headers: await headers(),
          body: { organizationId: fallbackOrg.organizationId },
        });
      } catch (error) {
        console.error('Failed to switch to fallback org:', error);
      }
    }

    return {
      success: true,
      fallbackOrgId: fallbackOrg?.organizationId ?? null,
    };
  });
