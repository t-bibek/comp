'use client';

import type {
  Control,
  FrameworkEditorFramework,
  FrameworkEditorRequirement,
  FrameworkInstance,
  Policy,
  RequirementMap,
  Task,
} from '@db';
import {
  PageHeader,
  PageHeaderActions,
  PageLayout,
  Stack,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@trycompai/design-system';
import { useState } from 'react';
import { PoliciesTable } from '@/app/(app)/[orgId]/controls/[controlId]/components/PoliciesTable';
import { RequirementsTable } from '@/app/(app)/[orgId]/controls/[controlId]/components/RequirementsTable';
import { TasksTable } from '@/app/(app)/[orgId]/controls/[controlId]/components/TasksTable';
import { LinkPolicySheet } from './LinkPolicySheet';
import { LinkRequirementForControlSheet } from './LinkRequirementForControlSheet';
import { LinkTaskSheet } from './LinkTaskSheet';

type ControlDetail = Control & {
  policies: Policy[];
  tasks: Task[];
  requirementsMapped: (RequirementMap & {
    frameworkInstance: FrameworkInstance & {
      framework: FrameworkEditorFramework;
    };
    requirement: FrameworkEditorRequirement;
  })[];
};

interface Breadcrumb {
  label: string;
  href?: string;
  isCurrent?: boolean;
}

interface Props {
  orgId: string;
  control: ControlDetail;
  breadcrumbs: Breadcrumb[];
}

export function FrameworkControlShell({
  orgId,
  control,
  breadcrumbs,
}: Props) {
  const [activeTab, setActiveTab] = useState('policies');

  const linkedPolicyIds = control.policies.map((p) => p.id);
  const linkedTaskIds = control.tasks.map((t) => t.id);
  const linkedRequirementIds = control.requirementsMapped.map(
    (rm) => rm.requirement.id,
  );

  const actions =
    activeTab === 'policies' ? (
      <LinkPolicySheet
        controlId={control.id}
        alreadyLinkedPolicyIds={linkedPolicyIds}
      />
    ) : activeTab === 'tasks' ? (
      <LinkTaskSheet
        controlId={control.id}
        alreadyLinkedTaskIds={linkedTaskIds}
      />
    ) : (
      <LinkRequirementForControlSheet
        controlId={control.id}
        alreadyLinkedRequirementIds={linkedRequirementIds}
      />
    );

  return (
    <Tabs value={activeTab} onValueChange={setActiveTab}>
      <PageLayout
        header={
          <PageHeader title={control.name} breadcrumbs={breadcrumbs}>
            <PageHeaderActions>{actions}</PageHeaderActions>
          </PageHeader>
        }
      >
        <Stack gap="lg">
          <TabsList variant="underline">
            <TabsTrigger value="policies">
              Policies ({control.policies.length})
            </TabsTrigger>
            <TabsTrigger value="tasks">
              Tasks ({control.tasks.length})
            </TabsTrigger>
            <TabsTrigger value="requirements">
              Requirements ({control.requirementsMapped.length})
            </TabsTrigger>
          </TabsList>

          <TabsContent value="policies">
            <PoliciesTable policies={control.policies} orgId={orgId} />
          </TabsContent>

          <TabsContent value="tasks">
            <TasksTable tasks={control.tasks} orgId={orgId} />
          </TabsContent>

          <TabsContent value="requirements">
            <RequirementsTable
              requirements={control.requirementsMapped}
              orgId={orgId}
            />
          </TabsContent>
        </Stack>
      </PageLayout>
    </Tabs>
  );
}
