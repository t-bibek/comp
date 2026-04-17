'use client';

import { apiClient } from '@/lib/api-client';
import useSWR from 'swr';

interface PolicyOption {
  id: string;
  name: string;
}

interface TaskOption {
  id: string;
  title: string;
}

interface RequirementOption {
  id: string;
  name: string;
  identifier: string;
  frameworkInstanceId: string;
  frameworkName: string;
}

interface ControlOptionsResponse {
  policies: PolicyOption[];
  tasks: TaskOption[];
  requirements: RequirementOption[];
}

export function useControlOptions(enabled: boolean) {
  const { data, isLoading, mutate } = useSWR<ControlOptionsResponse>(
    enabled ? '/v1/controls/options' : null,
    async (url: string) => {
      const res = await apiClient.get<ControlOptionsResponse>(url);
      if (res.error) throw new Error(res.error);
      return (
        res.data ?? {
          policies: [],
          tasks: [],
          requirements: [],
        }
      );
    },
    { revalidateOnFocus: false },
  );

  return {
    policies: data?.policies ?? [],
    tasks: data?.tasks ?? [],
    requirements: data?.requirements ?? [],
    isLoading,
    mutate,
  };
}
