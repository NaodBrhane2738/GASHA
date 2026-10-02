import type { ResponseAction } from '@/types/domain';

export const responsesFixture: ResponseAction[] = [
  {
    id: 'ra-1',
    incidentId: 'inc-1',
    kind: 'isolate-host',
    target: 'auth-svc',
    requiresApproval: true,
    state: 'proposed',
    blastRadius: {
      nodeIds: ['auth-svc', 'api-gate', 'web-app'],
      servicesAffected: ['Login', 'Checkout', 'Admin Console'],
      estimatedDowntime: '~2 min',
    },
    riskReduction: 34,
  },
  {
    id: 'ra-2',
    incidentId: 'inc-1',
    kind: 'revoke-credential',
    target: 'svc-role-auth',
    requiresApproval: true,
    state: 'proposed',
    blastRadius: {
      nodeIds: ['auth-svc'],
      servicesAffected: ['Background sync'],
      estimatedDowntime: 'none',
    },
    riskReduction: 18,
  },
  {
    id: 'ra-3',
    incidentId: 'inc-1',
    kind: 'block-ip',
    target: '203.0.113.0/24',
    requiresApproval: false,
    state: 'done',
    blastRadius: { nodeIds: ['edge-lb'], servicesAffected: [], estimatedDowntime: 'none' },
    riskReduction: 6,
  },
  {
    id: 'ra-4',
    incidentId: 'inc-2',
    kind: 'disable-route',
    target: 'worker→outbound',
    requiresApproval: true,
    state: 'proposed',
    blastRadius: {
      nodeIds: ['worker'],
      servicesAffected: ['Email digest', 'Report generator'],
      estimatedDowntime: '~10 min',
    },
    riskReduction: 12,
  },
];