import {
  Box,
  Cloud,
  Database,
  Globe,
  HardDrive,
  Server,
  UserCog,
  type LucideIcon,
} from 'lucide-react';
import type { NodeKind, Severity } from '@/types/domain';

export const KIND_ICON: Record<NodeKind, LucideIcon> = {
  compute: Server,
  database: Database,
  storage: HardDrive,
  network: Globe,
  identity: UserCog,
  endpoint: Box,
  external: Cloud,
};

export const SEVERITY_TOKEN: Record<string, string> = {
  critical: 'hsl(var(--critical))',
  high: 'hsl(var(--high))',
  medium: 'hsl(var(--medium))',
  low: 'hsl(var(--low))',
  CRITICAL: 'hsl(var(--critical))',
  HIGH: 'hsl(var(--high))',
  MEDIUM: 'hsl(var(--medium))',
  LOW: 'hsl(var(--low))',
};

export function riskColor(score: number): string {
  if (score >= 75) return 'hsl(var(--critical))';
  if (score >= 55) return 'hsl(var(--high))';
  if (score >= 35) return 'hsl(var(--medium))';
  return 'hsl(var(--low))';
}