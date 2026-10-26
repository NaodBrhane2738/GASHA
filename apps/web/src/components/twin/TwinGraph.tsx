'use client';

import { useEffect, useMemo } from 'react';
import {
  Background,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  type Edge,
  type Node,
  type NodeMouseHandler,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { TwinNode, type TwinNodeData } from './TwinNode';
import { layout } from '@/lib/graph/layout';
import { useUI } from '@/store/ui';
import { useDetections, useIncidents, useResponses } from '@/lib/api/queries';
import type { AttackPath, TwinGraphData } from '@/types/domain';

const nodeTypes = { twinNode: TwinNode };

export interface TwinGraphProps {
  twin: TwinGraphData;
  activePath?: AttackPath | null;
  highlightNodeIds?: string[];
  simulatedAttackNodeId?: string | null;
}

interface AttackedInfo {
  technique: string;
  severity: string;
  summary: string;
  count: number;
}

function Inner({ twin, activePath, highlightNodeIds, simulatedAttackNodeId }: TwinGraphProps) {
  const selectedNodeId = useUI((s) => s.selectedNodeId);
  const setSelectedNode = useUI((s) => s.setSelectedNode);

  const { data: detections } = useDetections();
  const { data: incidents } = useIncidents();

  // Correlate live detections & active incidents to identify nodes currently under attack
  const attackedMap = useMemo(() => {
    const map = new Map<string, AttackedInfo>();
    const now = Date.now();
    // 90 second sliding window for live telemetry attack reaction
    const RECENT_WINDOW_MS = 90_000;

    // 1. Check live detections
    if (detections && Array.isArray(detections)) {
      for (const det of detections) {
        const rawTime = det.ts || (det as any).timestamp;
        const timeMs = rawTime ? new Date(rawTime).getTime() : 0;
        const isRecent = !timeMs || (now - timeMs) <= RECENT_WINDOW_MS;
        const targetId = det.nodeId || (det as any).primaryAssetId;

        if (targetId && isRecent) {
          const ruleObj = typeof det.rule === 'object' ? det.rule : null;
          const technique =
            det.technique ||
            (det as any).metadata?.mitreTechniqueId ||
            ruleObj?.ruleId ||
            'T1110';
          const summary =
            det.summary ||
            (det as any).evidenceSummary ||
            ruleObj?.name ||
            'Active incursion detected';
          const severity = String(det.severity || ruleObj?.severity || 'HIGH').toLowerCase();

          const existing = map.get(targetId);
          if (!existing) {
            map.set(targetId, {
              technique,
              severity,
              summary,
              count: 1,
            });
          } else {
            existing.count += 1;
          }
        }
      }
    }

    // 2. Check active incidents
    if (incidents && Array.isArray(incidents)) {
      for (const inc of incidents) {
        const status = String(inc.status).toUpperCase();
        if (status === 'ACTIVE' || status === 'INVESTIGATING' || status === 'OPEN') {
          const targetId = (inc as any).primaryAffectedAssetId || inc.pathId;
          if (targetId) {
            const existing = map.get(targetId);
            if (!existing) {
              map.set(targetId, {
                technique: 'INCIDENT ACTIVE',
                severity: String(inc.severity || 'CRITICAL').toLowerCase(),
                summary: inc.title,
                count: 1,
              });
            }
          }
          // Also related assets affected
          const related = (inc as any).relatedAssetIds;
          if (Array.isArray(related)) {
            for (const relId of related) {
              if (!map.has(relId)) {
                map.set(relId, {
                  technique: 'ATTACK CHAIN',
                  severity: String(inc.severity || 'HIGH').toLowerCase(),
                  summary: inc.title,
                  count: 1,
                });
              }
            }
          }
        }
      }
    }

    // 3. Simulated test threat injection (if triggered via UI toggle)
    if (simulatedAttackNodeId && !map.has(simulatedAttackNodeId)) {
      map.set(simulatedAttackNodeId, {
        technique: 'T1110 · Brute Force',
        severity: 'critical',
        summary: 'Simulated brute force authentication incursion',
        count: 5,
      });
    }

    return map;
  }, [detections, incidents, simulatedAttackNodeId]);

  const inPath = useMemo(() => {
    if (!activePath) return null;
    return {
      nodes: new Set(activePath.nodeIds),
      edges: new Set(activePath.edgeIds),
    };
  }, [activePath]);

  const highlight = useMemo(() => new Set(highlightNodeIds ?? []), [highlightNodeIds]);

  const rfNodes: Node[] = useMemo(
    () =>
      twin.nodes.map((n) => {
        const onPath = inPath?.nodes.has(n.id) ?? false;
        const attackInfo = attackedMap.get(n.id);
        const isAttacked = !!attackInfo;
        const dimmed = !!inPath && !onPath && !isAttacked;

        return {
          id: n.id,
          type: 'twinNode',
          position: { x: 0, y: 0 },
          draggable: false,
          data: {
            label: n.label,
            kind: n.kind,
            provider: n.provider,
            exposure: n.exposure,
            riskScore: isAttacked ? 99 : n.riskScore,
            criticality: n.criticality,
            isCrownJewel: n.isCrownJewel,
            dimmed,
            onPath: onPath || highlight.has(n.id) || isAttacked,
            selected: selectedNodeId === n.id,
            isAttacked,
            attackTechnique: attackInfo?.technique,
            attackSeverity: attackInfo?.severity,
            attackSummary: attackInfo?.summary,
            attackCount: attackInfo?.count,
          } satisfies TwinNodeData,
        };
      }),
    [twin.nodes, inPath, highlight, selectedNodeId, attackedMap],
  );

  const rfEdges: Edge[] = useMemo(
    () =>
      twin.edges.map((e) => {
        const onPath = inPath?.edges.has(e.id) ?? false;
        const isTargetAttacked = attackedMap.has(e.target);
        const isSourceAttacked = attackedMap.has(e.source);
        const isAttackEdge = isTargetAttacked || (isSourceAttacked && (onPath || e.exploitable));

        let stroke = 'hsl(var(--border))';
        let strokeWidth = 1.2;
        let animated = false;
        let className = '';

        if (isAttackEdge) {
          stroke = '#ef4444';
          strokeWidth = 3;
          animated = true;
          className = 'threat-edge-active';
        } else if (onPath) {
          stroke = 'hsl(var(--critical))';
          strokeWidth = 2.5;
          animated = true;
        } else if (e.exploitable) {
          stroke = 'hsl(var(--high))';
        }

        return {
          id: e.id,
          source: e.source,
          target: e.target,
          type: 'smoothstep',
          animated,
          className,
          style: {
            stroke,
            strokeWidth,
            opacity: inPath && !onPath && !isAttackEdge ? 0.12 : 1,
          },
        };
      }),
    [twin.edges, inPath, attackedMap],
  );

  const laidOut = useMemo(() => layout(rfNodes, rfEdges, 'LR'), [rfNodes, rfEdges]);

  const [nodes, setNodes, onNodesChange] = useNodesState(laidOut);
  const [edges, setEdges, onEdgesChange] = useEdgesState(rfEdges);

  useEffect(() => setNodes(laidOut), [laidOut, setNodes]);
  useEffect(() => setEdges(rfEdges), [rfEdges, setEdges]);

  const onNodeClick: NodeMouseHandler = (_, n) => {
    setSelectedNode(n.id === selectedNodeId ? null : n.id);
  };

  return (
    <div className="h-full w-full">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onPaneClick={() => setSelectedNode(null)}
        fitView
        fitViewOptions={{ padding: 0.25 }}
        minZoom={0.2}
        maxZoom={2}
        onlyRenderVisibleElements
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={24} size={1} color="hsl(var(--border))" />
      </ReactFlow>
    </div>
  );
}

export function TwinGraph(props: TwinGraphProps) {
  return (
    <ReactFlowProvider>
      <Inner {...props} />
    </ReactFlowProvider>
  );
}
