'use client';

import { useEffect, useMemo } from 'react';
import {
  Background,
  Controls,
  MiniMap,
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
import type { AttackPath, TwinGraphData } from '@/types/domain';

const nodeTypes = { twinNode: TwinNode };

interface Props {
  twin: TwinGraphData;
  activePath?: AttackPath | null;
  highlightNodeIds?: string[];
}

function Inner({ twin, activePath, highlightNodeIds }: Props) {
  const selectedNodeId = useUI((s) => s.selectedNodeId);
  const setSelectedNode = useUI((s) => s.setSelectedNode);

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
        const dimmed = !!inPath && !onPath;
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
            riskScore: n.riskScore,
            criticality: n.criticality,
            isCrownJewel: n.isCrownJewel,
            dimmed,
            onPath: onPath || highlight.has(n.id),
            selected: selectedNodeId === n.id,
          } satisfies TwinNodeData,
        };
      }),
    [twin.nodes, inPath, highlight, selectedNodeId],
  );

  const rfEdges: Edge[] = useMemo(
    () =>
      twin.edges.map((e) => {
        const onPath = inPath?.edges.has(e.id) ?? false;
        const stroke = onPath
          ? 'hsl(var(--critical))'
          : e.exploitable
          ? 'hsl(var(--high))'
          : 'hsl(var(--border))';
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          type: 'smoothstep',
          animated: onPath,
          style: {
            stroke,
            strokeWidth: onPath ? 2.5 : 1.2,
            opacity: inPath && !onPath ? 0.12 : 1,
          },
        };
      }),
    [twin.edges, inPath],
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
      >
        <Background gap={24} size={1} color="hsl(var(--border))" />
        <Controls position="bottom-right" showInteractive={false} />
        <MiniMap
          pannable
          zoomable
          nodeColor={(n) => {
            const d = n.data as TwinNodeData;
            if (d.onPath) return 'hsl(var(--critical))';
            if (d.isCrownJewel) return 'hsl(var(--medium))';
            return 'hsl(var(--muted-foreground))';
          }}
          maskColor="hsl(var(--background) / 0.7)"
        />
      </ReactFlow>
    </div>
  );
}

export function TwinGraph(props: Props) {
  return (
    <ReactFlowProvider>
      <Inner {...props} />
    </ReactFlowProvider>
  );
}