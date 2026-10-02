import dagre from '@dagrejs/dagre';
import type { Edge, Node } from '@xyflow/react';

export function layout(nodes: Node[], edges: Edge[], dir: 'LR' | 'TB' = 'LR') {
  const g = new dagre.graphlib.Graph().setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: dir, nodesep: 60, ranksep: 140, marginx: 40, marginy: 40 });
  nodes.forEach((n) => g.setNode(n.id, { width: 220, height: 84 }));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);
  return nodes.map((n) => {
    const p = g.node(n.id);
    return { ...n, position: { x: p.x - 110, y: p.y - 42 } };
  });
}