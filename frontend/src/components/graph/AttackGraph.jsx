import React, { useMemo } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType
} from 'reactflow';
import 'reactflow/dist/style.css';
import { Mail, Globe, Server, Link2, Paperclip, User, ShieldAlert, Cpu } from 'lucide-react';

const NODE_COLORS = {
  email: { bg: '#0284c7', border: '#38bdf8', icon: Mail, label: 'Email Root' },
  sender: { bg: '#9333ea', border: '#c084fc', icon: User, label: 'Sender' },
  reply_to: { bg: '#d97706', border: '#fbbf24', icon: User, label: 'Reply-To' },
  domain: { bg: '#059669', border: '#34d399', icon: Globe, label: 'Domain' },
  url: { bg: '#ea580c', border: '#fb923c', icon: Link2, label: 'URL' },
  ip: { bg: '#0891b2', border: '#22d3ee', icon: Server, label: 'IP Node' },
  asn: { bg: '#4f46e5', border: '#818cf8', icon: Cpu, label: 'ASN' },
  attachment: { bg: '#e11d48', border: '#fb7185', icon: Paperclip, label: 'Attachment' }
};

export const AttackGraph = ({ graphData }) => {
  // Compute positions using radial / hierarchy layout
  const { initialNodes, initialEdges } = useMemo(() => {
    if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
      return { initialNodes: [], initialEdges: [] };
    }

    const total = graphData.nodes.length;
    const radius = 220;
    const centerX = 350;
    const centerY = 250;

    const nodes = graphData.nodes.map((n, i) => {
      const cfg = NODE_COLORS[n.type] || NODE_COLORS.domain;
      const Icon = cfg.icon;

      // Position center node in center, others in a circle
      let x = centerX;
      let y = centerY;
      if (n.id !== 'node_email_root') {
        const angle = ((i) / (total - 1)) * 2 * Math.PI;
        x = centerX + radius * Math.cos(angle);
        y = centerY + radius * Math.sin(angle);
      }

      return {
        id: n.id,
        position: { x, y },
        data: {
          label: (
            <div className="px-3 py-2 rounded-lg bg-soc-card border border-soc-border shadow-lg flex items-center gap-2 max-w-[200px]">
              <div
                className="p-1.5 rounded-md flex items-center justify-center"
                style={{ backgroundColor: `${cfg.bg}33`, color: cfg.border }}
              >
                <Icon className="h-4 w-4" />
              </div>
              <div className="overflow-hidden text-left">
                <p className="text-[10px] font-mono uppercase tracking-wider text-soc-muted truncate">{cfg.label}</p>
                <p className="text-xs font-mono font-semibold text-white truncate" title={n.label}>
                  {n.label}
                </p>
              </div>
            </div>
          )
        },
        style: {
          background: 'transparent',
          border: 'none',
          padding: 0
        }
      };
    });

    const edges = (graphData.edges || []).map((e, idx) => ({
      id: e.id || `edge-${idx}`,
      source: e.source,
      target: e.target,
      label: e.label,
      animated: true,
      style: { stroke: '#06b6d4', strokeWidth: 1.5 },
      labelStyle: { fill: '#94a3b8', fontSize: 10, fontFamily: 'monospace' },
      labelBgStyle: { fill: '#090d16', fillOpacity: 0.9, rx: 4, ry: 4 },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: '#06b6d4'
      }
    }));

    return { initialNodes: nodes, initialEdges: edges };
  }, [graphData]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Update when graphData changes
  React.useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
  }, [initialNodes, initialEdges]);

  if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
    return (
      <div className="h-96 rounded-xl border border-soc-border bg-soc-card flex items-center justify-center text-soc-muted font-mono text-xs">
        No graph relationship nodes extracted yet.
      </div>
    );
  }

  return (
    <div className="h-[460px] w-full rounded-xl border border-soc-border bg-[#090d16] overflow-hidden relative">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        fitView
      >
        <Background color="#1e293b" gap={16} size={1} />
        <Controls className="bg-soc-card border border-soc-border text-white rounded-lg" />
        <MiniMap
          nodeColor="#06b6d4"
          maskColor="rgba(9, 13, 22, 0.85)"
          className="bg-soc-card border border-soc-border rounded-lg"
        />
      </ReactFlow>
    </div>
  );
};

export default AttackGraph;
