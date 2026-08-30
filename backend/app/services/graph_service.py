import networkx as nx
from typing import List, Dict, Any, Optional
from app.schemas.analysis import ForensicGraph, GraphNode, GraphEdge, ParsedEmailData
from app.schemas.intelligence import IPIntelligenceData, DomainIntelligenceData


class GraphService:
    """
    Forensic Relationship Graph Engine:
    Builds a NetworkX graph correlating Email, Senders, Domains, IPs, ASNs, URLs, and Attachments,
    then translates it into a React Flow compatible graph structure for interactive visualization.
    """

    @classmethod
    def build_graph(
        cls,
        email_data: ParsedEmailData,
        ip_intel: List[IPIntelligenceData],
        domain_intel: List[DomainIntelligenceData]
    ) -> ForensicGraph:
        G = nx.DiGraph()

        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        node_ids = set()
        edge_ids = set()

        def add_node(nid: str, label: str, ntype: str, data: Dict[str, Any]):
            if nid not in node_ids:
                node_ids.add(nid)
                nodes.append(GraphNode(
                    id=nid,
                    label=label,
                    type=ntype,
                    data=data
                ))

        def add_edge(src: str, tgt: str, label: str, etype: str = "default"):
            eid = f"{src}->{tgt}:{label}"
            if eid not in edge_ids and src in node_ids and tgt in node_ids:
                edge_ids.add(eid)
                edges.append(GraphEdge(
                    id=eid,
                    source=src,
                    target=tgt,
                    label=label,
                    type=etype
                ))

        # 1. Central Email Node
        email_id = "node_email_root"
        add_node(
            email_id,
            email_data.subject[:30] + "..." if len(email_data.subject) > 30 else (email_data.subject or "Email Artifact"),
            "email",
            {"subject": email_data.subject, "message_id": email_data.message_id}
        )

        # 2. Sender Node
        if email_data.sender.email:
            sender_id = f"node_sender_{email_data.sender.email}"
            add_node(
                sender_id,
                email_data.sender.display_name or email_data.sender.email,
                "sender",
                {"email": email_data.sender.email, "display_name": email_data.sender.display_name}
            )
            add_edge(email_id, sender_id, "SENT_BY")

            # Sender Domain
            if email_data.sender.domain:
                dom_id = f"node_dom_{email_data.sender.domain}"
                add_node(dom_id, email_data.sender.domain, "domain", {"domain": email_data.sender.domain})
                add_edge(sender_id, dom_id, "BELONGS_TO")

        # 3. Reply-To Node (if different)
        if email_data.reply_to and email_data.reply_to.email:
            reply_id = f"node_reply_{email_data.reply_to.email}"
            add_node(
                reply_id,
                email_data.reply_to.email,
                "reply_to",
                {"email": email_data.reply_to.email}
            )
            add_edge(email_id, reply_id, "REPLIED_TO")

            if email_data.reply_to.domain:
                reply_dom_id = f"node_dom_{email_data.reply_to.domain}"
                add_node(reply_dom_id, email_data.reply_to.domain, "domain", {"domain": email_data.reply_to.domain})
                add_edge(reply_id, reply_dom_id, "BELONGS_TO")

        # 4. Received Hop IPs & ASNs
        for hop in email_data.received_hops:
            if hop.ip:
                ip_id = f"node_ip_{hop.ip}"
                add_node(ip_id, hop.ip, "ip", {"ip": hop.ip, "hop": hop.hop_number, "is_public": hop.ip_is_public})
                add_edge(email_id, ip_id, f"HOP_{hop.hop_number}")

        for ip_data in ip_intel:
            ip_id = f"node_ip_{ip_data.ip}"
            add_node(ip_id, ip_data.ip, "ip", {
                "ip": ip_data.ip,
                "country": ip_data.country,
                "org": ip_data.organization,
                "is_hosting": ip_data.is_hosting
            })
            if ip_data.asn and ip_data.asn != "N/A (Private)":
                asn_id = f"node_asn_{ip_data.asn}"
                add_node(asn_id, ip_data.asn, "asn", {"asn": ip_data.asn, "org": ip_data.organization})
                add_edge(ip_id, asn_id, "HOSTED_ON")

        # 5. URLs & Target Domains
        for idx, u in enumerate(email_data.urls[:8]):  # Limit to top 8 URLs for clean graph layout
            url_id = f"node_url_{idx}"
            display_url = u.domain or u.url[:25]
            add_node(url_id, display_url, "url", {"url": u.url, "risk": u.risk_level})
            add_edge(email_id, url_id, "LINKS_TO")

            if u.registered_domain:
                dom_id = f"node_dom_{u.registered_domain}"
                add_node(dom_id, u.registered_domain, "domain", {"domain": u.registered_domain})
                add_edge(url_id, dom_id, "RESOLVES_TO")

        # 6. Attachments
        for att in email_data.attachments:
            att_id = f"node_att_{att.sha256_hash[:8]}"
            add_node(att_id, att.filename, "attachment", {
                "filename": att.filename,
                "size": att.size_bytes,
                "sha256": att.sha256_hash,
                "suspicious": att.is_suspicious
            })
            add_edge(email_id, att_id, "CONTAINS")

        return ForensicGraph(nodes=nodes, edges=edges)
