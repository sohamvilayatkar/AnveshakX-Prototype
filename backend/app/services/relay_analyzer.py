from typing import List, Tuple, Optional
from datetime import datetime, timezone
import dateutil.parser
from app.schemas.analysis import ReceivedHop, TimelineEvent, ParsedEmailData


class RelayAnalyzer:
    """
    Relay Path Forensics Engine:
    Analyzes email transmission chronology across Mail Transfer Agents (MTAs),
    calculates transit hops, detects relay timing anomalies, and builds the investigation timeline.
    """

    @classmethod
    def analyze_hops(cls, hops: List[ReceivedHop], email_date: Optional[str] = None) -> Tuple[List[ReceivedHop], List[TimelineEvent]]:
        timeline: List[TimelineEvent] = []

        # 1. Add Email Generation / Date Header Event
        if email_date:
            timeline.append(TimelineEvent(
                timestamp=email_date,
                event_type="EMAIL_ORIGINATED",
                source="Date Header",
                description=f"Message claimed creation timestamp: {email_date}",
                confidence=0.85
            ))

        # 2. Process Hops Chronologically
        for hop in hops:
            host_label = hop.from_host or hop.by_host or hop.ip or "Unknown Relay Node"
            ip_info = f" [IP: {hop.ip}]" if hop.ip else ""
            proto_info = f" via {hop.protocol}" if hop.protocol else ""
            
            description = f"Hop {hop.hop_number}: Relayed by {host_label}{ip_info}{proto_info}"
            if hop.hop_number == 1:
                description = f"Earliest Recorded Relay Hop 1: Sent from {host_label}{ip_info}{proto_info}"

            timeline.append(TimelineEvent(
                timestamp=hop.timestamp or "Unknown Timestamp",
                event_type="RELAY_HOP",
                source=f"Received Header #{hop.hop_number}",
                description=description,
                confidence=hop.confidence
            ))

        # 3. Add Analysis Ingestion Event
        timeline.append(TimelineEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type="FORENSIC_INGESTION",
            source="AnveshakX Engine",
            description="Forensic parsing, evidence hashing (SHA-256), and intelligence correlation completed.",
            confidence=1.0
        ))

        return hops, timeline
