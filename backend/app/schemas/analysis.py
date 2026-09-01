from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from app.schemas.case import CaseResponse
from app.schemas.intelligence import IPIntelligenceData, DomainIntelligenceData, URLIntelligenceData, IOCItem


class EmailAddressInfo(BaseModel):
    display_name: str = ""
    email: str = ""
    domain: str = ""


class AttachmentInfo(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    sha256_hash: str
    md5_hash: str
    extension: str
    is_suspicious: bool = False
    suspicion_reasons: List[str] = Field(default_factory=list)


class ReceivedHop(BaseModel):
    hop_number: int
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    ip: Optional[str] = None
    ip_is_public: bool = False
    timestamp: Optional[str] = None
    protocol: Optional[str] = None
    helo_name: Optional[str] = None
    raw_header: str
    confidence: float = 0.9


class AuthenticationStatus(BaseModel):
    spf_result: str = "NONE"  # PASS, FAIL, SOFTFAIL, NEUTRAL, NONE
    spf_details: Optional[str] = None
    dkim_result: str = "NONE"  # PASS, FAIL, NONE
    dkim_details: Optional[str] = None
    dmarc_result: str = "NONE"  # PASS, FAIL, NONE
    dmarc_details: Optional[str] = None
    raw_auth_results: Optional[str] = None
    raw_dkim_signature: Optional[str] = None
    raw_spf: Optional[str] = None


class HeaderFinding(BaseModel):
    rule_id: str
    type: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    message: str
    evidence: str
    explanation: str


class RiskFactor(BaseModel):
    name: str
    points: int
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    explanation: str


class ThreatAssessment(BaseModel):
    score: int  # 0 - 100
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    classification: str  # BENIGN, SPAM, PHISHING, BUSINESS_EMAIL_COMPROMISE, BRAND_IMPERSONATION, SUSPICIOUS
    confidence: float
    summary: str
    factors: List[RiskFactor] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    timestamp: str
    event_type: str
    source: str
    description: str
    confidence: float = 1.0


class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # email, sender, recipient, domain, url, ip, asn, attachment, server
    data: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: Optional[str] = None
    type: str = "default"


class ForensicGraph(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)


class EvidencePreservation(BaseModel):
    case_id: str
    evidence_id: str
    filename: str
    file_size_bytes: int
    sha256_hash: str
    md5_hash: str
    preservation_timestamp: str
    integrity_verified: bool = True
    storage_path: Optional[str] = None


class LinguisticSignal(BaseModel):
    token: str
    weight: float
    description: str


class MLAnalysisData(BaseModel):
    model_name: str = "anveshakx-email-classifier"
    model_version: str = "v2.0"
    classification: str = "UNCLASSIFIED"
    raw_class: str = "legitimate"
    confidence: float = 0.50
    probabilities: Dict[str, float] = Field(default_factory=dict)
    linguistic_signals: List[LinguisticSignal] = Field(default_factory=list)
    status: str = "active"


class SocialEngineeringProfile(BaseModel):
    urgency: float = 0.0
    authority: float = 0.0
    financial_pressure: float = 0.0
    fear: float = 0.0
    secrecy: float = 0.0
    credential_request: float = 0.0
    call_to_action: float = 0.0


class EvidenceItem(BaseModel):
    title: str
    severity: str
    points: int = 0
    explanation: str


class RiskFusionBreakdown(BaseModel):
    forensic_score: int = 0
    forensic_weight: float = 0.50
    ml_score: int = 0
    ml_weight: float = 0.30
    intel_score: int = 0
    intel_weight: float = 0.20
    final_score: int = 0
    formula: str = ""
    technical_evidence: List[EvidenceItem] = Field(default_factory=list)
    ai_evidence: List[EvidenceItem] = Field(default_factory=list)
    intel_evidence: List[EvidenceItem] = Field(default_factory=list)
    top_factors: List[str] = Field(default_factory=list)


class AnomalyResult(BaseModel):
    is_anomaly: bool = False
    anomaly_score: float = 0.0
    explanation: str = ""


class CampaignMatch(BaseModel):
    campaign_id: str
    campaign_name: str
    type: str = "KNOWN_CAMPAIGN"
    similarity_score: float
    similarity_percent: int
    shared_traits: List[str] = Field(default_factory=list)


class ParsedEmailData(BaseModel):
    message_id: Optional[str] = None
    subject: str = ""
    date_header: Optional[str] = None
    sender: EmailAddressInfo = Field(default_factory=EmailAddressInfo)
    reply_to: Optional[EmailAddressInfo] = None
    return_path: Optional[EmailAddressInfo] = None
    recipients_to: List[EmailAddressInfo] = Field(default_factory=list)
    recipients_cc: List[EmailAddressInfo] = Field(default_factory=list)
    recipients_bcc: List[EmailAddressInfo] = Field(default_factory=list)
    received_hops: List[ReceivedHop] = Field(default_factory=list)
    earliest_source_ip: Optional[str] = None
    authentication: AuthenticationStatus = Field(default_factory=AuthenticationStatus)
    urls: List[URLIntelligenceData] = Field(default_factory=list)
    extracted_ips: List[str] = Field(default_factory=list)
    extracted_domains: List[str] = Field(default_factory=list)
    attachments: List[AttachmentInfo] = Field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    raw_headers: Dict[str, Any] = Field(default_factory=dict)


class AnalysisResponse(BaseModel):
    case: CaseResponse
    email: ParsedEmailData
    threat: ThreatAssessment
    authentication: AuthenticationStatus
    header_findings: List[HeaderFinding] = Field(default_factory=list)
    relay_path: List[ReceivedHop] = Field(default_factory=list)
    ips: List[IPIntelligenceData] = Field(default_factory=list)
    domains: List[DomainIntelligenceData] = Field(default_factory=list)
    urls: List[URLIntelligenceData] = Field(default_factory=list)
    attachments: List[AttachmentInfo] = Field(default_factory=list)
    iocs: List[IOCItem] = Field(default_factory=list)
    risk_factors: List[RiskFactor] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)
    graph: ForensicGraph = Field(default_factory=ForensicGraph)
    evidence: EvidencePreservation
    
    # Phase 2 ML Intelligence Additions
    ml_analysis: MLAnalysisData = Field(default_factory=MLAnalysisData)
    social_engineering: SocialEngineeringProfile = Field(default_factory=SocialEngineeringProfile)
    risk_fusion: RiskFusionBreakdown = Field(default_factory=RiskFusionBreakdown)
    anomaly_detection: AnomalyResult = Field(default_factory=AnomalyResult)
    campaign_matches: List[CampaignMatch] = Field(default_factory=list)
