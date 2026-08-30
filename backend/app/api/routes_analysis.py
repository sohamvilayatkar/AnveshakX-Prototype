import os
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, status
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.case import Case, CaseStatus
from app.models.email import EmailRecord
from app.models.indicator import Evidence, Indicator
from app.utils.hashing import compute_hashes
from app.utils.validators import validate_email_file
from app.services import (
    EmailParser, HeaderAnalyzer, AuthenticationAnalyzer, RelayAnalyzer,
    IPIntelligenceService, DomainAnalyzer, IndicatorExtractor,
    RuleEngine, RiskEngine, GraphService
)
from app.schemas.case import CaseResponse
from app.schemas.analysis import (
    AnalysisResponse, ParsedEmailData, EvidencePreservation
)

router = APIRouter(prefix="/analyze", tags=["Analysis"])


def generate_case_id(db: Session) -> str:
    """Generate a clean, professional sequential Case ID: CASE-2026-0001."""
    year = datetime.now().year
    prefix = f"CASE-{year}-"
    last_case = db.query(Case).filter(Case.id.like(f"{prefix}%")).order_by(Case.id.desc()).first()
    if last_case:
        try:
            seq_num = int(last_case.id.split("-")[-1]) + 1
        except ValueError:
            seq_num = 1
    else:
        seq_num = 1
    return f"{prefix}{seq_num:04d}"


def execute_full_forensic_pipeline(
    raw_bytes: bytes,
    filename: str,
    content_type: str,
    db: Session
) -> AnalysisResponse:
    """Run the complete deterministic forensic intelligence pipeline on raw email bytes."""
    # 1. Forensic Evidence Preservation (SHA-256 & MD5)
    sha256_hash, md5_hash = compute_hashes(raw_bytes)
    file_size = len(raw_bytes)
    case_id = generate_case_id(db)

    evidence_filename = f"{case_id}_{sha256_hash[:12]}.eml"
    evidence_path = os.path.join(settings.EVIDENCE_DIR, evidence_filename)
    try:
        with open(evidence_path, "wb") as ef:
            ef.write(raw_bytes)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to preserve evidence on disk: {str(e)}"
        )

    # 2. Parse Email
    parsed_email: ParsedEmailData = EmailParser.parse(raw_bytes)

    # 3. Analyze Headers and Identity
    header_findings = HeaderAnalyzer.analyze(parsed_email)

    # 4. Evaluate Authentication Findings
    auth_findings = AuthenticationAnalyzer.evaluate(parsed_email)
    all_header_findings = header_findings + auth_findings

    # 5. Relay & Timeline Reconstruction
    relay_hops, timeline = RelayAnalyzer.analyze_hops(parsed_email.received_hops, parsed_email.date_header)

    # 6. IP Geolocation & ASN Intelligence
    ip_intel = IPIntelligenceService.analyze_ips(parsed_email.extracted_ips, parsed_email.earliest_source_ip)

    # 7. Domain Intelligence & Lookalike Impersonation Detection
    domain_intel = DomainAnalyzer.analyze_domains(parsed_email.extracted_domains)

    # 8. Extract Standardized IOCs
    iocs = IndicatorExtractor.extract_all(parsed_email, ip_intel, domain_intel)

    # 9. Rule Engine Evaluation (Deterministic Triggers)
    rule_eval = RuleEngine.evaluate(parsed_email, all_header_findings, domain_intel, ip_intel)

    # 10. Explainable Risk Score Calculation
    threat_assessment = RiskEngine.calculate_score(rule_eval)

    # 11. Build Attack / Infrastructure Relationship Graph
    graph = GraphService.build_graph(parsed_email, ip_intel, domain_intel)

    # 12. Persist Database Records
    db_case = Case(
        id=case_id,
        filename=filename,
        file_size_bytes=file_size,
        sha256_hash=sha256_hash,
        evidence_path=evidence_path,
        threat_score=threat_assessment.score,
        severity=threat_assessment.severity,
        classification=threat_assessment.classification,
        status=CaseStatus.NEW.value,
        notes=threat_assessment.summary
    )
    db.add(db_case)

    evidence_id = f"EVID-{uuid.uuid4().hex[:8].upper()}"
    db_evidence = Evidence(
        case_id=case_id,
        evidence_type="RAW_EMAIL",
        filename=filename,
        file_size_bytes=file_size,
        sha256_hash=sha256_hash,
        md5_hash=md5_hash,
        storage_path=evidence_path,
        metadata_json={
            "original_filename": filename,
            "mime_type": content_type,
            "upload_timestamp": datetime.now(timezone.utc).isoformat()
        }
    )
    db.add(db_evidence)

    db_email = EmailRecord(
        case_id=case_id,
        message_id=parsed_email.message_id,
        subject=parsed_email.subject,
        date_header=parsed_email.date_header,
        sender_display_name=parsed_email.sender.display_name,
        sender_email=parsed_email.sender.email,
        sender_domain=parsed_email.sender.domain,
        reply_to=parsed_email.reply_to.email if parsed_email.reply_to else None,
        return_path=parsed_email.return_path.email if parsed_email.return_path else None,
        recipients_to=[r.model_dump() for r in parsed_email.recipients_to],
        recipients_cc=[r.model_dump() for r in parsed_email.recipients_cc],
        recipients_bcc=[r.model_dump() for r in parsed_email.recipients_bcc],
        body_text_preview=parsed_email.body_text[:1000] if parsed_email.body_text else "",
        body_html_preview=parsed_email.body_html[:1000] if parsed_email.body_html else "",
        content_type=content_type,
        attachment_count=len(parsed_email.attachments),
        raw_headers=parsed_email.raw_headers,
        received_headers=[h.model_dump() for h in relay_hops],
        authentication_results=parsed_email.authentication.model_dump()
    )
    db.add(db_email)

    for ioc in iocs:
        db_ioc = Indicator(
            case_id=case_id,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.value,
            source=ioc.source,
            risk_level=ioc.risk,
            confidence=ioc.confidence,
            details={"context": ioc.context}
        )
        db.add(db_ioc)

    db.commit()
    db.refresh(db_case)

    evidence_preservation = EvidencePreservation(
        case_id=case_id,
        evidence_id=evidence_id,
        filename=filename,
        file_size_bytes=file_size,
        sha256_hash=sha256_hash,
        md5_hash=md5_hash,
        preservation_timestamp=datetime.now(timezone.utc).isoformat(),
        integrity_verified=True,
        storage_path=evidence_path
    )

    return AnalysisResponse(
        case=CaseResponse.model_validate(db_case),
        email=parsed_email,
        threat=threat_assessment,
        authentication=parsed_email.authentication,
        header_findings=all_header_findings,
        relay_path=relay_hops,
        ips=ip_intel,
        domains=domain_intel,
        urls=parsed_email.urls,
        attachments=parsed_email.attachments,
        iocs=iocs,
        risk_factors=threat_assessment.factors,
        timeline=timeline,
        graph=graph,
        evidence=evidence_preservation
    )


@router.post("/upload", response_model=AnalysisResponse, status_code=status.HTTP_200_OK)
async def upload_and_analyze_email(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Upload raw .eml file and run full deterministic forensic analysis."""
    filename = file.filename or "unnamed.eml"
    content_type = file.content_type or "message/rfc822"

    try:
        raw_bytes = await file.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {str(e)}"
        )

    file_size = len(raw_bytes)
    is_valid, error_msg = validate_email_file(filename, content_type, file_size)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg
        )

    return execute_full_forensic_pipeline(raw_bytes, filename, content_type, db)


@router.post("/sample/{sample_name}", response_model=AnalysisResponse, status_code=status.HTTP_200_OK)
def load_and_analyze_sample(
    sample_name: str,
    db: Session = Depends(get_db)
):
    """Load one of the bundled demo sample emails (bec, phishing, impersonation, legitimate) for instant SIH demonstration."""
    allowed_samples = {
        "bec": "bec.eml",
        "phishing": "phishing.eml",
        "impersonation": "impersonation.eml",
        "legitimate": "legitimate.eml"
    }
    
    clean_name = sample_name.lower().replace(".eml", "")
    if clean_name not in allowed_samples:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample '{sample_name}' not found. Available samples: {list(allowed_samples.keys())}"
        )

    sample_filename = allowed_samples[clean_name]
    sample_path = os.path.join("./sample_emails", sample_filename)
    if not os.path.exists(sample_path):
        sample_path = os.path.join("../sample_emails", sample_filename)

    if not os.path.exists(sample_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample file {sample_filename} not found on server disk."
        )

    with open(sample_path, "rb") as sf:
        raw_bytes = sf.read()

    return execute_full_forensic_pipeline(raw_bytes, sample_filename, "message/rfc822", db)


@router.get("/case/{case_id}", response_model=AnalysisResponse)
def get_case_analysis(case_id: str, db: Session = Depends(get_db)):
    """Re-analyze and retrieve full forensic analysis for an existing stored case."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found."
        )

    if not case.evidence_path or not os.path.exists(case.evidence_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence file for this case could not be located on disk."
        )

    with open(case.evidence_path, "rb") as ef:
        raw_bytes = ef.read()

    # Re-run pipeline for this case to rebuild full graph, timeline, and intelligence
    return execute_full_forensic_pipeline(raw_bytes, case.filename, "message/rfc822", db)
