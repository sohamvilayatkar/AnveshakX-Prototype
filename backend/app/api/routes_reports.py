import os
from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.case import Case
from app.api.routes_analysis import execute_full_forensic_pipeline
from app.services.report_service import ReportService

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/{case_id}/status")
def get_report_status(case_id: str, db: Session = Depends(get_db)):
    """Check status of forensic report for a case."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found."
        )
    return {
        "case_id": case_id,
        "status": "AVAILABLE",
        "format": "PDF",
        "threat_score": case.threat_score,
        "severity": case.severity
    }


@router.get("/{case_id}/pdf")
def download_pdf_report(case_id: str, db: Session = Depends(get_db)):
    """Generate and return official downloadable Forensic Investigation PDF Report."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found."
        )

    if not case.evidence_path or not os.path.exists(case.evidence_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence file for this case could not be located on disk."
        )

    with open(case.evidence_path, "rb") as ef:
        raw_bytes = ef.read()

    # Re-run full pipeline to get comprehensive AnalysisResponse object
    analysis = execute_full_forensic_pipeline(raw_bytes, case.filename, "message/rfc822", db)

    # Generate PDF bytes via ReportLab
    pdf_bytes = ReportService.generate_pdf(analysis)

    pdf_filename = f"AnveshakX_Forensic_Report_{case_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={pdf_filename}",
            "X-Case-ID": case_id,
            "X-Threat-Score": str(case.threat_score)
        }
    )
