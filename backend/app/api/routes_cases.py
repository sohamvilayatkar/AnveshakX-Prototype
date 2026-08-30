from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.case import Case
from app.schemas.case import CaseResponse, CaseListResponse, CaseUpdate

router = APIRouter(prefix="/cases", tags=["Cases"])


@router.get("", response_model=CaseListResponse)
def list_cases(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    severity: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db)
):
    """List stored cases with optional severity and status filtering."""
    query = db.query(Case)
    if severity:
        query = query.filter(Case.severity == severity.upper())
    if status_filter:
        query = query.filter(Case.status == status_filter)
    
    total = query.count()
    cases = query.order_by(Case.created_at.desc()).offset(skip).limit(limit).all()
    
    return CaseListResponse(
        total=total,
        cases=[CaseResponse.model_validate(c) for c in cases]
    )


@router.get("/{case_id}", response_model=CaseResponse)
def get_case(case_id: str, db: Session = Depends(get_db)):
    """Get a specific case by Case ID."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found."
        )
    return CaseResponse.model_validate(case)


@router.patch("/{case_id}", response_model=CaseResponse)
def update_case(case_id: str, case_update: CaseUpdate, db: Session = Depends(get_db)):
    """Update case status or notes."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found."
        )
    
    if case_update.status is not None:
        case.status = case_update.status
    if case_update.notes is not None:
        case.notes = case_update.notes
    
    db.commit()
    db.refresh(case)
    return CaseResponse.model_validate(case)


@router.delete("/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_case(case_id: str, db: Session = Depends(get_db)):
    """Delete a case and associated evidence metadata."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found."
        )
    db.delete(case)
    db.commit()
    return None
