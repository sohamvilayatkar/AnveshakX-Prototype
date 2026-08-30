from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict


class CaseBase(BaseModel):
    filename: str
    file_size_bytes: int
    sha256_hash: str
    threat_score: int = 0
    severity: str = "LOW"
    classification: str = "UNCLASSIFIED"
    status: str = "New"
    notes: Optional[str] = None


class CaseCreate(CaseBase):
    id: str
    evidence_path: Optional[str] = None


class CaseUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None


class CaseResponse(CaseBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CaseListResponse(BaseModel):
    total: int
    cases: List[CaseResponse]
