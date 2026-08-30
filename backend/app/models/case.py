from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, Enum
import enum
from app.database import Base


class ThreatSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CaseStatus(str, enum.Enum):
    NEW = "New"
    UNDER_INVESTIGATION = "Under Investigation"
    RESOLVED = "Resolved"
    ARCHIVED = "Archived"


class Case(Base):
    __tablename__ = "cases"

    id = Column(String(50), primary_key=True, index=True)  # CASE-2026-0001
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Evidence info
    filename = Column(String(255), nullable=False)
    file_size_bytes = Column(Integer, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    evidence_path = Column(String(500), nullable=True)

    # Forensic Assessment Summary
    threat_score = Column(Integer, default=0, nullable=False)  # 0 - 100
    severity = Column(String(20), default=ThreatSeverity.LOW.value, nullable=False)
    classification = Column(String(100), default="UNCLASSIFIED", nullable=False)
    status = Column(String(50), default=CaseStatus.NEW.value, nullable=False)
    notes = Column(Text, nullable=True)
