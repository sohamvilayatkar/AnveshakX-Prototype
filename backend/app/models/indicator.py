from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, Text, JSON
from app.database import Base


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(50), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    
    ioc_type = Column(String(50), nullable=False, index=True)  # IP, Domain, URL, Email, Hash, Header
    ioc_value = Column(String(1000), nullable=False)
    source = Column(String(255), nullable=False)  # Received header, body, url, attachment
    risk_level = Column(String(20), default="INFO", nullable=False)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, default=1.0, nullable=False)
    details = Column(JSON, default=dict, nullable=False)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(50), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    
    evidence_type = Column(String(50), nullable=False)  # RAW_EMAIL, ATTACHMENT, HEADER_DUMP, PDF_REPORT
    filename = Column(String(255), nullable=False)
    file_size_bytes = Column(Integer, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    md5_hash = Column(String(32), nullable=True)
    storage_path = Column(String(500), nullable=False)
    metadata_json = Column(JSON, default=dict, nullable=False)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
