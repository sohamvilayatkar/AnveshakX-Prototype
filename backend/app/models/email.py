from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey, JSON
from app.database import Base


class EmailRecord(Base):
    __tablename__ = "emails"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(50), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Standard email headers
    message_id = Column(String(255), nullable=True, index=True)
    subject = Column(String(500), nullable=True)
    date_header = Column(String(255), nullable=True)
    parsed_date = Column(DateTime, nullable=True)

    # Sender info
    sender_display_name = Column(String(255), nullable=True)
    sender_email = Column(String(255), nullable=True, index=True)
    sender_domain = Column(String(255), nullable=True, index=True)
    reply_to = Column(String(255), nullable=True)
    return_path = Column(String(255), nullable=True)

    # Recipients (JSON lists)
    recipients_to = Column(JSON, default=list, nullable=False)
    recipients_cc = Column(JSON, default=list, nullable=False)
    recipients_bcc = Column(JSON, default=list, nullable=False)

    # Body & MIME stats
    body_text_preview = Column(Text, nullable=True)
    body_html_preview = Column(Text, nullable=True)
    content_type = Column(String(255), nullable=True)
    attachment_count = Column(Integer, default=0, nullable=False)
    
    # Raw headers and forensic artifacts stored in JSON
    raw_headers = Column(JSON, default=dict, nullable=False)
    received_headers = Column(JSON, default=list, nullable=False)
    authentication_results = Column(JSON, default=dict, nullable=False)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
