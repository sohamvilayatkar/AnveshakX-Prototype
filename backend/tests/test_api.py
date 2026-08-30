from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["platform"] == "AnveshakX"
    assert data["status"] == "OPERATIONAL"


def test_health_check_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "healthy"
    assert data["capabilities"]["ml_engine"] is False  # Phase 1 verification


def test_upload_and_analyze_endpoint():
    eml_path = Path(__file__).resolve().parent.parent.parent / "sample_emails" / "bec.eml"
    with open(eml_path, "rb") as f:
        file_bytes = f.read()

    response = client.post(
        "/api/v1/analyze/upload",
        files={"file": ("bec.eml", file_bytes, "message/rfc822")}
    )

    assert response.status_code == 200
    data = response.json()
    
    # Verify Case metadata
    assert "case" in data
    assert data["case"]["id"].startswith("CASE-")
    assert data["case"]["filename"] == "bec.eml"
    assert len(data["case"]["sha256_hash"]) == 64

    # Verify Evidence preservation
    assert "evidence" in data
    assert data["evidence"]["integrity_verified"] is True
    assert data["evidence"]["sha256_hash"] == data["case"]["sha256_hash"]

    # Verify Email parsing results
    assert "email" in data
    assert data["email"]["sender"]["email"] == "ceo@globalenterprise-corp.com"
    assert data["email"]["reply_to"]["email"] == "executive-desk-urgent@fast-offshore-transfers.net"
    assert data["email"]["authentication"]["spf_result"] == "FAIL"

    # Verify Case is retrievable via GET /api/v1/cases
    case_id = data["case"]["id"]
    get_res = client.get(f"/api/v1/cases/{case_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == case_id

    # Verify Case appears in list
    list_res = client.get("/api/v1/cases")
    assert list_res.status_code == 200
    assert list_res.json()["total"] >= 1


def test_upload_invalid_file_extension():
    response = client.post(
        "/api/v1/analyze/upload",
        files={"file": ("malware.exe", b"MZDummyBytes", "application/x-msdownload")}
    )
    assert response.status_code == 400
    assert "Invalid file extension" in response.json()["detail"]


def test_upload_empty_file():
    response = client.post(
        "/api/v1/analyze/upload",
        files={"file": ("empty.eml", b"", "message/rfc822")}
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"]
