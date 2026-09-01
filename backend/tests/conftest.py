import os
import sys
import pytest
from pathlib import Path

# Add backend directory and project root to sys.path
backend_dir = Path(__file__).resolve().parent.parent
project_root = backend_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

# Set test environment
os.environ["APP_ENV"] = "testing"
os.environ["DATABASE_URL"] = "sqlite:///./data/test_anveshakx.db"
os.environ["EVIDENCE_DIR"] = "./data/test_evidence"

from app.database import init_db, engine, Base


@pytest.fixture(autouse=True)
def setup_test_db():
    """Create clean database tables before each test and clean up afterwards."""
    os.makedirs("./data/test_evidence", exist_ok=True)
    init_db()
    yield
    Base.metadata.drop_all(bind=engine)
    # Clean up test db file if exists
    test_db = Path("./data/test_anveshakx.db")
    if test_db.exists():
        try:
            test_db.unlink()
        except Exception:
            pass
