# AnveshakX Backend Service

FastAPI-based digital forensics backend for **AnveshakX**.

## Running Locally

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the development server**:
   ```bash
   python -m uvicorn app.main:app --port 8000 --reload
   ```

3. **Run unit & integration tests**:
   ```bash
   pytest tests/ -v
   ```

## Directory Structure
- `app/api/`: REST endpoint routes (`/health`, `/analyze/upload`, `/cases`, `/reports`)
- `app/models/`: SQLAlchemy ORM database models (`Case`, `EmailRecord`, `Indicator`, `Evidence`)
- `app/schemas/`: Pydantic data schemas for requests and responses
- `app/services/`: Forensic analysis services (email parser, analyzers, rule engine, risk engine)
- `app/utils/`: Security & forensic utility modules (hashing, IP classification, URL/domain analysis)
- `tests/`: Pytest automated test suite
