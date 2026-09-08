import sys
from pathlib import Path

# Ensure project root is available for ml module imports
_backend_dir = Path(__file__).resolve().parent.parent
_project_root = _backend_dir.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.database import init_db
from app.api import api_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("anveshakx")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events."""
    logger.info("Starting AnveshakX Digital Forensics Engine...")
    # Initialize database tables
    init_db()
    logger.info(f"Database initialized at {settings.DATABASE_URL}")
    yield
    logger.info("AnveshakX shutting down.")


app = FastAPI(
    title=settings.APP_NAME,
    description="AI-ready Email Threat Detection, Geolocation & Forensic Intelligence Platform (Phase 1)",
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS if "*" not in settings.CORS_ORIGINS else ["*"],
    allow_origin_regex=r"https://.*\.netlify\.app|https://.*\.onrender\.com|http://localhost:\d+",
    allow_credentials=True if "*" not in settings.CORS_ORIGINS else False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API v1 router
app.include_router(api_router)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": True, "status_code": exc.status_code, "detail": exc.detail}
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"error": True, "status_code": 422, "detail": exc.errors()}
    )


@app.get("/")
def root():
    return {
        "platform": settings.APP_NAME,
        "tagline": "AI-ready Email Threat Detection, Geolocation & Forensic Intelligence Platform",
        "version": settings.APP_VERSION,
        "status": "OPERATIONAL",
        "docs": "/docs",
        "api": "/api/v1"
    }
