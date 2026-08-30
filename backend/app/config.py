import os
from typing import List, Union
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator


class Settings(BaseSettings):
    APP_NAME: str = "AnveshakX"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Storage & Database
    DATABASE_URL: str = "sqlite:///./data/anveshakx.db"
    EVIDENCE_DIR: str = "./data/evidence"
    MAX_UPLOAD_SIZE_MB: int = 25
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000"
    ]

    # Threat Intelligence Providers
    IP_INTELLIGENCE_ENABLED: bool = True
    IP_INTELLIGENCE_API_KEY: str = ""
    DOMAIN_INTELLIGENCE_ENABLED: bool = False
    DOMAIN_INTELLIGENCE_API_KEY: str = ""

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore"
    }


settings = Settings()

# Ensure directories exist
os.makedirs("./data", exist_ok=True)
os.makedirs(settings.EVIDENCE_DIR, exist_ok=True)
