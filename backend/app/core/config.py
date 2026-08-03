from pathlib import Path
from typing import List, Optional

from pydantic import PostgresDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    APP_NAME: str = "Network VAPT Platform"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = (
        "Internal Network Vulnerability Assessment & Penetration Testing Platform"
    )
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 1

    POSTGRES_USER: str = "vapt"
    POSTGRES_PASSWORD: str = "vaptpassword"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "vapt_db"
    DATABASE_URL: Optional[PostgresDsn] = None

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_db_url(cls, v: Optional[str], info) -> PostgresDsn:
        if v:
            return PostgresDsn(v)
        values = info.data
        return PostgresDsn(
            f"postgresql+asyncpg://{values['POSTGRES_USER']}:{values['POSTGRES_PASSWORD']}"
            f"@{values['POSTGRES_HOST']}:{values['POSTGRES_PORT']}/{values['POSTGRES_DB']}"
        )

    JWT_SECRET: str = "vapt-platform-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 30
    JWT_REFRESH_EXPIRATION_DAYS: int = 7

    AUTO_CREATE_ADMIN: bool = True
    ADMIN_USERNAME: str = "admin"
    ADMIN_EMAIL: str = "admin@networkvapt.local"
    ADMIN_PASSWORD: str = "Admin@123"

    NVD_API_KEY: Optional[str] = None

    MSF_RPC_HOST: str = "127.0.0.1"
    MSF_RPC_PORT: int = 55553
    MSF_RPC_PASSWORD: Optional[str] = None

    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["*"]
    CORS_ALLOW_HEADERS: List[str] = ["*"]

    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    REPORTS_DIR: Path = BASE_DIR.parent / "reports"
    SCREENSHOTS_DIR: Path = BASE_DIR.parent / "screenshots"
    WIRESHARK_DIR: Path = BASE_DIR.parent / "wireshark"

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}")
        return v.upper()

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v


settings = Settings()
