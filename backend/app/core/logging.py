import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from loguru import logger

from app.core.config import settings


class JsonFormatter:
    def format(self, record: Dict[str, Any]) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record["level"].name,
            "module": record["name"],
            "function": record["function"],
            "line": record["line"],
            "message": record["message"],
        }
        if record.get("exception"):
            log_entry["exception"] = record["exception"]
        return json.dumps(log_entry)


class InterceptHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno
        logger.opt(depth=6, exception=record.exc_info).log(
            level, record.getMessage()
        )


def setup_logging() -> None:
    logger.remove()

    log_level = settings.LOG_LEVEL.upper()
    log_format = settings.LOG_FORMAT

    if log_format == "json":
        formatter = JsonFormatter()
        logger.add(
            sys.stdout,
            level=log_level,
            format=lambda record: formatter.format(record),
            colorize=False,
        )
    else:
        logger.add(
            sys.stdout,
            level=log_level,
            format=(
                "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
                "<level>{level: <8}</level> | "
                "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
                "<level>{message}</level>"
            ),
            colorize=True,
        )

    log_file = settings.BASE_DIR / "logs" / "vapt.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)

    logger.add(
        str(log_file),
        level=log_level,
        rotation="10 MB",
        retention="30 days",
        compression="zip",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
    )

    logging.basicConfig(handlers=[InterceptHandler()], level=logging.INFO, force=True)

    for lib_logger in ("uvicorn", "uvicorn.access", "fastapi", "sqlalchemy"):
        logging.getLogger(lib_logger).handlers = [InterceptHandler()]
        logging.getLogger(lib_logger).propagate = False

    logger.info("Logging initialized", extra={"format": log_format, "level": log_level})
