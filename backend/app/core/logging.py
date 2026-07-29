import json
import logging
import sys
from pathlib import Path

from loguru import logger

from app.core.config import settings


def json_sink(message):
    record = message.record
    log_entry = {
        "timestamp": record["time"].isoformat(),
        "level": record["level"].name,
        "module": record["name"],
        "function": record["function"],
        "line": record["line"],
        "message": record["message"],
    }
    if record["exception"]:
        log_entry["exception"] = str(record["exception"])
    sys.stdout.write(json.dumps(log_entry) + "\n")


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
        logger.add(
            json_sink,
            level=log_level,
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
