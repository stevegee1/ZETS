import logging
import logging.handlers
import json
from datetime import datetime

# JSON formatter for structured logs
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "extra"):
            log_record.update(record.extra)
        return json.dumps(log_record)


def get_logger(name: str = "zets") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # Already configured

    logger.setLevel(logging.INFO)

    # Rotating file handler (10 MB × 5 backups)
    file_handler = logging.handlers.RotatingFileHandler(
        "backend.log", maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(JsonFormatter())
    logger.addHandler(file_handler)

    # Console handler for dev visibility
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    ))
    logger.addHandler(console_handler)

    return logger


# Singleton logger instance
log = get_logger("zets.pep")
