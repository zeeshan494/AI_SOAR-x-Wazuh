import logging
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Any, Dict


LOG_DIR = Path("/opt/soar-engine/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)


class JSONFormatter(logging.Formatter):
    """Formats log records as JSON for machine parsing."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        for key, value in record.__dict__.items():
            if key not in logging.LogRecord.__dict__ and key not in log_entry:
                if not key.startswith("_"):
                    log_entry[key] = value

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str, ensure_ascii=False)


class AuditLogger:
    """Dedicated audit logger for security events."""

    def __init__(self, log_dir: Path = LOG_DIR):
        self.audit_file = log_dir / "audit.jsonl"

    def log_alert(self, alert_id: str, data: Dict[str, Any]) -> None:
        """Write an immutable audit record for a processed alert."""
        record = {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id,
            "event_type": "ALERT_PROCESSED",
            **data
        }
        with open(self.audit_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")

    def log_action(self, alert_id: str, action: str, target: str, result: str) -> None:
        """Write an audit record for an executed response action."""
        record = {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id,
            "event_type": "RESPONSE_ACTION",
            "action": action,
            "target": target,
            "result": result,
        }
        with open(self.audit_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")


def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    """Configure and return a named logger."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level))

    if logger.handlers:
        return logger

    # JSON file handler
    file_handler = RotatingFileHandler(
        LOG_DIR / "soar.log",
        maxBytes=50 * 1024 * 1024,
        backupCount=10,
        encoding="utf-8"
    )
    file_handler.setFormatter(JSONFormatter())
    file_handler.setLevel(getattr(logging, level))

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_format = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler.setFormatter(console_format)
    console_handler.setLevel(logging.DEBUG)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.propagate = False

    return logger


app_logger = setup_logger("soar.app")
alert_logger = setup_logger("soar.alert")
response_logger = setup_logger("soar.response")
audit = AuditLogger()
