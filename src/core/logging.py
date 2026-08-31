"""Structured Logging with Correlation Context Tracking."""
import logging
import sys
import json
from contextvars import ContextVar
from typing import Any, Optional
from datetime import datetime, timezone

correlation_id_ctx: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)
incident_id_ctx: ContextVar[Optional[str]] = ContextVar("incident_id", default=None)
agent_run_id_ctx: ContextVar[Optional[str]] = ContextVar("agent_run_id", default=None)


class JSONFormatter(logging.Formatter):
    """Formats log records as structured JSON."""

    RESERVED_ATTRS = {
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "module", "msecs",
        "message", "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "thread", "threadName", "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }

        corr_id = correlation_id_ctx.get()
        if corr_id:
            log_entry["correlation_id"] = corr_id

        inc_id = incident_id_ctx.get()
        if inc_id:
            log_entry["incident_id"] = inc_id

        agent_id = agent_run_id_ctx.get()
        if agent_id:
            log_entry["agent_run_id"] = agent_id

        for key, value in record.__dict__.items():
            if key not in self.RESERVED_ATTRS and not key.startswith("_"):
                log_entry[key] = value

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


def setup_logger(name: str = "adaptive_soc", level: int = logging.INFO) -> logging.Logger:
    """Configures and returns a structured logger."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)

    return logger


logger = setup_logger()
