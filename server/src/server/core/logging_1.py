"""
Structured logging configuration for UEBA platform.
Supports both standard text format and JSON format for log aggregation.
"""

import logging
import sys
import json
import traceback
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime


class JSONFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.
    
    Formats log records as JSON for better parsing by log aggregation tools.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON.
        
        Includes: timestamp, level, logger, message, module, function, line,
        and exception info if present.
        """
        log_data: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add request ID if available (set by middleware in Phase 1)
        if hasattr(record, 'request_id'):
            log_data["request_id"] = record.request_id
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": traceback.format_exception(*record.exc_info)
            }
        
        # Add extra fields if present
        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)
        
        return json.dumps(log_data, default=str)


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    format_string: Optional[str] = None,
    json_format: bool = False
) -> None:
    """
    Configure application-wide logging.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional path to log file
        format_string: Optional custom format string (ignored if json_format=True)
        json_format: If True, use JSON format for structured logging
    """
    # Determine format
    if json_format:
        formatter = JSONFormatter()
    else:
        if format_string is None:
            format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        formatter = logging.Formatter(format_string)
    
    handlers = [logging.StreamHandler(sys.stdout)]
    
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(str(log_path)))
    
    # Apply formatter to all handlers
    for handler in handlers:
        handler.setFormatter(formatter)
    
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=None if json_format else format_string,
        handlers=handlers,
        force=True  # Override any existing configuration
    )
    
    # Reduce noise from some libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("websockets").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

