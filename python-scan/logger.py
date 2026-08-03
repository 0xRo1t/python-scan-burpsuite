#!/usr/bin/env python3
"""日志工具 — 所有错误/调试信息写入 log/ 目录，不在终端显示"""

import os
import threading
from datetime import datetime
from pathlib import Path

LOG_DIR = Path(__file__).parent / "logs"


class Logger:
    """线程安全的文件日志"""

    def __init__(self, log_dir: str = None):
        self._dir = Path(log_dir) if log_dir else LOG_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._today = datetime.now().strftime("%Y-%m-%d")
        self._path = self._dir / f"proxy-{self._today}.log"

    def _rotate(self):
        today = datetime.now().strftime("%Y-%m-%d")
        if today != self._today:
            self._today = today
            self._path = self._dir / f"proxy-{self._today}.log"

    def write(self, level: str, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] [{level}] {message}\n"
        with self._lock:
            self._rotate()
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line)

    def error(self, message: str):
        self.write("ERROR", message)

    def warn(self, message: str):
        self.write("WARN", message)

    def info(self, message: str):
        self.write("INFO", message)


# 全局单例
_logger = None


def get_logger() -> Logger:
    global _logger
    if _logger is None:
        _logger = Logger()
    return _logger


def log_error(msg: str):
    get_logger().error(msg)


def log_warn(msg: str):
    get_logger().warn(msg)


def log_info(msg: str):
    get_logger().info(msg)
