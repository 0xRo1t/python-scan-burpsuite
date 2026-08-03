#!/usr/bin/env python3
from __future__ import annotations
"""变量解析器 — 处理模版中的 {{...}} 变量"""

import re
import random
import string
import hashlib
import threading


class VariableResolver:
    """处理模版变量: {{BaseURL}}, {{Hostname}}, {{randstr}}, {{md5(var)}}, etc."""

    _COUNTERS: dict[str, int] = {}
    _lock = threading.Lock()

    @classmethod
    def reset_counters(cls):
        with cls._lock:
            cls._COUNTERS.clear()

    @classmethod
    def _next_counter(cls, prefix: str) -> int:
        with cls._lock:
            cls._COUNTERS[prefix] = cls._COUNTERS.get(prefix, 0) + 1
            return cls._COUNTERS[prefix]

    def __init__(self, base_url: str, host: str, port: int,
                 custom_vars=None):
        self.base_url = base_url
        self.host = host
        self.port = port
        self.hostname = f"{host}:{port}" if port not in (80, 443) else host
        self.custom = dict(custom_vars or {})
        self._rand_cache: dict[str, str] = {}

        # 预解析自定义变量值 (保证 {{rand_int}} 等只执行一次，多次引用结果一致)
        for key, val in list(self.custom.items()):
            self.custom[key] = self._resolve_builtins(str(val))

    def resolve(self, text: str) -> str:
        if not text or "{{" not in text:
            return text

        text = self._resolve_md5(text)

        result = text
        result = result.replace("{{BaseURL}}", self.base_url)
        result = result.replace("{{Hostname}}", self.hostname)

        # 自定义变量 — 先展开 (允许变量值中包含 {{rand_int}} 等)
        # 循环直到稳定，避免变量值中又引用了其他自定义变量
        for _ in range(3):
            changed = False
            for key, val in list(self.custom.items()):
                placeholder = "{{" + key + "}}"
                if placeholder in result:
                    result = result.replace(placeholder, str(val))
                    changed = True
            if not changed:
                break

        # {{randstr}}, {{randstr_N}}
        result = re.sub(
            r"\{\{randstr(_\d+)?\}\}",
            lambda m: self._get_randstr(m.group(0)),
            result
        )

        # {{rand_int(min, max)}}
        result = re.sub(
            r"\{\{rand_int\((\d+),\s*(\d+)\)\}\}",
            lambda m: str(random.randint(int(m.group(1)), int(m.group(2)))),
            result
        )

        # 清理未替换的变量
        result = re.sub(r"\{\{[^}]+\}\}", "", result)
        return result

    def _resolve_md5(self, text: str) -> str:
        def _md5_replacer(m):
            inner = m.group(1)
            inner_resolved = self.resolve("{{" + inner + "}}")
            return hashlib.md5(inner_resolved.encode()).hexdigest()
        return re.sub(r"\{\{md5\((\w+)\)\}\}", _md5_replacer, text)

    def _resolve_builtins(self, text: str) -> str:
        """仅解析内置变量 (randstr, rand_int)，不触碰自定义变量 (避免递归)"""
        result = text
        result = result.replace("{{BaseURL}}", self.base_url)
        result = result.replace("{{Hostname}}", self.hostname)
        result = re.sub(
            r"\{\{randstr(_\d+)?\}\}",
            lambda m: self._get_randstr(m.group(0)),
            result
        )
        result = re.sub(
            r"\{\{rand_int\((\d+),\s*(\d+)\)\}\}",
            lambda m: str(random.randint(int(m.group(1)), int(m.group(2)))),
            result
        )
        return result

    def _get_randstr(self, key: str) -> str:
        if key not in self._rand_cache:
            self._rand_cache[key] = ''.join(
                random.choices(string.ascii_lowercase + string.digits, k=8)
            )
        return self._rand_cache[key]
