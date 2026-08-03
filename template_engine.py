#!/usr/bin/env python3
from __future__ import annotations
"""
POC 模版扫描引擎 — 递归加载 poc/ 目录下的 YAML 模版，按 tag 匹配指纹后执行扫描

模版格式 (Nuclei 兼容):
  - 简单格式: http[].method + http[].path + http[].headers
  - Raw 格式: http[].raw (原始 HTTP 请求文本)
  - 变量替换: {{BaseURL}}, {{Hostname}}, {{randstr}}, {{rand_int}}, {{md5(var)}}
  - 匹配器: word(body/header), status, dsl(基础支持)
  - Payloads (pitchfork 模式)

使用:
  from template_engine import TemplateEngine
  engine = TemplateEngine("poc/")
  templates = engine.find(["nacos", "alibaba"])
  findings = engine.execute_all(templates, "https", "target.com", 443)
"""

import os
import re
import ssl
import socket
import random
import string
import hashlib
import pickle
import urllib.request
import urllib.parse
import threading
import yaml
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================================
# 终端颜色
# ============================================================
class _C:
    R = "\033[0m"
    B = "\033[1m"
    D = "\033[2m"
    r = "\033[91m"
    g = "\033[92m"
    y = "\033[93m"
    b = "\033[94m"
    m = "\033[95m"
    c = "\033[96m"
    w = "\033[97m"
    by = "\033[43m"


# ============================================================
# 变量解析器
# ============================================================
class VariableResolver:
    """处理模版中的变量替换"""

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
        self.base_url = base_url          # http://host:port 或 https://host:port
        self.host = host
        self.port = port
        self.hostname = f"{host}:{port}" if port not in (80, 443) else host
        self.custom = dict(custom_vars or {})
        self._rand_cache: dict[str, str] = {}

        # 预解析自定义变量值 (保证 {{rand_int}} 只执行一次)
        for key, val in list(self.custom.items()):
            self.custom[key] = self._resolve_builtins(str(val))

    def resolve(self, text: str) -> str:
        """替换文本中所有的 {{...}} 变量"""
        if not text or "{{" not in text:
            return text

        # 处理 md5 嵌套
        text = self._resolve_md5(text)

        # 逐个替换
        result = text
        result = result.replace("{{BaseURL}}", self.base_url)
        result = result.replace("{{Hostname}}", self.hostname)

        # 自定义变量 — 先展开 (允许变量值中包含 {{rand_int}} 等)
        # 循环直到稳定
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

        # 自定义变量
        for key, val in self.custom.items():
            result = result.replace("{{" + key + "}}", str(val))

        # 清理未替换的 {{...}}
        result = re.sub(r"\{\{[^}]+\}\}", "", result)
        return result

    def _resolve_md5(self, text: str) -> str:
        """处理 {{md5(var)}} 嵌套"""
        def _md5_replacer(m):
            inner = m.group(1)
            # 先解析内部变量
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


# ============================================================
# HTTP 请求发送
# ============================================================
class HttpSender:
    """发送 HTTP 请求 (支持简单格式 + raw 格式)"""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def send_simple(self, method: str, url: str, headers: dict | None = None,
                    body: bytes | None = None) -> dict | None:
        """发送简单 HTTP 请求"""
        try:
            req = urllib.request.Request(url, method=method, data=body)
            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            resp = urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": resp.read(),
            }
        except urllib.error.HTTPError as e:
            return {
                "status": e.code,
                "headers": dict(e.headers) if e.headers else {},
                "body": e.read() if e.fp else b"",
            }
        except Exception:
            return None

    def send_raw(self, raw_text: str, host: str, port: int,
                 use_tls: bool = False) -> dict | None:
        """发送原始 HTTP 请求 (socket 级别)"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            # 确保请求以 \r\n\r\n 结束
            raw_bytes = raw_text.encode("utf-8", errors="replace")
            if not raw_bytes.endswith(b"\r\n\r\n"):
                if raw_bytes.endswith(b"\n\n"):
                    raw_bytes = raw_bytes.replace(b"\n", b"\r\n")
                else:
                    raw_bytes = raw_bytes.rstrip() + b"\r\n\r\n"

            sock.sendall(raw_bytes)

            # 读取响应
            response = b""
            while True:
                try:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    response += chunk
                    # 非 chunked 时读完 headers 后尝试判断 body 长度
                    if b"\r\n\r\n" in response and len(response) > 131072:
                        break
                except socket.timeout:
                    break

            if not response:
                return None

            return self._parse_raw_response(response)

        except Exception:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    @staticmethod
    def _parse_raw_response(data: bytes) -> dict:
        """解析原始 HTTP 响应"""
        try:
            header_end = data.find(b"\r\n\r\n")
            if header_end == -1:
                return {"status": 0, "headers": {}, "body": data}

            header_part = data[:header_end].decode("utf-8", errors="replace")
            body = data[header_end + 4:]

            lines = header_part.split("\r\n")
            status = 0
            headers = {}

            if lines:
                first = lines[0].split(" ")
                if len(first) >= 2 and first[1].isdigit():
                    status = int(first[1])

            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            return {"status": status, "headers": headers, "body": body}
        except Exception:
            return {"status": 0, "headers": {}, "body": data}


# ============================================================
# 匹配器
# ============================================================
class Matcher:
    """检查 HTTP 响应是否匹配条件"""

    @staticmethod
    def check(matchers: list[dict], condition: str,
              response: dict, resolver: VariableResolver | None = None) -> bool:
        """
        检查响应是否通过所有 matchers

        matchers-condition: "and" (默认) 或 "or"
        """
        if not matchers:
            return True

        results = []
        for m in matchers:
            results.append(Matcher._check_one(m, response, resolver))

        if condition == "or":
            return any(results)
        return all(results)

    @staticmethod
    def _check_one(matcher: dict, response: dict,
                   resolver: VariableResolver | None = None) -> bool:
        mtype = matcher.get("type", "word")
        condition = matcher.get("condition", "or")

        if mtype == "status":
            codes = matcher.get("status", [])
            if isinstance(codes, int):
                codes = [codes]
            if condition == "and":
                return all(response.get("status") == c for c in codes)
            return response.get("status") in codes

        elif mtype == "word":
            part = matcher.get("part", "body")
            words = matcher.get("words", [])

            if part == "body":
                text = response.get("body", b"")
                if isinstance(text, bytes):
                    text = text.decode("utf-8", errors="replace")
            elif part == "header":
                text = " ".join(f"{k}: {v}" for k, v in response.get("headers", {}).items())
            elif part == "content_type":
                # 大小写不敏感查找 (urllib 返回 Content-Type, raw 返回 content-type)
                hdrs = response.get("headers", {})
                ct = ""
                for k, v in hdrs.items():
                    if k.lower() == "content-type":
                        ct = v
                        break
                text = str(ct)
            else:
                text = response.get("body", b"")
                if isinstance(text, bytes):
                    text = text.decode("utf-8", errors="replace")

            if resolver:
                resolved_words = [resolver.resolve(w) for w in words]
            else:
                resolved_words = list(words)

            if condition == "and":
                return all(w in text for w in resolved_words)
            return any(w in text for w in resolved_words)

        elif mtype == "dsl":
            # 简单 DSL: "status_code_1 == 200 && contains(body_1,'...')"
            return Matcher._check_dsl(matcher, response)

        return False

    @staticmethod
    def _check_dsl(matcher: dict, response: dict) -> bool:
        """基础 DSL 匹配器"""
        dsl_list = matcher.get("dsl", [])
        condition = matcher.get("condition", "and")
        results = []

        for expr in dsl_list:
            try:
                # 解析 status_code_N == 200
                expr = re.sub(r"status_code_(\d+)", str(response.get("status", 0)), expr)

                # 解析 contains(body_N, 'xxx')
                body_text = ""
                if isinstance(response.get("body"), bytes):
                    body_text = response["body"].decode("utf-8", errors="replace")
                elif isinstance(response.get("body"), str):
                    body_text = response["body"]

                # body_1, body_2 etc all map to the same body for single requests
                def _contains(m):
                    target = m.group(1).strip().strip("'").strip('"')
                    return str(target in body_text).lower()

                expr = re.sub(r"contains\(body_\d+,\s*'([^']*)'\)", _contains, expr)
                expr = re.sub(r'contains\(body_\d+,\s*"([^"]*)"\)', _contains, expr)

                # 替换 true/false → True/False
                expr = expr.replace("&&", " and ").replace("||", " or ")
                expr = expr.replace("true", "True").replace("false", "False")

                result = eval(expr)
                results.append(bool(result))
            except Exception:
                results.append(False)

        if condition == "and":
            return all(results)
        return any(results)


def _truncate_body(body, max_len: int = 2000):
    if isinstance(body, bytes):
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            text = str(body)
    else:
        text = str(body)
    return text if len(text) <= max_len else text[:max_len] + f"... ({len(body)} bytes total)"


def _make_finding_data(template: dict, name: str, severity: str,
                       url: str, detail: str,
                       req: dict | None = None,
                       resp: dict | None = None) -> dict:
    f = {
        "template_id": template.get("_id", "?"),
        "name": name, "severity": severity,
        "url": url, "matched": True, "detail": detail,
    }
    if req:
        f["request"] = req
    if resp:
        f["response"] = {
            "status": resp.get("status", 0),
            "headers": resp.get("headers", {}),
            "body": _truncate_body(resp.get("body", b"")),
        }
    return f


# ============================================================
# 模版扫描引擎
# ============================================================
class TemplateEngine:
    """POC 模版扫描引擎"""

    def __init__(self, poc_dir: str = None):
        self.templates: list[dict] = []          # 所有模版
        self.tag_index: dict[str, list[dict]] = {}  # tag → [模版]
        self._sender = HttpSender(timeout=10.0)
        if poc_dir:
            self.load(poc_dir)

    # ----------------------------------------------------------
    # 加载 (带 pickle 缓存)
    # ----------------------------------------------------------
    def load(self, poc_dir: str):
        """递归加载 poc/ 下所有 YAML 模版，首次加载后缓存到 .poc_cache.pkl"""
        root = Path(poc_dir)
        if not root.exists():
            print(f"  {_C.y}[!] POC 目录不存在: {poc_dir}{_C.R}")
            return

        cache_path = root / ".poc_cache.pkl" if root.is_dir() else root.parent / ".poc_cache.pkl"

        # 尝试从缓存加载
        if cache_path.exists():
            yaml_files = list(root.rglob("*.yaml")) + list(root.rglob("*.yml"))
            newest_yaml = max((f.stat().st_mtime for f in yaml_files), default=0)
            if cache_path.stat().st_mtime >= newest_yaml:
                try:
                    with open(cache_path, "rb") as f:
                        cached = pickle.load(f)
                    self.templates = cached["templates"]
                    self.tag_index = cached["tag_index"]
                    print(f"  [*] 从缓存加载: {len(self.templates)} 个模版, "
                          f"{len(self.tag_index)} 个标签 (跳过 {len(yaml_files)} 个 YAML 解析)")
                    print()
                    return
                except Exception as e:
                    print(f"  {_C.y}[!] 缓存损坏，重新解析: {e}{_C.R}")

        # 全量解析
        yaml_files = list(root.rglob("*.yaml")) + list(root.rglob("*.yml"))
        print(f"  [*] 加载 POC 模版: {poc_dir} ({len(yaml_files)} 个文件) ...")

        loaded = 0
        for fp in yaml_files:
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if not data or not isinstance(data, dict):
                    continue
                tid = data.get("id", fp.stem)
                data["_file"] = str(fp)
                data["_id"] = tid
                self.templates.append(data)

                # 建立 tag 索引
                tags_str = data.get("info", {}).get("tags", "")
                if isinstance(tags_str, str):
                    tags = [t.strip().lower() for t in tags_str.split(",") if t.strip()]
                elif isinstance(tags_str, list):
                    tags = [t.strip().lower() for t in tags_str if t.strip()]
                else:
                    tags = []

                for tag in tags:
                    self.tag_index.setdefault(tag, []).append(data)

                loaded += 1
            except Exception as e:
                print(f"  {_C.y}[!] 加载失败 {fp.name}: {e}{_C.R}")

        # 保存缓存
        try:
            with open(cache_path, "wb") as f:
                pickle.dump({
                    "templates": self.templates,
                    "tag_index": self.tag_index,
                }, f, protocol=pickle.HIGHEST_PROTOCOL)
            size_mb = cache_path.stat().st_size / 1024 / 1024
            print(f"  [*] 加载完毕: {loaded} 个模版, {len(self.tag_index)} 个标签")
            print(f"  [*] 缓存已保存: {cache_path.name} ({size_mb:.1f} MB)")
            print()
        except Exception as e:
            print(f"  [*] 加载完毕: {loaded} 个模版, {len(self.tag_index)} 个标签")
            print(f"  {_C.y}[!] 缓存保存失败: {e}{_C.R}")
            print()

    # ----------------------------------------------------------
    # 查找
    # ----------------------------------------------------------
    def find(self, cms_names: list[str]) -> list[dict]:
        """
        根据指纹 CMS 名称查找匹配的模版

        匹配规则: CMS 名称与模版 tag 做双向子串匹配
        如 CMS "nacos" 匹配 tag "nacos", "nacos-auth-bypass"
        """
        matched: list[dict] = []
        seen: set[str] = set()

        for cms in cms_names:
            cms_lower = cms.lower().strip()
            if not cms_lower:
                continue

            for tag, templates in self.tag_index.items():
                # 双向子串匹配
                if cms_lower in tag or tag in cms_lower:
                    for t in templates:
                        tid = t.get("_id", "")
                        if tid not in seen:
                            seen.add(tid)
                            matched.append(t)

        # 去重 + 按 severity 排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        matched.sort(key=lambda t: severity_order.get(
            t.get("info", {}).get("severity", "info").lower(), 9
        ))
        return matched

    # ----------------------------------------------------------
    # 执行
    # ----------------------------------------------------------
    def execute(self, template: dict, scheme: str, host: str, port: int) -> list[dict]:
        """
        对目标执行单个模版，返回漏洞发现列表

        返回: [{template_id, name, severity, url, matched, detail}, ...]
        """
        base_url = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
        use_tls = (scheme == "https")

        findings: list[dict] = []

        info = template.get("info", {})
        tpl_name = info.get("name", template.get("_id", "?"))
        tpl_severity = info.get("severity", "unknown")

        # 自定义变量
        custom_vars = dict(template.get("variables", {}))

        http_blocks = template.get("http", [])
        if isinstance(http_blocks, dict):
            http_blocks = [http_blocks]

        for block_idx, block in enumerate(http_blocks):
            resolver = VariableResolver(base_url, host, port, custom_vars)
            matchers = block.get("matchers", [])
            matchers_cond = block.get("matchers-condition", "and")

            # ---------- raw 格式 ----------
            if "raw" in block:
                raw_requests = block.get("raw", [])
                payloads = block.get("payloads", {})

                # 生成 payload 组合 (pitchfork 模式: 一一对应)
                payload_keys = list(payloads.keys())
                if payload_keys:
                    payload_values = [payloads[k] for k in payload_keys]
                    max_len = max(len(v) for v in payload_values)
                    for i in range(max_len):
                        # 每次组合使用新的 resolver
                        resolver_i = VariableResolver(base_url, host, port, custom_vars)
                        for ki, key in enumerate(payload_keys):
                            val = payload_values[ki][i % len(payload_values[ki])]
                            resolver_i.custom[key] = val

                        raw_text = raw_requests[i % len(raw_requests)] if i < len(raw_requests) else raw_requests[0]
                        raw_resolved = resolver_i.resolve(raw_text)

                        resp = self._sender.send_raw(raw_resolved, host, port, use_tls)
                        if resp and Matcher.check(matchers, matchers_cond, resp, resolver_i):
                            findings.append(_make_finding_data(
                                template, tpl_name, tpl_severity,
                                f"{scheme}://{host}:{port}",
                                f"payload[{i}] 命中",
                                req={"raw": raw_resolved}, resp=resp,
                            ))
                            if block.get("stop-at-first-match"):
                                break
                else:
                    # 无 payloads, 逐个 raw 请求发送
                    for ri, raw_text in enumerate(raw_requests):
                        resolver_ri = VariableResolver(base_url, host, port, custom_vars)
                        raw_resolved = resolver_ri.resolve(raw_text)
                        resp = self._sender.send_raw(raw_resolved, host, port, use_tls)
                        if resp and Matcher.check(matchers, matchers_cond, resp, resolver_ri):
                            findings.append(_make_finding_data(
                                template, tpl_name, tpl_severity,
                                f"{scheme}://{host}:{port}",
                                f"raw[{ri}] 命中",
                                req={"raw": raw_resolved}, resp=resp,
                            ))

                continue  # raw 处理完毕

            # ---------- 简单 path 格式 ----------
            method = block.get("method", "GET").upper()
            paths = block.get("path", [])
            headers = block.get("headers", {})

            # 模板级 body
            tpl_body = block.get("body", "")
            if isinstance(tpl_body, str):
                tpl_body = tpl_body.encode()

            for path_template in paths:
                url = resolver.resolve(path_template)
                # 处理 headers 中的 {{...}}
                resolved_headers = {k: resolver.resolve(str(v)) for k, v in headers.items()}

                resp = self._sender.send_simple(method, url, resolved_headers, tpl_body if tpl_body else None)

                if resp and Matcher.check(matchers, matchers_cond, resp, resolver):
                    findings.append(_make_finding_data(
                        template, tpl_name, tpl_severity, url,
                        "响应匹配",
                        req={
                            "method": method, "url": url,
                            "headers": resolved_headers,
                            "body": tpl_body.decode("utf-8", errors="replace") if tpl_body else "",
                        },
                        resp=resp,
                    ))
                    if block.get("stop-at-first-match"):
                        break

        return findings

    def execute_all(self, templates: list[dict], scheme: str, host: str, port: int,
                    max_workers: int = 5) -> list[dict]:
        """批量执行多个模版 (线程池)"""
        all_findings: list[dict] = []

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(self.execute, t, scheme, host, port): t
                for t in templates
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        all_findings.extend(result)
                except Exception:
                    pass

        return all_findings


# ============================================================
# 独立测试
# ============================================================
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("用法:")
        print("  python template_engine.py <poc_dir>                    # 列出所有模版")
        print("  python template_engine.py <poc_dir> <tag>              # 按 tag 查找模版")
        print("  python template_engine.py <poc_dir> <tag> <url>        # 执行扫描")
        sys.exit(1)

    engine = TemplateEngine(sys.argv[1])

    if len(sys.argv) == 2:
        print(f"\n模版列表 ({len(engine.templates)} 个):\n")
        for t in engine.templates:
            info = t.get("info", {})
            name = info.get("name", "?")
            tags = info.get("tags", "")
            sev = info.get("severity", "?")
            print(f"  {_C.B}{t['_id']}{_C.R}")
            print(f"    {name}")
            print(f"    severity: {sev}  tags: {tags}")
            print()

    elif len(sys.argv) == 3:
        tag = sys.argv[2].lower()
        matched = engine.find([tag])
        tags_list = sorted(engine.tag_index.keys())
        matching_tags = [t for t in tags_list if tag in t or t in tag]
        print(f"\n匹配 tag='{tag}': {len(matched)} 个模版")
        print(f"相关 tags: {matching_tags}\n")
        for t in matched:
            info = t.get("info", {})
            print(f"  {_C.B}{t['_id']}{_C.R} — {info.get('name', '?')}")
            print(f"    severity: {info.get('severity', '?')}  tags: {info.get('tags', '')}")
            print()

    elif len(sys.argv) >= 4:
        tag = sys.argv[2]
        url = sys.argv[3]
        from urllib.parse import urlparse
        u = urlparse(url)
        scheme = u.scheme or "https"
        host = u.hostname or "localhost"
        port = u.port or (443 if scheme == "https" else 80)

        matched = engine.find([tag])
        print(f"\n目标: {url}")
        print(f"匹配模版: {len(matched)} 个\n")

        findings = engine.execute_all(matched, scheme, host, port)
        if findings:
            print(f"{_C.r}发现 {len(findings)} 个漏洞:{_C.R}\n")
            for f in findings:
                print(f"  {_C.r}●{_C.R} {_C.B}{f['name']}{_C.R} [{f['severity']}]")
                print(f"    {f['url']}")
                print(f"    {f['detail']}")
                print()
        else:
            print(f"{_C.g}未发现漏洞{_C.R}")
