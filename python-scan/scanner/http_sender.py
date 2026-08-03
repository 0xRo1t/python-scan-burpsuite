#!/usr/bin/env python3
"""HTTP 请求发送 — 支持简单格式 + raw 格式，可选 verbose 输出"""

from __future__ import annotations

import ssl
import socket
import urllib.request
import urllib.error


class _C:
    R = "\033[0m"; B = "\033[1m"; D = "\033[2m"
    r = "\033[91m"; g = "\033[92m"; y = "\033[93m"
    c = "\033[96m"; m = "\033[95m"


class HttpSender:
    """发送 HTTP 请求"""

    def __init__(self, timeout: float = 10.0, verify_ssl: bool = False,
                 verbose: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose

    def _make_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # ----------------------------------------------------------
    # verbose 输出
    # ----------------------------------------------------------
    def _print_request(self, method: str, url: str,
                       headers: dict | None = None, body: bytes | None = None):
        if not self.verbose:
            return
        print(f"\n  {_C.D}── REQ ──────────────────────────────{_C.R}")
        print(f"  {_C.B}{method}{_C.R} {_C.c}{url}{_C.R}")
        if headers:
            for k, v in headers.items():
                print(f"  {_C.D}{k}: {v}{_C.R}")
        if body:
            body_str = body[:2000].decode("utf-8", errors="replace")
            print(f"  {_C.D}{body_str}{_C.R}")
            if len(body) > 2000:
                print(f"  {_C.D}... ({len(body)} bytes total){_C.R}")

    def _print_response(self, resp: dict):
        if not self.verbose:
            return
        status = resp.get("status", 0)
        color = _C.g if 200 <= status < 400 else _C.y if status < 500 else _C.r
        print(f"  {_C.D}── RESP ─────────────────────────────{_C.R}")
        print(f"  {color}HTTP {status}{_C.R}")
        for k, v in resp.get("headers", {}).items():
            print(f"  {_C.D}{k}: {v}{_C.R}")
        body = resp.get("body", b"")
        if body:
            if isinstance(body, bytes):
                body_str = body[:4000].decode("utf-8", errors="replace")
            else:
                body_str = str(body)[:4000]
            print(f"  {_C.D}{body_str}{_C.R}")
            if len(body) > 4000:
                print(f"  {_C.D}... ({len(body)} bytes total){_C.R}")

    def _print_raw_request(self, raw_text: str):
        if not self.verbose:
            return
        print(f"\n  {_C.D}── RAW REQ ──────────────────────────{_C.R}")
        text = raw_text[:2000]
        for line in text.split("\n"):
            print(f"  {_C.m}{line}{_C.R}")
        if len(raw_text) > 2000:
            print(f"  {_C.D}... ({len(raw_text)} chars total){_C.R}")

    # ----------------------------------------------------------
    # 简单请求 (method + path + headers)
    # ----------------------------------------------------------
    def send_simple(self, method: str, url: str,
                    headers=None, body=None):
        self._print_request(method, url, headers, body)
        try:
            req = urllib.request.Request(url, method=method, data=body)
            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)
            ctx = self._make_ssl_context()
            resp = urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
            result = {
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": resp.read(),
            }
            self._print_response(result)
            return result
        except urllib.error.HTTPError as e:
            result = {
                "status": e.code,
                "headers": dict(e.headers) if e.headers else {},
                "body": e.read() if e.fp else b"",
            }
            self._print_response(result)
            return result
        except Exception as e:
            if self.verbose:
                print(f"  {_C.r}[!] 请求失败: {e}{_C.R}")
            return None

    # ----------------------------------------------------------
    # raw 请求 (完整的 HTTP 文本)
    # ----------------------------------------------------------
    def send_raw(self, raw_text: str, host: str, port: int,
                 use_tls: bool = False):
        self._print_raw_request(raw_text)
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            if use_tls:
                ctx = self._make_ssl_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)

            raw_bytes = raw_text.encode("utf-8", errors="replace")
            if not raw_bytes.endswith(b"\r\n\r\n"):
                if raw_bytes.endswith(b"\n\n"):
                    raw_bytes = raw_bytes.replace(b"\n", b"\r\n")
                else:
                    raw_bytes = raw_bytes.rstrip() + b"\r\n\r\n"

            sock.sendall(raw_bytes)

            response = b""
            while True:
                try:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    response += chunk
                    if b"\r\n\r\n" in response and len(response) > 131072:
                        break
                except socket.timeout:
                    break

            if not response:
                if self.verbose:
                    print(f"  {_C.y}[!] 空响应{_C.R}")
                return None

            result = self._parse_raw_response(response)
            self._print_response(result)
            return result

        except Exception as e:
            if self.verbose:
                print(f"  {_C.r}[!] 请求失败: {e}{_C.R}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    @staticmethod
    def _parse_raw_response(data: bytes) -> dict:
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
