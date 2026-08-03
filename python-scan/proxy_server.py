#!/usr/bin/env python3
"""
MITM 代理服务器 — 配合 Burp Suite /指纹识别 / Nuclei 使用

架构:
  浏览器 → proxy_server.py (MITM 解密 + 指纹匹配) → 目标服务器

首次运行自动生成 CA 证书，需将 CA 证书导入系统信任库。
默认不打印请求/响应体，只显示指纹匹配结果，--verbose 可开启完整显示。
"""

import socket
import ssl
import threading
import sys
import json
import argparse
import datetime
from pathlib import Path

from fingerprint_engine import FingerprintEngine
from template_engine import TemplateEngine
from nuclei_scanner import NucleiScanner
from logger import log_error, log_warn, log_info


# ============================================================
# 证书管理 (自动生成 CA + 动态签发站点证书)
# ============================================================
CERT_DIR = Path(__file__).parent / ".certs"

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

import ipaddress


class CertManager:
    """管理 CA 证书和动态签发站点证书"""

    def __init__(self):
        self.ca_key = None
        self.ca_cert = None
        self.ca_key_path = CERT_DIR / "ca_key.pem"
        self.ca_cert_path = CERT_DIR / "ca_cert.pem"
        self.cert_cache: dict[str, tuple[str, str]] = {}
        self.cache_lock = threading.Lock()

    def ensure_ca(self):
        CERT_DIR.mkdir(parents=True, exist_ok=True)
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            self._load_ca()
            return
        if not HAS_CRYPTO:
            print()
            print("=" * 60)
            print("  [错误] 缺少 cryptography 库，无法生成 CA 证书")
            print("  请运行: pip install cryptography")
            print("=" * 60)
            print()
            sys.exit(1)
        self._generate_ca()

    def _load_ca(self):
        with open(self.ca_key_path, "rb") as f:
            self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(self.ca_cert_path, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())

    def _generate_ca(self):
        print()
        print("=" * 60)
        print("  首次运行 — 正在生成 MITM CA 根证书...")
        print("=" * 60)

        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ProxyScanner MITM CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ProxyScanner Root CA"),
        ])
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

        with open(self.ca_key_path, "wb") as f:
            f.write(self.ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(self.ca_cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

        crt_path = CERT_DIR / "ca_cert.crt"
        with open(crt_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

        print(f"  ✓ CA 私钥: {self.ca_key_path}")
        print(f"  ✓ CA 证书(可导入): {crt_path}")
        print()
        print("  ⚠  请将 CA 证书导入系统信任库:")
        print(f"    sudo security add-trusted-cert -d -r trustRoot -k \\")
        print(f"      /Library/Keychains/System.keychain {crt_path}")
        print("=" * 60)
        print()

    def get_cert_for_host(self, hostname: str) -> tuple[str, str]:
        with self.cache_lock:
            if hostname in self.cert_cache:
                return self.cert_cache[hostname]

        cert_path = CERT_DIR / f"{hostname}.crt"
        key_path = CERT_DIR / f"{hostname}.key"

        if cert_path.exists() and key_path.exists():
            cached = (str(cert_path), str(key_path))
            with self.cache_lock:
                self.cert_cache[hostname] = cached
            return cached

        host_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])

        # 判断是否为 IP 地址，SAN 需用 IPAddress 而非 DNSName
        try:
            ip_obj = ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            san_list = [x509.IPAddress(ip_obj)]
        else:
            san_list = [x509.DNSName(hostname)]
            if hostname.startswith("*."):
                san_list.append(x509.DNSName(hostname[2:]))
            else:
                san_list.append(x509.DNSName(f"*.{hostname}"))

        host_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(host_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=True,
                    content_commitment=False, key_cert_sign=False, crl_sign=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

        with open(key_path, "wb") as f:
            f.write(host_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(cert_path, "wb") as f:
            f.write(host_cert.public_bytes(serialization.Encoding.PEM))

        cached = (str(cert_path), str(key_path))
        with self.cache_lock:
            self.cert_cache[hostname] = cached
        return cached


# ============================================================
# 终端颜色
# ============================================================
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_YELLOW = "\033[43m"
    BG_RED = "\033[41m"


# ============================================================
# 输出辅助
# ============================================================
def print_sep(char="─", length=80):
    print(f"{Colors.DIM}{char * length}{Colors.RESET}")


def print_header(title: str, color: str = Colors.CYAN):
    print()
    print_sep("═")
    print(f"{color}{Colors.BOLD}  {title}{Colors.RESET}")
    print_sep("═")


def print_field(label: str, value: str, color: str = Colors.WHITE):
    print(f"  {Colors.DIM}{label}:{Colors.RESET} {color}{value}{Colors.RESET}")


def print_body(title: str, data: bytes):
    print()
    print(f"  {Colors.BOLD}{title}:{Colors.RESET}")
    print_sep("─", 60)
    try:
        text = data.decode("utf-8", errors="replace")
        max_lines = 80
        lines = text.split("\n")
        if len(lines) > max_lines:
            for line in lines[:max_lines]:
                print(f"  {Colors.DIM}{line}{Colors.RESET}")
            print(f"  {Colors.YELLOW}... 省略 {len(lines) - max_lines} 行 (共 {len(data)} 字节){Colors.RESET}")
        else:
            for line in lines:
                print(f"  {Colors.DIM}{line}{Colors.RESET}")
    except Exception:
        print(f"  {Colors.YELLOW}[二进制数据, {len(data)} 字节]{Colors.RESET}")
    print_sep("─", 60)


def print_http_message(direction: str, host: str, port: int, data: bytes):
    """详细打印 HTTP 消息 (verbose 模式)"""
    if direction == "REQUEST":
        color = Colors.GREEN
        arrow = "→"
    else:
        color = Colors.MAGENTA
        arrow = "←"

    if not data:
        return

    print_header(f"{arrow} {direction}  [{host}:{port}]", color)

    try:
        text = data.decode("utf-8", errors="replace")
        lines = text.split("\r\n")

        if lines:
            print_field("First Line", lines[0], Colors.BOLD + color)

        header_end = 0
        content_type = ""
        for i, line in enumerate(lines[1:], 1):
            if line == "":
                header_end = i
                break
            if ":" in line:
                key, value = line.split(":", 1)
                hl_color = Colors.WHITE
                if key.lower() in ("host", "content-type", "content-length",
                                   "user-agent", "cookie", "authorization",
                                   "x-request-id", "referer", "origin",
                                   "set-cookie", "server", "location"):
                    hl_color = Colors.YELLOW
                if key.lower() == "content-type":
                    content_type = value.strip().lower()
                print_field(key.strip(), value.strip(), hl_color)

        body_start = header_end + 1
        if body_start < len(lines):
            body_text = "\r\n".join(lines[body_start:])
            body_bytes = body_text.encode("utf-8", errors="replace")

            if "application/json" in content_type:
                try:
                    parsed = json.loads(body_text)
                    pretty = json.dumps(parsed, indent=2, ensure_ascii=False)
                    print_body("Body (JSON)", pretty.encode())
                except Exception:
                    print_body("Body", body_bytes)
            else:
                print_body("Body", body_bytes)

        print(f"  {Colors.DIM}总计: {len(data)} 字节{Colors.RESET}")
    except Exception as e:
        log_warn(f"[解析失败: {e}] 原始 {len(data)} 字节")


def print_finger_matches(host: str, port: int, status_code: int,
                         matches: list[dict], url_path: str = ""):
    """打印指纹匹配结果 — 紧凑格式"""
    path_display = url_path[:80] if url_path else ""
    print_sep("─")
    print(f"  {Colors.DIM}{host}:{port}{Colors.RESET}{path_display}"
          f"  {Colors.DIM}[{status_code}]{Colors.RESET}")

    for m in matches:
        cms = m["cms"]
        method = m["method"]
        rules_hit = m.get("rules_hit", 0)
        rule_info = f" {rules_hit} 条" if rules_hit > 1 else ""
        print(f"  {Colors.GREEN}● {cms}{Colors.RESET}"
              f"  {Colors.DIM}({method}{rule_info}){Colors.RESET}", end="")
        # 关键词追加在同一行
        kws = [kw for loc, kw in m["matches"][:3]]
        if kws:
            kw_str = ", ".join(f"\"{k[:40]}\"" for k in kws)
            print(f"  {Colors.DIM}{kw_str}{Colors.RESET}", end="")
        print()


# ============================================================
# HTTP 消息解析
# ============================================================
def http_parse_request(data: bytes) -> dict | None:
    try:
        text = data.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        first = lines[0].split(" ")
        if len(first) < 2:
            return None
        method, path = first[0], first[1]
        headers = {}
        for line in lines[1:]:
            if line == "":
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        header_end = 0
        for i, line in enumerate(lines[1:], 1):
            if line == "":
                header_end = i
                break
        body = "\r\n".join(lines[header_end + 1:]).encode("utf-8", errors="replace") if header_end else b""
        return {"method": method, "path": path, "headers": headers, "body": body}
    except Exception:
        return None


def http_parse_response(data: bytes) -> dict | None:
    try:
        text = data.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        first = lines[0].split(" ")
        if len(first) < 2:
            return None
        status_code = int(first[1]) if len(first) > 1 and first[1].isdigit() else 0
        status_text = " ".join(first[2:]) if len(first) > 2 else ""
        headers = {}
        for line in lines[1:]:
            if line == "":
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        header_end = 0
        for i, line in enumerate(lines[1:], 1):
            if line == "":
                header_end = i
                break
        body = "\r\n".join(lines[header_end + 1:]).encode("utf-8", errors="replace") if header_end else b""
        return {"status_code": status_code, "status_text": status_text, "headers": headers, "body": body}
    except Exception:
        return None


# ============================================================
# MITM 代理核心
# ============================================================
class MITMProxy:
    """MITM 代理 — 解密 HTTPS + 指纹匹配"""

    def __init__(self, listen_host="127.0.0.1", listen_port=8889,
                 verbose=False, max_display_bytes=65536,
                 finger_engine: FingerprintEngine | None = None,
                 template_engine=None, nuclei_scanner=None,
                 auto_scan=True, scan_workers=5,
                 upstream=None, finger_blacklist: set[str] = None):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.verbose = verbose
        self.max_display_bytes = max_display_bytes
        self.finger = finger_engine
        self.templates = template_engine
        self.nuclei = nuclei_scanner
        self.auto_scan = auto_scan and (template_engine is not None or nuclei_scanner is not None)
        self.scan_workers = scan_workers
        self.running = False
        self.server_socket = None
        self.cert_manager = CertManager()

        # 指纹黑名单: 这些 CMS 不显示、不触发扫描
        self.finger_blacklist: set[str] = finger_blacklist or set()

        # 上游代理 (如 Burp): (host, port) 或 None
        self.upstream = upstream  # ("127.0.0.1", 8080) 或 None

        # 已扫描过的 host+CMS 组合 (避免同 CMS 重复扫描，但不同 CMS 会触发新扫描)
        self._scanned_cms: dict[str, set[str]] = {}  # host_key → {cms_name, ...}
        self._scanned_lock = threading.Lock()

        # 统计
        self._stats_lock = threading.Lock()
        self.stats = {"requests": 0, "finger_hits": 0, "connects": 0,
                      "scans": 0, "findings": 0}

    def start(self):
        self.cert_manager.ensure_ca()

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.listen_host, self.listen_port))
        self.server_socket.listen(50)
        self.running = True

        print()
        print_header("MITM 代理已启动", Colors.GREEN)
        print_field("监听地址", f"{self.listen_host}:{self.listen_port}")
        print_field("详细模式", "开" if self.verbose else "关 (--verbose 开启)")
        print_field("指纹引擎", "就绪" if self.finger and self.finger._loaded else "未加载")
        print_field("POC 扫描", "开" if self.auto_scan else "关 (--no-scan 关闭)")
        if self.auto_scan and self.templates:
            print_field("POC 模版", f"{len(self.templates.templates)} 个")
        if self.auto_scan and self.nuclei and self.nuclei.available:
            print_field("Nuclei", "已就绪")
        if self.upstream:
            print_field("上游代理", f"{self.upstream[0]}:{self.upstream[1]} (Burp)")
        print()
        print(f"  {Colors.CYAN}链路:{Colors.RESET}")
        if self.upstream:
            print(f"  {Colors.DIM}  浏览器 → proxy:{self.listen_host}:{self.listen_port} → Burp:{self.upstream[0]}:{self.upstream[1]} → 目标{Colors.RESET}")
        else:
            print(f"  {Colors.DIM}  浏览器 → proxy:{self.listen_host}:{self.listen_port} → 目标{Colors.RESET}")
        print()
        print(f"  {Colors.CYAN}等待连接... (Ctrl+C 停止){Colors.RESET}")
        print_sep("═")
        print()

        try:
            while self.running:
                try:
                    client_socket, client_addr = self.server_socket.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_addr),
                        daemon=True,
                    ).start()
                except socket.timeout:
                    continue
                except OSError:
                    if not self.running:
                        break
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}收到中断，关闭中...{Colors.RESET}")
        finally:
            self.stop()

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        with self._stats_lock:
            s = self.stats
        print(f"{Colors.GREEN}代理已停止 | 请求: {s['requests']} 指纹命中: {s['finger_hits']}{Colors.RESET}")

    # ----------------------------------------------------------
    # 连接分发
    # ----------------------------------------------------------
    def _handle_client(self, client_sock: socket.SocketType, addr: tuple):
        conn_tag = f"{addr[0]}:{addr[1]}"
        try:
            request_data = self._recv_http_message(client_sock)
            if not request_data:
                client_sock.close()
                return

            parsed = http_parse_request(request_data)
            if not parsed:
                log_warn(f"[{conn_tag}] 无法解析请求")
                client_sock.close()
                return

            method = parsed["method"].upper()
            if method == "CONNECT":
                self._handle_connect(client_sock, conn_tag, parsed)
            else:
                self._handle_http(client_sock, conn_tag, parsed, request_data)

        except Exception as e:
            log_error(f"[{conn_tag}] 错误: {e}")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    # ----------------------------------------------------------
    # HTTP 明文转发
    # ----------------------------------------------------------
    def _handle_http(self, client_sock, conn_tag, parsed, raw_request):
        headers = parsed["headers"]
        host = headers.get("host", "")
        port = 80
        if ":" in host:
            host, port_str = host.rsplit(":", 1)
            port = int(port_str)

        path = parsed["path"]
        if path.startswith("http://") or path.startswith("https://"):
            from urllib.parse import urlparse
            u = urlparse(path)
            host = u.hostname or host
            port = u.port or 80

        with self._stats_lock:
            self.stats["requests"] += 1

        # 请求摘要 → 写入日志
        log_info(f"[{conn_tag}] HTTP {parsed['method']} {host}:{port}{parsed['path'][:120]}")

        # verbose: 显示请求
        if self.verbose:
            print_http_message("REQUEST", host, port, raw_request[:self.max_display_bytes])

        # 连接目标 (或上游代理)
        remote_sock = None
        try:
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.settimeout(30)

            if self.upstream:
                # 通过上游代理转发，确保请求是绝对 URI 格式
                up_host, up_port = self.upstream
                remote_sock.connect((up_host, up_port))
                # 如果 path 是相对路径，转为绝对 URI
                if not path.startswith("http://") and not path.startswith("https://"):
                    upstream_request = self._make_absolute_request(raw_request, host, port)
                else:
                    upstream_request = raw_request
                remote_sock.sendall(upstream_request)
            else:
                remote_sock.connect((host, port))
                remote_sock.sendall(raw_request)

            response_data = self._recv_http_message(remote_sock)
            remote_sock.close()
            remote_sock = None

            if response_data:
                # ---- 指纹匹配 ----
                self._match_and_display(host, port, path, response_data, scheme="http")

                # verbose: 显示响应
                if self.verbose:
                    print_http_message("RESPONSE", host, port, response_data[:self.max_display_bytes])

                client_sock.sendall(response_data)

        except Exception as e:
            log_error(f"[{conn_tag}] 转发 HTTP 失败: {e}")
        finally:
            if remote_sock:
                try:
                    remote_sock.close()
                except Exception:
                    pass

    # ----------------------------------------------------------
    # HTTPS CONNECT — MITM 解密
    # ----------------------------------------------------------
    def _handle_connect(self, client_sock, conn_tag, parsed):
        target = parsed["path"]
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            port = int(port_str)
        else:
            host, port = target, 443

        with self._stats_lock:
            self.stats["connects"] += 1
            self.stats["requests"] += 1

        #print(f"\n{Colors.BLUE}[{conn_tag}] CONNECT {host}:{port} (MITM){Colors.RESET}")

        # 1. 获取证书
        try:
            cert_path, key_path = self.cert_manager.get_cert_for_host(host)
        except Exception as e:
            log_error(f"[{conn_tag}] 证书错误: {e}")
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            client_sock.close()
            return

        # 2. 告诉浏览器隧道已建立
        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # 3. TLS 握手 (浏览器侧, 服务端角色)
        try:
            ctx_server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx_server.load_cert_chain(cert_path, key_path)
            ctx_server.check_hostname = False
            ctx_server.verify_mode = ssl.CERT_NONE
            # 兼容更多浏览器的 TLS 设置
            ctx_server.minimum_version = ssl.TLSVersion.TLSv1_2
        except AttributeError:
            pass  # Python < 3.7 不支持 minimum_version
        try:
            client_tls = ctx_server.wrap_socket(client_sock, server_side=True)
        except ssl.SSLError as e:
            if "BAD_CERTIFICATE" in str(e).upper() or "CERTIFICATE" in str(e).upper():
                log_warn(f"[{conn_tag}] 浏览器拒绝证书 ({host}): {e}. "
                         f"请将 CA 证书导入系统信任库: "
                         f"sudo security add-trusted-cert -d -r trustRoot "
                         f"-k /Library/Keychains/System.keychain "
                         f"{self.cert_manager.ca_cert_path}")
            else:
                log_error(f"[{conn_tag}] 浏览器 TLS 失败: {e}")
            client_sock.close()
            return
        except Exception as e:
            log_error(f"[{conn_tag}] 浏览器 TLS 失败: {e}")
            client_sock.close()
            return

        # 4. 连接出站 — 上游 或 直连
        if self.upstream:
            up_host, up_port = self.upstream
            try:
                remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_sock.settimeout(10)
                remote_sock.connect((up_host, up_port))
                remote_sock.sendall(
                    f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode()
                )
                resp = remote_sock.recv(4096)
                if b"200" not in resp:
                    resp_text = resp.decode(errors='replace')[:80]
                    log_error(f"[{conn_tag}] 上游拒绝: {resp_text}")
                    remote_sock.close()
                    client_tls.close()
                    return
                remote_side = remote_sock
                log_info(f"[{conn_tag}] 上游隧道已建立 (TLS由Burp处理)")
            except Exception as e:
                log_error(f"[{conn_tag}] 连接上游失败: {e}")
                client_tls.close()
                return
        else:
            try:
                remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_sock.settimeout(10)
                remote_sock.connect((host, port))
            except Exception as e:
                log_error(f"[{conn_tag}] 连接目标失败: {e}")
                client_tls.close()
                return
            try:
                ctx_client = ssl.create_default_context()
                ctx_client.check_hostname = False
                ctx_client.verify_mode = ssl.CERT_NONE
                remote_side = ctx_client.wrap_socket(remote_sock, server_hostname=host)
            except Exception as e:
                log_error(f"[{conn_tag}] 目标 TLS 失败: {e}")
                remote_sock.close()
                client_tls.close()
                return
            log_info(f"[{conn_tag}] TLS 隧道已建立")

        # 5. 双向中继
        self._relay_https(client_tls, remote_side, conn_tag, host, port)

    def _relay_https(self, client_tls, remote_sock, conn_tag, host, port):
        """HTTPS 双向中继 — 解密 → 显示+扫描 → 加密转发"""
        stop_event = threading.Event()
        results = {"req": b"", "resp": b""}

        def relay(src, dst, key):
            try:
                while not stop_event.is_set():
                    src.settimeout(0.5)
                    try:
                        chunk = src.recv(65536)
                    except (socket.timeout, ssl.SSLWantReadError):
                        continue
                    if not chunk:
                        break
                    results[key] += chunk
                    try:
                        dst.sendall(chunk)
                    except Exception:
                        break
            except Exception:
                pass
            finally:
                stop_event.set()

        t1 = threading.Thread(target=relay, args=(client_tls, remote_sock, "req"), daemon=True)
        t2 = threading.Thread(target=relay, args=(remote_sock, client_tls, "resp"), daemon=True)
        t1.start()
        t2.start()
        t1.join(timeout=60)
        t2.join(timeout=60)

        try:
            client_tls.close()
        except Exception:
            pass
        try:
            remote_sock.close()
        except Exception:
            pass

        # ---- 指纹匹配 + 扫描 ----
        if results["resp"] and self.finger:
            self._match_and_display(host, port, "", results["resp"], scheme="https")

        if self.verbose:
            if results["req"]:
                self._display_http_messages("REQUEST", host, port, results["req"])
            if results["resp"]:
                self._display_http_messages("RESPONSE", host, port, results["resp"])

        log_info(f"[{conn_tag}] 关闭 (req={len(results['req'])}B, resp={len(results['resp'])}B)")

    # ----------------------------------------------------------
    # 指纹匹配 + 显示
    # ----------------------------------------------------------
    def _match_and_display(self, host: str, port: int, path: str,
                           response_data: bytes, scheme: str = "https"):
        """解析响应、匹配指纹、触发 POC 扫描"""
        if not self.finger:
            return

        resp = http_parse_response(response_data)
        if not resp or not resp.get("body"):
            return

        matches = self.finger.match(resp["body"])
        if matches:
            # 指纹黑名单过滤
            if self.finger_blacklist:
                matches = [m for m in matches if m["cms"] not in self.finger_blacklist]
            if not matches:
                return

            with self._stats_lock:
                self.stats["finger_hits"] += 1

            # 提取 CMS 名称列表
            cms_names = [m["cms"] for m in matches]
            #print_finger_matches(host, port, resp.get("status_code", 0),matches, path)

            # ---- 触发 POC 扫描 (后台线程) ----
            has_tpl = self.auto_scan and self.templates
            has_nuclei = self.auto_scan and self.nuclei and self.nuclei.available
            if (has_tpl or has_nuclei) and cms_names:
                scan_key = f"{scheme}://{host}:{port}"
                with self._scanned_lock:
                    scanned_set = self._scanned_cms.get(scan_key, set())
                    # 只扫描新发现的 CMS (同 host 同 CMS 不重复扫)
                    new_cms = [c for c in cms_names if c not in scanned_set]
                    if not new_cms:
                        return
                    # 标记这些 CMS 为已扫描
                    for c in new_cms:
                        scanned_set.add(c)
                    self._scanned_cms[scan_key] = scanned_set

                threading.Thread(
                    target=self._scan_with_templates,
                    args=(new_cms, scheme, host, port),
                    daemon=True,
                ).start()

    def _scan_with_templates(self, cms_names: list[str], scheme: str,
                             host: str, port: int):
        """后台线程: 按指纹匹配到的 CMS 查找并执行 POC 模版 + Nuclei 扫描"""
        url = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
        all_findings: list[dict] = []

        # ---- 内置模版引擎 ----
        if self.templates:
            matched_tpls = self.templates.find(cms_names)
            if matched_tpls:
                tpl_ids = [t.get("_id", "?") for t in matched_tpls]
                #print(f"  {Colors.CYAN}[扫描] {url} → "
                      #f"指纹: {', '.join(cms_names[:3])} → "
                      #f"POC: {', '.join(tpl_ids)}{Colors.RESET}")

                findings = self.templates.execute_all(
                    matched_tpls, scheme, host, port,
                    max_workers=self.scan_workers,
                )
                if findings:
                    all_findings.extend(findings)

        # ---- Nuclei 扫描 ----
        if self.nuclei and self.nuclei.available:
            tags = [n.lower().strip().replace(" ", "-").replace("_", "-")
                    for n in cms_names]
            print(f"  {Colors.CYAN}[Nuclei] {url} → "
                  f"tags: {', '.join(tags[:5])}{Colors.RESET}")

            nuclei_findings = self.nuclei.scan(url, tags=tags)
            if nuclei_findings:
                all_findings.extend(nuclei_findings)

        # ---- 汇总 ----
        with self._stats_lock:
            self.stats["scans"] += 1
            if all_findings:
                self.stats["findings"] += len(all_findings)

        if all_findings:
            self._display_findings(all_findings, self.upstream)
        else:
            print(f"  {Colors.DIM}[扫描] {host}:{port} — 未发现漏洞{Colors.RESET}")

    @staticmethod
    def _display_findings(findings: list[dict], upstream=None):
        """打印扫描发现的漏洞 — 完整数据包展示 + 推送到 Burp"""
        print(f"  {Colors.RED}→ {len(findings)} 个漏洞{Colors.RESET}")
        for idx, f in enumerate(findings):
            sev = f.get("severity", "info").lower()
            sev_color = {"critical": Colors.RED, "high": Colors.RED,
                         "medium": Colors.YELLOW, "low": Colors.BLUE,
                         "info": Colors.DIM}[sev]
            tid = f.get('template_id', '?')
            print(f"\n  {Colors.BOLD}── 漏洞 {idx+1}{Colors.RESET}"
                  f"  {sev_color}● {f['name']} [{sev.upper()}]{Colors.RESET}"
                  f"  {Colors.DIM}{tid}{Colors.RESET}")

            req = f.get("request", {})
            resp = f.get("response", {})

            # ── 打印请求 ──
            if req:
                print(f"  {Colors.DIM}{'─'*60}{Colors.RESET}")
                if "raw" in req:
                    print(f"  {Colors.BOLD}REQUEST (raw){Colors.RESET}")
                    for line in req["raw"].strip().split("\n"):
                        print(f"  {Colors.MAGENTA}{line[:200]}{Colors.RESET}")
                else:
                    method = req.get("method", "GET")
                    url = req.get("url", "")
                    headers = req.get("headers", {})
                    body = req.get("body", "")
                    print(f"  {Colors.BOLD}{method}{Colors.RESET} {Colors.CYAN}{url}{Colors.RESET}")
                    for k, v in headers.items():
                        print(f"  {Colors.DIM}{k}: {v}{Colors.RESET}")
                    if body:
                        print(f"\n  {Colors.DIM}{body[:1000]}{Colors.RESET}")

            # ── 打印响应 ──
            if resp:
                status = resp.get("status", 0)
                print(f"\n  {Colors.BOLD}RESPONSE [{status}]{Colors.RESET}")
                for k, v in resp.get("headers", {}).items():
                    print(f"  {Colors.DIM}{k}: {v}{Colors.RESET}")
                body = resp.get("body", "")
                if body:
                    print(f"\n  {Colors.DIM}{body[:2000]}{Colors.RESET}")

            # ── 推送到 Burp ──
            if upstream and req:
                MITMProxy._replay_to_burp(upstream, req)

        print_sep("─")

    @staticmethod
    def _replay_to_burp(upstream, req: dict):
        """将漏洞请求通过原始 socket 重放到上游 Burp Suite"""
        import socket as sock_mod
        from urllib.parse import urlparse
        try:
            proxy_host, proxy_port = upstream

            # 构造要发送的 HTTP 请求
            if "raw" in req:
                raw_text = req["raw"].strip()
                # raw 格式：直接解析并构造代理请求
                raw_lines = raw_text.split("\n")
                first = raw_lines[0].split(" ")
                if len(first) < 2:
                    return
                method, path = first[0], first[1]
                host = ""
                rest_headers = []
                for line in raw_lines[1:]:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                    elif line.strip() and ":" in line:
                        rest_headers.append(line.strip())
                if not host or not path:
                    return
                scheme = "https" if ":443" in host else "http"
                url = f"{scheme}://{host}{path}"
                body_text = ""
                if "\n\n" in raw_text:
                    body_text = raw_text.split("\n\n", 1)[1]
            else:
                method = req.get("method", "GET")
                url = req.get("url", "")
                headers = req.get("headers", {})
                body_text = req.get("body", "")
                rest_headers = [f"{k}: {v}" for k, v in headers.items()
                                if k.lower() not in ("host", "content-length")]
                parsed = urlparse(url)
                host = parsed.netloc or parsed.hostname or ""
                if parsed.port and parsed.port not in (80, 443):
                    pass  # host already has port in netloc

            if not url:
                return

            # 通过 Burp HTTP 代理发送: GET http://target/path HTTP/1.1
            proxy_request = f"{method} {url} HTTP/1.1\r\n"
            proxy_request += f"Host: {host}\r\n"
            proxy_request += f"X-Replayed-By: ProxyScanner\r\n"
            for h in rest_headers:
                if not h.lower().startswith("host:") and not h.lower().startswith("content-length:"):
                    proxy_request += f"{h}\r\n"
            if body_text:
                body_bytes = body_text.encode() if isinstance(body_text, str) else body_text
                proxy_request += f"Content-Length: {len(body_bytes)}\r\n"
                proxy_request += "\r\n"
                proxy_request = proxy_request.encode() + body_bytes
            else:
                proxy_request += "\r\n"
                proxy_request = proxy_request.encode()

            # 发送到 Burp
            s = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
            s.settimeout(5)
            s.connect((proxy_host, proxy_port))
            s.sendall(proxy_request)
            # 读取响应 (不阻塞)
            try:
                resp = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > 65536:
                        break
            except sock_mod.timeout:
                pass
            s.close()

            # 检查响应状态
            status_line = resp.split(b"\r\n")[0].decode(errors="replace") if resp else "no response"
            print(f"  {Colors.GREEN}[→ Burp] 已推送 → {status_line[:60]}{Colors.RESET}")
        except Exception as e:
            print(f"  {Colors.YELLOW}[→ Burp] 推送失败: {e}{Colors.RESET}")

    # ----------------------------------------------------------
    # verbose: 多消息显示
    # ----------------------------------------------------------
    def _display_http_messages(self, direction, host, port, data):
        """按 HTTP 消息边界切分后逐条显示"""
        remaining = data
        count = 0
        while remaining and count < 20:
            if remaining.startswith(b"HTTP/"):
                parsed = http_parse_response(remaining)
                if not parsed:
                    break
                header_end = remaining.find(b"\r\n\r\n")
                if header_end == -1:
                    break
                if "content-length" in parsed.get("headers", {}):
                    cl = int(parsed["headers"]["content-length"])
                    msg_end = header_end + 4 + cl
                    msg_data = remaining[:msg_end]
                    remaining = remaining[msg_end:]
                else:
                    msg_data = remaining[:header_end + 4] + parsed.get("body", b"")
                    remaining = remaining[len(msg_data):]
                print_http_message(direction, host, port, msg_data[:self.max_display_bytes])
                count += 1
            elif remaining[:4] in (b"GET ", b"POST", b"PUT ", b"DELE", b"HEAD", b"OPTI", b"PATC"):
                parsed = http_parse_request(remaining)
                if not parsed:
                    break
                header_end = remaining.find(b"\r\n\r\n")
                if header_end == -1:
                    break
                if "content-length" in parsed.get("headers", {}):
                    cl = int(parsed["headers"]["content-length"])
                    msg_end = header_end + 4 + cl
                    msg_data = remaining[:msg_end]
                    remaining = remaining[msg_end:]
                else:
                    msg_data = remaining[:header_end + 4] + parsed.get("body", b"")
                    remaining = remaining[len(msg_data):]
                print_http_message(direction, host, port, msg_data[:self.max_display_bytes])
                count += 1
            else:
                break

        if remaining and len(remaining) > 4:
            print(f"  {Colors.DIM}[{direction}] 剩余 {len(remaining)} 字节未显示{Colors.RESET}")

    # ----------------------------------------------------------
    # 工具
    # ----------------------------------------------------------
    @staticmethod
    def _make_absolute_request(raw_request: bytes, host: str, port: int) -> bytes:
        """将相对路径请求转为绝对 URI (给上游代理用)"""
        try:
            text = raw_request.decode("utf-8", errors="replace")
            lines = text.split("\r\n")
            parts = lines[0].split(" ")
            if len(parts) >= 2:
                method, path = parts[0], parts[1]
                # 如果已经是绝对 URI 就不需要转换
                if not path.startswith("http://") and not path.startswith("https://"):
                    host_port = f"{host}:{port}" if port != 80 else host
                    abs_path = f"http://{host_port}{path}"
                    lines[0] = f"{method} {abs_path} {' '.join(parts[2:])}".strip()
                    return "\r\n".join(lines).encode("utf-8", errors="replace")
            return raw_request
        except Exception:
            return raw_request

    def _recv_http_message(self, sock: socket.SocketType, timeout=5.0) -> bytes:
        sock.settimeout(timeout)
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data += chunk
                if len(data) > 131072:
                    break

            if b"\r\n\r\n" not in data:
                return data if data else b""

            header_part = data.split(b"\r\n\r\n")[0].decode("utf-8", errors="replace")
            body_start = data.find(b"\r\n\r\n") + 4
            body_so_far = data[body_start:]

            cl = 0
            is_chunked = False
            for line in header_part.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    cl = int(line.split(":", 1)[1].strip())
                if line.lower().startswith("transfer-encoding:"):
                    if "chunked" in line.split(":", 1)[1].strip().lower():
                        is_chunked = True

            if cl > 0:
                while len(body_so_far) < cl:
                    chunk = sock.recv(min(8192, cl - len(body_so_far)))
                    if not chunk:
                        break
                    body_so_far += chunk
                data = data[:body_start] + body_so_far
            elif is_chunked:
                sock.settimeout(1.0)
                while True:
                    try:
                        chunk = sock.recv(8192)
                        if not chunk:
                            break
                        data += chunk
                        if data.endswith(b"0\r\n\r\n"):
                            break
                    except socket.timeout:
                        break
        except socket.timeout:
            pass
        except Exception:
            pass
        return data


# ============================================================
# 镜像观察模式 — 不作为代理，只接收流量副本做分析
# ============================================================
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse as _urlparse, parse_qs


class MirrorObserver:
    """
    镜像观察器 — 不在代理链路中，只接收流量副本做指纹 + 扫描

    用法:
      # 启动观察器
      python proxy_server.py --observe

      # 发送流量副本 (curl / Burp Extension / 脚本)
      curl -X POST 'http://127.0.0.1:8889/observe?scheme=https&host=target.com&port=443&path=/login' \
           --data-binary @response_body.bin

      # 也可以直接 POST 原始响应数据
      curl -X POST http://127.0.0.1:8889/observe?host=target.com \
           -H 'X-Target-Scheme: https' \
           -H 'X-Target-Port: 443' \
           --data-binary @response.bin
    """

    def __init__(self, listen_host="127.0.0.1", listen_port=8889,
                 finger_engine=None, template_engine=None,
                 nuclei_scanner=None, auto_scan=True, scan_workers=5,
                 finger_blacklist: set[str] = None):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.finger = finger_engine
        self.templates = template_engine
        self.nuclei = nuclei_scanner
        self.auto_scan = auto_scan and (template_engine is not None or nuclei_scanner is not None)
        self.scan_workers = scan_workers
        self.finger_blacklist: set[str] = finger_blacklist or set()
        self._scanned_cms: dict[str, set[str]] = {}  # host_key → {cms_name, ...}
        self._stats = {"received": 0, "finger_hits": 0, "findings": 0}

    def start(self):
        """启动 HTTP 观察服务器"""
        observer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # 静默 HTTP 日志

            def do_POST(this):
                """接收流量副本"""
                parsed = _urlparse(this.path)

                if parsed.path not in ("/observe", "/", ""):
                    this.send_error(404)
                    return

                # 解析目标信息 (query 参数 > headers)
                qs = parse_qs(parsed.query)
                scheme = qs.get("scheme", [None])[0] or \
                    this.headers.get("X-Target-Scheme", "https")
                host = qs.get("host", [None])[0] or \
                    this.headers.get("X-Target-Host", "unknown")
                port = int(qs.get("port", [None])[0] or
                          this.headers.get("X-Target-Port", "443"))
                path = qs.get("path", [None])[0] or \
                    this.headers.get("X-Target-Path", "/")

                # 读取 body
                content_len = int(this.headers.get("Content-Length", 0))
                response_body = this.rfile.read(content_len) if content_len > 0 else b""

                if not response_body:
                    this.send_error(400, "Empty body")
                    return

                observer._stats["received"] += 1

                # ---- 指纹匹配 ----
                finger_results = []
                if observer.finger:
                    matches = observer.finger.match(response_body)
                    if matches:
                        # 指纹黑名单过滤
                        if observer.finger_blacklist:
                            matches = [m for m in matches if m["cms"] not in observer.finger_blacklist]
                    if matches:
                        observer._stats["finger_hits"] += 1
                        cms_names = [m["cms"] for m in matches]
                        resp = http_parse_response(response_body)
                        status_code = resp["status_code"] if resp else 0
                        #print_finger_matches(host, port, status_code, matches, path)
                        finger_results = [{"cms": m["cms"], "method": m["method"]} for m in matches]
                    else:
                        cms_names = []

                # ---- POC 扫描 ----
                scan_results = []
                has_tpl = observer.auto_scan and observer.templates
                has_nuclei = observer.auto_scan and observer.nuclei and observer.nuclei.available
                if (has_tpl or has_nuclei) and cms_names:
                    scan_key = f"{scheme}://{host}:{port}"
                    # 只扫描新发现的 CMS (同 host 同 CMS 不重复扫)
                    scanned_set = observer._scanned_cms.get(scan_key, set())
                    new_cms = [c for c in cms_names if c not in scanned_set]
                    if new_cms:
                        for c in new_cms:
                            scanned_set.add(c)
                        observer._scanned_cms[scan_key] = scanned_set

                        url = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
                        all_findings = []

                        # ---- 内置模版引擎 ----
                        if has_tpl:
                            matched_tpls = observer.templates.find(new_cms)
                            if matched_tpls:
                                tpl_ids = [t.get("_id", "?") for t in matched_tpls]
                                #print(f"  {Colors.CYAN}[扫描] {url} → "
                                      #f"指纹: {', '.join(new_cms[:3])} → "
                                      #f"POC: {', '.join(tpl_ids)}{Colors.RESET}")

                                findings = observer.templates.execute_all(
                                    matched_tpls, scheme, host, port,
                                    max_workers=observer.scan_workers,
                                )
                                if findings:
                                    all_findings.extend(findings)

                        # ---- Nuclei 扫描 ----
                        if has_nuclei:
                            tags = [n.lower().strip().replace(" ", "-").replace("_", "-")
                                    for n in new_cms]
                            print(f"  {Colors.CYAN}[Nuclei] {url} → "
                                  f"tags: {', '.join(tags[:5])}{Colors.RESET}")

                            nuclei_findings = observer.nuclei.scan(url, tags=tags)
                            if nuclei_findings:
                                all_findings.extend(nuclei_findings)

                        if all_findings:
                            observer._stats["findings"] += len(all_findings)
                            MITMProxy._display_findings(all_findings)
                            scan_results = [{
                                "id": f.get("template_id", f.get("id", "?")),
                                "name": f.get("name", "?"),
                                "severity": f.get("severity", "?"),
                                "detail": f.get("detail", ""),
                            } for f in all_findings]
                        else:
                            print(f"  {Colors.DIM}[扫描] {host}:{port} — 未发现漏洞{Colors.RESET}")

                # 返回分析结果
                result = {
                    "host": host,
                    "port": port,
                    "scheme": scheme,
                    "path": path,
                    "body_size": len(response_body),
                    "fingerprints": finger_results,
                    "findings": scan_results,
                }
                resp_bytes = json.dumps(result, ensure_ascii=False, indent=2).encode()
                this.send_response(200)
                this.send_header("Content-Type", "application/json; charset=utf-8")
                this.send_header("Content-Length", str(len(resp_bytes)))
                this.end_headers()
                this.wfile.write(resp_bytes)

            def do_GET(this):
                """GET 返回统计信息"""
                result = {
                    "mode": "observer",
                    "stats": observer._stats,
                    "finger_loaded": observer.finger is not None and observer.finger.is_loaded,
                    "templates_loaded": observer.templates is not None,
                    "nuclei_available": observer.nuclei is not None and observer.nuclei.available,
                }
                resp_bytes = json.dumps(result, ensure_ascii=False, indent=2).encode()
                this.send_response(200)
                this.send_header("Content-Type", "application/json; charset=utf-8")
                this.end_headers()
                this.wfile.write(resp_bytes)

        server = HTTPServer((self.listen_host, self.listen_port), Handler)

        print()
        print_header("镜像观察器已启动", Colors.GREEN)
        print_field("监听地址", f"http://{self.listen_host}:{self.listen_port}")
        print_field("指纹引擎", "就绪" if self.finger and self.finger.is_loaded else "未加载")
        print_field("POC 扫描", "开" if self.auto_scan else "关")
        if self.templates:
            print_field("POC 模版", f"{len(self.templates.templates)} 个")
        if self.nuclei and self.nuclei.available:
            print_field("Nuclei", "已就绪")
        print()
        print(f"  {Colors.CYAN}接收流量副本:{Colors.RESET}")
        print(f"  {Colors.DIM}  curl -X POST 'http://{self.listen_host}:{self.listen_port}/observe?scheme=https&host=TARGET&port=443' --data-binary @response.bin{Colors.RESET}")
        print(f"  {Colors.DIM}  Burp Extension → POST 到 http://{self.listen_host}:{self.listen_port}/observe{Colors.RESET}")
        print()
        print(f"  {Colors.DIM}GET http://{self.listen_host}:{self.listen_port}/ → 查看统计{Colors.RESET}")
        print()
        print(f"  {Colors.CYAN}等待流量... (Ctrl+C 停止){Colors.RESET}")
        print_sep("═")
        print()

        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}收到中断，关闭中...{Colors.RESET}")
        finally:
            server.shutdown()
            print(f"{Colors.GREEN}观察器已停止 | 接收: {self._stats['received']} "
                  f"指纹命中: {self._stats['finger_hits']} "
                  f"漏洞发现: {self._stats['findings']}{Colors.RESET}")


# ============================================================
# 入口
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="MITM 代理 + 指纹识别 + POC 扫描 / 镜像观察模式",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 代理模式 (默认) - 作为中间人代理
  python proxy_server.py                                    # 代理 8889 端口
  python proxy_server.py -p 9999                            # 自定义端口
  python proxy_server.py --verbose                          # 显示完整数据包

  # 镜像观察模式 - 不作为代理，只接收流量副本
  python proxy_server.py --observe                          # 观察 8889 端口
  python proxy_server.py --observe -p 9999                  # 自定义端口
  curl -X POST 'http://127.0.0.1:8889/observe?host=target.com' --data-binary @response.bin

  # 其他选项
  python proxy_server.py --no-fingerprint                   # 关闭指纹
  python proxy_server.py --no-scan                          # 关闭 POC 扫描
  python proxy_server.py --poc-dir ./my-pocs                # 自定义 POC 目录
        """,
    )
    parser.add_argument("-H", "--host", default="127.0.0.1", help="监听地址 (默认 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=8889, help="监听端口 (默认 8889)")
    parser.add_argument("--observe", action="store_true",
                        help="镜像观察模式 (不作为代理，只接收流量副本)")
    parser.add_argument("-f", "--fingerprint", default="finger.json",
                        help="指纹文件路径 (默认 finger.json)")
    parser.add_argument("--no-fingerprint", action="store_true", help="禁用指纹匹配")
    parser.add_argument("--finger-blacklist", default=None,
                        help="指纹黑名单文件 (一行一个 CMS 名称，不显示不扫描)")
    parser.add_argument("--poc-dir", default="poc",
                        help="POC 模版目录 (默认 ./poc)")
    parser.add_argument("--no-scan", action="store_true", help="禁用 POC 自动扫描")
    parser.add_argument("--nuclei", action="store_true",
                        help="启用 Nuclei 扫描 (需安装: brew install nuclei)")
    parser.add_argument("--nuclei-timeout", type=int, default=30,
                        help="Nuclei 单目标超时秒数 (默认 30)")
    parser.add_argument("--scan-workers", type=int, default=5,
                        help="POC 扫描并发数 (默认 5)")
    parser.add_argument("--upstream",
                        help="上游代理地址 (如 127.0.0.1:8080, Burp 地址)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="代理模式: 显示完整请求/响应体")
    parser.add_argument("--max-bytes", type=int, default=65536, help="单包最大显示字节 (默认 65536)")
    args = parser.parse_args()

    # 加载指纹
    finger = None
    if not args.no_fingerprint:
        finger_path = Path(args.fingerprint)
        if not finger_path.is_absolute():
            if not finger_path.exists():
                finger_path = Path(__file__).parent / args.fingerprint
        finger = FingerprintEngine(str(finger_path))

    # 加载指纹黑名单
    finger_blacklist: set[str] = set()
    if args.finger_blacklist:
        bl_path = Path(args.finger_blacklist)
        if bl_path.exists():
            with open(bl_path, "r", encoding="utf-8") as f:
                for line in f:
                    name = line.strip()
                    if name and not name.startswith("#"):
                        finger_blacklist.add(name)
            print(f"  [*] 指纹黑名单: {len(finger_blacklist)} 个 ({', '.join(sorted(finger_blacklist)[:10])}{'...' if len(finger_blacklist) > 10 else ''})")
        else:
            print(f"  {Colors.YELLOW}[!] 黑名单文件不存在: {args.finger_blacklist}{Colors.RESET}")

    # 加载 POC 模版
    templates = None
    if not args.no_scan:
        poc_path = Path(args.poc_dir)
        if not poc_path.is_absolute():
            if not poc_path.exists():
                poc_path = Path(__file__).parent / args.poc_dir
        if poc_path.exists():
            templates = TemplateEngine(str(poc_path))
        else:
            print(f"  {Colors.YELLOW}[!] POC 目录不存在: {poc_path}，跳过{Colors.RESET}\n")

    # Nuclei 扫描器
    nuclei_scanner = None
    if not args.no_scan and args.nuclei:
        nuclei_scanner = NucleiScanner(
            template_dir=str(poc_path) if poc_path.exists() else None,
            timeout=args.nuclei_timeout,
            max_workers=args.scan_workers,
        )
        if not nuclei_scanner.available:
            print(f"  {Colors.YELLOW}[!] Nuclei 不可用，将仅使用内置引擎{Colors.RESET}\n")

    # ---- 镜像观察模式 ----
    if args.observe:
        observer = MirrorObserver(
            listen_host=args.host,
            listen_port=args.port,
            finger_engine=finger,
            template_engine=templates,
            nuclei_scanner=nuclei_scanner,
            auto_scan=not args.no_scan,
            scan_workers=args.scan_workers,
            finger_blacklist=finger_blacklist,
        )
        observer.start()
        return

    # ---- 代理模式 ----
    upstream = None
    if args.upstream:
        parts = args.upstream.split(":")
        if len(parts) == 2:
            upstream = (parts[0], int(parts[1]))

    proxy = MITMProxy(
        listen_host=args.host,
        listen_port=args.port,
        verbose=args.verbose,
        max_display_bytes=args.max_bytes,
        finger_engine=finger,
        template_engine=templates,
        nuclei_scanner=nuclei_scanner,
        auto_scan=not args.no_scan,
        scan_workers=args.scan_workers,
        upstream=upstream,
        finger_blacklist=finger_blacklist,
    )
    proxy.start()


if __name__ == "__main__":
    main()
