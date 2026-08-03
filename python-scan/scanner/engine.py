#!/usr/bin/env python3
from __future__ import annotations
"""
扫描引擎 — 加载 YAML 模版 + 执行扫描 (内置引擎 + Nuclei CLI)

使用:
  from scanner.engine import TemplateLoader, Scanner

  loader = TemplateLoader("poc/")             # 或单文件 "poc/CVE-2024-36837.yaml"
  scanner = Scanner(loader)

  # 按 tags 扫描
  findings = scanner.scan("https://target.com", tags=["crmeb", "sqli"])

  # 扫描所有模版
  findings = scanner.scan("https://target.com")
"""

import json
import pickle
import subprocess
import shutil
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml

from .http_sender import HttpSender
from .matcher import Matcher
from .resolver import VariableResolver

# ============================================================
# 终端颜色
# ============================================================
class _C:
    R = "\033[0m"; B = "\033[1m"; D = "\033[2m"
    r = "\033[91m"; g = "\033[92m"; y = "\033[93m"
    b = "\033[94m"; m = "\033[95m"; c = "\033[96m"


# ============================================================
# 模版加载器
# ============================================================
class TemplateLoader:
    """加载 Nuclei 兼容的 YAML 模版，建立 tag 索引"""

    def __init__(self, path: str = None):
        self.templates: list[dict] = []
        self.tag_index: dict[str, list[dict]] = {}
        if path:
            self.load(path)

    # ----------------------------------------------------------
    def load(self, path: str):
        """加载模版: 支持单文件或目录，目录模式首次加载后缓存到 .poc_cache.pkl"""
        p = Path(path)
        if not p.exists():
            print(f"  {_C.y}[!] 模版路径不存在: {path}{_C.R}")
            return

        # 单文件模式不缓存
        if p.is_file():
            self._load_files([p])
            return

        # 目录模式: 尝试缓存
        yaml_files = list(p.rglob("*.yaml")) + list(p.rglob("*.yml"))
        cache_path = p / ".poc_cache.pkl"

        if cache_path.exists():
            newest_yaml = max((f.stat().st_mtime for f in yaml_files), default=0)
            if cache_path.stat().st_mtime >= newest_yaml:
                try:
                    with open(cache_path, "rb") as f:
                        cached = pickle.load(f)
                    self.templates = cached["templates"]
                    self.tag_index = cached["tag_index"]
                    print(f"  [*] 从缓存加载: {len(self.templates)} 个模版, "
                          f"{len(self.tag_index)} 个标签 (跳过 {len(yaml_files)} 个 YAML 解析)\n")
                    return
                except Exception as e:
                    print(f"  {_C.y}[!] 缓存损坏，重新解析: {e}{_C.R}")

        # 全量解析 + 保存缓存
        self._load_files(yaml_files)
        try:
            with open(cache_path, "wb") as f:
                pickle.dump({
                    "templates": self.templates,
                    "tag_index": self.tag_index,
                }, f, protocol=pickle.HIGHEST_PROTOCOL)
            size_mb = cache_path.stat().st_size / 1024 / 1024
            print(f"  [*] 缓存已保存: .poc_cache.pkl ({size_mb:.1f} MB)\n")
        except Exception as e:
            print(f"  {_C.y}[!] 缓存保存失败: {e}{_C.R}\n")

    def _load_files(self, yaml_files: list):
        """逐个解析 YAML 文件"""
        print(f"  [*] 加载模版: {len(yaml_files)} 个文件 ...")
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
                info = data.get("info", {})
                tags_str = info.get("tags", "")
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
        print(f"  [*] 加载完毕: {loaded} 个模版, {len(self.tag_index)} 个标签")

    # ----------------------------------------------------------
    def find(self, names: list[str]) -> list[dict]:
        """
        按名称查找模版 (双向子串匹配 tag)
        如 name="crmeb" 匹配 tag "crmeb", "crmeb-sqli", "crmeb-unauth"
        """
        matched: list[dict] = []
        seen: set[str] = set()

        for name in names:
            name_lower = name.lower().strip()
            if not name_lower:
                continue
            for tag, templates in self.tag_index.items():
                if name_lower in tag or tag in name_lower:
                    for t in templates:
                        tid = t.get("_id", "")
                        if tid not in seen:
                            seen.add(tid)
                            matched.append(t)

        # 按 severity 排序
        severity_order = {
            "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
        }
        matched.sort(key=lambda t: severity_order.get(
            t.get("info", {}).get("severity", "info").lower(), 9
        ))
        return matched

    def list_tags(self) -> list[str]:
        return sorted(self.tag_index.keys())

    def info(self) -> dict:
        return {
            "templates": len(self.templates),
            "tags": len(self.tag_index),
            "tag_list": self.list_tags()[:50],
        }


def _truncate_body(body, max_len: int = 2000):
    """截断响应体用于显示"""
    if isinstance(body, bytes):
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            text = str(body)
    else:
        text = str(body)
    if len(text) > max_len:
        text = text[:max_len] + f"... ({len(body)} bytes total)"
    return text


# ============================================================
# 扫描器
# ============================================================
class Scanner:
    """
    POC 扫描器 — 内置引擎 + Nuclei CLI

    用法:
        loader = TemplateLoader("poc/")
        scanner = Scanner(loader)

        # 按 tags 扫描
        findings = scanner.scan("https://target.com", tags=["crmeb"])

        # 扫描所有模版
        findings = scanner.scan("https://target.com")
    """

    def __init__(self, loader: TemplateLoader = None,
                 timeout: int = 10,
                 max_workers: int = 5,
                 nuclei_bin: str = None,
                 enable_nuclei: bool = True,
                 verbose: bool = False):
        self.loader = loader or TemplateLoader()
        self.timeout = timeout
        self.max_workers = max_workers
        self.verbose = verbose
        self._sender = HttpSender(timeout=timeout, verbose=verbose)

        # Nuclei CLI
        self._nuclei = nuclei_bin or shutil.which("nuclei") or "nuclei"
        self._nuclei_available = enable_nuclei and self._check_nuclei()

        self._stats = {"scans": 0, "findings": 0, "errors": 0}
        self._lock = threading.Lock()

    # ----------------------------------------------------------
    # Nuclei 可用性
    # ----------------------------------------------------------
    def _check_nuclei(self) -> bool:
        try:
            result = subprocess.run(
                [self._nuclei, "-version"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                ver = result.stdout.strip().split("\n")[0]
                print(f"  {_C.g}[✓] Nuclei: {ver}{_C.R}")
                return True
        except (FileNotFoundError, Exception):
            pass
        print(f"  {_C.D}[*] Nuclei CLI 未安装，仅使用内置引擎{_C.R}")
        return False

    @property
    def nuclei_available(self) -> bool:
        return self._nuclei_available

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    # ----------------------------------------------------------
    # 主入口: 扫描
    # ----------------------------------------------------------
    def scan(self, url: str,
             templates=None,
             tags=None) -> list[dict]:
        """
        扫描目标 URL

        Args:
            url:        目标 URL (如 https://example.com:8443)
            templates:  指定模版列表 (None=使用所有已加载模版)
            tags:       tag 筛选 (None=不筛选，同时传给 nuclei -tags)

        Returns:
            [{template_id, name, severity, url, matched, detail}, ...]
        """
        from urllib.parse import urlparse
        u = urlparse(url)
        scheme = u.scheme or "https"
        host = u.hostname or "localhost"
        port = u.port or (443 if scheme == "https" else 80)

        # 确定要用的模版
        if templates:
            tpl_list = templates
        elif tags and self.loader.templates:
            tpl_list = self.loader.find(tags)
        else:
            tpl_list = self.loader.templates

        all_findings: list[dict] = []

        # ---- 内置引擎 ----
        if tpl_list:
            print(f"\n  {_C.c}[内置引擎] {url} → "
                  f"{len(tpl_list)} 个模版{_C.R}")
            findings = self._execute_all(tpl_list, scheme, host, port)
            all_findings.extend(findings)
            print(f"  {_C.c}[内置引擎] 完成: {len(findings)} 个发现{_C.R}")

        # ---- Nuclei CLI ----
        if self._nuclei_available:
            args = []
            if tags:
                args.extend(["-tags", ",".join(tags)])
            if tpl_list:
                tpl_files = list(set(
                    t["_file"] for t in tpl_list if t.get("_file")
                ))
                for f in tpl_files:
                    args.extend(["-t", f])

            if args:
                print(f"\n  {_C.b}[Nuclei] {url} ...{_C.R}")
                nuclei_findings = self._run_nuclei(url, extra_args=args)
                all_findings.extend(nuclei_findings)
                print(f"  {_C.b}[Nuclei] 完成: {len(nuclei_findings)} 个发现{_C.R}")
            else:
                print(f"\n  {_C.b}[Nuclei] {url} (全量扫描){_C.R}")
                nuclei_findings = self._run_nuclei(url)
                all_findings.extend(nuclei_findings)
                print(f"  {_C.b}[Nuclei] 完成: {len(nuclei_findings)} 个发现{_C.R}")

        return all_findings

    # ----------------------------------------------------------
    # verbose 辅助
    # ----------------------------------------------------------
    @staticmethod
    def _log_match_result(resp, matched, label=""):
        if matched:
            print(f"    {_C.g}[✓] 命中{_C.R}"
                  f"{' — ' + label if label else ''}")
        elif resp:
            print(f"    {_C.D}[✗] 不匹配{_C.R}"
                  f"  {_C.D}(HTTP {resp.get('status', 0)})"
                  f"{' — ' + label if label else ''}")
        else:
            print(f"    {_C.r}[✗] 无响应{_C.R}"
                  f"{' — ' + label if label else ''}")

    # ----------------------------------------------------------
    # 内置引擎 — 执行单个模版
    # ----------------------------------------------------------
    def _execute_one(self, template: dict, scheme: str, host: str,
                     port: int) -> list[dict]:
        base_url = (f"{scheme}://{host}"
                    if port in (80, 443)
                    else f"{scheme}://{host}:{port}")
        use_tls = (scheme == "https")

        info = template.get("info", {})
        tpl_name = info.get("name", template.get("_id", "?"))
        tpl_severity = info.get("severity", "unknown")
        custom_vars = dict(template.get("variables", {}))

        http_blocks = template.get("http", [])
        if isinstance(http_blocks, dict):
            http_blocks = [http_blocks]

        if self.verbose:
            sev_color = {"critical": _C.r, "high": _C.r, "medium": _C.y,
                         "low": _C.c, "info": _C.D}.get(tpl_severity, _C.D)
            print(f"\n  {_C.B}── [{tpl_severity.upper()}] {tpl_name} "
                  f"({template.get('_id', '?')}){_C.R}")

        findings: list[dict] = []

        for block in http_blocks:
            resolver = VariableResolver(base_url, host, port, custom_vars)
            matchers = block.get("matchers", [])
            matchers_cond = block.get("matchers-condition", "and")

            # ---- raw 格式 ----
            if "raw" in block:
                raw_requests = block.get("raw", [])
                payloads = block.get("payloads", {})
                payload_keys = list(payloads.keys())

                if payload_keys:
                    payload_values = [payloads[k] for k in payload_keys]
                    max_len = max(len(v) for v in payload_values)
                    for i in range(max_len):
                        resolver_i = VariableResolver(
                            base_url, host, port, custom_vars
                        )
                        for ki, key in enumerate(payload_keys):
                            val = payload_values[ki][i % len(payload_values[ki])]
                            resolver_i.custom[key] = val

                        raw_text = (
                            raw_requests[i % len(raw_requests)]
                            if i < len(raw_requests) else raw_requests[0]
                        )
                        raw_resolved = resolver_i.resolve(raw_text)
                        resp = self._sender.send_raw(
                            raw_resolved, host, port, use_tls
                        )

                        matched = resp and Matcher.check(
                            matchers, matchers_cond, resp, resolver_i
                        )
                        if self.verbose:
                            self._log_match_result(resp, matched, f"payload[{i}]")
                        if matched:
                            findings.append(self._make_finding(
                                template, tpl_name, tpl_severity,
                                f"{scheme}://{host}:{port}",
                                f"payload[{i}] 命中",
                                req={"raw": raw_resolved},
                                resp=resp,
                            ))
                            if block.get("stop-at-first-match"):
                                break
                else:
                    for ri, raw_text in enumerate(raw_requests):
                        resolver_ri = VariableResolver(
                            base_url, host, port, custom_vars
                        )
                        raw_resolved = resolver_ri.resolve(raw_text)
                        resp = self._sender.send_raw(
                            raw_resolved, host, port, use_tls
                        )
                        matched = resp and Matcher.check(
                            matchers, matchers_cond, resp, resolver_ri
                        )
                        if self.verbose:
                            self._log_match_result(resp, matched, f"raw[{ri}]")
                        if matched:
                            findings.append(self._make_finding(
                                template, tpl_name, tpl_severity,
                                f"{scheme}://{host}:{port}",
                                f"raw[{ri}] 命中",
                                req={"raw": raw_resolved},
                                resp=resp,
                            ))
                continue

            # ---- 简单 path 格式 ----
            method = block.get("method", "GET").upper()
            paths = block.get("path", [])
            headers = block.get("headers", {})

            tpl_body = block.get("body", "")
            if isinstance(tpl_body, str):
                tpl_body = tpl_body.encode()

            for path_template in paths:
                url = resolver.resolve(path_template)
                resolved_headers = {
                    k: resolver.resolve(str(v))
                    for k, v in headers.items()
                }
                resp = self._sender.send_simple(
                    method, url, resolved_headers,
                    tpl_body if tpl_body else None
                )
                matched = resp and Matcher.check(
                    matchers, matchers_cond, resp, resolver
                )
                if self.verbose:
                    self._log_match_result(resp, matched, url)
                if matched:
                    findings.append(self._make_finding(
                        template, tpl_name, tpl_severity,
                        url, "响应匹配",
                        req={
                            "method": method,
                            "url": url,
                            "headers": resolved_headers,
                            "body": tpl_body.decode("utf-8", errors="replace") if tpl_body else "",
                        },
                        resp=resp,
                    ))
                    if block.get("stop-at-first-match"):
                        break

        if self.verbose:
            if findings:
                print(f"  {_C.g}[✓] {tpl_name}: {len(findings)} 个发现{_C.R}")
            else:
                print(f"  {_C.D}[✗] {tpl_name}: 未匹配{_C.R}")

        return findings

    # ----------------------------------------------------------
    # 内置引擎 — 批量执行
    # ----------------------------------------------------------
    def _execute_all(self, templates: list[dict], scheme: str,
                     host: str, port: int) -> list[dict]:
        all_findings: list[dict] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._execute_one, t, scheme, host, port): t
                for t in templates
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        all_findings.extend(result)
                except Exception:
                    pass

        with self._lock:
            self._stats["scans"] += 1
            self._stats["findings"] += len(all_findings)

        return all_findings

    # ----------------------------------------------------------
    # Nuclei CLI
    # ----------------------------------------------------------
    def _run_nuclei(self, url: str,
                    extra_args=None) -> list[dict]:
        cmd = [
            self._nuclei, "-u", url,
            "-jsonl", "-silent", "-no-color",
            "-timeout", str(self.timeout),
            "-concurrency", str(self.max_workers),
            "-follow-redirects", "-no-mhe",
        ]
        if extra_args:
            cmd.extend(extra_args)

        findings = []
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout + 30
            )
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    info = entry.get("info", {})
                    findings.append({
                        "template_id": entry.get("template-id", "?"),
                        "name": info.get("name", "?"),
                        "severity": info.get("severity", "unknown"),
                        "url": entry.get("matched-at", url),
                        "matched": True,
                        "detail": entry.get("matcher-name", ""),
                        "source": "nuclei",
                    })
                except json.JSONDecodeError:
                    pass

            with self._lock:
                self._stats["scans"] += 1
                self._stats["findings"] += len(findings)

        except subprocess.TimeoutExpired:
            with self._lock:
                self._stats["errors"] += 1
        except Exception as e:
            with self._lock:
                self._stats["errors"] += 1

        return findings

    # ----------------------------------------------------------
    @staticmethod
    def _make_finding(template: dict, name: str, severity: str,
                      url: str, detail: str,
                      req: dict | None = None,
                      resp: dict | None = None) -> dict:
        f = {
            "template_id": template.get("_id", "?"),
            "name": name,
            "severity": severity,
            "url": url,
            "matched": True,
            "detail": detail,
            "source": "builtin",
        }
        if req:
            f["request"] = req
        if resp:
            # 只保留关键响应信息，body 截断
            f["response"] = {
                "status": resp.get("status", 0),
                "headers": resp.get("headers", {}),
                "body": _truncate_body(resp.get("body", b"")),
            }
        return f
