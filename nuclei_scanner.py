#!/usr/bin/env python3
"""
Nuclei 扫描引擎 — 封装 nuclei CLI，按 CMS 指纹匹配到的 tags 执行 POC 扫描

依赖: nuclei CLI (https://github.com/projectdiscovery/nuclei)
安装:
  brew install nuclei              # macOS
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

使用:
  from nuclei_scanner import NucleiScanner
  scanner = NucleiScanner(template_dir="poc/")
  findings = scanner.scan_by_tags("https://target.com", ["nacos", "springboot"])
"""

import json
import subprocess
import shutil
import shlex
import threading
from pathlib import Path


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
    c = "\033[96m"


# ============================================================
# Nuclei 扫描器
# ============================================================
class NucleiScanner:
    """封装 nuclei CLI 的 Python 接口"""

    def __init__(self, template_dir: str = None,
                 nuclei_bin: str = None,
                 timeout: int = 30,
                 severity: str = None,
                 max_workers: int = 3):
        """
        Args:
            template_dir: nuclei 模版目录 (POC YAML 文件)
            nuclei_bin: nuclei 可执行文件路径 (None=自动查找)
            timeout: 单个目标扫描超时 (秒)
            severity: 最低严重等级过滤 (info/low/medium/high/critical)
            max_workers: 并行扫描数
        """
        self.template_dir = Path(template_dir) if template_dir else None
        self.timeout = timeout
        self.severity = severity
        self.max_workers = max_workers
        self._lock = threading.Lock()
        self._stats = {"scans": 0, "findings": 0, "errors": 0}

        # 查找 nuclei 二进制
        if nuclei_bin:
            self._nuclei_bin = nuclei_bin
        else:
            self._nuclei_bin = shutil.which("nuclei") or "nuclei"

        self._available = self._check_binary()

    # ----------------------------------------------------------
    # 可用性检查
    # ----------------------------------------------------------
    def _check_binary(self) -> bool:
        """检查 nuclei 是否可用"""
        try:
            result = subprocess.run(
                [self._nuclei_bin, "-version"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                ver = result.stdout.strip().split("\n")[0]
                print(f"  {_C.g}[✓] Nuclei 已就绪: {ver}{_C.R}")
                return True
        except FileNotFoundError:
            print(f"  {_C.y}[!] nuclei 未找到，请安装:{_C.R}")
            print(f"      brew install nuclei")
            print(f"      或 go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        except Exception as e:
            print(f"  {_C.y}[!] nuclei 检测失败: {e}{_C.R}")
        return False

    @property
    def available(self) -> bool:
        return self._available

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    # ----------------------------------------------------------
    # 核心扫描
    # ----------------------------------------------------------
    def scan(self, target_url: str,
             templates: list[str] | None = None,
             tags: list[str] | None = None,
             extra_args: list[str] | None = None) -> list[dict]:
        """
        对单个目标执行 nuclei 扫描

        Args:
            target_url: 目标 URL (如 https://example.com:443)
            templates: 模版路径列表 (与 tags 二选一或同时使用)
            tags: nuclei tag 列表 (与 templates 二选一或同时使用)
            extra_args: 额外的 nuclei CLI 参数

        Returns:
            [{template_id, name, severity, url, matched_at, ...}, ...]
        """
        if not self._available:
            return []

        cmd = [self._nuclei_bin, "-u", target_url,
               "-jsonl",           # JSON Lines 输出, 方便解析
               "-silent",          # 不打印 banner
               "-no-color",        # 无 ANSI 颜色
               "-timeout", str(self.timeout),
               "-concurrency", str(self.max_workers),
               "-follow-redirects",
               "-no-mhe",          # 禁用多主机错误 (减少误报)
               ]

        if self.template_dir and not templates and not tags:
            cmd.extend(["-t", str(self.template_dir)])

        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        if templates:
            for t in templates:
                cmd.extend(["-t", t])

        if self.severity:
            cmd.extend(["-severity", self.severity])

        if extra_args:
            cmd.extend(extra_args)

        # 执行
        findings = []
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout + 30
            )

            with self._lock:
                self._stats["scans"] += 1

            # 解析 JSONL 输出
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    info = entry.get("info", {})
                    findings.append({
                        "template_id": entry.get("template-id", "?"),
                        "name": info.get("name", entry.get("template-id", "?")),
                        "severity": info.get("severity", "unknown"),
                        "url": entry.get("matched-at", target_url),
                        "type": entry.get("type", ""),
                        "host": entry.get("host", ""),
                        "matched_at": entry.get("matched-at", ""),
                        "detail": entry.get("matcher-name", ""),
                        "curl_command": entry.get("curl-command", ""),
                    })
                except json.JSONDecodeError:
                    pass

            # 检查 stderr 警告
            stderr = result.stderr.strip()
            if stderr:
                # nuclei 经常在 stderr 输出警告而非实际错误
                if any(kw in stderr.lower() for kw in
                       ["error", "panic", "fatal", "critical"]):
                    print(f"  {_C.y}[nuclei] {stderr[:200]}{_C.R}")
                    with self._lock:
                        self._stats["errors"] += 1

            with self._lock:
                self._stats["findings"] += len(findings)

        except subprocess.TimeoutExpired:
            print(f"  {_C.y}[nuclei] 扫描超时: {target_url}{_C.R}")
            with self._lock:
                self._stats["errors"] += 1
        except Exception as e:
            print(f"  {_C.y}[nuclei] 扫描异常: {e}{_C.R}")
            with self._lock:
                self._stats["errors"] += 1

        return findings

    # ----------------------------------------------------------
    # 指纹驱动的扫描
    # ----------------------------------------------------------
    def scan_by_tags(self, target_url: str,
                     cms_names: list[str],
                     template_dir: str = None) -> list[dict]:
        """
        根据 CMS 指纹名称扫描目标

        nuclei 模版 tags 通常与 CMS/技术名称对应，如:
          CMS "nacos" → nuclei tags "nacos"
          CMS "springboot" → nuclei tags "springboot,spring"

        Args:
            target_url: 目标 URL
            cms_names: CMS 名称列表 (来自 FingerprintEngine)
            template_dir: 模版目录 (覆盖构造参数)

        Returns:
            漏洞发现列表
        """
        if not self._available:
            return []

        # 清理 tags: nuclei tags 是小写、无特殊字符的
        tags = []
        for name in cms_names:
            tag = name.lower().strip().replace(" ", "-").replace("_", "-")
            if tag and tag not in tags:
                tags.append(tag)

        if not tags:
            return []

        # 保存原始 template_dir
        original_td = None
        if template_dir:
            original_td = self.template_dir
            self.template_dir = Path(template_dir)

        try:
            return self.scan(target_url, tags=tags)
        finally:
            if original_td is not None:
                self.template_dir = original_td

    # ----------------------------------------------------------
    # 批量扫描
    # ----------------------------------------------------------
    def scan_batch(self, targets: list[tuple[str, list[str]]]) -> dict[str, list[dict]]:
        """
        批量扫描多个目标

        Args:
            targets: [(url, cms_names), ...]

        Returns:
            {url: [findings], ...}
        """
        results = {}
        for url, cms_names in targets:
            findings = self.scan_by_tags(url, cms_names)
            if findings:
                results[url] = findings
        return results


# ============================================================
# 独立测试
# ============================================================
if __name__ == "__main__":
    import sys

    scanner = NucleiScanner(template_dir="poc/")

    if not scanner.available:
        print("请先安装 nuclei:")
        print("  brew install nuclei")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("用法:")
        print("  python nuclei_scanner.py <url> [tag1,tag2,...]")
        print("  python nuclei_scanner.py https://example.com nacos,springboot")
        sys.exit(1)

    url = sys.argv[1]
    tags = sys.argv[2].split(",") if len(sys.argv) > 2 else None

    if tags:
        findings = scanner.scan(url, tags=tags)
    else:
        findings = scanner.scan(url)

    print(f"\n扫描结果 ({len(findings)} 个发现):\n")
    for f in findings:
        sev = f["severity"].upper()
        color = _C.r if sev in ("CRITICAL", "HIGH") else _C.y if sev == "MEDIUM" else _C.c
        print(f"  {color}● {sev}{_C.R}  {_C.B}{f['name']}{_C.R}")
        print(f"    {f['url']}")
        if f.get("detail"):
            print(f"    {_C.D}{f['detail']}{_C.R}")
        if f.get("curl_command"):
            print(f"    {_C.D}{f['curl_command'][:120]}{_C.R}")
        print()

    print(f"{_C.D}统计: scans={scanner.stats['scans']}, "
          f"findings={scanner.stats['findings']}, "
          f"errors={scanner.stats['errors']}{_C.R}")
