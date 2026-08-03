#!/usr/bin/env python3
from __future__ import annotations
"""
独立 POC 扫描 CLI — 输入 YAML 模版 + URL，输出漏洞结果

用法:
  # 按 tags 扫描
  python -m scanner.cli --url https://target.com --templates poc/ --tags crmeb,sqli

  # 扫描单个模版文件
  python -m scanner.cli --url https://target.com --templates poc/CVE-2024-36837.yaml

  # 扫描所有模版 (无 tag 筛选)
  python -m scanner.cli --url https://target.com --templates poc/

  # 仅使用 Nuclei CLI
  python -m scanner.cli --url https://target.com --templates poc/ --nuclei-only

  # 列出模版 tags
  python -m scanner.cli --templates poc/ --list-tags
"""

import sys
import argparse
from pathlib import Path

# 允许从 scanner/ 目录直接运行
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.engine import TemplateLoader, Scanner


# ============================================================
# 颜色
# ============================================================
class C:
    R = "\033[0m"; B = "\033[1m"; D = "\033[2m"
    r = "\033[91m"; g = "\033[92m"; y = "\033[93m"
    c = "\033[96m"; m = "\033[95m"


# ============================================================
# 输出
# ============================================================
SEVERITY_COLORS = {
    "critical": C.r,
    "high": C.r,
    "medium": C.y,
    "low": C.c,
    "info": C.D,
}


def print_finding(f: dict):
    sev = f.get("severity", "unknown").lower()
    color = SEVERITY_COLORS.get(sev, C.D)
    src_tag = f"{C.D}[{f.get('source', '?')}]{C.R}" if f.get("source") else ""

    print(f"\n  {C.D}── 漏洞{C.R}"
          f"  {color}● {sev.upper()}{C.R}  {C.B}{f['name']}{C.R}  {src_tag}")
    print(f"    {C.D}URL  {f.get('url', '?')}{C.R}")
    # 完整请求
    req = f.get("request", {})
    if req:
        print(f"    {C.D}{'─'*50}{C.R}")
        if "raw" in req:
            print(f"    {C.B}REQUEST (raw){C.R}")
            for line in req["raw"].strip().split("\n"):
                print(f"    {C.m}{line[:200]}{C.R}")
        else:
            method = req.get("method", "GET")
            url = req.get("url", "")
            headers = req.get("headers", {})
            body = req.get("body", "")
            print(f"    {C.B}{method}{C.R} {url}")
            for k, v in headers.items():
                print(f"    {C.D}{k}: {v}{C.R}")
            if body:
                print(f"    {C.D}{body[:1000]}{C.R}")
    # 完整响应
    resp = f.get("response", {})
    if resp:
        status = resp.get("status", 0)
        print(f"\n    {C.B}RESPONSE [{status}]{C.R}")
        body = resp.get("body", "")
        if body:
            print(f"    {C.D}{body[:2000]}{C.R}")
        else:
            print(f"    {C.D}(empty){C.R}")
    print()


# ============================================================
# CLI
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="POC 漏洞扫描器 — 内置引擎 + Nuclei CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url", help="目标 URL (如 https://example.com:8443)")
    parser.add_argument("--templates", "-t",
                        help="模版路径: 目录 或 单文件 YAML")
    parser.add_argument("--tags",
                        help="按 tag 筛选模版 (逗号分隔)")
    parser.add_argument("--workers", type=int, default=5,
                        help="并发数 (默认 5)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="单请求超时秒数 (默认 10)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="详细模式: 显示完整请求/响应体和匹配过程")
    parser.add_argument("--nuclei-only", action="store_true",
                        help="仅使用 Nuclei CLI (不触发内置引擎)")
    parser.add_argument("--no-nuclei", action="store_true",
                        help="禁用 Nuclei CLI (仅内置引擎)")
    parser.add_argument("--list-tags", action="store_true",
                        help="列出模版 tags 后退出")
    parser.add_argument("--json", action="store_true",
                        help="JSON 格式输出")
    args = parser.parse_args()

    # ---- 加载模版 ----
    loader = None
    if args.templates:
        loader = TemplateLoader(args.templates)
    elif args.list_tags:
        print("错误: --list-tags 需要 --templates 参数")
        sys.exit(1)

    # ---- 列出 tags ----
    if args.list_tags and loader:
        tags = loader.list_tags()
        print(f"\nTags ({len(tags)}):\n")
        for t in tags:
            count = len(loader.tag_index[t])
            print(f"  {C.c}{t}{C.R}  ({count} 个模版)")
        print()
        return

    # ---- 检查 URL ----
    if not args.url:
        print("错误: 需要 --url 参数")
        sys.exit(1)

    if not loader:
        print("提示: 未指定 --templates，将仅使用 Nuclei CLI (如果可用)")

    # ---- 创建扫描器 ----
    scanner = Scanner(
        loader=loader,
        timeout=args.timeout,
        max_workers=args.workers,
        enable_nuclei=not args.no_nuclei,
        verbose=args.verbose,
    )

    # ---- 扫描 ----
    tags = None
    if args.tags:
        tags = [t.strip() for t in args.tags.split(",")]

    if args.nuclei_only:
        # 仅 nuclei
        findings = scanner._run_nuclei(args.url)
    else:
        findings = scanner.scan(args.url, tags=tags)

    # ---- 输出 ----
    if args.json:
        import json
        output = {
            "url": args.url,
            "tags": tags,
            "total": len(findings),
            "findings": findings,
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return

    # 汇总统计
    by_severity: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1

    print(f"\n{'═' * 72}")
    print(f"  扫描结果: {args.url}")
    print(f"{'─' * 72}")
    print(f"  模版数: {len(loader.templates) if loader else 'N/A'}"
          f"  |  tags: {tags or '全部'}"
          f"  |  发现: {len(findings)}")
    if by_severity:
        parts = [f"{s}:{n}" for s, n in sorted(by_severity.items())]
        print(f"  {C.D}按等级: {', '.join(parts)}{C.R}")
    print(f"{'─' * 72}\n")

    if not findings:
        print(f"  {C.g}未发现漏洞{C.R}\n")
        return

    for f in findings:
        print_finding(f)

    print(f"{C.D}总计: {len(findings)} 个发现  "
          f"| scans={scanner.stats['scans']}"
          f"  errors={scanner.stats['errors']}{C.R}\n")


if __name__ == "__main__":
    main()
