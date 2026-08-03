#!/usr/bin/env python3
"""
指纹匹配引擎 — 加载 finger.json，对 HTTP 响应体做 CMS/技术栈指纹识别

逻辑:
  - 每条 fingerprint 条目内的 keyword[] 是 AND 关系 (全部命中才算匹配)
  - 同一 CMS 的不同条目之间是 OR 关系 (任一条目命中即匹配)
  - 支持方法: keyword (body/title), faviconhash

使用:
  from fingerprint_engine import FingerprintEngine
  engine = FingerprintEngine("finger.json")
  matches = engine.match(response_body_bytes)
  for m in matches:
      print(m["cms"], m["matches"])
"""

import json
import re
import base64
from pathlib import Path

try:
    import mmh3
    HAS_MMH3 = True
except ImportError:
    HAS_MMH3 = False


# ============================================================
# 终端颜色 (独立使用时可关闭)
# ============================================================
class _Colors:
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


# ============================================================
# 指纹匹配引擎
# ============================================================
class FingerprintEngine:
    """
    指纹匹配引擎

    匹配逻辑:
      - 每条 fingerprint 条目: keyword[] 内的关键词必须全部命中 (AND)
      - 同一 CMS 的多条规则: 任一条命中即匹配 (OR)
    """

    MIN_KEYWORD_LEN = 2  # 过滤过短的关键词 (如 "body", "id", "if" 误报太多)

    def __init__(self, finger_path: str = None, min_keyword_len: int = 4):
        # keyword 规则: [{cms, location, keywords: [kw1, kw2, ...]}, ...]
        # keywords 之间是 AND 关系
        self.rules: list[dict] = []

        # faviconhash 规则: {cms -> [hash1, hash2, ...]}
        self.favicon_by_cms: dict[str, list[str]] = {}

        self._loaded = False
        self._total_rules = 0
        self._cms_count = 0
        self._min_kw_len = min_keyword_len
        self._skipped_kw = 0

        if finger_path:
            self.load(finger_path)

    # ----------------------------------------------------------
    # 加载指纹库
    # ----------------------------------------------------------
    def load(self, path: str):
        """加载 finger.json 指纹库"""
        fp = Path(path)
        if not fp.exists():
            print(f"  {_Colors.YELLOW}[!] 指纹文件不存在: {path}{_Colors.RESET}")
            return

        file_size_mb = fp.stat().st_size / 1024 / 1024
        print(f"  [*] 加载指纹库: {fp.name} ({file_size_mb:.1f} MB) ...")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        raw = data.get("fingerprint", [])
        self._total_rules = len(raw)

        for item in raw:
            cms = item.get("cms", "").strip()
            if not cms:
                continue
            method = item.get("method", "keyword")
            location = item.get("location", "body")
            keywords = item.get("keyword", [])

            if method == "keyword":
                # 过滤 + 去重
                filtered = []
                for kw in keywords:
                    kw = kw.strip()
                    if not kw:
                        continue
                    if len(kw) < self._min_kw_len:
                        self._skipped_kw += 1
                        continue
                    if kw not in filtered:
                        filtered.append(kw)

                if filtered:
                    loc = location if location in ("body", "title") else "body"
                    self.rules.append({
                        "cms": cms,
                        "location": loc,
                        "keywords": filtered,
                    })

            elif method == "faviconhash":
                if cms not in self.favicon_by_cms:
                    self.favicon_by_cms[cms] = []
                for h in keywords:
                    h = h.strip()
                    if h and h not in self.favicon_by_cms[cms]:
                        self.favicon_by_cms[cms].append(h)

        self._loaded = True
        self._cms_count = len(set(
            {r["cms"] for r in self.rules} | set(self.favicon_by_cms.keys())
        ))
        print(f"  [*] 加载完毕: {self._total_rules} 条原始规则 → {len(self.rules)} 条 keyword 规则,"
              f" {self._cms_count} 个产品, {len(self.favicon_by_cms)} 个 favicon 产品")
        if self._skipped_kw:
            print(f"  [*] 过滤掉 {self._skipped_kw} 个过短关键词 (len < {self._min_kw_len})")
        print()

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def stats(self) -> dict:
        return {
            "total_rules": self._total_rules,
            "keyword_rules": len(self.rules),
            "cms_count": self._cms_count,
            "favicon_cms": len(self.favicon_by_cms),
            "skipped_kw": self._skipped_kw,
        }

    # ----------------------------------------------------------
    # 核心匹配
    # ----------------------------------------------------------
    def match(self, response_body: bytes) -> list[dict]:
        """
        匹配响应体中的指纹

        每条规则内 keyword[] 全部命中才算匹配 (AND)
        同一 CMS 的多条规则任一条命中即可 (OR)
        """
        if not self._loaded or not response_body:
            return []

        try:
            body_text = response_body.decode("utf-8", errors="replace")
        except Exception:
            return []

        # 提取 <title>...</title>
        title_match = re.search(
            r"<title[^>]*>(.*?)</title>", body_text, re.IGNORECASE | re.DOTALL
        )
        title_text = title_match.group(1).strip() if title_match else ""

        # 汇总: {cms -> {method, matches: [(loc, kw), ...], rules_hit: int}}
        hit_map: dict[str, dict] = {}
        matched_cms: set[str] = set()

        # ---- keyword: AND logic ----
        for rule in self.rules:
            cms = rule["cms"]
            if cms in matched_cms:
                continue

            loc = rule["location"]
            keywords = rule["keywords"]
            target = title_text if loc == "title" else body_text

            # AND: 全部命中 (不区分大小写)
            matched_kws = []
            all_hit = True
            target_lower = target.lower()
            for kw in keywords:
                if kw.lower() in target_lower:
                    matched_kws.append((loc, kw))
                else:
                    all_hit = False
                    break  # 一个不命中，整条规则跳过

            if all_hit and matched_kws:
                if cms not in hit_map:
                    hit_map[cms] = {
                        "cms": cms,
                        "method": "keyword",
                        "matches": [],
                        "rules_hit": 0,
                    }
                hit_map[cms]["matches"].extend(matched_kws)
                hit_map[cms]["rules_hit"] += 1

        # ---- faviconhash ----
        if self.favicon_by_cms:
            favicon_hash = self._compute_favicon_hash(body_text)
            if favicon_hash:
                for cms, hashes in self.favicon_by_cms.items():
                    if cms in matched_cms:
                        continue
                    for h in hashes:
                        if h == favicon_hash or h == str(favicon_hash):
                            if cms not in hit_map:
                                hit_map[cms] = {
                                    "cms": cms,
                                    "method": "faviconhash",
                                    "matches": [],
                                    "rules_hit": 0,
                                }
                            hit_map[cms]["matches"].append(("favicon", favicon_hash))
                            hit_map[cms]["rules_hit"] += 1
                            break

        # 去重 matches (同一个 kw 可能被多条规则命中)
        for cms in hit_map:
            seen = set()
            unique = []
            for loc, kw in hit_map[cms]["matches"]:
                key = (loc, kw)
                if key not in seen:
                    seen.add(key)
                    unique.append((loc, kw))
            hit_map[cms]["matches"] = unique

        return list(hit_map.values())

    def match_batch(self, items: list[tuple[str, bytes]]) -> list[dict]:
        """批量匹配"""
        results = []
        for identifier, body in items:
            m = self.match(body)
            if m:
                results.append({"id": identifier, "body_size": len(body), "matches": m})
        return results

    # ----------------------------------------------------------
    # favicon 处理
    # ----------------------------------------------------------
    def _compute_favicon_hash(self, html: str):
        """从 HTML 提取 favicon 并计算 mmh3 hash"""
        if not HAS_MMH3:
            return None

        favicon_url = None
        for pattern in [
            r'<link[^>]*rel=["\'](?:shortcut\s+)?icon["\'][^>]*href=["\']([^"\']+)["\']',
            r'<link[^>]*href=["\']([^"\']+)["\'][^>]*rel=["\'](?:shortcut\s+)?icon["\']',
        ]:
            m = re.search(pattern, html, re.IGNORECASE)
            if m:
                favicon_url = m.group(1)
                break

        if not favicon_url:
            return None

        if favicon_url.startswith("data:image/"):
            try:
                if ";base64," in favicon_url:
                    b64_part = favicon_url.split(";base64,", 1)[1]
                else:
                    b64_part = favicon_url.split(",", 1)[1]
                raw = base64.b64decode(b64_part)
                return str(mmh3.hash(raw))
            except Exception:
                return None

        return None

    def compute_mmh3(self, data: bytes) -> str:
        """计算 mmh3 hash"""
        if not HAS_MMH3:
            raise ImportError("需要安装 mmh3: pip install mmh3")
        return str(mmh3.hash(data))

    # ----------------------------------------------------------
    # 导出 / 统计
    # ----------------------------------------------------------
    def get_cms_list(self) -> list[str]:
        """所有已知 CMS 名称"""
        cms_set = {r["cms"] for r in self.rules} | set(self.favicon_by_cms.keys())
        return sorted(cms_set)

    def get_rules_for_cms(self, cms: str) -> list[dict]:
        """获取某个 CMS 的所有规则"""
        keyword_rules = [r for r in self.rules if r["cms"] == cms]
        favicon_hashes = self.favicon_by_cms.get(cms, [])
        result = []
        for r in keyword_rules:
            result.append({
                "method": "keyword",
                "location": r["location"],
                "keywords": r["keywords"],
            })
        if favicon_hashes:
            result.append({
                "method": "faviconhash",
                "location": "favicon",
                "keywords": favicon_hashes,
            })
        return result


# ============================================================
# 独立测试
# ============================================================
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("用法: python fingerprint_engine.py <finger.json> [测试HTML文件]")
        print("      python fingerprint_engine.py <finger.json> --list-cms")
        sys.exit(1)

    engine = FingerprintEngine(sys.argv[1])

    if "--list-cms" in sys.argv:
        cms_list = engine.get_cms_list()
        print(f"\n共 {len(cms_list)} 个产品:\n")
        for i, name in enumerate(cms_list, 1):
            rules = engine.get_rules_for_cms(name)
            parts = []
            for r in rules:
                if r["method"] == "keyword":
                    parts.append(f"{r['location']}:{len(r['keywords'])}kw")
                elif r["method"] == "faviconhash":
                    parts.append(f"favicon:{len(r['keywords'])}")
            print(f"  {i:4d}. {name}  ({', '.join(parts)})")
        sys.exit(0)

    if len(sys.argv) >= 3:
        with open(sys.argv[2], "rb") as f:
            body = f.read()
    else:
        print("输入 HTML 内容 (Ctrl+D 结束):")
        body = sys.stdin.buffer.read()

    print(f"\n测试数据: {len(body)} 字节\n")
    matches = engine.match(body)

    if matches:
        print(f"命中 {len(matches)} 个产品:\n")
        for m in matches:
            rule_count = m.get("rules_hit", 0)
            print(f"  ● {m['cms']} ({m['method']}, {rule_count} 条规则)")
            for loc, kw in m["matches"][:8]:
                kw_short = kw if len(kw) <= 60 else kw[:57] + "..."
                print(f"      {loc}: \"{kw_short}\"")
            if len(m["matches"]) > 8:
                print(f"      ... 还有 {len(m['matches']) - 8} 条")
            print()
    else:
        print("未命中任何指纹")
