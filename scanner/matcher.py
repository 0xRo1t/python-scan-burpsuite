#!/usr/bin/env python3
from __future__ import annotations
"""匹配器 — 检查 HTTP 响应是否满足模版条件"""

import re


class Matcher:
    """支持 word / status / dsl 三种匹配器"""

    @staticmethod
    def check(matchers: list[dict], condition: str,
              response: dict, resolver=None) -> bool:
        if not matchers:
            return True  # 无 matcher 时默认通过

        results = []
        for m in matchers:
            results.append(Matcher._check_one(m, response, resolver))

        if condition == "or":
            return any(results)
        return all(results)

    @staticmethod
    def _check_one(matcher: dict, response: dict, resolver=None) -> bool:
        mtype = matcher.get("type", "word")
        condition = matcher.get("condition", "or")

        # ---- status ----
        if mtype == "status":
            codes = matcher.get("status", [])
            if isinstance(codes, int):
                codes = [codes]
            if condition == "and":
                return all(response.get("status") == c for c in codes)
            return response.get("status") in codes

        # ---- word ----
        elif mtype == "word":
            part = matcher.get("part", "body")
            words = matcher.get("words", [])

            if part == "body":
                text = response.get("body", b"")
                if isinstance(text, bytes):
                    text = text.decode("utf-8", errors="replace")
            elif part == "header":
                text = " ".join(
                    f"{k}: {v}" for k, v in response.get("headers", {}).items()
                )
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

        # ---- dsl ----
        elif mtype == "dsl":
            return Matcher._check_dsl(matcher, response)

        return False

    @staticmethod
    def _check_dsl(matcher: dict, response: dict) -> bool:
        dsl_list = matcher.get("dsl", [])
        if isinstance(dsl_list, str):
            dsl_list = [dsl_list]
        condition = matcher.get("condition", "and")
        results = []

        body_text = ""
        if isinstance(response.get("body"), bytes):
            body_text = response["body"].decode("utf-8", errors="replace")
        elif isinstance(response.get("body"), str):
            body_text = response["body"]

        for expr in dsl_list:
            try:
                expr = re.sub(
                    r"status_code_(\d+)",
                    str(response.get("status", 0)), expr
                )

                def _contains(m):
                    target = m.group(1).strip().strip("'").strip('"')
                    return str(target in body_text).lower()

                expr = re.sub(
                    r"contains\(body_\d+,\s*'([^']*)'\)", _contains, expr
                )
                expr = re.sub(
                    r'contains\(body_\d+,\s*"([^"]*)"\)', _contains, expr
                )

                expr = expr.replace("&&", " and ").replace("||", " or ")
                expr = expr.replace("true", "True").replace("false", "False")

                result = eval(expr)
                results.append(bool(result))
            except Exception:
                results.append(False)

        if condition == "and":
            return all(results)
        return any(results)
