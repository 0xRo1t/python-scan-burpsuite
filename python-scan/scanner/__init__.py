"""
POC 漏洞扫描器 — 独立可测试的扫描引擎

支持两种模式:
  1. 内置引擎 — 解析 Nuclei 兼容的 YAML 模版并执行
  2. Nuclei CLI — 调用本地 nuclei 二进制扫描

使用:
  from scanner import Scanner, TemplateLoader

  loader = TemplateLoader("poc/")
  scanner = Scanner(loader)

  findings = scanner.scan("https://target.com", tags=["crmeb"])
"""

from .engine import Scanner, TemplateLoader, HttpSender, Matcher
