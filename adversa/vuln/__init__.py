"""Vulnerability analysis phase package.

Orchestrates 5 parallel DeepAgent analyzers (injection, XSS, SSRF, auth, authz),
each with an isolated Playwright browser session, and aggregates results into a
validated VulnReport.
"""
