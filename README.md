# dagu-v1.30.3 - 漏洞总览

| # | CVE | 端点 | 漏洞类型 | 状态 |
|---|---|---|---|---|
| 1 | GHSA-6qr9-g2xw-cw92 | `POST /api/v2/dag-runs` | 未授权RCE (CWE-306) | VULNERABLE |
| 2 | CVE-2026-27598 | `POST /api/v1/dags/{name}` | 路径遍历 (CWE-22) | VULNERABLE |
