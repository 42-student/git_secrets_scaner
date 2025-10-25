# git_secrets_scanner

**Detect leaked secrets in your Git history** AWS keys, API tokens, passwords and more.

Lightweight, fast and zero-dependency (beyond `git-python`). Scans commit messages and file diffs using smart regex patterns and heuristics.

Perfect for CI/CD pipelines, pre-commit hooks or local repo audits.

---

## Features

- Scans **last N commits** (default: 5)
- Detects:
  - AWS Access + Secret Keys
  - Stripe / OpenAI / generic `sk_live_...` keys
  - Passwords, tokens, and long secrets
  - Standalone key patterns
- Works on **local repos** and **remote URLs**
- Outputs **structured JSON report**
- Skips false positives (`example`, `test`, `dummy`, etc.)
- Debug mode for pattern tuning

---

## Installation

- Requires Python 3.7+

```bash
pip install gitpython
```

---

## Usage

```bash
# scan for local repo
python git_secrets_scanner.py --repo /path/to/your/repo --n 10 --out report.json

# scan a remote github repo
python git_secrets_scanner.py --repo https://github.com/username/repo.git --n 5 --out findings.json

# enable debug
python git_secrets_scanner.py --repo . --debug
```

---

## Example output
```bash
{
  "summary": {
    "total_commits_scanned": 5,
    "total_findings": 2,
    "timestamp": "2025-04-05 14:30:22"
  },
  "findings": [
    {
      "commit_hash": "a1b2c3d4",
      "file": "config.env",
      "line": 12,
      "snippet": "AWS_SECRET_ACCESS_KEY= wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "type": "AWS_SECRET_ACCESS_KEY",
      "confidence": "high"
    }
  ]
}
```

---

## Detected patterns

| Type                  | Example                                      |
|-----------------------|----------------------------------------------|
|AWS_ACCESS_KEY_ID      |     AKIAIOSFODNN7EXAMPLE                     | 
|AWS_SECRET_ACCESS_KEY  |     wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY |
|API_KEY                |     sk_live_51J...                           |
|GENERIC_SECRET         |     "password = ""SuperSecret123!"""         |

- Standalone keys, Raw keys in code/comments
- False positives filtered: example, test, sample, etc.

---

## Use in CI/CD (GitHub Actions)
```bash
name: Secret Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 50  # Scan more history

      - name: Install dependencies
        run: pip install GitPython

      - name: Run scanner
        run: python git_secrets_scanner.py --repo . --n 20 --out report.json

      - name: Upload report
        uses: actions/upload-artifact@v3
        with:
          name: secret-scan-report
          path: report.json
```

---

## Disclaimer
- This tool uses heuristic regex patterns and may produce false positives. Always manually verify findings.
- Not affiliated with GitHub, AWS or Stripe.

---

#### Made with ☕ by {[-_-]}

<p align="center">
  <img src="https://img.shields.io/badge/python-3.7%2B-blue" />
  <img src="https://img.shields.io/badge/secrets-detected-red" />
</p>
