# ioc-analyzer

Pull IOCs (public IPv4, domains, MD5/SHA1/SHA256) out of any text — an alert, an email, a ticket — and look them up on VirusTotal and AbuseIPDB. Prints a readable report for analysts, or JSON for scripts and SOAR playbooks.

## Setup

Until Phase 7 adds packaging, run it from the repo:

```powershell
python -m venv venv; venv\Scripts\Activate.ps1
pip install requests python-dotenv pyperclip
$env:PYTHONPATH = "src"
```

Create `.env` in the repo root (it is gitignored):

```
VIRUSTOTAL_API=your-key        # required
ABUSEIPDB_API=your-key         # optional; without it, IPs get VirusTotal only
```

## Usage

```powershell
python -m ioc_analyzer.app "beacon to 8.8.8.8 and evil.example"   # text
python -m ioc_analyzer.app --file alert.txt                       # UTF-8 file
Get-Content alert.txt | python -m ioc_analyzer.app -              # stdin
python -m ioc_analyzer.app                                        # clipboard
```

Choose one input source per run; text plus `--file` is a usage error.

| Flag              | Effect                                       |
| ----------------- | -------------------------------------------- |
| `--json`          | One JSON document on stdout (shape below)    |
| `--no-color`      | Plain text; setting `NO_COLOR` does the same |
| `-v`, `--verbose` | Debug messages on stderr                     |
| `--version`       | Print `ioc-analyzer <version>`               |

stdout carries results only. Warnings, errors and debug messages go to stderr, so `--json | jq` is always safe.

## Exit codes

| Code | Meaning                                                                                         | What a script should do                                        |
| ---- | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `0`  | Every lookup got an answer. "Not found" (404) and "no IOCs in the text" count as answers.       | Trust the results.                                             |
| `1`  | At least one lookup failed (5xx, timeout, rate limit, rejected key). Results may be partial.    | Use what came back, don't auto-close; check `errors` / stderr. |
| `2`  | Usage or config problem: bad arguments, missing `VIRUSTOTAL_API`, unreadable file or clipboard. | Fix the call or the config; nothing was looked up.             |

## JSON output

```json
{
  "results": [
    {
      "indicator": "8.8.8.8",
      "type": "ip",
      "providers": {
        "virustotal": { "status": "ok" },
        "abuseipdb": { "status": "unavailable" }
      },
      "report": {
        "virustotal": {
          "malicious": 0,
          "suspicious": 0,
          "total": 62,
          "reputation": 0
        },
        "abuseipdb": null,
        "network_context": {
          "country": "US",
          "asn": 15169,
          "owner": "GOOGLE",
          "is_tor": null,
          "...": "..."
        }
      },
      "errors": []
    },
    {
      "indicator": "aaaa…",
      "type": "file",
      "providers": { "virustotal": { "status": "not_found" } },
      "report": null,
      "errors": []
    }
  ]
}
```

- `type`: `ip`, `domain` or `file`.
- `providers.<name>.status`:
  - `ok`: answered with data
  - `not_found`: answered "no record"
  - `unavailable`: not asked (no key, or disabled after 401/429 earlier in the run)
  - `error`: asked, and the request failed
- `abuseipdb` appears only for IPs.
- Missing values are `null`, never `"Unknown"` and never `0`. A `0` is real data. Test for `null` before comparing: `malicious is not None and malicious > 5`.
- `report` is `null` when VirusTotal had no record or failed (an IP still gets a report from AbuseIPDB). The sections inside it depend on `type`.
- `errors`: the same messages printed on stderr.
- No IOCs found → `{"results": []}` and exit code 0.

Field names are a contract: renaming one is a breaking change.
