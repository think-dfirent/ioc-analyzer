# ioc-analyzer

[![CI](https://github.com/think-dfirent/ioc-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/think-dfirent/ioc-analyzer/actions/workflows/ci.yml)
Pull IOCs (public IPv4, domains, MD5/SHA1/SHA256) out of any text — an alert, an email, a ticket — and look them up on VirusTotal and AbuseIPDB. Prints a readable report for analysts, or JSON for scripts and SOAR playbooks.

## Install

Needs Python 3.12 or newer.

```powershell
git clone https://github.com/think-dfirent/ioc-analyzer.git
cd ioc-analyzer
python -m venv venv; venv\Scripts\Activate.ps1      # Linux/macOS: source venv/bin/activate
python -m pip install -U pip
pip install .                                        # for development: pip install -e . --group dev
ioc-analyzer --version
```

## Settings

API keys are read from **environment variables**, or else from one **per-user settings file**:

| OS            | Settings file                                                           |
| ------------- | ----------------------------------------------------------------------- |
| Windows       | `%APPDATA%\ioc-analyzer\.env`                                           |
| Linux / macOS | `~/.config/ioc-analyzer/.env` (or `$XDG_CONFIG_HOME/ioc-analyzer/.env`) |

Create it from the template in this repo:

```powershell
New-Item -ItemType Directory -Force "$env:APPDATA\ioc-analyzer" | Out-Null
$settings = "$env:APPDATA\ioc-analyzer\.env"
if (-not (Test-Path $settings)) { Copy-Item .env.example $settings }   # never overwrite existing keys
notepad $settings
```

Fill in your keys in Notepad, **save and close it**, then continue. (Notepad opens in its own window; PowerShell does not wait for it.)

| Setting                   | Required | Meaning                                                          |
| ------------------------- | -------- | ---------------------------------------------------------------- |
| `VIRUSTOTAL_API`          | yes      | VirusTotal API key                                               |
| `ABUSEIPDB_API`           | no       | AbuseIPDB API key; without it, IPs get VirusTotal only           |
| `VIRUSTOTAL_RATE_PER_MIN` | no       | VirusTotal requests per rolling minute (default 4; 0 = no limit) |

An environment variable with the same name overrides the file, which is how a SOAR runner or CI should pass keys.

**A `.env` file in your current folder is never read.** Analysts often run tools inside evidence folders, and a planted `.env` could redirect traffic (with your API key in it) through an attacker's proxy. Only the three settings above are read from the settings file; anything else in it is ignored.

## Usage

```powershell
python -m ioc_analyzer "beacon to 8.8.8.8 and evil.example"   # text
python -m ioc_analyzer --file alert.txt                       # UTF-8 file
Get-Content alert.txt | python -m ioc_analyzer -              # stdin
python -m ioc_analyzer                                        # clipboard
```

Choose one input source per run; text plus `--file` is a usage error.

| Flag              | Effect                                                                  |
| ----------------- | ----------------------------------------------------------------------- |
| `--json`          | One JSON document on stdout (shape below)                               |
| `--no-color`      | Plain text; setting `NO_COLOR` does the same                            |
| `-v`, `--verbose` | Also show debug messages on stderr (waits and retries are always shown) |
| `--version`       | Print `ioc-analyzer <version>`                                          |

stdout carries results only. Warnings, errors and debug messages go to stderr, so `--json | jq` is always safe.

`python -m ioc_analyzer` works the same.

## What gets extracted

- **IPv4** addresses that are public (`8.8.8.8`); private and reserved ranges (`10.x`, `192.168.x`, documentation ranges) are skipped. IPv6 is not supported yet.
- **Domains** whose top-level domain really exists (IANA's list, bundled in `src/ioc_analyzer/data/tlds.txt`), plus the reserved `.example` and `.test`. This keeps user names (`CORP\j.doe`), code (`Net.WebClient`) and file names (`payload.exe`, `detect.py`, `invoice.one`) out of your lookups. `.zip`, `.mov`, `.sh` and `.app` are treated as domains, because attackers register them to look like files. Hostnames inside URLs are extracted; paths and query strings are ignored.
- **Hashes:** MD5, SHA1 and SHA256, any case.
- **Defanged IOCs** are read as real ones: `hxxp://`, `hxxps://`, `[.]`, `(.)`, `{.}`, `[dot]`, `(dot)`, `{dot}`, `[:]`, `[://]`. Only bracketed markers count; "evil dot com" or "evil . com" is left alone. Results always show the real (refanged) value.

Each IOC is looked up once per run, however often it appears.

To refresh the TLD list (a few new TLDs appear each year):

    Invoke-WebRequest https://data.iana.org/TLD/tlds-alpha-by-domain.txt -OutFile src\ioc_analyzer\data\tlds.txt

## Rate limits, retries and waiting

The tool waits instead of failing when a provider is slow, briefly broken or rate-limited. Every wait is announced on stderr, so a quiet terminal means it is working, not hung.

- **VirusTotal throttle:** at most `VIRUSTOTAL_RATE_PER_MIN` requests (default 4, the free public API limit) start in any rolling 60 s. Up to 4 IOCs go out at once; 10 IOCs take about 2 minutes. Set it to `0` if your key has no per-minute limit. Retries count against it too.
- **Retries:** timeouts, dropped connections and HTTP 5xx are retried twice, after 1 s and 2 s. 401, 404, other 4xx and malformed responses are never retried, because the answer would be the same.
- **HTTP 429:** the tool waits 60 s and tries once more. A second 429 means the quota is used up: that provider is skipped for the rest of the run, and the run exits 1.
- **Worst case:** a provider that times out on every try costs about 33 s per lookup (3 × 10 s timeout + 3 s of backoff). If you run this from SOAR, set the step timeout with that in mind; a killed step returns no output at all.

Only read-only lookups (HTTP GET) are ever retried.

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
