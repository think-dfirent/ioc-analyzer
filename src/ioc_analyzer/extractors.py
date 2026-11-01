import ipaddress
import re
from urllib.parse import urlsplit
from functools import cache
from importlib.resources import files

# the non-domain file extensions
FILE_EXTENSIONS = frozenset(
    {
        "exe",
        "dll",
        "scr",
        "msi",
        "bat",
        "cmd",
        "vbs",
        "js",
        "jar",
        "hta",
        "lnk",
        "doc",
        "docx",
        "docm",
        "xls",
        "xlsx",
        "xlsm",
        "ppt",
        "pptx",
        "pdf",
        "rtf",
        "txt",
        "log",
        "csv",
        "json",
        "xml",
        "html",
        "htm",
        "yaml",
        "yml",
        "ini",
        "cfg",
        "iso",
        "img",
        "rar",
        "gz",
        "tar",
        "eml",
        "msg",
        "tmp",
        "bin",
        "dat",
        "sys",
    }
)

_DEFANGED_SCHEME = re.compile(r"\bhxxp(s?)(?=\[?:)", re.IGNORECASE)
_DEFANGED_COLON = re.compile(r"\[(://|:)\]")
_DEFANGED_DOT = re.compile(
    r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}", re.IGNORECASE
)


def refang(text: str) -> str:
    """Undo common defanging so the extractors see real IOCs.
    hxxp/hxxps -> http/https, [:] and [://] -> : and ://,
    [.] (.) {.} [dot] (dot) {dot} -> .
    Text without these markers is returned unchanged.
    """
    text = _DEFANGED_SCHEME.sub(r"http\1", text)
    text = _DEFANGED_COLON.sub(r"\1", text)
    return _DEFANGED_DOT.sub(".", text)


def ip_extraction(text):
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    potential_ips = ip_re.findall(text)

    valid_ips = []

    for ip in potential_ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_global:
                valid_ips.append(str(ip_obj))
        except ValueError:
            continue
    return valid_ips


def domain_extraction(text):
    domains = []

    def extract_host(match):
        try:
            url = match.group().rstrip(".,;!?)")
            if not url.startswith("//") and "://" not in url:
                url = "//" + url
            host = urlsplit(url).hostname
            if host and is_domain(host):
                domains.append(host.lower())
        except ValueError:
            pass
        return " "

    # Consume entire URLs so paths and query strings cannot become domains.
    remaining = re.sub(
        r"(?:[a-zA-Z][a-zA-Z0-9+.-]*://|//)[^\s<>\"']+", extract_host, text
    )
    remaining = re.sub(
        r"(?<![\w.-])(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}" r"(?::\d+)?[/?#][^\s<>\"']*",
        extract_host,
        remaining,
    )
    for candidate in re.findall(r"[a-zA-Z0-9_.-]+", remaining):
        candidate = candidate.rstrip(".")
        if is_domain(candidate):
            domains.append(candidate.lower())
    return list(dict.fromkeys(domains))


_LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
_TLD = r"(?:[a-zA-Z]{2,63}|xn--[a-zA-Z0-9]{2,59})"
DOMAIN_REGEX = re.compile(rf"(?:{_LABEL}\.)+{_TLD}", re.IGNORECASE)


# Reserved for documentation and tests (RFC 2606); not in the root zone, but
# the fixtures use them, and a lookup of one is harmless (VirusTotal says 404).
RESERVED_TLDS = frozenset({"example", "test"})


@cache
def known_tlds() -> frozenset[str]:
    """Every real top-level domain, from IANA's list bundled in data/tlds.txt.

    Read once per process (@cache). To refresh, download
    https://data.iana.org/TLD/tlds-alpha-by-domain.txt over the bundled file.
    """
    text = files("ioc_analyzer").joinpath("data/tlds.txt").read_text(encoding="ascii")
    tlds = {
        line.strip().lower()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    }
    return frozenset(tlds) | RESERVED_TLDS


def is_domain(value: str) -> bool:
    """True if value looks like a domain whose TLD really exists.

    The TLD check is what stops user names (j.doe), code (Net.WebClient) and
    header fields (smtp.mailfrom) from being looked up as domains. The file
    extension check stays for real TLDs that are mostly file names in alerts.
    """
    if len(value) > 253 or not DOMAIN_REGEX.fullmatch(value):
        return False
    tld = value.rsplit(".", 1)[1].lower()
    return tld in known_tlds() and tld not in FILE_EXTENSIONS


def hash_extraction(text):
    md5_re = re.compile(r"\b[A-Fa-f0-9]{32}\b")
    sha1_re = re.compile(r"\b[A-Fa-f0-9]{40}\b")
    sha256_re = re.compile(r"\b[A-Fa-f0-9]{64}\b")

    hash_list = md5_re.findall(text) + (sha1_re.findall(text)) + sha256_re.findall(text)
    return hash_list


def extract_indicators(text: str) -> list[tuple[str, str]]:
    """Refang the text, then return each unique (value, kind) in a stable order.

    kind is "ip", "domain" or "file" (a hash). Hashes are lowercased so the same
    hash in upper and lower case counts once. Order: IPs, domains, hashes, each
    in the order they first appear.
    """
    text = refang(text)
    found = (
        [(ip, "ip") for ip in ip_extraction(text)]
        + [(domain, "domain") for domain in domain_extraction(text)]
        + [(value.lower(), "file") for value in hash_extraction(text)]
    )
    return list(dict.fromkeys(found))
