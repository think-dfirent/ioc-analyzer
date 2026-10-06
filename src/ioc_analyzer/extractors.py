import re, ipaddress
from urllib.parse import urlsplit


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


def is_domain(value):
    label = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    return (
        len(value) <= 253
        and re.fullmatch(rf"(?:{label}\.)+[a-zA-Z]{{2,63}}", value) is not None
    )


def hash_extraction(text):
    md5_re = re.compile(r"\b[A-Fa-f0-9]{32}\b")
    sha1_re = re.compile(r"\b[A-Fa-f0-9]{40}\b")
    sha256_re = re.compile(r"\b[A-Fa-f0-9]{64}\b")

    hash_list = md5_re.findall(text) + (sha1_re.findall(text)) + sha256_re.findall(text)
    return hash_list
