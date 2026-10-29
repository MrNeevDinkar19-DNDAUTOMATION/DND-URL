
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from urllib.parse import urlsplit, unquote
from difflib import SequenceMatcher
import ipaddress
import re
import unicodedata


app = FastAPI(
    title="URL Guard API",
    description="Local rule-based phishing URL detection",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class URLRequest(BaseModel):
    url: HttpUrl


# Official domains used for brand impersonation checks.
# This is a curated starter list, not a complete brand registry.
BRANDS = {
    "Google": {
        "tokens": ["google"],
        "domains": ["google.com", "google.co.in"],
    },
    "Microsoft": {
        "tokens": ["microsoft"],
        "domains": ["microsoft.com", "microsoftonline.com"],
    },
    "Apple": {
        "tokens": ["apple"],
        "domains": ["apple.com"],
    },
    "PayPal": {
        "tokens": ["paypal"],
        "domains": ["paypal.com"],
    },
    "Amazon": {
        "tokens": ["amazon"],
        "domains": ["amazon.com", "amazon.in"],
    },
    "Facebook": {
        "tokens": ["facebook"],
        "domains": ["facebook.com"],
    },
    "Instagram": {
        "tokens": ["instagram"],
        "domains": ["instagram.com"],
    },
    "Netflix": {
        "tokens": ["netflix"],
        "domains": ["netflix.com"],
    },
    "WhatsApp": {
        "tokens": ["whatsapp"],
        "domains": ["whatsapp.com"],
    },
    "OpenAI": {
        "tokens": ["openai"],
        "domains": ["openai.com"],
    },
    "ChatGPT": {
        "tokens": ["chatgpt"],
        "domains": ["chatgpt.com"],
    },
    "Binance": {
        "tokens": ["binance"],
        "domains": ["binance.com"],
    },
    "Coinbase": {
        "tokens": ["coinbase"],
        "domains": ["coinbase.com"],
    },
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "shorturl.at", "rebrand.ly",
    "ow.ly", "buff.ly", "rb.gy",
}

SUSPICIOUS_TERMS = {
    "login", "signin", "verify", "verification",
    "password", "credential", "wallet", "recover",
    "account", "authenticate", "reset", "webscr",
    "secure", "security", "confirm",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "country", "gq",
    "tk", "ml", "cf",
}

UNUSUAL_PORTS = {81, 444, 591, 8080, 8443, 8888}

# Fixed heuristic weights, not probabilities.
WEIGHTS = {
    "http": 5,
    "userinfo": 25,
    "ip_host": 25,
    "punycode": 20,
    "brand_impersonation": 35,
    "brand_lookalike": 30,
    "many_subdomains": 10,
    "long_url": 8,
    "long_hostname": 8,
    "many_hyphens": 8,
    "encoded_url": 4,
    "control_chars": 15,
    "suspicious_terms": 8,
    "shortener": 8,
    "unusual_port": 8,
    "suspicious_tld": 5,
}


def normalize_hostname(hostname: str) -> str:
    """Normalize a hostname for comparisons."""
    hostname = unicodedata.normalize("NFKC", hostname).lower().rstrip(".")

    try:
        return hostname.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return hostname


def is_official_domain(hostname: str, domains: list[str]) -> bool:
    """Match the official domain or a genuine subdomain of it."""
    return any(
        hostname == domain or hostname.endswith("." + domain)
        for domain in domains
    )


def detect_brand_impersonation(hostname: str):
    """
    Return the strongest brand-related finding, if any.

    Checks hostname labels only, not URL paths or query strings.
    """
    labels = hostname.split(".")

    for brand, details in BRANDS.items():
        if is_official_domain(hostname, details["domains"]):
            continue

        tokens = details["tokens"]

        # Brand name used in a misleading hostname, for example:
        # paypal-account.example.org
        for label in labels:
            parts = [
                part for part in re.split(r"[^a-z0-9]+", label)
                if part
            ]

            if any(token in parts for token in tokens):
                return {
                    "type": "brand_impersonation",
                    "brand": brand,
                    "reason": (
                        f"The hostname uses the name {brand}, "
                        "but is not on the configured official-domain list."
                    ),
                }

        # Similar-looking labels, such as paypa1 or g00gle.
        # This is deliberately conservative and can miss some variants.
        for label in labels:
            compact = re.sub(r"[^a-z0-9]", "", label)

            for token in tokens:
                if len(compact) < 4:
                    continue

                if abs(len(compact) - len(token)) > 2:
                    continue

                similarity = SequenceMatcher(
                    None, compact, token
                ).ratio()

                if similarity >= 0.82 and compact != token:
                    return {
                        "type": "brand_lookalike",
                        "brand": brand,
                        "reason": (
                            f"The hostname contains a label resembling "
                            f"{brand}. Verify the domain carefully."
                        ),
                    }

    return None


def analyze_url(url: str) -> dict:
    parsed = urlsplit(url)

    hostname = normalize_hostname(parsed.hostname or "")
    labels = hostname.split(".") if hostname else []

    reasons = []
    findings = []
    score = 0
    triggered = set()

    def flag(rule: str, reason: str, details=None):
        nonlocal score

        # Each rule contributes at most once.
        if rule in triggered:
            return

        triggered.add(rule)
        score += WEIGHTS[rule]
        reasons.append(reason)

        finding = {
            "rule": rule,
            "weight": WEIGHTS[rule],
            "reason": reason,
        }

        if details:
            finding.update(details)

        findings.append(finding)

    # 1. URL transport scheme
    if parsed.scheme.lower() != "https":
        flag("http", "The URL does not use HTTPS.")

    # 2. User information can hide the actual destination.
    if parsed.username is not None or parsed.password is not None:
        flag(
            "userinfo",
            "The URL contains user information before the hostname.",
        )

    # 3. IP address used directly as a hostname.
    try:
        ipaddress.ip_address(hostname)
        flag("ip_host", "The hostname is an IP address, not a domain.")
    except ValueError:
        pass

    # 4. Internationalized/punycode hostname.
    if any(label.startswith("xn--") for label in labels):
        flag("punycode", "The hostname contains a punycode label.")

    # 5. Brand impersonation and lookalike checks.
    brand_result = detect_brand_impersonation(hostname)

    if brand_result:
        flag(
            brand_result["type"],
            brand_result["reason"],
            {"brand": brand_result["brand"]},
        )

    # 6. Excessive subdomains.
    if hostname.count(".") >= 4:
        flag(
            "many_subdomains",
            "The hostname contains many subdomains.",
        )

    # 7. Long URL or hostname.
    if len(url) > 200:
        flag("long_url", "The URL is unusually long.")

    if len(hostname) > 60:
        flag("long_hostname", "The hostname is unusually long.")

    # 8. Multiple hyphens in hostname labels.
    if sum(label.count("-") for label in labels) >= 3:
        flag(
            "many_hyphens",
            "The hostname contains several hyphens.",
        )

    # 9. Percent-encoding: weak signal, not inherently malicious.
    if re.search(r"%[0-9a-fA-F]{2}", url):
        flag(
            "encoded_url",
            "The URL contains percent-encoded characters.",
        )

    decoded = unquote(url)

    if re.search(r"[\x00-\x1f\x7f]", decoded):
        flag(
            "control_chars",
            "The URL contains encoded or literal control characters.",
        )

    # 10. Phishing-related words, counted as one rule.
    searchable = (
        hostname + " " + parsed.path + " " + parsed.query
    ).lower()

    found_terms = sorted(
        term for term in SUSPICIOUS_TERMS
        if re.search(
            rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])",
            searchable,
        )
    )

    if found_terms:
        flag(
            "suspicious_terms",
            "Phishing-related terms detected: "
            + ", ".join(found_terms[:6])
            + ".",
            {"matched_terms": found_terms[:6]},
        )

    # 11. Known URL shorteners hide their final destination.
    if hostname in SHORTENERS:
        flag(
            "shortener",
            "The URL uses a known URL-shortening service.",
        )

    # 12. Nonstandard ports.
    try:
        port = parsed.port

        if port in UNUSUAL_PORTS:
            flag(
                "unusual_port",
                f"The URL uses a nonstandard port: {port}.",
            )
    except ValueError:
        # HttpUrl normally validates the port before this function.
        pass

    # 13. Selected TLD warning list.
    tld = labels[-1] if labels else ""

    if tld in SUSPICIOUS_TLDS:
        flag(
            "suspicious_tld",
            f"The domain uses the .{tld} top-level domain, "
            "which merits additional context checks.",
        )

    # Fixed score thresholds. These are heuristic categories.
    risk_score = min(score, 100)

    if risk_score >= 50:
        risk_level = "high"
        status = "caution"
        message = (
            "Multiple or strong warning indicators were found. "
            "Avoid entering sensitive information until verified."
        )
    elif risk_score >= 20:
        risk_level = "medium"
        status = "caution"
        message = (
            "Potential warning indicators were found. "
            "Verify the domain before proceeding."
        )
    else:
        risk_level = "low"
        status = "not_verified"
        message = (
            "Few warning indicators were found. "
            "This URL has not been verified as safe."
        )

    return {
        "hostname": hostname,
        "status": status,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "reasons": reasons,
        "findings": findings,
        "message": message,
        "detector": "url_guard_rules_v3",
    }


@app.get("/")
def home():
    return {
        "status": "online",
        "message": "URL Guard API is running",
        "version": "3.0.0",
        "detector": "url_guard_rules_v3",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/scan")
def scan_url(request: URLRequest):
    url = str(request.url)
    return {
        "url": url,
        **analyze_url(url),
    }
