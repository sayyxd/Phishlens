
import io
import json
import re
import ipaddress
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlsplit

from flask import Flask, render_template, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB

URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"']+""")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "shorturl.at", "rb.gy"
}

RISK_TERMS = {
    "urgent": 12,
    "immediately": 10,
    "verify your account": 18,
    "confirm your password": 20,
    "reset your password": 12,
    "account suspended": 18,
    "account will be closed": 18,
    "click here": 8,
    "wire transfer": 16,
    "payment overdue": 12,
    "gift card": 12,
    "confidential": 5,
    "login to avoid": 15,
    "unusual activity": 10,
}


def extract_domain(address):
    """Return a normalized email domain, or an empty string."""
    address = (address or "").strip()
    if "@" not in address:
        return ""
    domain = address.rsplit("@", 1)[1].strip().strip(">").lower()
    return domain.rstrip(".")


def get_email_address(value):
    return parseaddr(value or "")[1].strip().lower()


def analyze_email(raw_text):
    msg = BytesParser(policy=policy.default).parsebytes(
        raw_text.encode("utf-8", errors="replace")
    )

    sender = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    subject = str(msg.get("Subject", "(No subject)"))
    sender_email = get_email_address(sender)
    reply_email = get_email_address(reply_to)

    body_parts = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
            if isinstance(content, str):
                body_parts.append(content)
        except (LookupError, UnicodeError, ValueError):
            continue

    body = "\n".join(body_parts)
    # Strip markup for basic text checks; never render the original HTML.
    plain_body = re.sub(r"<[^>]*>", " ", body)
    plain_body = re.sub(r"\s+", " ", plain_body).strip()
    full_text = f"{subject}\n{plain_body}"
    lower_text = full_text.lower()

    findings = []
    score = 0

    def add_finding(title, detail, points, severity="medium"):
        nonlocal score
        findings.append({
            "title": title,
            "detail": detail,
            "points": points,
            "severity": severity,
        })
        score += points

    if not sender_email or not extract_domain(sender_email):
        add_finding(
            "Sender address unavailable",
            "The From field did not contain a clearly parsed email address.",
            8, "low"
        )

    if sender_email and reply_email:
        sender_domain = extract_domain(sender_email)
        reply_domain = extract_domain(reply_email)
        if sender_domain and reply_domain and sender_domain != reply_domain:
            add_finding(
                "From and Reply-To domains differ",
                f"From uses {sender_domain}; Reply-To uses {reply_domain}. "
                "This can be legitimate, but warrants verification.",
                20, "high"
            )

    # Check SPF, DKIM and DMARC only when results appear in the headers.
    auth_headers = " ".join(
        str(value) for name, value in msg.items()
        if name.lower() in ("authentication-results", "received-spf")
    ).lower()

    auth_checks = [
        ("SPF", r"\bspf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b"),
        ("DKIM", r"\bdkim\s*=\s*(pass|fail|neutral|none|temperror|permerror)\b"),
        ("DMARC", r"\bdmarc\s*=\s*(pass|fail|bestguesspass|none|temperror|permerror)\b"),
    ]

    auth_results = {}
    for name, pattern in auth_checks:
        match = re.search(pattern, auth_headers)
        result = match.group(1) if match else "not reported"
        auth_results[name] = result

        if result == "fail":
            add_finding(
                f"{name} authentication failed",
                f"The available authentication header reports {name}=fail.",
                18 if name == "DMARC" else 12,
                "high"
            )

    # Detect suspicious links without opening or resolving them.
    urls = []
    seen_urls = set()

    for match in URL_RE.finditer(plain_body):
        url = match.group(0).rstrip(".,;:!?)]}")
        if url.lower().startswith("www."):
            url = "http://" + url
        if url not in seen_urls:
            seen_urls.add(url)
            urls.append(url)

    url_results = []
    for url in urls[:50]:
        try:
            parsed = urlsplit(url)
            host = (parsed.hostname or "").lower().rstrip(".")
            reasons = []

            if not host:
                continue

            try:
                ipaddress.ip_address(host)
                reasons.append("Uses an IP address instead of a domain")
            except ValueError:
                pass

            if host.startswith("xn--") or ".xn--" in host:
                reasons.append("Contains an internationalized/punycode domain")

            if host in SHORTENERS:
                reasons.append("Uses a URL-shortening service")

            if parsed.username or parsed.password:
                reasons.append("Contains user information before the hostname")

            if len(host.split(".")) >= 5:
                reasons.append("Has an unusually deep subdomain structure")

            if parsed.scheme.lower() == "http":
                reasons.append("Uses unencrypted HTTP")

            # A hostname such as login-example.com is not proof of impersonation.
            suspicious = bool(reasons)
            url_results.append({
                "url": url,
                "host": host,
                "reasons": reasons,
                "suspicious": suspicious,
            })

            if suspicious:
                add_finding(
                    "Suspicious URL indicator",
                    f"{host}: " + "; ".join(reasons),
                    min(12, 5 + 2 * len(reasons)),
                    "high" if len(reasons) >= 2 else "medium"
                )

        except (ValueError, UnicodeError):
            continue

    # Flag social-engineering language; a keyword alone is not proof.
    for phrase, points in RISK_TERMS.items():
        if phrase in lower_text:
            add_finding(
                "Potential social-engineering language",
                f'The phrase "{phrase}" appears in the subject or email body.',
                points, "medium"
            )

    if not urls:
        findings.append({
            "title": "No plain-text URLs detected",
            "detail": "This does not rule out hidden HTML links or other threats.",
            "points": 0,
            "severity": "info",
        })

    # Keep the total score capped at 100.
    score = min(100, score)

    if score >= 60:
        verdict = "High risk"
        verdict_key = "high"
    elif score >= 30:
        verdict = "Suspicious"
        verdict_key = "medium"
    else:
        verdict = "Lower risk"
        verdict_key = "low"

    if not findings:
        findings.append({
            "title": "No configured indicators found",
            "detail": "The current rules did not identify known warning signs. "
                      "This does not prove the email is safe.",
            "points": 0,
            "severity": "info",
        })

    return {
        "sender": sender or "(Not provided)",
        "reply_to": reply_to or "(Not provided)",
        "subject": subject,
        "date": str(msg.get("Date", "(Not provided)")),
        "message_id": str(msg.get("Message-ID", "(Not provided)")),
        "body_preview": plain_body[:5000],
        "score": score,
        "verdict": verdict,
        "verdict_key": verdict_key,
        "findings": findings,
        "auth_results": auth_results,
        "urls": url_results,
        "url_count": len(urls),
        "disclaimer": (
            "This score is based on local heuristic rules, not a definitive "
            "classification. Verify findings independently."
        ),
    }


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", report=None, error=None)


@app.route("/analyze", methods=["POST"])
def analyze():
    pasted = request.form.get("email_text", "").strip()
    uploaded = request.files.get("email_file")
    raw_text = pasted

    if uploaded and uploaded.filename:
        if not uploaded.filename.lower().endswith(".eml"):
            return render_template(
                "index.html", report=None,
                error="Please upload an .eml email file."
            ), 400

        data = uploaded.read(1_048_577)
        if len(data) > 1_048_576:
            return render_template(
                "index.html", report=None,
                error="The email file exceeds the 1 MB limit."
            ), 413

        raw_text = data.decode("utf-8", errors="replace")

    if not raw_text:
        return render_template(
            "index.html", report=None,
            error="Paste an email or upload an .eml file."
        ), 400

    if len(raw_text) > 1_048_576:
        return render_template(
            "index.html", report=None,
            error="Email content exceeds the 1 MB limit."
        ), 413

    try:
        report = analyze_email(raw_text)
    except Exception:
        app.logger.exception("Email analysis failed")
        return render_template(
            "index.html", report=None,
            error="Unable to parse this email. Check the input and try again."
        ), 400

    return render_template("index.html", report=report, error=None)


@app.errorhandler(413)
def too_large(_error):
    return render_template(
        "index.html", report=None,
        error="Upload too large. The limit is 1 MB."
    ), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)
