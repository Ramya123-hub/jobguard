
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.responses import FileResponse
import re

app = FastAPI()


# Job description input
class JobInput(BaseModel):
    description: str


# Home page
@app.get("/")
def home():
    return {
        "project": "JobGuard",
        "message": "Fake Internship & Job Alert Checker",
        "status": "Backend running successfully"
    }


# Fake internship and job detection
@app.post("/check-job")
def check_job(job: JobInput):

    description = job.description.lower()

    # Scam warning detection rules
    rules = [
        {
            "name": "Upfront Payment Request",
            "patterns": [
                r"registration fee",
                r"security deposit",
                r"pay to apply",
                r"pay\s*(?:rs\.?|₹|inr)\s*\d+",
                r"(?:rs\.?|₹|inr)\s*\d+\s*(?:fee|deposit)"
            ],
            "points": 40,
            "explanation":
                "The offer requests payment. Verify the employer independently before paying."
        },
        {
            "name": "Guaranteed Selection",
            "patterns": [
                r"guaranteed job",
                r"guaranteed placement",
                r"100%\s*selection",
                r"instant selection"
            ],
            "points": 25,
            "explanation":
                "Guaranteed selection claims may be misleading."
        },
        {
            "name": "No Interview",
            "patterns": [
                r"no interview",
                r"without interview",
                r"direct selection"
            ],
            "points": 20,
            "explanation":
                "Selection without an interview may require additional verification."
        },
        {
            "name": "Urgency Pressure",
            "patterns": [
                r"limited slots",
                r"apply immediately",
                r"offer expires today",
                r"last chance"
            ],
            "points": 15,
            "explanation":
                "Urgency can pressure applicants into making quick decisions."
        },
        {
            "name": "Unusual Contact Method",
            "patterns": [
                r"whatsapp only",
                r"telegram only",
                r"contact only on whatsapp"
            ],
            "points": 20,
            "explanation":
                "Verify that the contact belongs to the official employer."
        }
    ]

    score = 0
    warnings = []
    explanations = []

    # Analyze the job description
    for rule in rules:

        matched = any(
            re.search(pattern, description)
            for pattern in rule["patterns"]
        )

        if matched:
            score += rule["points"]

            warnings.append(rule["name"])

            explanations.append({
                "warning": rule["name"],
                "reason": rule["explanation"]
            })

    # Maximum risk score is 100
    score = min(score, 100)

    # Determine risk level
    if score >= 60:
        risk = "High"
    elif score >= 25:
        risk = "Medium"
    else:
        risk = "Low"

    # Return analysis results
    return {
        "risk_level": risk,
        "risk_score": score,
        "warnings": warnings,
        "explanations": explanations,
        "message":
            "This score indicates detected warning signs, not a verified fraud probability."
    }


# Display JobGuard website
@app.get("/app")
def show_website():
    return FileResponse("index.html")

# --------------------------------------
# Recruiter Email Warning Sign Checker
# --------------------------------------

class EmailInput(BaseModel):
    email: str


@app.post("/check-email")
def check_email(data: EmailInput):
    email = data.email.strip().lower()

    warnings = []
    explanations = []
    score = 0

    # Basic email format validation
    email_pattern = r"^[a-z0-9._%+\-]+@[a-z0-9\-]+(?:\.[a-z0-9\-]+)+$"

    if not re.fullmatch(email_pattern, email):
        return {
            "risk_level": "Invalid",
            "risk_score": 0,
            "warnings": ["Invalid Email Format"],
            "explanations": [
                {
                    "warning": "Invalid Email Format",
                    "reason": "Enter a valid email address before checking it."
                }
            ],
            "message": "The email format is invalid."
        }

    domain = email.split("@")[1]

    free_providers = {
        "gmail.com",
        "yahoo.com",
        "outlook.com",
        "hotmail.com",
        "rediffmail.com",
        "proton.me"
    }

    # Rule 1: Free email provider
    if domain in free_providers:
        score += 25
        warnings.append("Free Email Provider")

        explanations.append({
            "warning": "Free Email Provider",
            "reason":
                "The recruiter is using a public email service. "
                "This is not proof of fraud, but verify their "
                "identity through the company's official website."
        })

    # Rule 2: Suspicious words in domain
    suspicious_terms = [
        "job-offer",
        "instant-hiring",
        "guaranteed-job",
        "pay-to-apply"
    ]

    if any(term in domain for term in suspicious_terms):
        score += 30
        warnings.append("Suspicious Domain Wording")

        explanations.append({
            "warning": "Suspicious Domain Wording",
            "reason":
                "The domain contains recruitment-related wording "
                "sometimes associated with misleading offers."
        })

    # Rule 3: Numeric character substitution
    substitutions = {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s"
    }

    normalized_domain = domain

    for number, letter in substitutions.items():
        normalized_domain = normalized_domain.replace(
            number, letter
        )

    if normalized_domain != domain:
        score += 20
        warnings.append("Possible Lookalike Domain")

        explanations.append({
            "warning": "Possible Lookalike Domain",
            "reason":
                "The domain contains digits that could imitate "
                "letters. This is only a heuristic warning; "
                "some legitimate domains also contain numbers."
        })

    score = min(score, 100)

    if score >= 60:
        risk = "High"
    elif score >= 25:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "risk_level": risk,
        "risk_score": score,
        "warnings": warnings,
        "explanations": explanations,
        "message":
            "This checks email warning signs only. "
            "It does not confirm who owns the address "
            "or whether the recruiter is genuine."
    }

from urllib.parse import urlsplit
import ipaddress
from pydantic import BaseModel


class JobURLInput(BaseModel):
    url: str


@app.post("/check-url")
def check_job_url(data: JobURLInput):
    url = data.url.strip()
    score = 0
    explanations = []

    def add_warning(warning, reason, points):
        nonlocal score
        score += points
        explanations.append({
            "warning": warning,
            "reason": reason
        })

    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("Invalid scheme")

        hostname = parsed.hostname

        if not hostname:
            raise ValueError("Missing hostname")

        hostname = hostname.lower()

        # Validate the port if one is supplied.
        _ = parsed.port

        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        if not is_ip and (
            "." not in hostname
            or " " in hostname
            or hostname.startswith(".")
            or hostname.endswith(".")
        ):
            raise ValueError("Invalid hostname")

    except ValueError:
        return {
            "risk_level": "Invalid",
            "risk_score": 0,
            "warnings": ["Invalid URL"],
            "explanations": [{
                "warning": "Invalid URL",
                "reason": "Enter a complete URL beginning with https:// or http://."
            }],
            "message": "Please enter a valid website URL."
        }

    if parsed.scheme.lower() == "http":
        add_warning(
            "No HTTPS",
            "This link does not use HTTPS.",
            20
        )

    if is_ip:
        add_warning(
            "IP Address Domain",
            "The link uses an IP address instead of a company domain.",
            30
        )

    shorteners = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly"
    }

    if hostname in shorteners:
        add_warning(
            "Shortened URL",
            "This link hides its final destination.",
            25
        )

    suspicious_words = [
        "guaranteed-job",
        "instant-hiring",
        "registration-fee",
        "pay-to-apply",
        "job-offer"
    ]

    if any(word in url.lower() for word in suspicious_words):
        add_warning(
            "Suspicious URL Wording",
            "The link contains recruitment-related wording that deserves verification.",
            20
        )

    score = min(score, 100)

    if score >= 60:
        risk = "High"
    elif score >= 25:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "risk_level": risk,
        "risk_score": score,
        "warnings": [
            item["warning"] for item in explanations
        ],
        "explanations": explanations,
        "message": (
            "This is a rule-based URL check. "
            "It does not visit the website or verify that it is safe."
        )
    }




