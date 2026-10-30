"""PrivacyLens local scanner and protected-transmission server."""

from __future__ import annotations

import base64
import hmac
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Generator

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError:
    AESGCM = None
    InvalidTag = ValueError

try:
    from PIL import Image, ImageOps
except ImportError:
    Image = None
    ImageOps = None

try:
    import pytesseract
except ImportError:
    pytesseract = None


ROOT = Path(__file__).resolve().parent
MAX_TEXT_CHARS = 100_000
MAX_REQUEST_BYTES = 8_000_000
MAX_IMAGE_BYTES = 5_000_000
MAX_IMAGE_PIXELS = 20_000_000
AAD = b"PrivacyLens protected message v1"


def _compile_rules() -> list[tuple[re.Pattern[str], str, int, float]]:
    definitions = [
        (r"\b(?:aadhaar|aadhar|uidai)(?:\s+(?:card|number|no\.?|id))?\b\s*(?::|=|\bis\b)?\s*(?P<value>(?:\d[ \t.-]?){11}\d)(?!\d)", "Aadhaar number", 110, 0.99),
        (r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b", "PAN number", 105, 0.99),
        (r"\b(?:ifsc(?:\s+code)?|swift(?:\s+code)?|bic)\b\s*(?::|=|\bis\b)?\s*(?P<value>[A-Z]{4}0[A-Z0-9]{6}|[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b", "Banking code", 105, 0.99),
        (r"\b(?:upi\s+(?:id|address)|vpa)\b\s*(?::|=|\bis\b)?\s*(?P<value>[A-Z0-9._-]+@[A-Z0-9.-]+)\b", "Banking identifier", 100, 0.97),
        (r"\b[A-Z]{2}\d{2}(?:[ \t]?[A-Z0-9]){11,30}\b", "Bank account details", 100, 0.98),
        (r"\b(?:password|passwd|passcode|pin)\b\s*(?::|=|\bis\b)\s*(?P<value>[^\r\n,;]{2,})", "Authentication secret", 100, 0.99),
        (r"\b(?:cvv|cvc|security\s+code)\b\s*(?::|=|\bis\b)\s*(?P<value>\d{3,4})\b", "Payment credential", 100, 0.99),
        (r"\b(?:(?:credit|debit|atm|bank|prepaid|gift|store|charge|virtual|travel|fuel|forex|corporate|business|identity|id|student|employee|membership|loyalty|health|insurance|visa|mastercard|master\s+card|amex|american\s+express|discover|rupay|maestro|unionpay|jcb|diners\s+club)\s+)?card\s+(?:number|details|info|no\.?|code)\b\s*(?::|=|\bis\b)?\s*(?P<value>\d(?:[ \t.-]?\d){7,18})(?!\d)", "Payment card", 110, 0.98),
        (r"\b(?:bank\s+account(?:\s+(?:number|no\.?))?|account\s+number|routing\s+number|account\s+no\.?)\b\s*(?::|=|\bis\b)?\s*(?P<value>\d(?:[ \t.-]?\d){5,33})(?!\d)", "Bank account details", 100, 0.96),
        (r"\bbank\s+details\b\s*(?::|=|\bis\b)?\s*(?P<value>[^\r\n,;]{4,120})", "Bank account details", 95, 0.94),
        (r"\b[A-Z]{4}0[A-Z0-9]{6}\b", "Banking code", 90, 0.99),
        (r"(?<!\d)(?:\d[ \t.-]?){12,18}\d(?!\d)", "Payment card", 85, 0.95),
        (r"\b(?:api[_ -]?key|access[_ -]?token|auth(?:entication)?[_ -]?token|client[_ -]?secret|private[_ -]?key|bearer)\b\s*(?::|=|\bis\b)\s*(?P<value>[A-Za-z0-9/+=_.:-]{8,})", "API key or token", 100, 0.99),
        (r"\b(?:student\s+(?:id|number|roll)|roll\s+number|registration\s+(?:number|id)|employee\s+id|passport\s+(?:number|no\.?)|ssn|social\s+security\s+(?:number|no\.?))\b\s*(?::|=|\bis\b)\s*(?P<value>[A-Z0-9-]{4,24})", "Personal identifier", 95, 0.97),
        (r"\b(?:phone|mobile|telephone)\s+(?:number|no\.?)\b\s*(?::|=|\bis\b)?\s*(?P<value>\+?[\d(). -]{7,25})", "Phone number", 95, 0.95),
        (r"\b(?:full\s+name|student\s+name|customer(?:\s+name)?|name)\b\s*(?::|=)\s*(?P<value>[A-Za-z][A-Za-z'’-]*(?:[ \t]+[A-Za-z][A-Za-z'’-]*){0,3})", "Personal name", 90, 0.92),
        (r"\b(?:home\s+address|mailing\s+address|street\s+address|address)\b\s*(?::|=)\s*(?P<value>[^\r\n,;]{8,120})", "Home address", 90, 0.94),
        (r"\b(?:date\s+of\s+birth|birthdate|dob)\b\s*(?::|=|\bis\b)\s*(?P<value>\d{1,4}[/-]\d{1,2}[/-]\d{1,4})", "Date of birth", 95, 0.97),
        (r"\b(?:medical\s+record|health\s+record|diagnosis)\b\s*(?::|=)\s*(?P<value>[^\r\n,;]{3,100})", "Health information", 90, 0.93),
        (r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "Email address", 85, 0.99),
        (r"(?<![\w])(?:\+\d{1,3}|00\d{1,3})[ \t().-]*\d(?:[ \t().-]*\d){6,14}(?!\w)", "Phone number", 90, 0.96),
        (r"(?<!\w)(?:\+?1[ \t().-]?)?\(?[2-9]\d{2}\)?[ \t.-]?[2-9]\d{2}[ \t.-]?\d{4}(?!\w)", "Phone number", 75, 0.9),
        (r"(?<!\w)[6-9]\d{4}[ \t.-]?\d{5}(?!\w)", "Phone number", 75, 0.9),
        (r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)", "Personal identifier", 80, 0.97),
        (r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{30,}|xox[baprs]-[A-Za-z0-9-]{16,})\b", "API key or token", 85, 0.99),
    ]
    return [
        (re.compile(pattern, re.IGNORECASE), category, priority, confidence)
        for pattern, category, priority, confidence in definitions
    ]


RULES = _compile_rules()
SENSITIVE_WORDING = [
    (re.compile(r"\b(?:password|passwd|passcode|pin)\b", re.IGNORECASE), "Authentication secret"),
    (re.compile(r"\b(?:(?:credit|debit|atm|bank|prepaid|gift|store|charge|virtual|travel|fuel|forex|corporate|business|identity|id|student|employee|membership|loyalty|health|insurance|visa|mastercard|master\s+card|amex|american\s+express|discover|rupay|maestro|unionpay|jcb|diners\s+club)\s+card|card\s+(?:number|details|info|no\.?|code)|cvv|cvc)\b", re.IGNORECASE), "Payment card"),
    (re.compile(r"\b(?:bank\s+(?:account|details|information)|account\s+number|routing\s+number|iban)\b", re.IGNORECASE), "Bank account details"),
    (re.compile(r"\b(?:phone|mobile|telephone)\s+(?:number|details)\b", re.IGNORECASE), "Phone number"),
    (re.compile(r"\bemail\s+(?:address|details)\b", re.IGNORECASE), "Email address"),
    (re.compile(r"\b(?:home\s+address|mailing\s+address|street\s+address)\b", re.IGNORECASE), "Home address"),
    (re.compile(r"\b(?:student\s+(?:id|number|roll)|roll\s+number|registration\s+(?:number|id)|employee\s+id|passport\s+number|ssn|social\s+security\s+number)\b", re.IGNORECASE), "Personal identifier"),
    (re.compile(r"\b(?:api[_ -]?key|access[_ -]?token|auth(?:entication)?[_ -]?token|client[_ -]?secret|private[_ -]?key|bearer\s+token)\b", re.IGNORECASE), "API key or token"),
    (re.compile(r"\b(?:date\s+of\s+birth|birthdate|dob)\b", re.IGNORECASE), "Date of birth"),
    (re.compile(r"\b(?:medical\s+record|health\s+record|diagnosis)\b", re.IGNORECASE), "Health information"),
    (re.compile(r"\b(?:confidential|private\s+information|personal\s+information)\b", re.IGNORECASE), "Confidential information"),
]

AADHAAR_NUMBER_PATTERN = re.compile(r"(?<![\w])(?:\d[ \t.-]?){11}\d(?![\w])")
VERHOEFF_MULTIPLICATION = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
VERHOEFF_PERMUTATION = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
VERHOEFF_INVERSE = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def _passes_luhn(value: str) -> bool:
    digits = [int(character) for character in value if character.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _passes_verhoeff(value: str) -> bool:
    checksum = 0
    digits = [int(character) for character in value if character.isdigit()]
    for index, digit in enumerate(reversed(digits)):
        checksum = VERHOEFF_MULTIPLICATION[
            checksum
        ][VERHOEFF_PERMUTATION[(index + 1) % 8][digit]]
    return checksum == 0


def scan_text(text: str, field_name: str = "") -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []

    for pattern, category, priority, confidence in RULES:
        for match in pattern.finditer(text):
            if category == "Payment card" and priority < 100 and not _passes_luhn(match.group(0)):
                continue
            if category == "Phone number" and (match.group(0).startswith("+") or match.group(0).startswith("00")):
                digit_count = sum(character.isdigit() for character in match.group(0))
                if not 8 <= digit_count <= 15:
                    continue
            start, end = match.span("value") if "value" in match.re.groupindex else match.span()
            while start < end and text[start].isspace():
                start += 1
            while end > start and (text[end - 1].isspace() or text[end - 1] in "\"'"):
                end -= 1
            if start < end:
                candidates.append({
                    "start": start,
                    "end": end,
                    "category": category,
                    "priority": priority,
                    "confidence": confidence,
                })

    for match in AADHAAR_NUMBER_PATTERN.finditer(text):
        value = match.group(0)
        if value[0] in "01" or not _passes_verhoeff(value):
            continue
        candidates.append({
            "start": match.start(),
            "end": match.end(),
            "category": "Aadhaar number",
            "priority": 85,
            "confidence": 0.95,
        })

    for pattern, category in SENSITIVE_WORDING:
        for match in pattern.finditer(text):
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            if line_end < 0:
                line_end = len(text)
            has_value_match = any(
                candidate["category"] == category
                and candidate["start"] >= line_start
                and candidate["end"] <= line_end
                and candidate["priority"] > 10
                for candidate in candidates
            )
            if not has_value_match:
                candidates.append({
                    "start": match.start(),
                    "end": match.end(),
                    "category": category,
                    "priority": 10,
                    "confidence": 0.75,
                })

    contextual_categories = {
        "phone number": "Phone number",
        "student id": "Personal identifier",
        "employee id": "Personal identifier",
        "payment card": "Payment card",
        "bank account": "Bank account details",
        "medical record": "Health information",
    }
    if field_name in contextual_categories and not candidates and text.strip():
        start = len(text) - len(text.lstrip())
        end = len(text.rstrip())
        candidates.append({
            "start": start,
            "end": end,
            "category": contextual_categories[field_name],
            "priority": 70,
            "confidence": 0.75,
        })

    selected: list[dict[str, Any]] = []
    for candidate in sorted(
        candidates,
        key=lambda item: (-item["priority"], item["start"], -(item["end"] - item["start"])),
    ):
        if any(
            candidate["start"] < existing["end"]
            and candidate["end"] > existing["start"]
            for existing in selected
        ):
            continue
        selected.append(candidate)
    selected.sort(key=lambda item: item["start"])

    findings = [
        {
            "rule_id": re.sub(r"[^a-z0-9]+", "-", item["category"].lower()).strip("-"),
            "category": item["category"],
            "severity": "high" if item["priority"] >= 85 else "medium",
            "confidence": item["confidence"],
            "action": "Remove or protect before sharing.",
        }
        for item in selected
    ]

    segments: list[dict[str, Any]] = []
    cursor = 0
    for item in selected:
        if cursor < item["start"]:
            segments.append({"kind": "text", "text": text[cursor:item["start"]]})
        segments.append({
            "kind": "finding",
            "text": text[item["start"]:item["end"]],
            "finding": {
                "category": item["category"],
                "severity": "high" if item["priority"] >= 85 else "medium",
                "confidence": item["confidence"],
            },
        })
        cursor = item["end"]
    if cursor < len(text):
        segments.append({"kind": "text", "text": text[cursor:]})

    return {
        "state": "review_required" if findings else "no_matches_unverified",
        "message": "Sensitive information detected. Protect it before sending." if findings else "No configured sensitive patterns matched.",
        "findings": findings,
        "preview_segments": segments,
    }


def censor_text(text: str, segments: list[dict[str, Any]]) -> str:
    return "".join(
        "[REDACTED]" if segment["kind"] == "finding" else segment["text"]
        for segment in segments
    )


def public_scan_result(
    result: dict[str, Any],
    safe_content: str,
    record_id: str,
    source_kind: str,
    extracted_text: str | None = None,
) -> dict[str, Any]:
    preview_segments = [
        {
            **segment,
            "text": "[REDACTED]" if segment["kind"] == "finding" else segment["text"],
        }
        for segment in result["preview_segments"]
    ]
    response = {
        "state": result["state"],
        "message": result["message"],
        "findings": result["findings"],
        "preview_segments": preview_segments,
        "safe_content": safe_content,
        "record_id": record_id,
        "source_kind": source_kind,
        "encrypted_storage": True,
    }
    if extracted_text is not None:
        response["extracted_text"] = extracted_text
    return response


def encryption_key_from_environment() -> bytes:
    encoded = os.environ.get("PRIVACY_ENCRYPTION_KEY", "")
    if encoded:
        try:
            key = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise RuntimeError("Encryption configuration is invalid; transmission blocked.") from error
    else:
        key_path = Path(os.environ.get(
            "PRIVACY_ENCRYPTION_KEY_FILE",
            str(vault_path().with_suffix(".key")),
        ))
        key_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with key_path.open("xb") as key_file:
                key_file.write(secrets.token_bytes(32))
        except FileExistsError:
            pass
        key = key_path.read_bytes()
        if os.name != "nt":
            key_path.chmod(0o600)
    if len(key) != 32:
        raise RuntimeError("Encryption key must contain exactly 32 bytes.")
    if AESGCM is None:
        raise RuntimeError("AES-GCM support is unavailable; transmission blocked.")
    return key


def vault_path() -> Path:
    configured = os.environ.get("PRIVACY_VAULT_PATH", "").strip()
    if configured:
        return Path(configured)
    if os.name == "nt":
        data_root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        data_root = Path.home() / ".local" / "share"
    return data_root / "PrivacyLens" / "vault.sqlite3"


def encrypt_message(text: str, key: bytes) -> dict[str, str]:
    if AESGCM is None:
        raise RuntimeError("AES-GCM support is unavailable; transmission blocked.")
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(key).encrypt(nonce, text.encode("utf-8"), AAD)
    return {
        "algorithm": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(encrypted[:-16]).decode("ascii"),
        "tag": base64.b64encode(encrypted[-16:]).decode("ascii"),
    }


def _connect_vault() -> sqlite3.Connection:
    path = vault_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS protected_records (
            record_id TEXT PRIMARY KEY,
            created_at REAL NOT NULL,
            source_kind TEXT NOT NULL,
            original_mime TEXT NOT NULL,
            original_nonce BLOB NOT NULL,
            original_ciphertext BLOB NOT NULL,
            safe_content TEXT NOT NULL,
            categories TEXT NOT NULL,
            delivered_at REAL
        )
        """
    )
    return connection


@contextmanager
def _vault_connection() -> Generator[sqlite3.Connection, None, None]:
    connection = _connect_vault()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def store_protected_record(
    original: bytes,
    safe_content: str,
    categories: list[str],
    source_kind: str,
    original_mime: str,
) -> str:
    key = encryption_key_from_environment()
    record_id = secrets.token_urlsafe(24)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(
        nonce,
        original,
        AAD + b":" + record_id.encode("ascii"),
    )
    with _vault_connection() as connection:
        connection.execute(
            """
            INSERT INTO protected_records (
                record_id, created_at, source_kind, original_mime,
                original_nonce, original_ciphertext, safe_content, categories
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record_id,
                time.time(),
                source_kind,
                original_mime,
                nonce,
                ciphertext,
                safe_content,
                json.dumps(categories),
            ),
        )
    return record_id


def get_protected_record(record_id: str) -> sqlite3.Row | None:
    with _vault_connection() as connection:
        return connection.execute(
            "SELECT * FROM protected_records WHERE record_id = ?",
            (record_id,),
        ).fetchone()


def decrypt_record(record: sqlite3.Row) -> bytes:
    key = encryption_key_from_environment()
    return AESGCM(key).decrypt(
        record["original_nonce"],
        record["original_ciphertext"],
        AAD + b":" + record["record_id"].encode("ascii"),
    )


def extract_image_text(image_data: bytes) -> tuple[str, str]:
    if Image is None or ImageOps is None or pytesseract is None:
        raise RuntimeError("Local OCR is unavailable. Install Pillow, pytesseract, and the Tesseract OCR engine.")
    configured_engine = os.environ.get("TESSERACT_CMD", "").strip()
    if configured_engine:
        pytesseract.pytesseract.tesseract_cmd = configured_engine
    elif os.name == "nt" and shutil.which("tesseract") is None:
        common_engine_path = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Tesseract-OCR" / "tesseract.exe"
        if common_engine_path.is_file():
            pytesseract.pytesseract.tesseract_cmd = str(common_engine_path)
    if not image_data or len(image_data) > MAX_IMAGE_BYTES:
        raise ValueError("Image is empty or exceeds the 5 MB limit.")

    try:
        with Image.open(io.BytesIO(image_data)) as image:
            if image.format not in {"PNG", "JPEG", "WEBP"}:
                raise ValueError("Use a PNG, JPEG, or WEBP image.")
            if image.width * image.height > MAX_IMAGE_PIXELS:
                raise ValueError("Image dimensions exceed the local OCR limit.")
            image_mime = {
                "PNG": "image/png",
                "JPEG": "image/jpeg",
                "WEBP": "image/webp",
            }[image.format]
            image.load()
            normalized = ImageOps.exif_transpose(image).convert("RGB")
            text = pytesseract.image_to_string(normalized, timeout=20)
    except pytesseract.TesseractNotFoundError as error:
        raise RuntimeError("Tesseract OCR engine is not installed or not on PATH; the image was not sent.") from error
    except ValueError:
        raise
    except (OSError, RuntimeError, Image.DecompressionBombError) as error:
        raise RuntimeError("Local OCR failed; the image was not sent.") from error

    if not text.strip():
        raise RuntimeError("OCR could not read text from this image; it was not sent.")
    if len(text) > MAX_TEXT_CHARS:
        raise ValueError("OCR text exceeds the scanner limit.")
    return text, image_mime


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request: Any, file_pointer: Any, code: int, message: str, headers: Any, new_url: str) -> None:
        return None


def configured_destination() -> str:
    destination = os.environ.get("DESTINATION_URL", "").strip()
    parsed = urllib.parse.urlsplit(destination)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise RuntimeError("A valid HTTPS destination is not configured; transmission blocked.")
    return destination


def forward_protected_payload(content: str, categories: list[str]) -> None:
    destination = configured_destination()
    body = json.dumps({
        "type": "privacy-lens.cleaned-content.v1",
        "mode": "redacted",
        "categories": categories,
        "content": content,
    }, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    bearer_token = os.environ.get("DESTINATION_BEARER_TOKEN", "")
    if bearer_token:
        headers["Authorization"] = "Bearer " + bearer_token
    request = urllib.request.Request(destination, data=body, headers=headers, method="POST")
    opener = urllib.request.build_opener(NoRedirectHandler())
    try:
        with opener.open(request, timeout=12) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError("Destination rejected the protected message.")
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"Destination rejected the protected message (HTTP {error.code}).") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise RuntimeError("Destination unavailable. Protected transmission did not complete.") from error


def secure_send(record_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,}", record_id):
        raise ValueError("Protected record identifier is invalid.")
    record = get_protected_record(record_id)
    if record is None:
        raise ValueError("Protected record was not found.")

    try:
        original = decrypt_record(record)
    except (InvalidTag, RuntimeError, ValueError) as error:
        raise RuntimeError("Encrypted staging could not be verified; transmission blocked.") from error

    if record["source_kind"] == "text":
        try:
            source_text = original.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RuntimeError("Encrypted text could not be verified; transmission blocked.") from error
    elif record["source_kind"] == "image":
        source_text, _ = extract_image_text(original)
    else:
        raise RuntimeError("Protected record type is invalid; transmission blocked.")

    result = scan_text(source_text)
    safe_content = censor_text(source_text, result["preview_segments"])
    categories = sorted({finding["category"] for finding in result["findings"]})
    forward_protected_payload(safe_content, categories)
    with _vault_connection() as connection:
        connection.execute(
            "UPDATE protected_records SET safe_content = ?, delivered_at = ? WHERE record_id = ?",
            (safe_content, time.time(), record_id),
        )
    return {
        "success": True,
        "mode": "redacted",
        "encrypted_storage": True,
        "finding_count": len(categories),
        "categories": categories,
        "record_id": record_id,
    }


def verify_local_encryption(record_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,}", record_id):
        raise ValueError("Protected record identifier is invalid.")
    record = get_protected_record(record_id)
    if record is None:
        raise ValueError("Protected record was not found.")

    try:
        decrypt_record(record)
    except (InvalidTag, RuntimeError, ValueError) as error:
        raise RuntimeError("Encrypted staging could not be verified.") from error

    try:
        categories = json.loads(record["categories"])
    except (TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("Encrypted record metadata could not be verified.") from error
    if not isinstance(categories, list) or not all(isinstance(item, str) for item in categories):
        raise RuntimeError("Encrypted record metadata could not be verified.")

    return {
        "success": True,
        "mode": "local-encrypted",
        "encrypted_storage": True,
        "finding_count": len(categories),
        "categories": categories,
        "record_id": record_id,
    }


def _configured_origins() -> set[str]:
    origins = {
        value.strip().rstrip("/")
        for value in os.environ.get("PRIVACY_ALLOWED_ORIGINS", "").split(",")
        if value.strip()
    }
    origins.update({
        f"http://{host}:{port}"
        for host in ("127.0.0.1", "localhost")
        for port in range(5500, 5600)
    })
    return origins


def recipient_is_authorized(authorization: str) -> bool:
    expected = os.environ.get("PRIVACY_RECIPIENT_TOKEN", "")
    if len(expected) < 32 or not authorization.startswith("Bearer "):
        return False
    supplied = authorization[7:]
    return hmac.compare_digest(supplied, expected)


class PrivacyLensHandler(SimpleHTTPRequestHandler):
    server_version = "PrivacyLens"
    sys_version = ""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, format_string: str, *args: Any) -> None:
        return

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        if self.path.startswith("/api/"):
            self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/api/health":
            self._send_json(200, {"status": "ok"})
            return
        record_match = re.fullmatch(r"/api/records/([A-Za-z0-9_-]{20,})/original", path)
        if record_match:
            if not self._origin_is_allowed():
                self._send_json(403, {"message": "Request origin is not allowed."})
                return
            if not recipient_is_authorized(self.headers.get("Authorization", "")):
                self._send_json(401, {"message": "Authorized recipient access is required."})
                return
            try:
                record = get_protected_record(record_match.group(1))
                if record is None:
                    self._send_json(404, {"message": "Protected record was not found."})
                    return
                original = decrypt_record(record)
                response: dict[str, Any] = {
                    "record_id": record["record_id"],
                    "source_kind": record["source_kind"],
                    "original_mime": record["original_mime"],
                }
                if record["source_kind"] == "image":
                    response["original_base64"] = base64.b64encode(original).decode("ascii")
                else:
                    response["original_text"] = original.decode("utf-8")
                self._send_json(200, response)
            except (sqlite3.Error, UnicodeDecodeError, RuntimeError, ValueError, InvalidTag):
                self._send_json(503, {"message": "The protected record could not be decrypted."})
            return
        super().do_GET()

    def _origin_is_allowed(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        if origin == "null":
            return self.path.split("?", 1)[0] in {
                "/api/scan",
                "/api/scan-image",
                "/api/local-seal",
            }
        parsed = urllib.parse.urlsplit(origin)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path:
            return False
        host = self.headers.get("Host", "").lower()
        is_local_origin = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        local_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        is_common_dev_port = (
            local_port in {3000, 4173, 4200, 5173, 8000, 8080, 8888}
            or 5500 <= local_port <= 5599
        )
        return (
            origin.rstrip("/") in _configured_origins()
            or parsed.netloc.lower() == host
            or (is_local_origin and is_common_dev_port)
        )

    def _cors_headers(self) -> None:
        origin = self.headers.get("Origin", "").rstrip("/")
        if origin and self._origin_is_allowed():
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            if self.headers.get("Access-Control-Request-Private-Network", "").lower() == "true":
                self.send_header("Access-Control-Allow-Private-Network", "true")

    def _send_json(self, status: int, value: dict[str, Any]) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._cors_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        if not self._origin_is_allowed():
            self._send_json(403, {"message": "Request origin is not allowed."})
            return
        self.send_response(204)
        self._cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:
        if not self._origin_is_allowed():
            self._send_json(403, {"message": "Request origin is not allowed."})
            return
        path = self.path.split("?", 1)[0]
        if path not in {"/api/scan", "/api/scan-image", "/api/local-seal", "/api/secure-send"}:
            self._send_json(404, {"message": "API endpoint not found."})
            return
        if self.headers.get_content_type() != "application/json":
            self._send_json(415, {"message": "Send a JSON request."})
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"message": "Request length is invalid."})
            return
        if content_length <= 0 or content_length > MAX_REQUEST_BYTES:
            self._send_json(413, {"message": "Request is empty or exceeds the size limit."})
            return

        try:
            payload = json.loads(self.rfile.read(content_length))
            if not isinstance(payload, dict):
                raise ValueError("Request body must be an object.")
            if path == "/api/scan":
                if not isinstance(payload.get("text"), str):
                    raise ValueError("Request must include text.")
                text = payload["text"]
                if not text.strip():
                    raise ValueError("Enter information before scanning.")
                if len(text) > MAX_TEXT_CHARS:
                    raise ValueError("Text exceeds the scanner limit.")
                field_name = payload.get("field_name", "")
                if not isinstance(field_name, str):
                    raise ValueError("Field type must be text.")
                result = scan_text(text, field_name)
                safe_content = censor_text(text, result["preview_segments"])
                categories = sorted({finding["category"] for finding in result["findings"]})
                record_id = store_protected_record(
                    text.encode("utf-8"),
                    safe_content,
                    categories,
                    "text",
                    "text/plain; charset=utf-8",
                )
                self._send_json(200, public_scan_result(result, safe_content, record_id, "text"))
                return

            if path == "/api/local-seal":
                record_id = payload.get("record_id", "")
                if not isinstance(record_id, str):
                    raise ValueError("Protected record identifier is invalid.")
                self._send_json(200, verify_local_encryption(record_id))
                return

            if path == "/api/scan-image":
                encoded_image = payload.get("image")
                if not isinstance(encoded_image, str):
                    raise ValueError("Request must include an image.")
                try:
                    image_data = base64.b64decode(encoded_image, validate=True)
                except (ValueError, base64.binascii.Error) as error:
                    raise ValueError("Image data is invalid.") from error
                if len(image_data) > MAX_IMAGE_BYTES:
                    raise ValueError("Image exceeds the 5 MB limit.")
                field_name = payload.get("field_name", "")
                if not isinstance(field_name, str):
                    raise ValueError("Field type must be text.")
                text, image_mime = extract_image_text(image_data)
                result = scan_text(text, field_name)
                safe_content = censor_text(text, result["preview_segments"])
                categories = sorted({finding["category"] for finding in result["findings"]})
                record_id = store_protected_record(
                    image_data,
                    safe_content,
                    categories,
                    "image",
                    image_mime,
                )
                self._send_json(
                    200,
                    public_scan_result(
                        result,
                        safe_content,
                        record_id,
                        "image",
                        extracted_text=text,
                    ),
                )
                return

            record_id = payload.get("record_id", "")
            if not isinstance(record_id, str):
                raise ValueError("Protected record identifier is invalid.")
            self._send_json(200, secure_send(record_id))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"message": "Request JSON is invalid."})
        except ValueError as error:
            self._send_json(400, {"message": str(error)})
        except RuntimeError as error:
            self._send_json(503, {"message": str(error)})
        except sqlite3.Error:
            self._send_json(503, {"message": "Encrypted local storage failed; nothing was sent."})


def main() -> None:
    host = os.environ.get("PRIVACY_HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "localhost"}:
        raise RuntimeError("PrivacyLens must bind to loopback; deploy behind an authenticated HTTPS gateway to expose it.")
    port = int(os.environ.get("PRIVACY_PORT", "8000"))
    server = ThreadingHTTPServer((host, port), PrivacyLensHandler)
    server.daemon_threads = True
    print(f"PrivacyLens is available at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
