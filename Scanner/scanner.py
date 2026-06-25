import html
import re
from email import policy
from email.message import Message
from email.parser import BytesParser, Parser
from typing import Dict, Iterable, List

from Recognizers.in_aadhaar_recognizer import InAadhaarRecognizer
from Recognizers.in_bank_account_recognizer import InBankAccountRecognizer
from Recognizers.in_driving_license_recognizer import InDrivingLicenseRecognizer
from Recognizers.in_gstin_recognizer import InGstinRecognizer
from Recognizers.in_ifsc_recognizer import InIfscRecognizer
from Recognizers.in_micr_recognizer import InMicrRecognizer
from Recognizers.in_name_recognizer import InNameRecognizer
from Recognizers.in_pan_recognizer import InPanRecognizer
from Recognizers.in_passport_recognizer import InPassportRecognizer
from Recognizers.in_payment_card_recognizer import InPaymentCardRecognizer
from Recognizers.in_upi_recognizer import InUpiRecognizer
from Recognizers.in_vehicle_registration_recognizer import InVehicleRegistrationRecognizer
from Recognizers.in_voter_recognizer import InVoterRecognizer


# Active recognizers. Legacy credit/debit card files are intentionally absent;
# payment cards are detected once and classified by subtype afterward.
RECOGNIZERS = [
    InAadhaarRecognizer(),
    InNameRecognizer(),
    InPanRecognizer(),
    InGstinRecognizer(),
    InIfscRecognizer(),
    InMicrRecognizer(),
    InBankAccountRecognizer(),
    InPaymentCardRecognizer(),
    InDrivingLicenseRecognizer(),
    InPassportRecognizer(),
    InVoterRecognizer(),
    InUpiRecognizer(),
    InVehicleRegistrationRecognizer(),
]

# Base sensitivity points applied before context and confidence bonuses.
RISK_WEIGHTS = {
    "IN_AADHAAR": 35,
    "PERSON_NAME": 10,
    "IN_PAN": 30,
    "IN_GSTIN": 25,
    "IN_IFSC": 15,
    "IN_MICR": 10,
    "IN_BANK_ACCOUNT": 25,
    "PAYMENT_CARD": 35,
    "IN_DRIVING_LICENSE": 25,
    "IN_PASSPORT": 25,
    "IN_VOTER": 20,
    "IN_UPI": 20,
    "IN_VEHICLE_REGISTRATION": 10,
}

RISK_LEVELS = (
    (75, "critical", "block_or_escalate"),
    (50, "high", "escalate_for_review"),
    (25, "medium", "review"),
    (1, "low", "monitor"),
    (0, "none", "allow"),
)

# Scanner-level gates are kept for entities whose broad shape needs stronger
# field or section evidence than regex validation alone can provide.
BANK_ACCOUNT_CONTEXT = (
    "account number",
    "account no",
    "account details",
    "acct",
    "acct no",
    "bank account",
    "bank account number",
    "bank details",
    "beneficiary account",
    "beneficiary account number",
    "beneficiary details",
    "payee account",
    "salary account",
    "savings account",
    "current account",
    "wire transfer",
    "bank transfer",
    "neft",
    "rtgs",
    "imps",
)

AADHAAR_CONTEXT = (
    "aadhaar",
    "aadhar",
    "aadhaar number",
    "aadhar number",
    "aadhaar no",
    "aadhar no",
    "uidai",
    "uid number",
)

PAN_CONTEXT = (
    "permanent account number",
    "pan",
    "pan card",
    "pan number",
    "pan no",
    "pan details",
    "income tax pan",
    "income tax",
    "form 16",
    "itr",
    "gst",
    "gstin",
    "gst number",
    "gst registration",
    "gst registration number",
    "goods and services tax",
    "tax invoice",
    "vendor gst",
    "supplier gst",
)

MICR_CONTEXT = (
    "micr",
    "micr code",
    "micr number",
    "micr details",
    "cheque",
    "cheque number",
    "cheque leaf",
    "check",
    "bank",
    "bank branch",
    "branch code",
    "branch micr",
    "bank details",
    "routing",
    "clearing",
    "ecs",
)

PASSPORT_CONTEXT = (
    "passport",
    "indian passport",
    "passport number",
    "passport no",
    "passport id",
    "passport details",
    "passport copy",
    "passport document",
    "machine readable zone",
    "mrz",
    "p<ind",
    "travel document",
    "travel id",
    "visa application",
    "immigration",
    "identity proof",
    "id proof",
    "kyc",
    "visa",
)

DRIVING_LICENSE_CONTEXT = (
    "driving licence",
    "driving license",
    "driver licence",
    "driver license",
    "driving licence number",
    "driving license number",
    "driving licence no",
    "driving license no",
    "driver licence number",
    "driver license number",
    "dl number",
    "dl no",
    "dl details",
    "licence copy",
    "license copy",
    "driving permit",
    "transport licence",
    "transport license",
    "sarathi",
    "parivahan",
)

UPI_CONTEXT = (
    "upi",
    "upi id",
    "upi number",
    "upi details",
    "upi handle",
    "upi address",
    "vpa",
    "virtual payment address",
    "pay via upi",
)

EMAIL_FIELD_CONTEXT = (
    "email",
    "email address",
    "email id",
    "mail",
    "mail address",
    "mail id",
    "contact email",
    "registered email",
)


def extract_email_body(raw_email: bytes | str) -> str:
    """Extract only the body from .eml/raw email input."""
    if isinstance(raw_email, bytes):
        try:
            message = BytesParser(policy=policy.default).parsebytes(raw_email)
        except Exception:
            return raw_email.decode("utf-8", errors="replace")
    else:
        if not _looks_like_email(raw_email):
            return raw_email
        try:
            message = Parser(policy=policy.default).parsestr(raw_email)
        except Exception:
            return raw_email

    body = _message_body(message)
    return body if body.strip() else _message_payload_fallback(message)


def scan_email_body(body: str) -> Dict:
    """Scan body text using recognizer classes from the Recognizers folder."""
    return scan_text_content(body)


def scan_text_content(content: str) -> Dict:
    """
    Run every recognizer from Recognizers/ and return JSON-ready findings.

    This intentionally does not use the old duplicate scanner.py regex list.
    Patterns, context words, entity names, and validation now come from the
    recognizer classes themselves.
    """
    content = content or ""
    findings = []
    seen = set()

    # Recognizers own regex, entity names, context words, and value validation.
    for recognizer in RECOGNIZERS:
        entity_type = recognizer.supported_entity
        for pattern in recognizer.patterns:
            compiled = re.compile(pattern.regex, re.IGNORECASE)
            for match in compiled.finditer(content):
                if "value" in match.groupdict():
                    # Named groups let a pattern include a label/MRZ while the
                    # finding contains only the sensitive value.
                    raw_value = match.group("value")
                    group_start = match.start("value")
                else:
                    raw_value = match.group(0)
                    group_start = match.start()
                value = raw_value.strip()
                leading_trim = len(raw_value) - len(raw_value.lstrip())
                start = group_start + leading_trim
                end = start + len(value)
                context_hits = _context_hits(
                    content, start, end, recognizer.context
                )
                # Table headers act as field labels even when they sit outside
                # the normal 80-character context window.
                if (
                    entity_type == "IN_BANK_ACCOUNT"
                    and _has_account_table_context(content, start)
                    and "account column" not in context_hits
                ):
                    context_hits.append("account column")
                if (
                    entity_type == "IN_PAN"
                    and _has_pan_table_context(content, start)
                    and "pan column" not in context_hits
                ):
                    context_hits.append("pan column")
                if (
                    entity_type == "IN_UPI"
                    and _has_upi_table_context(content, start)
                    and "upi column" not in context_hits
                ):
                    context_hits.append("upi column")

                if not _is_valid_recognizer_match(recognizer, value, match):
                    continue
                # Suppression resolves cross-entity collisions and mandatory
                # context policies after the recognizer validates the value.
                if _should_suppress_match(entity_type, value, content, start, end):
                    continue

                score = min(1.0, pattern.score + (0.25 if context_hits else 0.0))
                risk = _finding_risk(
                    entity_type,
                    score,
                    context_hits,
                )
                key = (entity_type, start, end, value)
                # Multiple patterns may match the same span; emit it only once.
                if key in seen:
                    continue
                seen.add(key)
                finding = {
                    "rule_type": "recognizer",
                    "entity_type": entity_type,
                    "recognizer": recognizer.__class__.__name__,
                    "pattern_name": pattern.name,
                    "text": value,
                    "start": start,
                    "end": end,
                    "score": round(score, 2),
                    "risk_weight": risk["base_points"],
                    "risk_points": risk["total_points"],
                    "risk_components": risk,
                    "context": context_hits,
                }
                if entity_type == "PAYMENT_CARD":
                    finding["card_subtype"] = _payment_card_subtype(
                        content, start, end
                    )
                findings.append(finding)

    # Prefer the complete Luhn-valid card over a checksum-valid 12-digit prefix.
    findings = _remove_contained_aadhaar_card_collisions(findings)
    findings.sort(key=lambda item: (item["start"], item["end"], item["entity_type"]))
    risk = _calculate_risk(findings)
    return {
        "content_length": len(content),
        "findings_count": len(findings),
        "risk_score": risk,
        "final_decision": risk["decision"],
        "recognizer_source": "Recognizers/",
        "findings": findings,
        "regex_matches": findings,
        "regex_matches_count": len(findings),
        "keyword_matches": [],
        "keyword_matches_count": 0,
    }


def _is_valid_recognizer_match(recognizer, value: str, match=None) -> bool:
    """Use match-aware validation when a recognizer needs adjacent fields."""
    if match is not None and hasattr(recognizer, "validate_match"):
        return bool(recognizer.validate_match(match))
    try:
        return bool(recognizer.validate_result(value))
    except AttributeError:
        return True


def _should_suppress_match(
    entity_type: str, value: str, content: str, start: int, end: int
) -> bool:
    """
    Enforce mandatory context and resolve collisions between broad entities.

    Recognizers answer "does the value have a valid shape?" This function
    answers "does this location provide enough evidence for that entity?"
    """
    if entity_type == "IN_MICR":
        return not _has_context(content, start, end, MICR_CONTEXT)
    if entity_type == "IN_PASSPORT":
        return not _has_context(content, start, end, PASSPORT_CONTEXT)
    if entity_type == "IN_DRIVING_LICENSE":
        return not _has_context(content, start, end, DRIVING_LICENSE_CONTEXT)
    if entity_type == "IN_AADHAAR":
        return not _has_context(content, start, end, AADHAAR_CONTEXT)
    if entity_type == "IN_UPI":
        if _has_same_line_context(content, start, EMAIL_FIELD_CONTEXT):
            return True
        if _has_email_table_context(content, start):
            return True
        return not (
            _has_context(content, start, end, UPI_CONTEXT)
            or _has_same_line_context(content, start, UPI_CONTEXT)
            or _has_upi_table_context(content, start)
        )
    if entity_type == "IN_PAN":
        has_pan_context = _has_context(content, start, end, PAN_CONTEXT)
        has_same_line_context = _has_same_line_context(
            content, start, PAN_CONTEXT
        )
        has_table_context = _has_pan_table_context(content, start)
        if not (
            has_pan_context
            or has_same_line_context
            or has_table_context
        ):
            return True
        return _is_embedded_in_gstin(content, start, end)
    if entity_type == "PAYMENT_CARD":
        if not _has_context(
            content,
            start,
            end,
            InPaymentCardRecognizer.CONTEXT,
        ):
            return True
        # A directly labelled account number remains an account even when its
        # digits happen to pass Luhn.
        return _has_same_line_context(
            content,
            start,
            (
                "account",
                "account number",
                "bank account",
                "beneficiary account",
                "salary account",
            ),
        ) and not _has_same_line_context(
            content,
            start,
            InPaymentCardRecognizer.CONTEXT,
        )
    if entity_type == "IN_BANK_ACCOUNT":
        has_direct_label = _has_same_line_context(
            content,
            start,
            (
                "account",
                "account number",
                "account no",
                "bank account",
                "beneficiary account",
                "payee account",
                "salary account",
                "acct no",
            ),
        )
        has_table_context = _has_account_table_context(content, start)
        has_bank_context = _has_context(
            content, start, end, BANK_ACCOUNT_CONTEXT
        )

        if not (has_direct_label or has_table_context or has_bank_context):
            return True
        if _is_part_of_upi(content, start, end):
            return True
        # An Aadhaar-labelled 12-digit value must not fall back to a bank
        # account finding unless the number has direct account evidence.
        if len(_digits(value)) == 12 and _has_context(
            content, start, end, AADHAAR_CONTEXT
        ) and not (has_direct_label or has_table_context):
            return True
        if len(_digits(value)) == 9 and _has_context(content, start, end, ("micr", "micr code")):
            return True
        # A Luhn-valid value near card fields is a card unless the same line or
        # table column explicitly identifies it as a bank account.
        if (
            13 <= len(_digits(value)) <= 18
            and _is_luhn_valid(_digits(value))
            and _has_context(
                content,
                start,
                end,
                ("card number", "credit card", "debit card", "cvv", "expiry"),
            )
            and not (has_direct_label or has_table_context)
        ):
            return True
        return False
    return False


def _finding_risk(entity_type: str, score: float, context_hits: List[str]) -> Dict:
    """Calculate Phase 1 risk contribution for one regex-based finding."""
    base_points = RISK_WEIGHTS.get(entity_type, 10)
    context_bonus = 5 if context_hits else 0
    confidence_bonus = 5 if score >= 0.75 else 0
    total_points = min(50, base_points + context_bonus + confidence_bonus)
    return {
        "base_points": base_points,
        "context_bonus": context_bonus,
        "confidence_bonus": confidence_bonus,
        "total_points": total_points,
    }


def _calculate_risk(findings: List[Dict]) -> Dict:
    """Convert regex findings into a simple Phase 1 DLP risk score."""
    finding_points = sum(item["risk_points"] for item in findings)
    volume_bonus = min(20, max(0, len(findings) - 1) * 5)
    raw_score = finding_points + volume_bonus
    score = min(100, raw_score)
    level, decision = _risk_level_and_decision(score)

    # Risk is occurrence-based in Phase 1, so repeated values count separately.
    entity_counts = {}
    for finding in findings:
        entity_type = finding["entity_type"]
        entity_counts[entity_type] = entity_counts.get(entity_type, 0) + 1

    return {
        "score": score,
        "level": level,
        "decision": decision,
        "max_score": 100,
        "components": {
            "finding_points": finding_points,
            "volume_bonus": volume_bonus,
            "raw_score": raw_score,
        },
        "entity_counts": entity_counts,
    }


def _risk_level_and_decision(score: int) -> tuple[str, str]:
    for threshold, level, decision in RISK_LEVELS:
        if score >= threshold:
            return level, decision
    return "none", "allow"


def _looks_like_email(text: str) -> bool:
    head = text[:1000].lower()
    return any(header in head for header in ("subject:", "from:", "to:", "mime-version:"))


def _message_body(message: Message) -> str:
    """Prefer text/plain body parts and fall back to text/html converted to text."""
    plain_parts = []
    html_parts = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            disposition = (part.get_content_disposition() or "").lower()
            # Attachments are deliberately out of scope for Phase 1.
            if disposition == "attachment":
                continue
            content_type = part.get_content_type()
            content = _part_content(part)
            if not content:
                continue
            if content_type == "text/plain":
                plain_parts.append(content)
            elif content_type == "text/html":
                html_parts.append(_html_to_text(content))
    else:
        content = _part_content(message)
        if message.get_content_type() == "text/html":
            html_parts.append(_html_to_text(content))
        else:
            plain_parts.append(content)

    return "\n".join(plain_parts or html_parts)


def _part_content(part: Message) -> str:
    try:
        content = part.get_content()
    except Exception:
        payload = part.get_payload(decode=True)
        if payload is None:
            payload = str(part.get_payload()).encode("utf-8", errors="replace")
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    return content if isinstance(content, str) else str(content)


def _message_payload_fallback(message: Message) -> str:
    payload = message.get_payload()
    if isinstance(payload, list):
        return "\n".join(str(item) for item in payload)
    return str(payload or "")


def _html_to_text(value: str) -> str:
    """Convert a basic HTML email body into text without executing markup."""
    value = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", value)
    value = re.sub(r"(?i)<br\s*/?>", "\n", value)
    value = re.sub(r"(?i)</p\s*>", "\n", value)
    value = re.sub(r"<[^>]+>", " ", value)
    value = html.unescape(value)
    return re.sub(r"[ \t\r\f\v]+", " ", value)


def _context_hits(text: str, start: int, end: int, context_words: Iterable[str]) -> List[str]:
    # A small symmetric window supports nearby labels without scanning headers.
    window = text[max(0, start - 80) : min(len(text), end + 80)].lower()
    return [word for word in context_words if _contains_context(window, word)]


def _has_context(text: str, start: int, end: int, context_words: Iterable[str]) -> bool:
    window = text[max(0, start - 80) : min(len(text), end + 80)].lower()
    return any(_contains_context(window, word) for word in context_words)


def _contains_context(window: str, word: str) -> bool:
    """Match keyword boundaries while allowing flexible whitespace in phrases."""
    escaped = re.escape(word.lower())
    if re.fullmatch(r"[a-z0-9 ]+", word.lower()):
        escaped = escaped.replace(r"\ ", r"\s+")
        return bool(re.search(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])", window))
    return word.lower() in window


def _has_same_line_context(
    text: str, start: int, context_words: Iterable[str]
) -> bool:
    """Check labels on the same line so nearby unrelated fields do not leak."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end == -1:
        line_end = len(text)
    line_before_value = text[line_start:start].lower()
    return any(
        _contains_context(line_before_value, word) for word in context_words
    )


def _has_account_table_context(text: str, start: int) -> bool:
    """Associate a value with an Account-labelled column in a text table."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end == -1:
        line_end = len(text)
    row = text[line_start:line_end]
    if "|" not in row:
        return False

    column_index = row[: start - line_start].count("|")
    prior_text = text[max(0, line_start - 2500) : line_start]

    for header in reversed(prior_text.splitlines()):
        if "|" not in header:
            continue
        cells = header.split("|")
        if column_index >= len(cells):
            continue
        cell = cells[column_index].strip().lower()
        if "account" in cell and any(
            token in cell for token in ("account", "acct")
        ):
            return True
        # Stop at the first plausible table header rather than leaking context
        # from an unrelated table farther up the email.
        if any(
            label in header.lower()
            for label in ("name", "ifsc", "upi", "employee", "vendor")
        ):
            return False
    return False


def _has_pan_table_context(text: str, start: int) -> bool:
    """Associate a value with a PAN-labelled column in a text table."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end == -1:
        line_end = len(text)
    row = text[line_start:line_end]
    if "|" not in row:
        return False

    column_index = row[: start - line_start].count("|")
    prior_text = text[max(0, line_start - 2500) : line_start]

    for header in reversed(prior_text.splitlines()):
        if "|" not in header:
            continue
        cells = header.split("|")
        if column_index >= len(cells):
            continue
        if cells[column_index].strip().lower() in {"pan", "pan number", "pan no"}:
            return True
        if any(
            label in header.lower()
            for label in ("name", "status", "applicant", "vendor")
        ):
            return False
    return False


def _has_upi_table_context(text: str, start: int) -> bool:
    """Associate a value only with a UPI/VPA-labelled table column."""
    return _has_named_table_column(
        text,
        start,
        {"upi", "upi id", "upi handle", "vpa"},
    )


def _has_email_table_context(text: str, start: int) -> bool:
    """Identify values located in an email/mail-labelled table column."""
    return _has_named_table_column(
        text,
        start,
        {"email", "email address", "email id", "mail", "mail id"},
    )


def _has_named_table_column(
    text: str, start: int, accepted_headers: set[str]
) -> bool:
    """Check the current Markdown/text-table column against known headers."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end == -1:
        line_end = len(text)
    row = text[line_start:line_end]
    if "|" not in row:
        return False

    # The number of separators before the match identifies its table column.
    column_index = row[: start - line_start].count("|")
    prior_text = text[max(0, line_start - 2500) : line_start]
    for header in reversed(prior_text.splitlines()):
        if "|" not in header:
            continue
        cells = header.split("|")
        if column_index >= len(cells):
            continue
        cell = re.sub(r"[^a-z0-9 ]+", " ", cells[column_index].lower())
        cell = re.sub(r"\s+", " ", cell).strip()
        if cell in accepted_headers:
            return True
        if any(
            label in header.lower()
            for label in ("name", "email", "upi", "amount", "employee", "customer")
        ):
            return False
    return False


def _is_part_of_upi(text: str, start: int, end: int) -> bool:
    """Reject numeric account candidates immediately followed by a UPI handle."""
    return end < len(text) and text[end] == "@"


def _is_embedded_in_gstin(text: str, start: int, end: int) -> bool:
    """Prevent reporting the ten-character PAN component of a full GSTIN."""
    gstin_start = start - 2
    gstin_end = end + 3
    if gstin_start < 0 or gstin_end > len(text):
        return False
    candidate = text[gstin_start:gstin_end].upper()
    return bool(
        re.fullmatch(
            r"(?:0[1-9]|[1-2][0-9]|3[0-7])"
            r"[A-Z]{3}[PFCHABTGLJ][A-Z][0-9]{4}[A-Z][0-9A-Z]Z[0-9A-Z]",
            candidate,
        )
    )


def _payment_card_subtype(text: str, start: int, end: int) -> str:
    """Classify funding type only when debit- or credit-specific words exist."""
    debit_same_line = _has_same_line_context(
        text, start, InPaymentCardRecognizer.DEBIT_CONTEXT
    )
    credit_same_line = _has_same_line_context(
        text, start, InPaymentCardRecognizer.CREDIT_CONTEXT
    )

    if debit_same_line and not credit_same_line:
        return "debit"
    if credit_same_line and not debit_same_line:
        return "credit"

    debit_nearby = _has_context(
        text, start, end, InPaymentCardRecognizer.DEBIT_CONTEXT
    )
    credit_nearby = _has_context(
        text, start, end, InPaymentCardRecognizer.CREDIT_CONTEXT
    )
    if debit_nearby and not credit_nearby:
        return "debit"
    if credit_nearby and not debit_nearby:
        return "credit"
    return "unknown"


def _remove_contained_aadhaar_card_collisions(findings: List[Dict]) -> List[Dict]:
    """Prefer a complete validated payment card over an overlapping Aadhaar."""
    card_spans = [
        (item["start"], item["end"])
        for item in findings
        if item["entity_type"] == "PAYMENT_CARD"
    ]
    if not card_spans:
        return findings

    return [
        item
        for item in findings
        if not (
            item["entity_type"] == "IN_AADHAAR"
            and any(
                card_start <= item["start"] and item["end"] <= card_end
                for card_start, card_end in card_spans
            )
        )
    ]


def _is_luhn_valid(value: str) -> bool:
    """Use Luhn only for collision resolution, never as account validation."""
    total = 0
    parity = len(value) % 2
    for index, char in enumerate(value):
        digit = ord(char) - ord("0")
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)
