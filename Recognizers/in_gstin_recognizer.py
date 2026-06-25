import re
from typing import List, Optional, Tuple

from Recognizers.base import Pattern, PatternRecognizer


class InGstinRecognizer(PatternRecognizer):
    """
    Detect and validate 15-character Indian GSTIN values.

    Validation checks the state code, embedded PAN structure, fixed ``Z``
    position, and base-36 checksum. It verifies the identifier's structure,
    not whether the GST registration is currently active.
    """

    COUNTRY_CODE = "in"
    # GSTIN positions 3-12 contain a PAN with one of these holder categories.
    PAN_HOLDER_TYPE_CODES = "PFCHABTGLJ"

    PATTERNS = [
        Pattern(
            "GSTIN (High)",
            rf"\b((?:0[1-9]|[1-2][0-9]|3[0-7])[A-Za-z]{{3}}[{PAN_HOLDER_TYPE_CODES}{PAN_HOLDER_TYPE_CODES.lower()}][A-Za-z][0-9]{{4}}[A-Za-z][0-9A-Za-z]Z[0-9A-Za-z])\b",
            0.85,
        ),
        Pattern(
            "GSTIN (Medium)",
            r"\b((?:0[1-9]|[1-2][0-9]|3[0-7])[A-Za-z0-9]{11}Z[A-Za-z0-9])\b",
            0.4,
        ),
    ]

    CONTEXT = [
        "gstin",
        "gstin number",
        "gstin no",
        "gstin details",
        "gst",
        "goods and services tax",
        "tax identification",
        "tax identification number",
        "gst number",
        "gst no",
        "gst registration",
        "gst registration number",
        "tax registration",
        "tax invoice",
        "invoice",
        "vendor gst",
        "supplier gst",
        "business registration",
    ]

    _GSTIN_RE = re.compile(
        r"^(?:0[1-9]|[1-2][0-9]|3[0-7])"
        rf"[A-Z]{{3}}[{PAN_HOLDER_TYPE_CODES}][A-Z][0-9]{{4}}[A-Z][0-9A-Z]Z[0-9A-Z]$"
    )
    _CHECKSUM_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "IN_GSTIN",
        replacement_pairs: Optional[List[Tuple[str, str]]] = None,
        name: Optional[str] = None,
    ):
        self.replacement_pairs = (
            replacement_pairs if replacement_pairs else [("-", ""), (" ", "")]
        )
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
            name=name,
        )
        self.supported_entity = supported_entity

    def validate_result(self, pattern_text: str) -> bool:
        """Normalize the candidate, then validate its structure and checksum."""
        sanitized_value = self._sanitize_value(pattern_text)
        return self._validate_gstin(sanitized_value)

    def _sanitize_value(self, text: str) -> str:
        """Remove common separators and normalize the text."""
        sanitized = text.upper()
        for old, new in self.replacement_pairs:
            sanitized = sanitized.replace(old, new)
        return sanitized

    def _validate_gstin(self, gstin: str) -> bool:
        """Reject malformed GSTINs before running the checksum."""
        if not self._GSTIN_RE.fullmatch(gstin):
            return False

        return self._is_valid_checksum(gstin)

    def _validate_pan_format(self, pan: str) -> bool:
        """
        Validate a ten-character PAN component independently.

        Kept as a reusable helper for focused tests and future decomposition of
        GSTIN fields.
        """
        if len(pan) != 10:
            return False

        if not re.fullmatch(
            rf"[A-Z]{{3}}[{self.PAN_HOLDER_TYPE_CODES}][A-Z][0-9]{{4}}[A-Z]",
            pan,
        ):
            return False

        return True

    def _is_valid_checksum(self, gstin: str) -> bool:
        # GSTIN uses a base-36 alternating-factor checksum over positions 1-14.
        factor = 2
        total = 0

        for char in reversed(gstin[:14]):
            code_point = self._CHECKSUM_CHARS.find(char)
            if code_point == -1:
                return False
            addend = factor * code_point
            factor = 1 if factor == 2 else 2
            total += (addend // 36) + (addend % 36)

        check_code_point = (36 - (total % 36)) % 36
        return self._CHECKSUM_CHARS[check_code_point] == gstin[14]
