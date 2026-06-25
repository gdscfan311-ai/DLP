import re
from typing import List, Optional, Tuple

from Recognizers.base import Pattern, PatternRecognizer


class InGstinRecognizer(PatternRecognizer):
    """
    Recognizes Indian Goods and Services Tax Identification Number ("GSTIN").

    The GSTIN is a 15-character identifier with the following structure:
    - First 2 digits: State code (01-37)
    - Next 10 digits: PAN of the entity
    - 13th digit: Registration number for same PAN in the state
    - 14th digit: 'Z'
    - 15th digit: Checksum

    Reference: https://www.gst.gov.in/
    This recognizer identifies GSTIN using regex and context words.

    :param patterns: List of patterns to be used by this recognizer
    :param context: List of context words to increase confidence in detection
    :param supported_language: Language this recognizer supports
    :param supported_entity: The entity this recognizer can detect
    :param replacement_pairs: List of tuples with potential replacement values
    for different strings to be used during pattern matching.
    This can allow a greater variety in input, for example by removing dashes or spaces.
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
        """
        Validate the GSTIN format and structure.

        :param pattern_text: The text pattern to validate
        :return: True if the GSTIN is valid, False otherwise
        """
        sanitized_value = self._sanitize_value(pattern_text)
        return self._validate_gstin(sanitized_value)

    def _sanitize_value(self, text: str) -> str:
        """Remove common separators and normalize the text."""
        sanitized = text.upper()
        for old, new in self.replacement_pairs:
            sanitized = sanitized.replace(old, new)
        return sanitized

    def _validate_gstin(self, gstin: str) -> bool:
        """
        Validate GSTIN structure and format.

        :param gstin: The GSTIN string to validate
        :return: True if valid, False otherwise
        """
        if not self._GSTIN_RE.fullmatch(gstin):
            return False

        return self._is_valid_checksum(gstin)

    def _validate_pan_format(self, pan: str) -> bool:
        """
        Validate PAN format within GSTIN.

        PAN format: 5 letters + 4 digits + 1 letter.
        The 4th character must be a valid PAN holder type code.

        :param pan: The PAN part of GSTIN (10 characters)
        :return: True if valid PAN format, False otherwise
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
