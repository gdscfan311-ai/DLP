import re
from typing import List, Optional, Tuple

from Recognizers.base import Pattern, PatternRecognizer


class InPanRecognizer(PatternRecognizer):
    """
    Recognizes Indian Permanent Account Number ("PAN").

    The Permanent Account Number (PAN) is a ten-character alpha-numeric code.
    Its fourth character identifies the PAN holder category. PAN does not
    expose a public checksum that this Phase 1 recognizer can validate.
    This recognizer identifies PAN using regex and context words.
    Reference: https://en.wikipedia.org/wiki/Permanent_account_number,
               https://incometaxindia.gov.in/Forms/tps/1.Permanent%20Account%20Number%20(PAN).pdf

    :param patterns: List of patterns to be used by this recognizer
    :param context: List of context words to increase confidence in detection
    :param supported_language: Language this recognizer supports
    :param supported_entity: The entity this recognizer can detect
    :param replacement_pairs: List of tuples with potential replacement values
    for different strings to be used during pattern matching.
    This can allow a greater variety in input, for example by removing dashes or spaces.
    """

    COUNTRY_CODE = "in"

    # P, F, C, H, A, B, T, G, L and J are the valid holder categories.
    PAN_HOLDER_TYPE_CODES = "PFCHABTGLJ"

    # Hyphen-aware boundaries reject PAN-shaped portions of FILE-/REF- IDs.
    PATTERNS = [
        Pattern(
            "PAN (High)",
            rf"(?<![A-Za-z0-9-])"
            rf"([A-Za-z]{{3}}[{PAN_HOLDER_TYPE_CODES}{PAN_HOLDER_TYPE_CODES.lower()}]"
            rf"[A-Za-z][0-9]{{4}}[A-Za-z])"
            rf"(?![A-Za-z0-9-])",
            0.75,
        ),
    ]

    CONTEXT = [
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
    ]

    _PAN_RE = re.compile(rf"^[A-Z]{{3}}[{PAN_HOLDER_TYPE_CODES}][A-Z][0-9]{{4}}[A-Z]$")

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "IN_PAN",
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

    def validate_result(self, pattern_text: str) -> bool:
        # PAN has no public checksum used here; validate its official structure.
        sanitized_value = pattern_text.upper()
        for old, new in self.replacement_pairs:
            sanitized_value = sanitized_value.replace(old, new)
        return bool(self._PAN_RE.fullmatch(sanitized_value))
