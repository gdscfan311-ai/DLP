import re
from typing import List, Optional

from Recognizers.base import Pattern, PatternRecognizer


class InPassportRecognizer(PatternRecognizer):
    """
    Detect Indian passport numbers in visible text and TD3 MRZ data.

    Visible numbers use one letter followed by seven digits and require
    passport context. A complete MRZ additionally provides an ICAO check digit.
    Local validation cannot confirm issuance or passport status.
    """

    COUNTRY_CODE = "in"

    # The MRZ pattern captures only the passport number as the finding value;
    # validate_match also checks the adjacent ICAO check digit.
    PATTERNS = [
        Pattern(
            "Indian Passport Number from TD3 MRZ",
            r"(?m)^P<IND[A-Z<]{39}\r?\n"
            r"(?P<value>[A-Z][1-9][0-9]{6})<"
            r"(?P<check_digit>[0-9])",
            0.85,
        ),
        Pattern(
            "Indian Passport Number",
            r"(?<![A-Za-z0-9])[A-Za-z]\s?[1-9][0-9]{6}"
            r"(?![A-Za-z0-9])(?!<[0-9])",
            0.35,
        ),
    ]

    CONTEXT = [
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
    ]

    _PASSPORT_RE = re.compile(r"^[A-Z][1-9][0-9]{6}$")

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "IN_PASSPORT",
        name: Optional[str] = None,
    ):
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
        """Validate the public Indian passport-number structure."""
        sanitized_value = pattern_text.replace(" ", "").upper()
        return bool(self._PASSPORT_RE.fullmatch(sanitized_value))

    def validate_match(self, match: re.Match) -> bool:
        """
        Validate a regex match, including the ICAO check digit for MRZ input.

        The TD3 document-number field is nine characters. An eight-character
        Indian passport number is padded with '<' before its check digit.
        """
        value = match.groupdict().get("value") or match.group(0)
        if not self.validate_result(value):
            return False

        check_digit = match.groupdict().get("check_digit")
        if check_digit is None:
            return True

        document_number_field = value.upper().replace(" ", "") + "<"
        return self._mrz_check_digit(document_number_field) == check_digit

    @staticmethod
    def _mrz_check_digit(value: str) -> str:
        """Calculate an ICAO Doc 9303 MRZ check digit using 7-3-1 weights."""
        weights = (7, 3, 1)
        total = 0

        for index, char in enumerate(value):
            if char == "<":
                char_value = 0
            elif char.isdigit():
                char_value = int(char)
            elif "A" <= char <= "Z":
                char_value = ord(char) - ord("A") + 10
            else:
                raise ValueError("MRZ fields may contain only A-Z, 0-9, and '<'")
            total += char_value * weights[index % len(weights)]

        return str(total % 10)
