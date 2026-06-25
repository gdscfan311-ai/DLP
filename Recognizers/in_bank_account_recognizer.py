from typing import List, Optional, Tuple

from Recognizers.base import EntityRecognizer, Pattern, PatternRecognizer


class InBankAccountRecognizer(PatternRecognizer):
    """
    Recognizes Indian bank account numbers.

    Bank account numbers are institution-specific and do not have a public
    checksum, so this recognizer intentionally uses low base scores and relies
    on nearby banking context to reduce false positives.
    """

    COUNTRY_CODE = "in"

    # Strong patterns capture directly labelled fields. The fallback pattern
    # supports tables and nearby bank context handled by scanner.py.
    PATTERNS = [
        Pattern(
            "Labelled Indian Bank Account Number",
            r"(?<![A-Za-z0-9])"
            r"(?:bank[ \t]+account(?:[ \t]+number|[ \t]+no)?|"
            r"beneficiary[ \t]+account(?:[ \t]+number|[ \t]+no)?|"
            r"payee[ \t]+account(?:[ \t]+number|[ \t]+no)?|"
            r"salary[ \t]+account(?:[ \t]+number|[ \t]+no)?|"
            r"account[ \t]+number|account[ \t]+no|acct[ \t]+no)"
            r"[ \t]*(?::|-|is)?[ \t]*"
            r"(?P<value>(?<![A-Za-z0-9@-])(?:\d[ -]?){9,18}"
            r"(?![A-Za-z0-9@-]))",
            0.65,
        ),
        Pattern(
            "Short-labelled Indian Bank Account Number",
            r"(?<![A-Za-z0-9])(?:account|acct)[ \t]*:[ \t]*"
            r"(?P<value>(?<![A-Za-z0-9@-])(?:\d[ -]?){9,18}"
            r"(?![A-Za-z0-9@-]))",
            0.65,
        ),
        Pattern(
            "Indian Bank Account Number",
            # Do not extract a numeric tail from IDs such as
            # APP-KYC-2026-001234, a UPI ID, or TXN-1234-5678-9012.
            r"(?<![A-Za-z0-9@-])(?:\d[ -]?){9,18}(?![A-Za-z0-9@-])",
            0.18,
        ),
    ]

    CONTEXT = [
        "account",
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
        "transfer",
        "wire transfer",
        "bank transfer",
        "neft",
        "rtgs",
        "imps",
    ]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "IN_BANK_ACCOUNT",
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
        # Separators are presentation only; length validation uses raw digits.
        sanitized_value = EntityRecognizer.sanitize_value(
            pattern_text, self.replacement_pairs
        )

        if not sanitized_value.isdecimal():
            return False

        if not 9 <= len(sanitized_value) <= 18:
            return False

        # Reject only a single repeated digit. Two-digit-heavy sequences can
        # still be legitimate account numbers and must not be discarded.
        if len(set(sanitized_value)) == 1:
            return False

        return True
