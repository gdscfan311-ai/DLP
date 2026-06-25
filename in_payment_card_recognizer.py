from typing import List, Optional, Tuple

from Recognizers.base import EntityRecognizer, Pattern, PatternRecognizer


class InPaymentCardRecognizer(PatternRecognizer):
    """
    Recognize payment-card primary account numbers.

    A card number and its Luhn checksum do not encode whether the funding
    source is debit or credit. The scanner therefore emits PAYMENT_CARD and
    classifies the subtype separately from nearby context.
    """

    PATTERNS = [
        Pattern(
            "Payment Card Number",
            # Reject numeric tails embedded in REF-, TXN-, email, or other IDs.
            r"(?<![A-Za-z0-9@-])(?:\d[ -]?){13,19}(?![A-Za-z0-9@-])",
            0.55,
        ),
    ]

    CONTEXT = [
        "payment card",
        "payment card number",
        "card number",
        "card no",
        "card details",
        "cardholder",
        "card holder",
        "debit card",
        "debit card number",
        "atm card",
        "visa debit",
        "mastercard debit",
        "master card debit",
        "rupay debit",
        "credit card",
        "credit card number",
        "corporate credit card",
        "visa credit",
        "mastercard credit",
        "master card credit",
        "rupay credit",
        "expiry",
        "expiry date",
        "exp date",
        "cvv",
        "cvc",
        "visa",
        "mastercard",
        "master card",
        "amex",
        "american express",
        "rupay",
    ]

    DEBIT_CONTEXT = [
        "debit card",
        "debit card number",
        "debit card no",
        "debit card details",
        "atm card",
        "atm card number",
        "atm card details",
        "visa debit",
        "mastercard debit",
        "master card debit",
        "rupay debit",
    ]

    CREDIT_CONTEXT = [
        "credit card",
        "credit card number",
        "credit card no",
        "credit card details",
        "corporate credit card",
        "visa credit",
        "mastercard credit",
        "master card credit",
        "rupay credit",
    ]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "PAYMENT_CARD",
        replacement_pairs: Optional[List[Tuple[str, str]]] = None,
        name: Optional[str] = None,
    ):
        self.replacement_pairs = replacement_pairs or [("-", ""), (" ", "")]
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns or self.PATTERNS,
            context=context or self.CONTEXT,
            supported_language=supported_language,
            name=name,
        )

    def validate_result(self, pattern_text: str) -> bool:
        """Validate length, numeric content, repetition, and Luhn checksum."""
        # Spaces and hyphens are formatting; Luhn runs over digits only.
        value = EntityRecognizer.sanitize_value(
            pattern_text, self.replacement_pairs
        )
        return (
            value.isdecimal()
            and 13 <= len(value) <= 19
            and len(set(value)) > 1
            and self._is_luhn_valid(value)
        )

    @staticmethod
    def _is_luhn_valid(value: str) -> bool:
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
