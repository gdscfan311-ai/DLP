from typing import List, Optional, Tuple

from Recognizers.base import EntityRecognizer, Pattern, PatternRecognizer


class InAadhaarRecognizer(PatternRecognizer):
    """
    Recognizes Indian UIDAI Person Identification Number ("AADHAAR").

    Reference: https://en.wikipedia.org/wiki/Aadhaar
    A 12 digit unique number that is issued to each individual by Government of India
    :param patterns: List of patterns to be used by this recognizer
    :param context: List of context words to increase confidence in detection
    :param supported_language: Language this recognizer supports
    :param supported_entity: The entity this recognizer can detect
    :param replacement_pairs: List of tuples with potential replacement values
    for different strings to be used during pattern matching.
    This can allow a greater variety in input, for example by removing dashes or spaces.
    """

    COUNTRY_CODE = "in"

    # Boundaries prevent a valid 12-digit prefix from being taken out of a
    # longer card/account number. Verhoeff validation is applied afterward.
    PATTERNS = [
        Pattern(
            "AADHAAR (Very Weak)",
            r"(?<![0-9])[2-9][0-9]{11}(?![ -:]?[0-9])",
            0.01,
        ),
        Pattern(
            "AADHAAR (Weak)",
            r"(?<![0-9])[2-9][0-9]{3}[- :][0-9]{4}[- :][0-9]{4}"
            r"(?![ -:]?[0-9])",
            0.2,
        ),
    ]

    CONTEXT = [
        "aadhaar",
        "aadhar",
        "aadhaar card",
        "aadhar card",
        "aadhaar number",
        "aadhar number",
        "aadhaar no",
        "aadhar no",
        "aadhaar details",
        "aadhar details",
        "uidai",
        "uid",
        "uid number",
    ]

    utils = None

    # Verhoeff multiplication and permutation tables used by UIDAI numbers.
    _VERHOEFF_D = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ]
    _VERHOEFF_P = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "IN_AADHAAR",
        replacement_pairs: Optional[List[Tuple[str, str]]] = None,
        name: Optional[str] = None,
    ) -> None:
        self.replacement_pairs = (
            replacement_pairs
            if replacement_pairs
            else [("-", ""), (" ", ""), (":", "")]
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
        """Determine absolute value based on calculation."""
        sanitized_value = EntityRecognizer.sanitize_value(
            pattern_text, self.replacement_pairs
        )
        return self.__check_aadhaar(sanitized_value)

    def __check_aadhaar(self, sanitized_value: str) -> bool:
        return (
            len(sanitized_value) == 12
            and sanitized_value.isdecimal()
            and sanitized_value[0] >= "2"
            and not self._is_palindrome(sanitized_value)
            and self._is_verhoeff_number(sanitized_value)
        )

    @staticmethod
    def _is_palindrome(text: str, case_insensitive: bool = False) -> bool:
        """
        Validate if input text is a true palindrome.

        :param text: input text string to check for palindrome
        :param case_insensitive: optional flag to check palindrome with no case
        :return: True / False
        """
        palindrome_text = text
        if case_insensitive:
            palindrome_text = palindrome_text.replace(" ", "").lower()
        return palindrome_text == palindrome_text[::-1]

    @staticmethod
    def _is_verhoeff_number(input_number: str) -> bool:
        """
        Check if the input number is a true verhoeff number.

        :param input_number:
        :return:
        """
        c = 0
        for i, digit in enumerate(reversed(input_number)):
            c = InAadhaarRecognizer._VERHOEFF_D[c][
                InAadhaarRecognizer._VERHOEFF_P[i % 8][ord(digit) - ord("0")]
            ]
        return c == 0
