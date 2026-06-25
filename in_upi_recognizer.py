import re
from typing import List, Optional

from Recognizers.base import Pattern, PatternRecognizer


class InUpiRecognizer(PatternRecognizer):
    """
    Recognizes UPI virtual payment addresses (VPAs).

    UPI IDs look similar to email addresses. Phase 1 therefore validates the
    suffix against a maintained handle allowlist and requires UPI/VPA context
    in scanner.py.
    """

    COUNTRY_CODE = "in"

    # Strict boundaries prevent partial extraction from emails and multiple-@
    # strings such as rahul@ok@sbi.
    PATTERNS = [
        Pattern(
            "UPI ID",
            r"(?<![A-Za-z0-9._%+@-])"
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}"
            r"@[A-Za-z][A-Za-z0-9]{1,31}"
            r"(?![A-Za-z0-9._@-])",
            0.65,
        ),
    ]

    CONTEXT = [
        "upi",
        "upi id",
        "upi number",
        "upi details",
        "upi handle",
        "upi address",
        "vpa",
        "virtual payment address",
        "pay via upi",
    ]

    _UPI_RE = re.compile(
        r"^[A-Z0-9][A-Z0-9._-]{0,254}@[A-Z][A-Z0-9]{1,31}$",
        re.IGNORECASE,
    )

    # Phase 1 allowlist supplied by the user. Values are stored without '@'.
    ALLOWED_HANDLES = {
        "ptaxis",
        "ptyes",
        "ptsbi",
        "pthdfc",
        "okhdfcbank",
        "okicici",
        "oksbi",
        "okaxis",
        "ybl",
        "ibl",
        "axl",
        "sliceaxis",
        "slicepay",
        "slc",
        "kotak",
        "kotak811",
        "axisb",
        "yescred",
        "yescurie",
        "apl",
        "yapl",
        "fam",
        "yesfam",
        "inhdfc",
        "seyes",
        "mahb",
        "bpunity",
        "waicici",
        "upi",
        "jupiteraxis",
        "boi",
        "pz",
        "centralbank",
        "abcdicici",
        "dlb",
        "zoicici",
        "indus",
        "indie",
        "jkb",
        "airtel",
        "pnb",
        "jio",
        "sbi",
        "yespop",
        "barodampay",
        "shriramhdfcbank",
        "mboi",
        "timecosmos",
        "trans",
        "yespay",
        "payu",
        "icici",
        "iob",
        "rapl",
        "jarunity",
        "dbs",
        "kbaxis",
        "equitas",
        "kphdfc",
        "naviaxis",
        "mvhdfc",
        "axb",
        "abfspay",
        "paulpay",
        "oneyes",
        "fifederal",
        "cnrb",
        "fincarebank",
        "ikwik",
        "finobank",
        "rmrbl",
        "fkaxis",
        "pingpay",
        "freecharge",
        "sib",
        "hsbc",
        "superyes",
        "freoicici",
        "tapicici",
        "gwaxis",
        "yestp",
        "niyoicici",
        "yes",
    }

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "IN_UPI",
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
        if not self._UPI_RE.fullmatch(pattern_text):
            return False

        # A syntactically valid value is accepted only for a supplied PSP handle.
        local_part, handle = pattern_text.split("@", 1)
        return (
            ".." not in local_part
            and "--" not in local_part
            and "__" not in local_part
            and handle.lower() in self.ALLOWED_HANDLES
        )
