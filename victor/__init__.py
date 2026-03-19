"""
Victor — Anonymiseur de logs et documents de sécurité.

Utilisation :
    from victor import Anonymizer

    anon = Anonymizer()
    result = anon.anonymize_text("Block IP 10.0.0.1 on fw01.company.local")
    print(result["anonymized_text"])
    # → "Block IP {{IP_PRIVE}} on {{HOSTNAME}}"

    batch = anon.anonymize_batch(["log line 1", "log line 2"])
    original = anon.deanonymize_text(result["anonymized_text"])
"""

from .anonymizer import Anonymizer
from .gap_collector import GapCollector
from .rule_writer import RuleWriter
from .annotation_writer import AnnotationWriter

__all__ = ["Anonymizer", "GapCollector", "RuleWriter", "AnnotationWriter"]
__version__ = "0.1.0"
