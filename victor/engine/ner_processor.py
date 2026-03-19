import re
import logging
from typing import List, Dict, Tuple, Set

from .spacy_engine import SpaCyEngine
from .spacy_engine import EMAIL_REGEX, DATE_REGEX, PHONE_REGEX, IBAN_REGEX

logger = logging.getLogger(__name__)


class NERProcessor:
    """
    Détecte les entités nommées (NER) dans des blocs de texte
    en utilisant spaCy et des regex additionnelles.
    """

    def __init__(
        self,
        spacy_engine: SpaCyEngine,
        enabled_labels: Set[str],
        excluded_labels: Set[str],
    ):
        self.spacy_engine = spacy_engine
        self.enabled_labels = enabled_labels
        self.excluded_labels = excluded_labels
        self.final_enabled_labels_for_spacy = self.enabled_labels - self.excluded_labels
        logger.debug(
            "NERProcessor : labels actifs pour la détection : %s",
            self.final_enabled_labels_for_spacy,
        )

    def detect_entities_in_blocks(
        self, text_blocks: List[str]
    ) -> Tuple[List[Tuple[str, str]], List[List[Tuple[str, str, int, int]]]]:
        """
        Détecte les entités dans une liste de blocs de texte.

        Retourne :
          1. Liste de tuples (entity_text, label) — entités uniques détectées.
          2. Liste de listes de tuples (entity_text, label, start_char, end_char) par bloc.
        """
        all_unique_entities: Dict[str, Tuple[str, str]] = {}
        entities_per_block: List[List[Tuple[str, str, int, int]]] = []

        regex_sources = {
            "EMAIL": EMAIL_REGEX,
            "DATE": DATE_REGEX,
            "PHONE": PHONE_REGEX,
            "IBAN": IBAN_REGEX,
        }
        PRIORITY_REGEX_LABELS = {"EMAIL", "DATE", "PHONE", "IBAN"}

        for block_text in text_blocks:
            detected: List[Tuple[str, str, int, int]] = []

            if block_text.strip():
                doc = self.spacy_engine.nlp_doc(block_text)

                for ent in doc.ents:
                    if ent.label_ in self.final_enabled_labels_for_spacy:
                        detected.append((ent.text, ent.label_, ent.start_char, ent.end_char))

                for label, pattern in regex_sources.items():
                    if label in self.final_enabled_labels_for_spacy:
                        for match in re.finditer(
                            pattern, block_text, re.IGNORECASE if label == "DATE" else 0
                        ):
                            detected.append((match.group(0), label, match.start(), match.end()))

                # Déduplication par span avec priorité regex
                detected.sort(key=lambda x: x[2])
                best_by_span: Dict[Tuple[int, int], Tuple[str, str]] = {}
                for ent_text, ent_label, start, end in detected:
                    span = (start, end)
                    if span in best_by_span:
                        existing_label = best_by_span[span][1]
                        if ent_label in PRIORITY_REGEX_LABELS and existing_label not in PRIORITY_REGEX_LABELS:
                            best_by_span[span] = (ent_text, ent_label)
                    else:
                        best_by_span[span] = (ent_text, ent_label)

                processed = sorted(
                    [(text, label, start, end) for (start, end), (text, label) in best_by_span.items()],
                    key=lambda x: x[2],
                )

                for ent_text, ent_label, _, _ in processed:
                    if ent_text not in all_unique_entities:
                        all_unique_entities[ent_text] = (ent_label, "initial")
                    else:
                        existing_label = all_unique_entities[ent_text][0]
                        if ent_label in PRIORITY_REGEX_LABELS and existing_label not in PRIORITY_REGEX_LABELS:
                            all_unique_entities[ent_text] = (ent_label, "regex_override")

                entities_per_block.append(processed)

        final_unique = [(text, data[0]) for text, data in all_unique_entities.items()]
        return final_unique, entities_per_block
