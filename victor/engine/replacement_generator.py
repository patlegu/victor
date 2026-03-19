from typing import List, Dict, Any, Tuple

from .replacer import ReplacementSession
from .audit import AuditLogger


class ReplacementGenerator:
    """
    Génère les mappings de remplacement pour les entités spaCy détectées
    et les journalise dans l'audit logger.

    La ReplacementSession interne est stateful : une même entité reçoit
    toujours le même token à travers tous les appels à generate_spacy_replacements().
    Appeler reset_session() pour repartir d'une session vierge.
    """

    def __init__(self, config: Dict[str, Any], audit_logger: AuditLogger):
        self.config = config
        self.audit_logger = audit_logger
        self.replacement_rules_spacy_config = self.config.get("replacements", {})
        self.session = ReplacementSession()

    def reset_session(self):
        """Remet la session de remplacement à zéro (nouvelle session vierge)."""
        self.session.reset()

    def generate_spacy_replacements(
        self,
        unique_spacy_entities: List[Tuple[str, str]],
        entities_per_block_with_offsets: List[List[Tuple[str, str, int, int]]],
    ) -> Tuple[Dict[str, str], Dict[str, str]]:
        """
        Génère les remplacements pour les entités spaCy et met à jour l'audit log.
        Retourne (replacements_map, mapping_dict).
        """
        replacements_map_spacy, mapping_dict_spacy = self.session.generate_replacements(
            unique_spacy_entities,
            replacement_rules=self.replacement_rules_spacy_config,
        )

        for original, code in mapping_dict_spacy.items():
            label = next(
                (lbl for txt, lbl in unique_spacy_entities if txt == original),
                "UNKNOWN_SPACY_LABEL",
            )
            n_repl = 0
            for block_entities in entities_per_block_with_offsets:
                for ent_text, ent_label, _, _ in block_entities:
                    if ent_text == original and ent_label == label:
                        n_repl += 1
            if n_repl > 0:
                self.audit_logger.log(original, code, f"spacy_{label}", n_repl)

        return replacements_map_spacy, mapping_dict_spacy
