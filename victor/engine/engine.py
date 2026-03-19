"""
victor/engine/engine.py

Moteur d'anonymisation extrait de anonyfiles_core.
Seule la méthode anonymize_text() est utilisée par Victor ;
les méthodes fichier (anonymize / anonymize_async) sont conservées
mais leurs imports lourds (FileProcessorFactory, Writer) sont chargés
à la demande pour ne pas alourdir l'installation de base.
"""

import re
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

from .spacy_engine import SpaCyEngine
from .replacer import ReplacementSession
from .utils import apply_positional_replacements
from .audit import AuditLogger
from .custom_rules_processor import CustomRulesProcessor
from .ner_processor import NERProcessor
from .replacement_generator import ReplacementGenerator

logger = logging.getLogger(__name__)

# Remplace les tokens {{...}} par des espaces de même longueur avant NER.
_CUSTOM_TOKEN_RE = re.compile(r'\{\{[^{}]+\}\}')


def _sanitize_for_ner(text: str) -> str:
    """Remplace {{TOKEN}} par des espaces de même longueur — préserve les offsets."""
    return _CUSTOM_TOKEN_RE.sub(lambda m: ' ' * len(m.group()), text)


class AnonyfilesEngine:
    """
    Orchestre le processus complet d'anonymisation d'un texte.
    """

    def __init__(
        self,
        config: Dict[str, Any],
        exclude_entities_cli: Optional[List[str]] = None,
        custom_replacement_rules: Optional[List[Dict[str, str]]] = None,
        shared_mapping_proxy: Optional[Dict] = None,
    ):
        self.config = config or {}

        self.audit_logger = AuditLogger()
        self.custom_rules_processor = CustomRulesProcessor(custom_replacement_rules, self.audit_logger)

        self.entities_exclude = set()
        self.entities_exclude.update(self.config.get("exclude_entities", []))

        mapping_gui_keys = {
            "anonymizePersons": "PER",
            "anonymizeLocations": "LOC",
            "anonymizeOrgs": "ORG",
            "anonymizeEmails": "EMAIL",
            "anonymizeDates": "DATE",
            "anonymizeMisc": "MISC",
            "anonymizePhones": "PHONE",
            "anonymizeIbans": "IBAN",
            "anonymizeAddresses": "ADDRESS",
        }
        self.enabled_labels = set()
        for key, label in mapping_gui_keys.items():
            if self.config.get(key, True):
                self.enabled_labels.add(label)
            else:
                self.entities_exclude.add(label)

        for label in self.config.get("extra_labels", []):
            self.enabled_labels.add(label)

        if exclude_entities_cli:
            for e_list in exclude_entities_cli:
                for e in e_list.split(","):
                    self.entities_exclude.add(e.strip().upper())

        model = self.config.get("spacy_model", "fr_core_news_md")
        self.spacy_engine = SpaCyEngine(model=model)
        self.ner_processor = NERProcessor(
            self.spacy_engine, self.enabled_labels, self.entities_exclude
        )
        self.replacement_generator = ReplacementGenerator(self.config, self.audit_logger)

    def reset_state(self):
        """Réinitialise l'état interne du moteur pour un nouveau lot."""
        self.audit_logger.reset()
        self.custom_rules_processor.reset()
        if hasattr(self.replacement_generator, 'reset_session'):
            self.replacement_generator.reset_session()
        logger.debug("AnonyfilesEngine : état réinitialisé.")

    def anonymize_text(self, text: str) -> Tuple[str, Dict[str, Any]]:
        """
        Anonymise un texte en mémoire (synchrone).

        La session interne du ReplacementGenerator est STATEFUL : les appels
        successifs partagent les compteurs — une même entité reçoit toujours
        le même token sur tout le cycle de vie du moteur.
        Appeler reset_state() pour repartir d'une session vierge.

        Returns:
            (anonymized_text, report) où report contient :
              - status, audit_log, total_replacements, mapping
        """
        # 1. Custom rules regex
        block_after_custom_rules = self.custom_rules_processor.apply_to_block(text)

        if not block_after_custom_rules.strip():
            return block_after_custom_rules, {
                "status": "success",
                "message": "Input is empty.",
                "audit_log": self.audit_logger.summary(),
                "total_replacements": self.audit_logger.total(),
                "mapping": {},
            }

        # 2. NER — sur texte sanitisé ({{...}} → espaces) pour éviter les faux positifs
        unique_spacy_entities, spacy_entities_per_block = self.ner_processor.detect_entities_in_blocks(
            [_sanitize_for_ner(block_after_custom_rules)]
        )

        if not unique_spacy_entities and self.custom_rules_processor.get_custom_replacements_count() == 0:
            return block_after_custom_rules, {
                "status": "success",
                "message": "No entities found to anonymize.",
                "audit_log": self.audit_logger.summary(),
                "total_replacements": self.audit_logger.total(),
                "mapping": {},
            }

        # 3. Génération des remplacements
        replacements_map_spacy, mapping_dict_spacy = self.replacement_generator.generate_spacy_replacements(
            unique_spacy_entities, spacy_entities_per_block
        )

        # 4. Application positionnelle sur le texte original (non sanitisé)
        final_text = apply_positional_replacements(
            block_after_custom_rules,
            replacements_map_spacy,
            spacy_entities_per_block[0],
        )

        # 5. Rapport
        full_mapping = {
            **self.custom_rules_processor.get_custom_replacements_mapping(),
            **mapping_dict_spacy,
        }
        report = {
            "status": "success",
            "audit_log": self.audit_logger.summary(),
            "total_replacements": self.audit_logger.total(),
            "mapping": full_mapping,
        }

        return final_text, report
