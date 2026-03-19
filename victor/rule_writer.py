"""
victor/rule_writer.py

Écrit les règles regex validées dans custom_rules_security.json.

Principe :
  - N'écrit que des règles explicitement validées (accept() dans GapCollector)
  - Vérifie l'absence de doublon (pattern déjà présent → skip)
  - Conserve le formatage JSON lisible du fichier existant
  - Crée le fichier s'il n'existe pas

Usage :
    from victor.rule_writer import RuleWriter
    from victor.gap_collector import GapCollector

    collector = GapCollector()
    writer = RuleWriter()

    for gap in collector.candidates():
        rule = collector.to_regex_rule(gap["text"], gap["label"])
        added = writer.add(rule)
        if added:
            collector.accept(gap["text"], gap["label"])
"""

import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_RULES_PATH = Path(__file__).parent / "config" / "custom_rules_security.json"


class RuleWriter:
    """
    Gère l'ajout de nouvelles règles dans custom_rules_security.json.

    Les règles sont ajoutées en fin de fichier, avant le dernier bloc
    de même type (regroupement par label si possible).
    """

    def __init__(self, rules_path: Optional[Path] = None):
        """
        :param rules_path: Chemin vers custom_rules_security.json.
                           Par défaut : victor/config/custom_rules_security.json.
        """
        self._path = rules_path or _DEFAULT_RULES_PATH

    def add(self, rule: Dict) -> bool:
        """
        Ajoute une règle dans le fichier si son pattern n'est pas déjà présent.

        :param rule: Dict compatible custom_rules.json
                     (doit contenir au moins "pattern" et "replacement").
        :return: True si la règle a été ajoutée, False si doublon ou erreur.
        """
        pattern = rule.get("pattern")
        if not pattern:
            logger.warning("RuleWriter.add : règle sans 'pattern' — ignorée.")
            return False

        rules = self._load()

        # Vérifie si le pattern est déjà présent
        for existing in rules:
            if existing.get("pattern") == pattern:
                logger.info(
                    "RuleWriter : pattern déjà présent — skip (%s)", pattern
                )
                return False

        # Valide que le pattern est un regex valide avant d'écrire
        if rule.get("isRegex", False):
            try:
                re.compile(pattern)
            except re.error as e:
                logger.error(
                    "RuleWriter : pattern invalide '%s' : %s — non ajouté.",
                    pattern, e,
                )
                return False

        rules.append(rule)
        self._save(rules)
        logger.info(
            "RuleWriter : règle ajoutée [%s] pattern=%s",
            rule.get("_comment", "sans commentaire"),
            pattern,
        )
        return True

    def add_batch(self, rules: List[Dict]) -> int:
        """
        Ajoute plusieurs règles en une seule opération (une seule écriture disque).

        :return: Nombre de règles effectivement ajoutées.
        """
        existing_rules = self._load()
        existing_patterns = {r.get("pattern") for r in existing_rules}

        added = 0
        for rule in rules:
            pattern = rule.get("pattern")
            if not pattern or pattern in existing_patterns:
                continue
            if rule.get("isRegex", False):
                try:
                    re.compile(pattern)
                except re.error as e:
                    logger.error("RuleWriter : pattern invalide '%s' : %s — ignoré.", pattern, e)
                    continue
            existing_rules.append(rule)
            existing_patterns.add(pattern)
            added += 1

        if added:
            self._save(existing_rules)
            logger.info("RuleWriter : %d règle(s) ajoutée(s) en batch.", added)

        return added

    def list_patterns(self) -> List[str]:
        """Retourne la liste des patterns actuellement dans le fichier."""
        return [r.get("pattern", "") for r in self._load() if r.get("pattern")]

    # ------------------------------------------------------------------
    # Helpers internes
    # ------------------------------------------------------------------

    def _load(self) -> List[Dict]:
        """Charge les règles existantes. Retourne [] si le fichier n'existe pas."""
        if not self._path.exists():
            return []
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except Exception as e:
            logger.error("RuleWriter : erreur lecture %s : %s", self._path, e)
            return []

    def _save(self, rules: List[Dict]):
        """Écrit les règles sur disque en JSON formaté."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(rules, f, ensure_ascii=False, indent=2)
