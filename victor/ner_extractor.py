"""
victor/ner_extractor.py — Extracteur NER léger basé sur le modèle AnonyNER.

Charge le modèle AnonyNER (spaCy) et expose extract() → dict[str, list[str]].
Utilisé par Anonymizer comme couche d'observabilité (détection des gaps moteur).

Chargement lazy, instance réutilisable, graceful degradation si modèle absent.

Usage :
    from victor.ner_extractor import NERExtractor
    ner = NERExtractor()
    entities = ner.extract("Block IP 10.0.0.1 on WAN interface eth0")
    # → {"IP_ADDRESS": ["10.0.0.1"], "INTERFACE": ["eth0", "WAN"], ...}
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Labels NER reconnus par AnonyNER
NER_LABELS = {
    "IP_ADDRESS", "IP_SUBNET", "HOSTNAME", "PORT_NUMBER", "INTERFACE",
    "MAC_ADDRESS", "SERVICE_ACCOUNT", "CVE", "HASH", "FIREWALL_RULE",
    "VPN_USER", "SNMP_COMMUNITY",
}

_DEFAULT_MODEL_PATH = Path(__file__).parent.parent / "models" / "anonyner_model" / "model-best"


class NERExtractor:
    """
    Extracteur NER léger basé sur le modèle AnonyNER.

    - Chargement lazy au premier appel à extract()
    - Thread-safe en lecture (spaCy nlp() est ré-entrant)
    - Retourne toujours un dict complet avec toutes les clés NER_LABELS
    - Valeur vide [] si aucune entité de ce type détectée
    - Déduplique les valeurs au sein de chaque type
    - N'anonymise pas : retourne les valeurs originales
    """

    def __init__(self, model_path: Optional[Path] = None):
        self._model_path = model_path or _DEFAULT_MODEL_PATH
        self._nlp = None

    def _load(self) -> bool:
        """Charge le modèle spaCy. Retourne True si succès."""
        if self._nlp is not None:
            return True
        try:
            import spacy
            self._nlp = spacy.load(str(self._model_path))
            logger.info("AnonyNER chargé depuis %s", self._model_path)
            return True
        except ImportError:
            logger.warning("spaCy non disponible — NERExtractor désactivé")
            return False
        except OSError:
            logger.warning(
                "Modèle AnonyNER introuvable : %s — NERExtractor désactivé",
                self._model_path,
            )
            return False

    def extract(self, text: str) -> dict[str, list[str]]:
        """
        Extrait les entités de sécurité dans le texte.

        Returns:
            Dict complet avec toutes les clés NER_LABELS.
            Chaque valeur est une liste dédupliquée, ordre d'apparition conservé.
            Retourne des listes vides si le modèle n'est pas disponible.

        Exemple :
            extract("Block IP 10.0.0.1 on WAN interface")
            → {"IP_ADDRESS": ["10.0.0.1"], "INTERFACE": ["WAN"], ...}
        """
        result: dict[str, list[str]] = {label: [] for label in NER_LABELS}

        if not text or not text.strip():
            return result

        if not self._load():
            return result

        try:
            doc = self._nlp(text)
            for ent in doc.ents:
                if ent.label_ in NER_LABELS:
                    lst = result[ent.label_]
                    val = ent.text.strip()
                    if val and val not in lst:
                        lst.append(val)
        except Exception as exc:
            logger.warning("NERExtractor.extract() erreur : %s", exc)

        return result

    def is_available(self) -> bool:
        """Retourne True si le modèle est chargé et opérationnel."""
        return self._load()
