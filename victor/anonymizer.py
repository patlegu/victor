"""
victor/anonymizer.py

Anonymiseur de logs et documents de sécurité — projet Victor.

Architecture :
  AnonyfilesEngine (victor/engine/) = moteur — regex, NER, remplacement, réversibilité
  NERExtractor     (victor/)         = observabilité — détecte les gaps moteur
  Anonymizer       (ce fichier)      = coordinateur — batch, session, cohérence

Flux d'anonymisation (anonymize_text) :
  1. Moteur traite le texte : custom rules regex + NER spaCy intégré
     → cohérence intra-session via ReplacementGenerator stateful (même entité = même token)
  2. NERExtractor analyse le texte original (observabilité — log des gaps moteur)
  3. Retour : {anonymized_text, mapping, entities_detected}

Cohérence garantie :
  - intra-texte  : session stateful du ReplacementGenerator
  - cross-appels : idem (même instance de moteur, compteurs partagés)
  - cross-fichiers (batch) : idem — session unique sur tout le batch

Limite connue (engine) :
  Le moteur applique les custom rules AVANT le NER. Les tokens {{...}} produits par
  les règles regex s'intègrent dans le texte NER, ce qui peut dans certains contextes
  classer des spans adjacents comme de nouvelles entités.
  Mitigation : _sanitize_for_ner() dans engine.py remplace {{...}} par des espaces
  de même longueur avant de passer le texte au NER.
"""

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from .gap_collector import GapCollector

logger = logging.getLogger(__name__)

# Modèle AnonyNER — résolution par ordre de priorité :
#   1. Package installé : en_anonyner  (pip install dist/en_anonyner-*.tar.gz)
#   2. Répertoire local : models/anonyner_model/model-best  (après entraînement)
#   3. Fallback         : None → en_core_web_md
_ANONYNER_PACKAGE = "en_anonyner"
_ANONYNER_MODEL_PATH = Path(__file__).parent.parent / "models" / "anonyner_model" / "model-best"

_DEFAULT_RULES_PATH = Path(__file__).parent / "config" / "custom_rules_security.json"


def _resolve_anonyner_model() -> Optional[str]:
    """Retourne le nom/chemin du modèle AnonyNER disponible, par ordre de priorité."""
    import importlib.util
    if importlib.util.find_spec(_ANONYNER_PACKAGE) is not None:
        return _ANONYNER_PACKAGE
    if _ANONYNER_MODEL_PATH.exists():
        return str(_ANONYNER_MODEL_PATH)
    return None


class Anonymizer:
    """
    Anonymise des logs et documents de sécurité.

    API principale :
      anonymize_text(text)              → anonymise un texte en mémoire
      anonymize_batch(texts)            → batch cohérent multi-textes
      deanonymize_text(anonymized_text) → réversibilité via mapping de session
      get_session_mapping()             → mapping courant {original: token}
      reset_session()                   → repart d'une session vierge

    Exemple :
        from victor import Anonymizer

        anon = Anonymizer()
        result = anon.anonymize_text("Block IP 10.0.0.1 on fw01.company.local")
        print(result["anonymized_text"])
        # → "Block IP {{IP_PRIVE}} on {{HOSTNAME}}"
    """

    def __init__(
        self,
        config: Optional[Dict] = None,
        custom_rules_path: Optional[str] = None,
        gap_collector: Optional["GapCollector"] = None,
    ):
        """
        :param config:           Configuration passée à AnonyfilesEngine.
                                 Voir _default_config() pour les valeurs par défaut.
        :param custom_rules_path: Chemin vers un fichier custom_rules.json.
                                  Si None, utilise victor/config/custom_rules_security.json.
        :param gap_collector:    Instance de GapCollector pour l'auto-apprentissage.
                                 Si None, les gaps sont seulement loggés (comportement actuel).
        """
        self.config = config or self._default_config()
        self._custom_rules: Optional[List[Dict]] = self._load_custom_rules(custom_rules_path)
        self._gap_collector = gap_collector

        # Lazy-init — le chargement spaCy est coûteux, on attend le premier appel
        self._engine = None
        self._ner = None
        self._ner_ready: bool = False

        # Mapping de session accumulé sur tous les appels
        # Format : {texte_original: token_anonyme}
        self._session_mapping: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _default_config(self) -> Dict:
        anonyner = _resolve_anonyner_model()
        spacy_model = anonyner or "en_core_web_md"
        if not anonyner:
            logger.warning(
                "AnonyNER introuvable (package '%s' ni répertoire '%s') — "
                "fallback en_core_web_md. Entités cyber non détectées. "
                "Installer avec : pip install dist/en_anonyner-*.tar.gz",
                _ANONYNER_PACKAGE,
                _ANONYNER_MODEL_PATH,
            )
        else:
            logger.debug("AnonyNER résolu : %s", spacy_model)

        return {
            "spacy_model": spacy_model,
            # Entités NLP classiques
            "anonymizePersons": True,
            "anonymizeLocations": True,
            "anonymizeOrgs": True,
            "anonymizeEmails": True,
            "anonymizeDates": True,
            "anonymizeMisc": False,
            "anonymizePhones": True,
            # Labels AnonyNER — injectés via extra_labels
            "extra_labels": [
                "IP_ADDRESS", "IP_SUBNET",
                "HOSTNAME", "DOMAIN",
                "CVE",
                "MAC_ADDRESS",
                "SERVICE_ACCOUNT",
                "FIREWALL_RULE",
                "INTERFACE",
                "PORT_NUMBER",
                "VPN_USER",
                "PROTOCOL",
                "SERVICE",
            ] if anonyner else [],
            # Tags de remplacement (préfixes lisibles)
            "replacements": {
                "PER":            {"type": "codes", "options": {"prefix": "PERSON"}},
                "LOC":            {"type": "codes", "options": {"prefix": "LOCATION"}},
                "ORG":            {"type": "codes", "options": {"prefix": "ORG"}},
                "EMAIL":          {"type": "codes", "options": {"prefix": "EMAIL"}},
                "DATE":           {"type": "codes", "options": {"prefix": "DATE"}},
                "MISC":           {"type": "codes", "options": {"prefix": "MISC"}},
                "PHONE":          {"type": "codes", "options": {"prefix": "PHONE"}},
                "IBAN":           {"type": "codes", "options": {"prefix": "IBAN"}},
                "IP_ADDRESS":     {"type": "codes", "options": {"prefix": "IP"}},
                "IP_SUBNET":      {"type": "codes", "options": {"prefix": "SUBNET"}},
                "HOSTNAME":       {"type": "codes", "options": {"prefix": "HOST"}},
                "DOMAIN":         {"type": "codes", "options": {"prefix": "DOMAIN"}},
                "CVE":            {"type": "codes", "options": {"prefix": "CVE"}},
                "MAC_ADDRESS":    {"type": "codes", "options": {"prefix": "MAC"}},
                "SERVICE_ACCOUNT":{"type": "codes", "options": {"prefix": "SVC_ACCOUNT"}},
                "FIREWALL_RULE":  {"type": "codes", "options": {"prefix": "FW_RULE"}},
                "INTERFACE":      {"type": "codes", "options": {"prefix": "IFACE"}},
                "PORT_NUMBER":    {"type": "codes", "options": {"prefix": "PORT"}},
                "VPN_USER":       {"type": "codes", "options": {"prefix": "VPN_USER"}},
                "PROTOCOL":       {"type": "codes", "options": {"prefix": "PROTO"}},
                "SERVICE":        {"type": "codes", "options": {"prefix": "SVC"}},
            },
        }

    def _load_custom_rules(self, path: Optional[str]) -> Optional[List[Dict]]:
        resolved = Path(path) if path else _DEFAULT_RULES_PATH
        try:
            with open(resolved, encoding="utf-8") as f:
                rules = json.load(f)
            logger.info("custom_rules chargées depuis %s (%d règles)", resolved, len(rules))
            return rules
        except FileNotFoundError:
            logger.debug("custom_rules introuvable (%s) — désactivées", resolved)
            return None
        except Exception as e:
            logger.warning("Erreur chargement custom_rules: %s", e)
            return None

    # ------------------------------------------------------------------
    # Lazy-init
    # ------------------------------------------------------------------

    def _get_engine(self):
        """Lazy-init : crée le moteur AnonyfilesEngine au premier appel."""
        if self._engine is None:
            from .engine import AnonyfilesEngine
            self._engine = AnonyfilesEngine(
                config=self.config,
                custom_replacement_rules=self._custom_rules,
            )
            logger.info(
                "AnonyfilesEngine initialisé (spaCy: %s, labels_cyber: %d, custom_rules: %s)",
                self.config.get("spacy_model"),
                len(self.config.get("extra_labels", [])),
                "oui" if self._custom_rules else "non",
            )
        return self._engine

    def _get_ner(self):
        """
        Lazy-init du NERExtractor, partageant le chemin modèle avec le moteur.
        Retourne None si AnonyNER n'est pas disponible (graceful degradation).
        """
        if not self._ner_ready:
            try:
                from .ner_extractor import NERExtractor
                anonyner = _resolve_anonyner_model()
                if anonyner:
                    self._ner = NERExtractor(model_path=Path(anonyner))
                    logger.debug("NERExtractor initialisé (modèle : %s)", anonyner)
                else:
                    logger.debug("NERExtractor désactivé — AnonyNER introuvable")
            except ImportError:
                logger.debug("NERExtractor non importable — désactivé")
            self._ner_ready = True
        return self._ner

    # ------------------------------------------------------------------
    # API publique
    # ------------------------------------------------------------------

    def anonymize_text(self, text: str) -> Dict[str, Any]:
        """
        Anonymise un texte en mémoire.

        :param text: Texte brut à anonymiser.
        :return: {anonymized_text, total_replacements, mapping, entities_detected}
        """
        engine = self._get_engine()
        ner = self._get_ner()

        anonymized, report = engine.anonymize_text(text)
        self._session_mapping.update(self._sanitize_mapping(report.get("mapping", {})))

        ner_entities: Dict[str, List[str]] = {}
        ner_gaps: Dict[str, List[str]] = {}
        if ner and ner.is_available():
            ner_entities = ner.extract(text)
            for label, vals in ner_entities.items():
                for val in vals:
                    if val and val not in self._session_mapping:
                        logger.debug(
                            "NER gap : '%s' (%s) détecté mais non anonymisé par le moteur",
                            val, label,
                        )
                        ner_gaps.setdefault(label, []).append(val)

        if self._gap_collector and ner_gaps:
            self._gap_collector.record(ner_gaps, contexts=[text])

        return {
            "anonymized_text": anonymized,
            "total_replacements": report["total_replacements"],
            "mapping": dict(self._session_mapping),
            "entities_detected": ner_entities,
            "ner_gaps": ner_gaps,
        }

    def anonymize_batch(
        self,
        texts: List[str],
        reset_session: bool = False,
    ) -> Dict[str, Any]:
        """
        Anonymise un lot de textes avec cohérence garantie sur tout le batch.
        La même entité reçoit le même token grâce à la session stateful du moteur.

        :param texts:         Liste de textes à anonymiser.
        :param reset_session: Si True, repart d'une session vierge avant le batch.
        :return: {results: [{anonymized_text, replacements}], session_mapping, total_texts, ner_gaps}
        """
        if reset_session:
            self.reset_session()

        engine = self._get_engine()
        ner = self._get_ner()
        original_texts = list(texts)

        # Phase 1 : Anonymisation texte par texte (moteur stateful)
        results = []
        for text in original_texts:
            anonymized, report = engine.anonymize_text(text)
            self._session_mapping.update(self._sanitize_mapping(report.get("mapping", {})))
            results.append({
                "anonymized_text": anonymized,
                "replacements": report["total_replacements"],
            })

        # Phase 2 : NER sur textes originaux — inventaire des gaps (observabilité)
        ner_gaps: Dict[str, List[str]] = {}
        if ner and ner.is_available():
            for text in original_texts:
                for label, vals in ner.extract(text).items():
                    for val in vals:
                        if val and val not in self._session_mapping:
                            lst = ner_gaps.setdefault(label, [])
                            if val not in lst:
                                lst.append(val)
                                logger.debug(
                                    "NER gap batch : '%s' (%s) non anonymisé par le moteur",
                                    val, label,
                                )

        if self._gap_collector and ner_gaps:
            self._gap_collector.record(ner_gaps, contexts=original_texts)

        return {
            "results": results,
            "session_mapping": dict(self._session_mapping),
            "total_texts": len(original_texts),
            "ner_gaps": ner_gaps,
        }

    def deanonymize_text(self, anonymized_text: str) -> Dict[str, Any]:
        """
        Réintroduit les valeurs originales à partir du mapping de session courant.

        :param anonymized_text: Texte contenant des tokens (ex: {{HOST_001}}).
        :return: {original_text, replacements_made}
        """
        result = anonymized_text
        count = 0

        # Tri par longueur décroissante pour éviter les collisions
        for original, token in sorted(
            self._session_mapping.items(), key=lambda x: len(x[1]), reverse=True
        ):
            if token in result:
                result = result.replace(token, original)
                count += 1

        return {"original_text": result, "replacements_made": count}

    def get_session_mapping(self) -> Dict[str, Any]:
        """Retourne le mapping courant {entité_originale: token}."""
        return {"mapping": dict(self._session_mapping)}

    def reset_session(self) -> Dict[str, Any]:
        """Repart d'une session vierge (efface le mapping accumulé)."""
        self._session_mapping.clear()
        if self._engine is not None:
            self._engine.reset_state()
        return {"status": "ok", "message": "Session réinitialisée"}

    # ------------------------------------------------------------------
    # Helpers internes
    # ------------------------------------------------------------------

    def _sanitize_mapping(self, mapping: Dict[str, str]) -> Dict[str, str]:
        """
        Filtre les entrées corrompues du mapping (clés contenant '{' ou '}').
        Ces artefacts peuvent apparaître si le NER analyse du texte post-custom-rules
        contenant des tokens {{...}} — mitigation partielle en attendant le fix engine.
        """
        clean = {}
        corrupted = []
        for original, token in mapping.items():
            if '{' in original or '}' in original:
                corrupted.append(original)
            else:
                clean[original] = token
        if corrupted:
            logger.warning(
                "Entrées corrompues filtrées du mapping : %s",
                corrupted,
            )
        return clean
