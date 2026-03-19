"""
victor/gap_collector.py

Collecte les gaps NER (entités détectées mais non anonymisées par le moteur)
et les agrège pour alimenter les deux pistes d'apprentissage :

  Piste courte : règle regex candidate → custom_rules.json
  Piste longue : exemple annoté spaCy  → data/dataset/

Cycle de vie d'un gap :
  1. record()     — enregistre le gap avec son contexte et la session courante
  2. candidates() — retourne les gaps au-dessus du seuil (occurrences / sessions)
  3. to_regex_rule() / to_spacy_examples() — génère les artefacts pour validation
  4. La validation (accept/reject) est toujours externe — GapCollector ne modifie
     jamais custom_rules.json ni le dataset de lui-même.

Persistance :
  Les gaps sont stockés dans data/gaps/gaps.json — un dict JSON keyed sur
  "{label}::{text}" pour un accès O(1) et une lisibilité directe du fichier.
"""

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Seuils par défaut pour qu'un gap devienne candidat
DEFAULT_MIN_OCCURRENCES = 3   # vus au moins N fois au total
DEFAULT_MIN_SESSIONS    = 2   # dans au moins M sessions distinctes

# Préfixes infrastructure connus — pour la génération de regex HOSTNAME numéroté
_INFRA_PREFIXES = {
    "fw", "rt", "sw", "srv", "dc", "wg", "gw", "vpn",
    "idps", "siem", "proxy", "bastion", "log", "mon", "mgmt",
    "web", "db", "app", "mail", "dns", "ntp", "ldap", "ad",
}

# Suffixes zones privées — pour la détection de FQDN
_PRIVATE_SUFFIXES = {
    "local", "lan", "internal", "corp", "home", "intranet", "priv",
}


class GapCollector:
    """
    Collecte, agrège et score les gaps NER pour proposer des règles
    ou des exemples d'entraînement spaCy.

    Usage avec Anonymizer :
        from victor import Anonymizer
        from victor.gap_collector import GapCollector
        from pathlib import Path

        collector = GapCollector(data_dir=Path("data"))
        anon = Anonymizer(gap_collector=collector)

        result = anon.anonymize_text("Block fw-corp-001 at 10.10.5.23")
        # Les gaps sont automatiquement enregistrés dans le collector.

        for gap in collector.candidates():
            print(gap["text"], gap["label"], gap["occurrences"], gap["sessions"])
            print(collector.to_regex_rule(gap["text"], gap["label"]))
    """

    def __init__(self, data_dir: Optional[Path] = None):
        """
        :param data_dir: Répertoire racine des données.
                         Par défaut : <projet>/data/
        """
        self._data_dir = data_dir or Path(__file__).parent.parent / "data"
        self._gaps_file = self._data_dir / "gaps" / "gaps.json"
        self._state: Dict[str, Dict[str, Any]] = {}
        self._load()

    # ------------------------------------------------------------------
    # API publique
    # ------------------------------------------------------------------

    def record(
        self,
        gaps: Dict[str, List[str]],
        contexts: Optional[List[str]] = None,
        session_id: Optional[str] = None,
    ) -> int:
        """
        Enregistre les gaps d'un appel anonymize.

        :param gaps:       {label: [entity_text, ...]} — retourné par anonymize_*()
        :param contexts:   Textes originaux (pour générer les annotations spaCy).
                           Si fournis, les spans sont calculés par re.search().
        :param session_id: Identifiant de la session courante (UUID si None).
        :return:           Nombre de nouvelles entrées créées.
        """
        if not gaps:
            return 0

        sid = session_id or str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        created = 0

        for label, values in gaps.items():
            for text in values:
                if not text or not text.strip():
                    continue

                key = f"{label}::{text}"
                if key not in self._state:
                    self._state[key] = {
                        "text":        text,
                        "label":       label,
                        "occurrences": 0,
                        "sessions":    [],
                        "first_seen":  now,
                        "last_seen":   now,
                        "contexts":    [],   # [(session_id, snippet)]
                        "status":      "pending",  # pending | accepted | rejected
                    }
                    created += 1

                entry = self._state[key]
                entry["occurrences"] += 1
                entry["last_seen"] = now

                if sid not in entry["sessions"]:
                    entry["sessions"].append(sid)

                # Stocke jusqu'à 5 contextes distincts pour l'annotation
                if contexts and len(entry["contexts"]) < 5:
                    for ctx in contexts:
                        if text in ctx:
                            snippet = self._extract_snippet(ctx, text)
                            pair = (sid, snippet)
                            if pair not in entry["contexts"]:
                                entry["contexts"].append(pair)
                                break

        if created:
            logger.debug("GapCollector : %d nouveau(x) gap(s) enregistré(s)", created)

        self.save()
        return created

    def candidates(
        self,
        min_occurrences: int = DEFAULT_MIN_OCCURRENCES,
        min_sessions: int = DEFAULT_MIN_SESSIONS,
    ) -> List[Dict[str, Any]]:
        """
        Retourne les gaps candidats (au-dessus des seuils, status=pending).

        :param min_occurrences: Nombre minimum d'occurrences totales.
        :param min_sessions:    Nombre minimum de sessions distinctes.
        :return: Liste de dicts triée par occurrences décroissantes.
        """
        result = []
        for entry in self._state.values():
            if entry["status"] != "pending":
                continue
            n_sessions = len(entry["sessions"])
            if entry["occurrences"] >= min_occurrences and n_sessions >= min_sessions:
                result.append({**entry, "sessions": n_sessions})

        result.sort(key=lambda x: x["occurrences"], reverse=True)
        return result

    def accept(self, text: str, label: str) -> bool:
        """Marque un gap comme accepté (validation humaine positive)."""
        return self._set_status(text, label, "accepted")

    def reject(self, text: str, label: str) -> bool:
        """Marque un gap comme rejeté — ne remontera plus dans candidates()."""
        return self._set_status(text, label, "rejected")

    def to_regex_rule(self, text: str, label: str) -> Dict[str, Any]:
        """
        Génère une règle regex candidate pour custom_rules.json.

        Stratégie :
          - HOSTNAME numéroté (fw01, srv-003) → regex préfixe + chiffres
          - HOSTNAME FQDN (host.domain.local) → regex littérale escapée + suffixe variable
          - IP_ADDRESS                         → regex sous-réseau /16
          - Autres                             → regex littérale escapée

        :return: dict compatible custom_rules.json (sans _comment, à ajouter manuellement)
        """
        pattern = self._infer_regex(text, label)
        return {
            "_comment": f"[auto — {label}] généré depuis gap : {text!r}",
            "_note": "Valider avant intégration — pattern inféré automatiquement.",
            "pattern": pattern,
            "replacement": f"{{{{{label}}}}}",
            "isRegex": True,
        }

    def to_spacy_examples(self, text: str, label: str) -> List[Tuple[str, Dict]]:
        """
        Génère des exemples annotés au format spaCy (doc, entities).

        Format : (context_text, {"entities": [(start, end, label)]})

        :return: Liste d'exemples prêts pour spaCy train / Prodigy.
        """
        key = f"{label}::{text}"
        entry = self._state.get(key)
        if not entry or not entry["contexts"]:
            logger.warning(
                "to_spacy_examples : aucun contexte pour '%s' (%s) — "
                "passer des contexts= lors du record()",
                text, label,
            )
            return []

        examples = []
        for _sid, snippet in entry["contexts"]:
            spans = []
            for match in re.finditer(re.escape(text), snippet):
                spans.append((match.start(), match.end(), label))
            if spans:
                examples.append((snippet, {"entities": spans}))

        return examples

    def summary(self) -> Dict[str, int]:
        """Retourne un résumé de l'état du collector."""
        counts = {"pending": 0, "accepted": 0, "rejected": 0}
        for entry in self._state.values():
            counts[entry["status"]] = counts.get(entry["status"], 0) + 1
        counts["total"] = sum(counts.values())
        return counts

    def save(self):
        """Persiste l'état sur disque (data/gaps/gaps.json)."""
        self._gaps_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self._gaps_file, "w", encoding="utf-8") as f:
            json.dump(self._state, f, ensure_ascii=False, indent=2)

    # ------------------------------------------------------------------
    # Helpers internes
    # ------------------------------------------------------------------

    def _load(self):
        """Charge l'état depuis le disque si le fichier existe."""
        if self._gaps_file.exists():
            try:
                with open(self._gaps_file, encoding="utf-8") as f:
                    self._state = json.load(f)
                logger.debug(
                    "GapCollector : %d gaps chargés depuis %s",
                    len(self._state), self._gaps_file,
                )
            except Exception as e:
                logger.warning("GapCollector : erreur chargement %s : %s", self._gaps_file, e)
                self._state = {}

    def _set_status(self, text: str, label: str, status: str) -> bool:
        key = f"{label}::{text}"
        if key not in self._state:
            logger.warning("GapCollector : gap '%s' (%s) introuvable", text, label)
            return False
        self._state[key]["status"] = status
        self.save()
        return True

    def _extract_snippet(self, text: str, entity: str, window: int = 80) -> str:
        """Extrait un snippet centré sur l'entité (±window caractères)."""
        idx = text.find(entity)
        if idx == -1:
            return text[:160]
        start = max(0, idx - window)
        end = min(len(text), idx + len(entity) + window)
        snippet = text[start:end]
        if start > 0:
            snippet = "…" + snippet
        if end < len(text):
            snippet = snippet + "…"
        return snippet

    def _infer_regex(self, text: str, label: str) -> str:
        """Infère un pattern regex depuis le texte et le label."""

        # HOSTNAME — format numéroté (ex: fw01, srv-003, dc-1024)
        if label == "HOSTNAME":
            m = re.match(r'^([a-zA-Z]+)[-_]?(\d+)$', text)
            if m:
                prefix = re.escape(m.group(1))
                return f"\\b{prefix}[-_]?\\d{{2,4}}\\b"

            # HOSTNAME — FQDN (ex: host.company.local)
            parts = text.split(".")
            if len(parts) >= 2 and parts[-1] in _PRIVATE_SUFFIXES:
                suffix = re.escape(parts[-1])
                return (
                    f"\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{{0,61}}[a-zA-Z0-9])?\\.)"
                    f"+{suffix}\\b"
                )

        # IP_ADDRESS — généralise au sous-réseau /16
        if label in ("IP_ADDRESS", "IP_SUBNET"):
            m = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', text)
            if m:
                a, b = m.group(1), m.group(2)
                return f"\\b{re.escape(a)}\\.{re.escape(b)}\\.\\d{{1,3}}\\.\\d{{1,3}}\\b"

        # Fallback — littérale escapée avec word boundary
        escaped = re.escape(text)
        return f"\\b{escaped}\\b"
