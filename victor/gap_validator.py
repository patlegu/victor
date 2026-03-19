"""
victor/gap_validator.py

Validation automatique des gaps NER via un SLM local (Ollama).

Rôle : décider si une entité détectée comme gap (vue par NER mais non anonymisée
par le moteur) est réellement sensible et doit être traitée.

Runtime : Ollama (http://localhost:11434) — CPU-first, aucun GPU requis.
Modèle   : qwen2.5:1.5b par défaut (~1 GB Q4).

Fallback : si Ollama n'est pas disponible, retourne decision="unsure" sans
           lever d'exception — la validation humaine reste toujours possible.

Usage :
    from victor.gap_validator import GapValidator

    validator = GapValidator()

    decision = validator.validate(
        text="custom-host-99",
        label="HOSTNAME",
        context="custom-host-99 connected from 172.16.50.1",
    )
    # → {"decision": "ACCEPT", "reason": "...", "confidence": 0.9}

    # Validation d'un batch de candidats issus du GapCollector :
    from victor import GapCollector
    from pathlib import Path

    collector = GapCollector(data_dir=Path("data"))
    results   = validator.validate_candidates(collector)
    # → [{"text": ..., "label": ..., "decision": ..., "reason": ...}, ...]
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_MODEL   = "qwen2.5:1.5b"
_DEFAULT_HOST    = "http://localhost:11434"
_OLLAMA_ENDPOINT = "/api/generate"

# Prompt système — bref et structuré pour les petits modèles
_SYSTEM_PROMPT = """\
You are a security data classifier.
Your only task is to decide whether a detected entity in a log or document \
is sensitive and should be anonymized.
Reply strictly in JSON with three fields:
  "decision"   : "ACCEPT" or "REJECT"
  "confidence" : float between 0.0 and 1.0
  "reason"     : one short sentence (max 20 words)
Do not add any text outside the JSON object.\
"""

# Prompt utilisateur — instancie les variables
_USER_PROMPT_TEMPLATE = """\
Entity  : {text}
Type    : {label}
Context : {context}

Should this entity be anonymized?\
"""


class GapValidator:
    """
    Valide automatiquement les gaps NER via un SLM Ollama local.

    Retourne toujours un dict structuré — ne lève jamais d'exception
    si Ollama est indisponible (decision="unsure").
    """

    def __init__(
        self,
        model: str = _DEFAULT_MODEL,
        host: str = _DEFAULT_HOST,
        timeout: int = 30,
        confidence_threshold: float = 0.7,
    ):
        """
        :param model:                Modèle Ollama à utiliser.
        :param host:                 URL du serveur Ollama.
        :param timeout:              Timeout HTTP en secondes.
        :param confidence_threshold: Seuil en dessous duquel la décision
                                     est déclassée en "unsure".
        """
        self._model     = model
        self._host      = host.rstrip("/")
        self._timeout   = timeout
        self._threshold = confidence_threshold
        self._available: Optional[bool] = None   # None = pas encore testé

    # ------------------------------------------------------------------
    # API publique
    # ------------------------------------------------------------------

    def validate(
        self,
        text: str,
        label: str,
        context: str = "",
    ) -> Dict[str, Any]:
        """
        Valide un gap unique.

        :param text:    Texte de l'entité (ex: "custom-host-99").
        :param label:   Label NER (ex: "HOSTNAME").
        :param context: Extrait de log contenant l'entité.
        :return: {decision, confidence, reason}
                 decision ∈ {"ACCEPT", "REJECT", "unsure"}
        """
        if not self._is_available():
            return self._unsure("Ollama indisponible")

        prompt = _USER_PROMPT_TEMPLATE.format(
            text=text,
            label=label,
            context=context or text,
        )

        raw = self._call_ollama(prompt)
        if raw is None:
            return self._unsure("Erreur appel Ollama")

        return self._parse_response(raw)

    def validate_candidates(
        self,
        collector,
        min_occurrences: int = 3,
        min_sessions: int = 2,
    ) -> List[Dict[str, Any]]:
        """
        Valide tous les candidats d'un GapCollector et applique les décisions.

        - ACCEPT  → collector.accept()
        - REJECT  → collector.reject()
        - unsure  → laissé en pending pour validation humaine

        :param collector:        Instance de GapCollector.
        :param min_occurrences:  Seuil occurrences pour candidates().
        :param min_sessions:     Seuil sessions pour candidates().
        :return: Liste des résultats de validation.
        """
        candidates = collector.candidates(
            min_occurrences=min_occurrences,
            min_sessions=min_sessions,
        )

        if not candidates:
            logger.info("GapValidator : aucun candidat à valider.")
            return []

        results = []
        for gap in candidates:
            text    = gap["text"]
            label   = gap["label"]
            # Récupère le premier contexte disponible
            context = ""
            raw_contexts = gap.get("contexts", [])
            if raw_contexts:
                # contexts = [(session_id, snippet), ...]
                context = raw_contexts[0][1] if isinstance(raw_contexts[0], (list, tuple)) else str(raw_contexts[0])

            decision = self.validate(text, label, context)

            entry = {
                "text":       text,
                "label":      label,
                "decision":   decision["decision"],
                "confidence": decision["confidence"],
                "reason":     decision["reason"],
            }
            results.append(entry)

            if decision["decision"] == "ACCEPT":
                collector.accept(text, label)
                logger.info(
                    "GapValidator ACCEPT [%s] '%s' (%.2f) — %s",
                    label, text, decision["confidence"], decision["reason"],
                )
            elif decision["decision"] == "REJECT":
                collector.reject(text, label)
                logger.info(
                    "GapValidator REJECT [%s] '%s' (%.2f) — %s",
                    label, text, decision["confidence"], decision["reason"],
                )
            else:
                logger.info(
                    "GapValidator unsure [%s] '%s' — laissé en pending",
                    label, text,
                )

        return results

    def is_available(self) -> bool:
        """Retourne True si Ollama est joignable et le modèle disponible."""
        return self._is_available()

    def model_info(self) -> Dict[str, str]:
        """Retourne le modèle et l'hôte configurés."""
        return {"model": self._model, "host": self._host}

    # ------------------------------------------------------------------
    # Helpers internes
    # ------------------------------------------------------------------

    def _is_available(self) -> bool:
        """Vérifie la disponibilité d'Ollama (avec mise en cache)."""
        if self._available is not None:
            return self._available

        try:
            import urllib.request
            req = urllib.request.urlopen(
                f"{self._host}/api/tags", timeout=5
            )
            data = json.loads(req.read().decode())
            available_models = [m["name"] for m in data.get("models", [])]
            # Vérifie si le modèle (ou sa version courte) est disponible
            model_short = self._model.split(":")[0]
            self._available = any(
                self._model in m or model_short in m
                for m in available_models
            )
            if not self._available:
                logger.warning(
                    "GapValidator : modèle '%s' absent d'Ollama. "
                    "Installer avec : ollama pull %s",
                    self._model, self._model,
                )
        except Exception as e:
            logger.warning("GapValidator : Ollama non joignable (%s).", e)
            self._available = False

        return self._available

    def _call_ollama(self, prompt: str) -> Optional[str]:
        """Appelle l'API Ollama /api/generate et retourne la réponse brute."""
        try:
            import urllib.request
            import urllib.error

            payload = json.dumps({
                "model":  self._model,
                "prompt": prompt,
                "system": _SYSTEM_PROMPT,
                "stream": False,
                "options": {
                    "temperature": 0.1,   # déterministe — classification
                    "num_predict": 80,    # la réponse JSON est courte
                },
            }).encode("utf-8")

            req = urllib.request.Request(
                f"{self._host}{_OLLAMA_ENDPOINT}",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode())
                return data.get("response", "")

        except Exception as e:
            logger.warning("GapValidator._call_ollama : erreur : %s", e)
            self._available = False   # invalide le cache si l'appel échoue
            return None

    def _parse_response(self, raw: str) -> Dict[str, Any]:
        """
        Parse la réponse JSON du modèle.

        Robuste aux artefacts courants des petits modèles :
        - texte avant/après le JSON
        - guillemets simples à la place de doubles
        - majuscules/minuscules sur les valeurs
        """
        # Extrait le premier bloc JSON trouvé dans la réponse
        match = re.search(r'\{[^{}]+\}', raw, re.DOTALL)
        if not match:
            logger.debug("GapValidator : pas de JSON dans la réponse : %r", raw[:200])
            return self._unsure("Réponse non parseable")

        try:
            data = json.loads(match.group())
        except json.JSONDecodeError:
            # Tente de corriger les guillemets simples
            try:
                data = json.loads(match.group().replace("'", '"'))
            except json.JSONDecodeError:
                return self._unsure("JSON invalide")

        decision   = str(data.get("decision", "")).upper()
        confidence = float(data.get("confidence", 0.0))
        reason     = str(data.get("reason", "")).strip()

        if decision not in ("ACCEPT", "REJECT"):
            return self._unsure(f"Décision inconnue : {decision!r}")

        if confidence < self._threshold:
            return self._unsure(f"Confiance insuffisante ({confidence:.2f} < {self._threshold})")

        return {
            "decision":   decision,
            "confidence": confidence,
            "reason":     reason,
        }

    @staticmethod
    def _unsure(reason: str) -> Dict[str, Any]:
        return {"decision": "unsure", "confidence": 0.0, "reason": reason}
