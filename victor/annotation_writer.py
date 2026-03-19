"""
victor/annotation_writer.py

Écrit les exemples annotés validés dans le dataset spaCy (piste longue).

Deux formats de sortie :
  - JSON lisible  : data/dataset/annotations.json  — pour review humaine
  - spaCy binaire : data/dataset/train.spacy        — pour spacy train

Le format JSON est le format de travail. Le binaire est regénéré depuis le JSON
via compile() — appeler cette méthode avant chaque cycle d'entraînement.

Format JSON interne :
  [
    {
      "text":     "custom-host-99 connected from 172.16.50.1",
      "label":    "HOSTNAME",
      "source":   "gap::HOSTNAME::custom-host-99",
      "entities": [[0, 13, "HOSTNAME"]],
      "validated": true
    },
    ...
  ]

Usage :
    from victor.annotation_writer import AnnotationWriter
    from victor.gap_collector import GapCollector

    collector = GapCollector()
    writer = AnnotationWriter()

    for gap in collector.candidates():
        examples = collector.to_spacy_examples(gap["text"], gap["label"])
        added = writer.add_examples(examples, label=gap["label"], source_key=f"gap::{gap['label']}::{gap['text']}")
        if added:
            collector.accept(gap["text"], gap["label"])

    # Avant spacy train :
    count = writer.compile()
    print(f"{count} exemples compilés dans train.spacy")
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_DEFAULT_DATA_DIR = Path(__file__).parent.parent / "data" / "dataset"


class AnnotationWriter:
    """
    Gère l'ajout d'exemples annotés au dataset et la compilation en format spaCy.
    """

    def __init__(self, data_dir: Optional[Path] = None):
        """
        :param data_dir: Répertoire du dataset.
                         Par défaut : <projet>/data/dataset/
        """
        self._data_dir = data_dir or _DEFAULT_DATA_DIR
        self._json_path = self._data_dir / "annotations.json"
        self._spacy_path = self._data_dir / "train.spacy"

    def add_examples(
        self,
        examples: List[Tuple[str, Dict]],
        label: str,
        source_key: str = "",
    ) -> int:
        """
        Ajoute des exemples annotés au dataset JSON.

        Déduplique sur (text, entities) — un même contexte avec les mêmes
        spans n'est pas ajouté deux fois.

        :param examples:   [(context_text, {"entities": [(start, end, label)]})]
                           Format retourné par GapCollector.to_spacy_examples()
        :param label:      Label NER principal de l'exemple (pour le logging).
        :param source_key: Clé de traçabilité — identifie le gap d'origine.
        :return:           Nombre d'exemples effectivement ajoutés.
        """
        if not examples:
            return 0

        dataset = self._load()
        existing = {
            (e["text"], str(e["entities"]))
            for e in dataset
        }

        added = 0
        for text, annotation in examples:
            entities = annotation.get("entities", [])
            dedup_key = (text, str(entities))
            if dedup_key in existing:
                continue

            dataset.append({
                "text":      text,
                "label":     label,
                "source":    source_key,
                "entities":  entities,
                "validated": True,
            })
            existing.add(dedup_key)
            added += 1

        if added:
            self._save(dataset)
            logger.info(
                "AnnotationWriter : %d exemple(s) ajouté(s) [%s]", added, label
            )

        return added

    def compile(self) -> int:
        """
        Compile annotations.json → train.spacy (format binaire spaCy DocBin).

        Appeler avant chaque cycle `spacy train`.

        :return: Nombre d'exemples compilés (0 si spaCy non installé).
        """
        dataset = self._load()
        if not dataset:
            logger.warning("AnnotationWriter.compile : dataset vide — rien à compiler.")
            return 0

        try:
            import spacy
            from spacy.tokens import DocBin
        except ImportError:
            logger.error(
                "AnnotationWriter.compile : spaCy non disponible — "
                "installer avec : pip install spacy"
            )
            return 0

        # Charge le modèle de tokenisation — n'importe quel modèle fait l'affaire
        # car on n'a besoin que du tokenizer pour aligner les spans.
        try:
            nlp = spacy.blank("en")
        except Exception as e:
            logger.error("AnnotationWriter.compile : impossible d'init spaCy blank : %s", e)
            return 0

        db = DocBin()
        skipped = 0

        for entry in dataset:
            text = entry.get("text", "")
            entities = entry.get("entities", [])
            if not text:
                continue

            doc = nlp.make_doc(text)
            spans = []
            for start_char, end_char, ent_label in entities:
                span = doc.char_span(start_char, end_char, label=ent_label)
                if span is None:
                    logger.debug(
                        "AnnotationWriter : span (%d, %d, %s) hors limites dans '%s…' — ignoré",
                        start_char, end_char, ent_label, text[:40],
                    )
                    skipped += 1
                    continue
                spans.append(span)

            doc.ents = spans
            db.add(doc)

        self._data_dir.mkdir(parents=True, exist_ok=True)
        db.to_disk(self._spacy_path)

        compiled = len(dataset) - skipped
        logger.info(
            "AnnotationWriter : %d exemple(s) compilés dans %s (%d span(s) ignorés)",
            compiled, self._spacy_path, skipped,
        )
        return compiled

    def stats(self) -> Dict:
        """Retourne des statistiques sur le dataset courant."""
        dataset = self._load()
        label_counts: Dict[str, int] = {}
        for entry in dataset:
            label = entry.get("label", "UNKNOWN")
            label_counts[label] = label_counts.get(label, 0) + 1

        return {
            "total_examples": len(dataset),
            "by_label":       label_counts,
            "json_path":      str(self._json_path),
            "spacy_path":     str(self._spacy_path) if self._spacy_path.exists() else None,
        }

    # ------------------------------------------------------------------
    # Helpers internes
    # ------------------------------------------------------------------

    def _load(self) -> List[Dict]:
        """Charge le dataset JSON. Retourne [] si le fichier n'existe pas."""
        if not self._json_path.exists():
            return []
        try:
            with open(self._json_path, encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error("AnnotationWriter : erreur lecture %s : %s", self._json_path, e)
            return []

    def _save(self, dataset: List[Dict]):
        """Écrit le dataset JSON sur disque."""
        self._data_dir.mkdir(parents=True, exist_ok=True)
        with open(self._json_path, "w", encoding="utf-8") as f:
            json.dump(dataset, f, ensure_ascii=False, indent=2)
