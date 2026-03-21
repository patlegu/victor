"""
victor/log_processor.py

Traitement par batch de fichiers logs.

Principe :
  - Un batch = tous les fichiers présents dans inbox/ au moment de l'appel
  - Session unique partagée sur tout le batch : même entité → même token dans
    tous les fichiers (ex: IP_001 dans firewall.log == IP_001 dans ids.log)
  - Routing automatique selon les gaps NER résiduels :
      clean/   → 0 gap détecté — anonymisation complète
      partial/ → gaps résiduels — review recommandée avant diffusion
      error/   → exception pendant le traitement

Sorties par batch (outbox/batch_YYYYMMDD_HHMMSS/) :
  ├── batch_mapping.json   — mapping global {original: token}
  ├── batch_report.json    — résumé du batch (stats, fichiers, gaps)
  ├── clean/               — fichiers .anon sans gap résiduel
  ├── partial/             — fichiers .anon avec gaps résiduels
  └── error/               — fichiers d'erreur (.error.txt)

Archivage des originaux :
  Si archive_dir est fourni, les fichiers sources sont copiés dans
  archive_dir/ après traitement au lieu d'être supprimés (move_inbox=True)
  ou laissés en place (move_inbox=False).
  Structure : archive_dir/<batch_id>/<nom_du_fichier_original>

Formats supportés :
  Tout fichier lisible en texte (UTF-8 / latin-1 fallback).
  Les fichiers binaires non décodables sont routés vers error/.

Usage :
    from pathlib import Path
    from victor import Anonymizer, GapCollector
    from victor.log_processor import LogProcessor

    processor = LogProcessor(
        inbox_dir  = Path("logs/inbox"),
        outbox_dir = Path("logs/outbox"),
    )
    report = processor.process_batch()
    print(f"Batch {report['batch_id']} — {report['total_files']} fichier(s)")
    print(f"  clean: {report['clean']}  partial: {report['partial']}  error: {report['error']}")
"""

import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Encodages tentés dans l'ordre pour la lecture des fichiers
_ENCODINGS = ["utf-8", "utf-8-sig", "latin-1", "cp1252"]

# Suffixe ajouté aux fichiers anonymisés
_ANON_SUFFIX = ".anon"
_ERROR_SUFFIX = ".error.txt"


class LogProcessor:
    """
    Traite un batch de fichiers logs depuis inbox/ vers outbox/.

    Une session Anonymizer unique est partagée sur tout le batch —
    la cohérence des tokens est garantie entre tous les fichiers.
    """

    def __init__(
        self,
        inbox_dir: Path,
        outbox_dir: Path,
        anonymizer=None,
        gap_collector=None,
        move_inbox: bool = True,
        archive_dir: Optional[Path] = None,
    ):
        """
        :param inbox_dir:     Répertoire source — fichiers à anonymiser.
        :param outbox_dir:    Répertoire de sortie — batches horodatés.
        :param anonymizer:    Instance Anonymizer à utiliser.
                              Si None, une instance par défaut est créée.
        :param gap_collector: Instance GapCollector (optionnel).
        :param move_inbox:    Si True, les fichiers traités avec succès sont
                              supprimés de inbox/ après traitement.
                              Si False, ils sont laissés en place (mode dry-run).
        :param archive_dir:   Si fourni, les originaux sont copiés dans
                              archive_dir/<batch_id>/ avant suppression.
                              Ignoré si move_inbox=False.
        """
        self.inbox_dir      = Path(inbox_dir)
        self.outbox_dir     = Path(outbox_dir)
        self.move_inbox     = move_inbox
        self.archive_dir    = Path(archive_dir) if archive_dir else None
        self._gap_collector = gap_collector

        if anonymizer is not None:
            self._anon = anonymizer
        else:
            from .anonymizer import Anonymizer
            self._anon = Anonymizer(gap_collector=gap_collector)

    # ------------------------------------------------------------------
    # API publique
    # ------------------------------------------------------------------

    def process_batch(self, pattern: str = "*") -> Dict[str, Any]:
        """
        Traite tous les fichiers de inbox/ correspondant au pattern.

        La session Anonymizer est réinitialisée en début de batch pour
        garantir des compteurs indépendants entre batches.

        :param pattern: Glob pattern pour filtrer les fichiers (ex: "*.log").
                        Par défaut "*" — tous les fichiers.
        :return: Rapport du batch (dict).
        """
        files = sorted(
            f for f in self.inbox_dir.glob(pattern)
            if f.is_file()
        )

        if not files:
            logger.info("LogProcessor : inbox vide (%s) — rien à traiter.", self.inbox_dir)
            return self._empty_report()

        # Identifiant de batch horodaté
        batch_id  = datetime.now(timezone.utc).strftime("batch_%Y%m%d_%H%M%S")
        batch_dir = self.outbox_dir / batch_id
        (batch_dir / "clean").mkdir(parents=True, exist_ok=True)
        (batch_dir / "partial").mkdir(parents=True, exist_ok=True)
        (batch_dir / "error").mkdir(parents=True, exist_ok=True)

        # Session vierge pour ce batch
        self._anon.reset_session()

        report_files: List[Dict[str, Any]] = []
        counts = {"clean": 0, "partial": 0, "error": 0}

        logger.info(
            "LogProcessor : début batch %s — %d fichier(s) dans %s",
            batch_id, len(files), self.inbox_dir,
        )

        for file_path in files:
            result = self._process_file(file_path, batch_dir)
            report_files.append(result)
            counts[result["status"]] += 1

            logger.info(
                "  [%s] %s — %d remplacement(s), %d gap(s)",
                result["status"].upper(),
                file_path.name,
                result["replacements"],
                result["gap_count"],
            )

        # Mapping global de la session (tous fichiers confondus)
        session_mapping = self._anon.get_session_mapping()["mapping"]

        # batch_mapping.json
        mapping_path = batch_dir / "batch_mapping.json"
        with open(mapping_path, "w", encoding="utf-8") as f:
            json.dump(session_mapping, f, ensure_ascii=False, indent=2)

        # batch_report.json
        report = {
            "batch_id":    batch_id,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "total_files": len(files),
            "clean":       counts["clean"],
            "partial":     counts["partial"],
            "error":       counts["error"],
            "total_tokens": len(session_mapping),
            "files":       report_files,
        }
        report_path = batch_dir / "batch_report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        logger.info(
            "LogProcessor : batch %s terminé — clean:%d partial:%d error:%d — "
            "%d token(s) dans le mapping global",
            batch_id, counts["clean"], counts["partial"], counts["error"],
            len(session_mapping),
        )

        return report

    def list_batches(self) -> List[Dict[str, Any]]:
        """
        Liste les batches existants dans outbox/ avec leur résumé.

        :return: Liste de dicts triés par date décroissante.
        """
        batches = []
        for batch_dir in sorted(self.outbox_dir.iterdir(), reverse=True):
            if not batch_dir.is_dir() or not batch_dir.name.startswith("batch_"):
                continue
            report_path = batch_dir / "batch_report.json"
            if report_path.exists():
                try:
                    with open(report_path, encoding="utf-8") as f:
                        batches.append(json.load(f))
                except Exception:
                    batches.append({"batch_id": batch_dir.name, "error": "rapport illisible"})
        return batches

    def get_batch_mapping(self, batch_id: str) -> Dict[str, str]:
        """
        Retourne le mapping global d'un batch.

        :param batch_id: Identifiant du batch (ex: "batch_20260319_143022").
        :return: {original: token} ou {} si le batch n'existe pas.
        """
        mapping_path = self.outbox_dir / batch_id / "batch_mapping.json"
        if not mapping_path.exists():
            logger.warning("LogProcessor : mapping introuvable pour %s", batch_id)
            return {}
        with open(mapping_path, encoding="utf-8") as f:
            return json.load(f)

    # ------------------------------------------------------------------
    # Helpers internes
    # ------------------------------------------------------------------

    def _process_file(self, file_path: Path, batch_dir: Path) -> Dict[str, Any]:
        """Traite un fichier unique et l'écrit dans le bon sous-répertoire."""
        base_result = {
            "filename":     file_path.name,
            "size_bytes":   file_path.stat().st_size,
            "status":       "error",
            "replacements": 0,
            "gap_count":    0,
            "gaps":         {},
            "error":        None,
        }

        # Lecture du fichier
        text, encoding = self._read_file(file_path)
        if text is None:
            base_result["error"] = f"Impossible de décoder le fichier (encodages tentés : {_ENCODINGS})"
            self._write_error(file_path, batch_dir, base_result["error"])
            return base_result

        # Anonymisation
        try:
            result = self._anon.anonymize_text(text)
        except Exception as exc:
            base_result["error"] = str(exc)
            self._write_error(file_path, batch_dir, str(exc))
            logger.warning("LogProcessor : erreur anonymisation %s : %s", file_path.name, exc)
            return base_result

        anonymized_text = result["anonymized_text"]
        replacements    = result["total_replacements"]
        ner_gaps        = result.get("ner_gaps", {})
        gap_count       = sum(len(v) for v in ner_gaps.values())

        # Routing
        status     = "partial" if gap_count > 0 else "clean"
        output_dir = batch_dir / status
        out_path   = output_dir / (file_path.name + _ANON_SUFFIX)

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(anonymized_text)

        # Archivage + suppression de l'original si move_inbox activé
        if self.move_inbox:
            if self.archive_dir is not None:
                archive_batch_dir = self.archive_dir / batch_dir.name
                archive_batch_dir.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copy2(file_path, archive_batch_dir / file_path.name)
                except Exception as e:
                    logger.warning(
                        "LogProcessor : impossible d'archiver %s : %s", file_path, e
                    )
            try:
                file_path.unlink()
            except Exception as e:
                logger.warning(
                    "LogProcessor : impossible de supprimer %s : %s", file_path, e
                )

        base_result.update({
            "status":       status,
            "replacements": replacements,
            "gap_count":    gap_count,
            "gaps":         ner_gaps,
            "encoding":     encoding,
            "output":       str(out_path),
        })
        return base_result

    def _read_file(self, path: Path):
        """
        Lit un fichier texte en testant plusieurs encodages.

        :return: (texte, encodage) ou (None, None) si tous les encodages échouent.
        """
        for enc in _ENCODINGS:
            try:
                text = path.read_text(encoding=enc)
                return text, enc
            except (UnicodeDecodeError, LookupError):
                continue
        return None, None

    def _write_error(self, file_path: Path, batch_dir: Path, message: str):
        """Écrit un fichier d'erreur dans batch_dir/error/."""
        out_path = batch_dir / "error" / (file_path.name + _ERROR_SUFFIX)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(f"Fichier : {file_path}\n")
            f.write(f"Erreur  : {message}\n")

    @staticmethod
    def _empty_report() -> Dict[str, Any]:
        return {
            "batch_id":    None,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "total_files": 0,
            "clean":       0,
            "partial":     0,
            "error":       0,
            "total_tokens": 0,
            "files":       [],
        }
