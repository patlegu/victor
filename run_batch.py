#!/usr/bin/env python3
"""
run_batch.py — Traitement par batch des logs Victor

Traite tous les fichiers présents dans logs/inbox/, puis affiche
un résumé du batch et les gaps NER détectés.

Usage :
    source venv/bin/activate
    python run_batch.py

Résultats :
    logs/outbox/batch_YYYYMMDD_HHMMSS/
        clean/      — fichiers entièrement anonymisés (0 gap)
        partial/    — fichiers avec gaps résiduels (relecture recommandée)
        error/      — fichiers non traités (encodage inconnu, binaire…)
        batch_mapping.json  — mapping global {valeur_originale: token}
        batch_report.json   — statistiques du batch

Gaps NER :
    Les gaps (entités détectées par AnonyNER mais non anonymisées) sont
    accumulés dans data/gaps/gaps.json entre les sessions.
    Utiliser GapValidator ou RuleWriter pour les traiter.
"""
from pathlib import Path
from victor import LogProcessor, GapCollector

collector = GapCollector(data_dir=Path("data"))

processor = LogProcessor(
    inbox_dir     = Path("logs/inbox"),
    outbox_dir    = Path("logs/outbox"),
    gap_collector = collector,
    archive_dir   = Path("logs/archive"),
)

report = processor.process_batch()

print(f"\nBatch : {report['batch_id']}")
print(f"  clean   : {report['clean']}")
print(f"  partial : {report['partial']}")
print(f"  error   : {report['error']}")
print(f"  tokens  : {report['total_tokens']}")

candidates = collector.candidates(min_occurrences=1, min_sessions=1)
if candidates:
    print(f"\nGaps détectés ({len(candidates)}) :")
    for gap in candidates:
        print(f"  [{gap['label']}] {gap['text']}  ({gap['occurrences']}x)")
else:
    print("\nAucun gap détecté.")
