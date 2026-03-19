# Victor

Anonymiseur de logs et documents de sécurité.

Détecte et remplace les entités sensibles (IPs, hostnames, CVE, MAC, comptes de service…)
par des tokens pseudonymisés cohérents sur toute une session.
S'améliore automatiquement au fil des logs via une boucle de détection de gaps NER.

---

## Installation

```bash
python -m venv venv && source venv/bin/activate
pip install -e .

# Modèle AnonyNER (recommandé — entités cyber)
pip install https://github.com/patlegu/anonyfiles/releases/download/anonyner-v3.0.0/en_anonyner-3.0.0.tar.gz

# Modèle générique (fallback sans entités cyber)
# python -m spacy download en_core_web_md
```

---

## Utilisation rapide

```python
from victor import Anonymizer

anon = Anonymizer()

result = anon.anonymize_text("Block IP 192.168.1.50 on fw01.company.local — CVE-2024-12345")
print(result["anonymized_text"])
# → Block IP {{IP_PRIVE}} on {{HOSTNAME}} — {{CVE_ID}}

print(result["mapping"])
# → {'192.168.1.50': '{{IP_PRIVE}}', 'fw01.company.local': '{{HOSTNAME}}', ...}
```

### Batch cohérent

La même entité reçoit le même token sur tout le batch.

```python
results = anon.anonymize_batch([
    "fw01.corp.local rejected connection from 10.0.0.5",
    "alert on fw01.corp.local : CVE-2024-9999 detected",
])
print(results["session_mapping"])
print(results["ner_gaps"])   # entités vues par le NER mais non anonymisées
```

### Désanonymisation

```python
original = anon.deanonymize_text(result["anonymized_text"])
print(original["original_text"])
```

### Session

```python
anon.reset_session()   # repart d'une session vierge
anon.get_session_mapping()   # mapping complet de la session courante
```

---

## Traitement par batch de fichiers

Victor traite les fichiers de logs en batch depuis un répertoire `inbox/`.
Tous les fichiers d'un même batch partagent la même session — une entité
anonymisée `{{IP_001}}` dans `firewall.log` sera `{{IP_001}}` dans `ids.log`.

### Structure des répertoires

```
logs/
├── inbox/                          ← déposer les logs ici

logs/outbox/
└── batch_20260319_143022/
    ├── batch_mapping.json          ← mapping global du batch {original: token}
    ├── batch_report.json           ← résumé (stats, fichiers, gaps)
    ├── clean/                      ← anonymisés, 0 gap résiduel
    │   ├── firewall.log.anon
    │   └── ids.log.anon
    ├── partial/                    ← anonymisés, gaps résiduels (review recommandée)
    │   └── crowdsec.log.anon
    └── error/                      ← échec de traitement
        └── corrupted.bin.error.txt
```

### Lancer un batch

```python
from pathlib import Path
from victor import LogProcessor

processor = LogProcessor(
    inbox_dir  = Path("logs/inbox"),
    outbox_dir = Path("logs/outbox"),
)
report = processor.process_batch()

print(f"Batch {report['batch_id']}")
print(f"  clean: {report['clean']}  partial: {report['partial']}  error: {report['error']}")
print(f"  tokens: {report['total_tokens']}")
```

### Avec GapCollector intégré

```python
from victor import LogProcessor, GapCollector

collector = GapCollector(data_dir=Path("data"))
processor = LogProcessor(
    inbox_dir      = Path("logs/inbox"),
    outbox_dir     = Path("logs/outbox"),
    gap_collector  = collector,
)
processor.process_batch()

# Gaps accumulés sur tous les fichiers du batch
for gap in collector.candidates(min_occurrences=2, min_sessions=1):
    print(f"[{gap['label']}] {gap['text']} — {gap['occurrences']}x")
```

### Consulter les batches passés

```python
for batch in processor.list_batches():
    print(f"{batch['batch_id']} — {batch['total_files']} fichiers")

mapping = processor.get_batch_mapping("batch_20260319_143022")
```

---

## Auto-apprentissage

Victor détecte les **gaps NER** — entités vues par le modèle mais non anonymisées
par le moteur — et les accumule pour proposer de nouvelles règles ou des exemples
d'entraînement spaCy.

### Activer le collecteur

```python
from pathlib import Path
from victor import Anonymizer, GapCollector

collector = GapCollector(data_dir=Path("data"))
anon = Anonymizer(gap_collector=collector)

# Les gaps sont enregistrés automatiquement à chaque appel anonymize_*()
anon.anonymize_text("custom-host-99 connected from 172.16.50.1")
```

### Consulter les candidats

```python
for gap in collector.candidates(min_occurrences=3, min_sessions=2):
    print(f"[{gap['label']}] {gap['text']}  ({gap['occurrences']}x, {gap['sessions']} sessions)")
```

### Validation automatique via SLM (optionnel)

Victor peut déléguer la validation des gaps à un SLM local via **Ollama**.
Aucun GPU requis — tourne sur CPU avec `qwen2.5:1.5b` (~1 GB).

```bash
# Prérequis
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:1.5b
```

```python
from victor import GapValidator, RuleWriter, AnnotationWriter

validator  = GapValidator()                  # Ollama localhost:11434, qwen2.5:1.5b
rule_writer = RuleWriter()
ann_writer  = AnnotationWriter(data_dir=Path("data/dataset"))

# Valide tous les candidats et applique les décisions automatiquement
results = validator.validate_candidates(collector)
# ACCEPT → collector.accept()  — prêt pour rule_writer / ann_writer
# REJECT → collector.reject()  — blacklisté
# unsure → laissé en pending   — validation humaine requise

for r in results:
    print(f"[{r['decision']}] {r['label']} '{r['text']}' — {r['reason']}")
```

Si Ollama n'est pas disponible, `validate()` retourne `decision="unsure"` sans exception.
La validation humaine reste toujours possible indépendamment.

### Valider et écrire (piste courte — règle regex)

```python
from victor import RuleWriter

writer = RuleWriter()

for gap in collector.candidates():
    rule = collector.to_regex_rule(gap["text"], gap["label"])
    print(rule)  # inspecter avant d'accepter

    writer.add(rule)                              # → custom_rules_security.json
    collector.accept(gap["text"], gap["label"])   # marque le gap comme traité
```

### Valider et écrire (piste longue — dataset spaCy)

```python
from victor import AnnotationWriter

ann_writer = AnnotationWriter(data_dir=Path("data/dataset"))

for gap in collector.candidates():
    examples = collector.to_spacy_examples(gap["text"], gap["label"])
    ann_writer.add_examples(
        examples,
        label=gap["label"],
        source_key=f"gap::{gap['label']}::{gap['text']}",
    )
    collector.accept(gap["text"], gap["label"])

# Compiler avant spacy train
ann_writer.compile()   # → data/dataset/train.spacy
```

---

## Architecture

```
victor/
├── anonymizer.py        — Anonymizer : API principale
├── gap_collector.py     — GapCollector : agrégation, scoring, propositions
├── rule_writer.py       — RuleWriter : piste courte → custom_rules.json
├── annotation_writer.py — AnnotationWriter : piste longue → train.spacy
├── ner_extractor.py     — NERExtractor : observabilité NER (gaps moteur)
├── engine/              — Moteur d'anonymisation (extrait de anonyfiles_core)
│   ├── engine.py        — AnonyfilesEngine.anonymize_text()
│   ├── replacer.py      — ReplacementSession (stateful)
│   ├── ner_processor.py — Détection NER spaCy + regex
│   ├── custom_rules_processor.py
│   ├── replacement_generator.py
│   ├── spacy_engine.py
│   ├── audit.py
│   ├── utils.py
│   └── format_utils.py
└── config/
    └── custom_rules_security.json   — règles regex pré-définies (IPs RFC1918, CVE, MAC…)

data/
├── gaps/        — gaps.json (persistance GapCollector)
├── reviewed/    — exports de review (usage libre)
└── dataset/     — annotations.json + train.spacy (piste longue)
```

### Flux d'anonymisation

```
texte brut
  └─► CustomRulesProcessor    (regex : IPs RFC1918, CVE, MAC, hostnames…)
        └─► NERProcessor       (spaCy : entités AnonyNER + labels classiques)
              └─► ReplacementGenerator  (tokens cohérents : HOST_001, IP_001…)
                    └─► texte anonymisé + mapping + rapport
```

### Flux d'auto-apprentissage

```
anonymize_*()
  └─► ner_gaps (entités non anonymisées)
        └─► GapCollector.record()
              └─► fréquence N / M sessions
                    └─► candidates()
                          ├─► to_regex_rule()      → RuleWriter    → custom_rules.json
                          └─► to_spacy_examples()  → AnnotationWriter → train.spacy
```

La validation humaine est le seul verrou entre `candidates()` et l'écriture.
`GapCollector` ne modifie jamais les fichiers de sortie de lui-même.

---

## Règles custom

Les règles pré-définies dans `victor/config/custom_rules_security.json` couvrent :

| Catégorie | Exemples détectés |
|-----------|-------------------|
| IP RFC1918 | `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x` |
| CVE | `CVE-2024-12345` |
| FQDN zones privées | `host.company.local`, `srv01.corp.lan` |
| Hostnames numérotés | `fw01`, `srv-003`, `dc-1024` |
| Services internes | `crowdsec-agent`, `wireguard_peer` |
| Adresses MAC | `aa:bb:cc:dd:ee:ff` |
| Tokens hexadécimaux | secrets 32–64 chars hex |

Ajouter des règles manuellement dans le JSON ou via `RuleWriter.add()`.

---

## Limitations connues

**Tokens statiques pour les custom rules** — plusieurs IPs ou hostnames distincts
capturés par la même règle regex reçoivent le même token (`{{IP_PRIVE}}`).
La numérotation séquentielle (`{{IP_001}}`, `{{IP_002}}`) ne s'applique qu'aux
entités détectées par le NER spaCy.

**Modèle de fallback** — sans AnonyNER, le modèle générique `en_core_web_md`
ne détecte pas les entités cyber (IPs, hostnames, CVE…). Les custom rules
fonctionnent dans les deux cas.
