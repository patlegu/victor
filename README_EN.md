# Victor

Security log and document anonymizer.

Detects and replaces sensitive entities (IPs, hostnames, CVEs, MAC addresses, service accounts…)
with consistent pseudonymized tokens across an entire session.
Self-improves over time through a NER gap detection loop that feeds both a fast rule track
and a long-term spaCy training track.

---

## Requirements

- Python 3.10+
- spaCy 3.7+
- [AnonyNER](https://github.com/patlegu/anonyfiles/releases/tag/anonyner-v3.0.0) — custom spaCy model for cyber entities (recommended)

---

## Installation

```bash
python -m venv venv && source venv/bin/activate
pip install -e .

# AnonyNER model (recommended — cyber entities)
pip install https://github.com/patlegu/anonyfiles/releases/download/anonyner-v3.0.0/en_anonyner-3.0.0.tar.gz

# Generic fallback model (no cyber entities)
# python -m spacy download en_core_web_md
```

---

## Quick start

```python
from victor import Anonymizer

anon = Anonymizer()

result = anon.anonymize_text("Block IP 192.168.1.50 on fw01.company.local — CVE-2024-12345")
print(result["anonymized_text"])
# → Block IP {{IP_PRIVE}} on {{HOSTNAME}} — {{CVE_ID}}

print(result["mapping"])
# → {'192.168.1.50': '{{IP_PRIVE}}', 'fw01.company.local': '{{HOSTNAME}}', 'CVE-2024-12345': '{{CVE_ID}}'}
```

### Batch anonymization

The same entity always receives the same token across the entire batch.

```python
results = anon.anonymize_batch([
    "fw01.corp.local rejected connection from 10.0.0.5",
    "alert on fw01.corp.local : CVE-2024-9999 detected",
])
print(results["session_mapping"])
print(results["ner_gaps"])   # entities seen by NER but missed by the engine
```

### Deanonymization

```python
original = anon.deanonymize_text(result["anonymized_text"])
print(original["original_text"])
```

### Session management

```python
anon.reset_session()         # start a fresh session
anon.get_session_mapping()   # full mapping for the current session
```

---

## Batch log processing

Victor processes log files in batches from an `inbox/` directory.
All files in the same batch share the same session — an entity anonymized
as `{{IP_001}}` in `firewall.log` will be `{{IP_001}}` in `ids.log`.

### Directory structure

```
logs/
├── inbox/                          ← drop log files here

logs/outbox/
└── batch_20260319_143022/
    ├── batch_mapping.json          ← global batch mapping {original: token}
    ├── batch_report.json           ← summary (stats, files, gaps)
    ├── clean/                      ← anonymized, 0 residual gaps
    │   ├── firewall.log.anon
    │   └── ids.log.anon
    ├── partial/                    ← anonymized, residual gaps (review recommended)
    │   └── crowdsec.log.anon
    └── error/                      ← processing failure
        └── corrupted.bin.error.txt
```

### Run a batch

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

### With integrated GapCollector

```python
from victor import LogProcessor, GapCollector

collector = GapCollector(data_dir=Path("data"))
processor = LogProcessor(
    inbox_dir      = Path("logs/inbox"),
    outbox_dir     = Path("logs/outbox"),
    gap_collector  = collector,
)
processor.process_batch()

# Gaps accumulated across all files in the batch
for gap in collector.candidates(min_occurrences=2, min_sessions=1):
    print(f"[{gap['label']}] {gap['text']} — {gap['occurrences']}x")
```

### Browse past batches

```python
for batch in processor.list_batches():
    print(f"{batch['batch_id']} — {batch['total_files']} files")

mapping = processor.get_batch_mapping("batch_20260319_143022")
```

---

## Self-learning loop

Victor tracks **NER gaps** — entities detected by the model but not anonymized by the
engine — and accumulates them across sessions to propose new rules or spaCy training examples.

```
anonymize_*()
  └─► ner_gaps (unhandled entities)
        └─► GapCollector.record()
              └─► frequency N / M sessions
                    └─► candidates()
                          ├─► to_regex_rule()      → RuleWriter    → custom_rules.json  (fast track)
                          └─► to_spacy_examples()  → AnnotationWriter → train.spacy     (long track)
```

Human validation is the only gate between `candidates()` and any write operation.
`GapCollector` never modifies output files on its own.

### Enable the collector

```python
from pathlib import Path
from victor import Anonymizer, GapCollector

collector = GapCollector(data_dir=Path("data"))
anon = Anonymizer(gap_collector=collector)

# Gaps are recorded automatically on every anonymize_*() call
anon.anonymize_text("custom-host-99 connected from 172.16.50.1")
```

### Review candidates

```python
for gap in collector.candidates(min_occurrences=3, min_sessions=2):
    print(f"[{gap['label']}] {gap['text']}  ({gap['occurrences']}x, {gap['sessions']} sessions)")

print(collector.summary())
# → {'pending': 4, 'accepted': 1, 'rejected': 0, 'total': 5}
```

### Automatic validation via SLM (optional)

Victor can delegate gap validation to a local SLM via **Ollama**.
No GPU required — runs on CPU with `qwen2.5:1.5b` (~1 GB).

```bash
# Prerequisites
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:1.5b
```

```python
from victor import GapValidator, RuleWriter, AnnotationWriter

validator   = GapValidator()                 # Ollama localhost:11434, qwen2.5:1.5b
rule_writer = RuleWriter()
ann_writer  = AnnotationWriter(data_dir=Path("data/dataset"))

# Validate all candidates and apply decisions automatically
results = validator.validate_candidates(collector)
# ACCEPT → collector.accept()  — ready for rule_writer / ann_writer
# REJECT → collector.reject()  — blacklisted
# unsure → stays pending        — requires human review

for r in results:
    print(f"[{r['decision']}] {r['label']} '{r['text']}' — {r['reason']}")
```

If Ollama is not available, `validate()` returns `decision="unsure"` without raising an exception.
Human validation always remains available independently.

### Fast track — new regex rule

```python
from victor import RuleWriter

writer = RuleWriter()

for gap in collector.candidates():
    rule = collector.to_regex_rule(gap["text"], gap["label"])
    print(rule)          # inspect before accepting

    writer.add(rule)                               # → appended to custom_rules.json
    collector.accept(gap["text"], gap["label"])    # mark as handled
```

### Long track — spaCy training example

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

# Compile before running spacy train
ann_writer.compile()   # → data/dataset/train.spacy
```

---

## Architecture

```
victor/
├── anonymizer.py        — Anonymizer: main API
├── gap_collector.py     — GapCollector: aggregation, scoring, proposals
├── rule_writer.py       — RuleWriter: fast track → custom_rules.json
├── annotation_writer.py — AnnotationWriter: long track → train.spacy
├── ner_extractor.py     — NERExtractor: NER observability (gap detection)
├── engine/              — Anonymization engine
│   ├── engine.py        — AnonyfilesEngine.anonymize_text()
│   ├── replacer.py      — ReplacementSession (stateful tokens)
│   ├── ner_processor.py — spaCy NER + regex detection
│   ├── custom_rules_processor.py
│   ├── replacement_generator.py
│   ├── spacy_engine.py
│   ├── audit.py
│   ├── utils.py
│   └── format_utils.py
└── config/
    └── custom_rules_security.json   — pre-defined regex rules

data/
├── gaps/        — gaps.json  (GapCollector persistence)
├── reviewed/    — review exports (free use)
└── dataset/     — annotations.json + train.spacy (long track)
```

### Anonymization pipeline

```
raw text
  └─► CustomRulesProcessor   (regex: RFC1918 IPs, CVEs, MACs, hostnames…)
        └─► NERProcessor      (spaCy: AnonyNER entities + standard NLP labels)
              └─► ReplacementGenerator  (consistent tokens: HOST_001, IP_001…)
                    └─► anonymized text + mapping + report
```

---

## Built-in rules

Rules pre-defined in `victor/config/custom_rules_security.json`:

| Category | Examples matched |
|----------|-----------------|
| RFC1918 IPs | `10.x.x.x`, `172.16–31.x.x`, `192.168.x.x` |
| CVE identifiers | `CVE-2024-12345` |
| Private zone FQDNs | `host.company.local`, `srv01.corp.lan` |
| Numbered hostnames | `fw01`, `srv-003`, `dc-1024` |
| Internal services | `crowdsec-agent`, `wireguard_peer` |
| MAC addresses | `aa:bb:cc:dd:ee:ff` |
| Hex tokens / API keys | 32–64 char hex secrets |

Add new rules manually in the JSON file or programmatically via `RuleWriter.add()`.

---

## Known limitations

**Static tokens for custom rules** — multiple distinct IPs or hostnames matched by
the same regex rule receive the same static token (`{{IP_PRIVE}}`).
Sequential numbering (`{{IP_001}}`, `{{IP_002}}`) only applies to entities detected
by the spaCy NER model.

**Fallback model** — without AnonyNER, the generic `en_core_web_md` model does not
detect cyber-specific entities (IPs, hostnames, CVEs…). Custom rules still apply
regardless of the model in use.
