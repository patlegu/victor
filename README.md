# Victor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub release](https://img.shields.io/github/v/release/patlegu/victor)](https://github.com/patlegu/victor/releases/latest)

---

Anonymiseur de logs et documents de sécurité.

Détecte et remplace les entités sensibles (IPs, hostnames, CVE, MAC, comptes de service…)
par des tokens pseudonymisés cohérents sur toute une session.
S'améliore automatiquement au fil des logs via une boucle de détection de gaps NER.

---

## Installation

```bash
python -m venv venv && source venv/bin/activate
pip install -e .

# Modèle AnonyNER v0.1.0 (recommandé — 30 labels, F1 96%, entités cyber)
pip install https://github.com/patlegu/victor/releases/latest/download/en_anonyner-latest.tar.gz

# Version épinglée
# pip install https://github.com/patlegu/victor/releases/download/v0.1.0/en_anonyner-0.1.0.tar.gz

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
├── gap_validator.py     — GapValidator : validation automatique via Ollama (circuit 1)
├── log_processor.py     — LogProcessor : traitement batch inbox/outbox
├── ner_extractor.py     — NERExtractor : observabilité NER (gaps moteur)
├── engine/              — Moteur d'anonymisation
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

training/               — pipeline d'entraînement AnonyNER (versionné sur GitLab)
├── logs/               — logs bruts par source (circuit 2)
│   ├── linux/
│   ├── apache/
│   └── windows/
├── scripts/
│   ├── annotate_corpus.py             — circuit 2 : annotation + score confiance
│   ├── review_corpus.py               — circuit 2 : revue humaine CLI
│   ├── eval_anonyner.py               — évaluation par label (P/R/F1/FN)
│   ├── analyze_fn.py                  — diagnostic faux négatifs par label
│   ├── prepare_spacy_dataset.py       — JSONL → train.spacy / dev.spacy
│   ├── train_anonyner.py              — entraînement tok2vec ou transformer
│   ├── diversify_hostname_corpus.py   — correction mislabels EC2 HOSTNAME
│   ├── relabel_key_fingerprint.py     — FILE_HASH → KEY_FINGERPRINT
│   ├── generate_hostname_contexts.py  — données synthétiques HOSTNAME
│   ├── generate_command_line_contexts.py
│   ├── generate_url_uri_contexts.py
│   ├── generate_scheduled_task_contexts.py
│   ├── generate_key_fingerprint_contexts.py
│   └── generate_file_hash_contexts.py
├── data/               — corpus annotés + compilés (v3.0 → v3.20)
└── models/             — modèles entraînés (non versionnés)
```

### Flux d'anonymisation

```
texte brut
  └─► CustomRulesProcessor    (regex : IPs RFC1918, CVE, MAC, hostnames…)
        └─► NERProcessor       (spaCy : entités AnonyNER + labels classiques)
              └─► ReplacementGenerator  (tokens cohérents : HOST_001, IP_001…)
                    └─► texte anonymisé + mapping + rapport
```

### Flux d'auto-apprentissage — Circuit 1 (formats connus)

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

### Flux d'annotation — Circuit 2 (nouveaux formats)

Pour les formats inconnus du modèle (Linux syslog, Apache, Windows Event Log…),
un pipeline d'annotation externe basé sur un LLM plus puissant génère le corpus
d'entraînement avec filtrage par score de confiance.

```
training/logs/<source>/
  └─► annotate_corpus.py     (Ollama qwen2.5-coder:7b, score confiance par entité)
        ├─► confiance ≥ seuil → <source>_annotated.jsonl  (auto-accept)
        └─► confiance < seuil → <source>_review.jsonl     (spot-check humain)
              └─► review_corpus.py  (CLI : accept / edit label / skip)
  └─► prepare_spacy_dataset.py → train.spacy → train_anonyner.py
```

Les deux circuits alimentent le même pipeline d'entraînement spaCy.

---

## Formats de logs supportés

Suivi de la couverture AnonyNER par format de log. Le statut reflète la qualité
de la détection NER, indépendamment des règles regex (toujours actives).

| Format | Source | Statut | Notes |
|--------|--------|--------|-------|
| OPNsense firewall | Réseau | ✅ Bon | Corpus multi-versions depuis v3.0 |
| WireGuard | VPN | ✅ Bon | Corpus multi-versions depuis v3.0 |
| CrowdSec | IDS/IPS | ✅ Bon | Corpus multi-versions depuis v3.0 |
| Linux syslog / auth.log | Système | ✅ Bon | Corpus CTU-13 + OpenSSH + Linux_2k (v3.11+) |
| Apache / Nginx access | Web | ✅ Bon | Corpus Apache Combined Log + Logstash (v3.16+) |
| Windows Event Log | Système | ✅ Bon | Corpus OTRF Windows + EventID (v3.11+) |
| Sysmon | Endpoint | ⚠️ Partiel | Hashes et chemins couverts, enrichissement en cours |
| Squid / HAProxy / WAF | Proxy | ⚠️ Partiel | Couverture URL_URI — corpus limité |
| Fortinet / FortiGate | Réseau | 🔲 Non testé | Contribution bienvenue |
| Stormshield | Réseau | 🔲 Non testé | Contribution bienvenue |
| Journald (systemd) | Système | 🔲 Non testé | Contribution bienvenue |
| Auditd | Système | 🔲 Non testé | Contribution bienvenue |
| Kubernetes / containerd | Cloud | 🔲 Non testé | Contribution bienvenue |

**Légende :**
- ✅ Bon — détection fiable, peu de faux positifs
- ⚠️ Partiel — détection dégradée, corpus circuit 2 recommandé
- 🔲 Non testé — contribution bienvenue (`training/logs/<source>/`)

Pour contribuer un nouveau format : déposer des logs bruts dans `training/logs/<source>/`
et lancer `annotate_corpus.py` (voir [training/README.md](training/README.md)).

---

## Labels NER

30 labels couvrant les entités sensibles des logs réseau, système et sécurité. F1 global **96%** (corpus v3.20, modèle RoBERTa).

**Réseau / Firewall**

| Label | Entités détectées | F1 |
|-------|-------------------|----|
| `IP_ADDRESS` | Adresses IPv4 et IPv6 | 99.3% |
| `IP_SUBNET` | Sous-réseaux CIDR (`10.0.0.0/8`…) | 93.3% |
| `HOSTNAME` | Hostnames et FQDNs internes | 99.0% |
| `DOMAIN` | Domaines publics (`example.com`, `github.com`) | 96.6% |
| `INTERFACE` | Interfaces réseau (`eth0`, `wg0`, `en0`…) | 92.4% |
| `MAC_ADDRESS` | Adresses MAC (`aa:bb:cc:dd:ee:ff`) | 76.5% |
| `PORT_NUMBER` | Numéros de port | 91.6% |
| `PROTOCOL` | Protocoles réseau (`TCP`, `UDP`, `ICMP`, `BGP`…) | 85.8% |
| `ASN` | Numéros de système autonome (`AS12345`) | 100% |
| `CVE` | Identifiants CVE (`CVE-YYYY-NNNNN`) | 97.9% |
| `URL_URI` | URLs et URIs dans les logs web/proxy | 86.6% |
| `SERVICE_ACCOUNT` | Comptes de service infra (`crowdsec-agent`, `wireguard_peer`…) | 89.1% |
| `FIREWALL_RULE` | Règles et noms de politiques firewall | 82.9% |
| `VPN_USER` | Identifiants utilisateur VPN | 90.5% |

**Linux / Unix**

| Label | Entités détectées | F1 |
|-------|-------------------|----|
| `UNIX_USER` | Utilisateurs OS locaux (`root`, `www-data`, `oracle`…) | 98.9% |
| `UNIX_GROUP` | Groupes OS (`wheel`, `docker`, `sudo`…) | 100% |
| `PROCESS_NAME` | Processus et daemons (`sshd`, `cron`, `sudo`…) | 97.8% |
| `COMMAND_LINE` | Lignes de commande complètes (Unix et Windows) | 87.5% |
| `FILE_PATH` | Chemins filesystem (`/etc/passwd`, `C:\Windows\…`) | 91.5% |
| `FILE_HASH` | Checksums de fichiers (`md5:…`, `SHA256:…`, hex brut) | — |
| `KEY_FINGERPRINT` | Empreintes de clés SSH (`RSA SHA256:…`, `ED25519 SHA256:…`) | 93.9% |
| `PID` | Identifiants de processus | 90.0% |

**Windows**

| Label | Entités détectées | F1 |
|-------|-------------------|----|
| `WIN_USER` | Comptes Windows (`DOMAIN\user`, `Administrator`) | 99.1% |
| `WIN_SID` | Security Identifiers (`S-1-5-21-…`) | 93.6% |
| `WIN_HOST` | Noms de machines Windows (`DESKTOP-AB12CD`, `COMPUTER01$`) | 83.9% |
| `WIN_GROUP` | Groupes Windows (`Domain Admins`, `Administrators`) | 100% |
| `REGISTRY_KEY` | Clés de registre (`HKLM\SOFTWARE\…`, `HKCU\…`) | 99.7% |
| `EVENT_ID` | Identifiants d'événements Windows (`4698`, `7045`…) | 87.5% |
| `SCHEDULED_TASK` | Tâches planifiées (`\Microsoft\Windows\…`, `schtasks /tn`) | 97.2% |
| `ACTION` | Actions firewall/IDS (`BLOCK`, `ALLOW`, `DROP`…) | 94.7% |

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
| Windows SID | `S-1-5-21-…` |
| Clés de registre | `HKLM\SOFTWARE\…`, `HKCU\…` |
| Chemins Linux | `/etc/…`, `/var/…`, `/home/…` |
| Chemins Windows | `C:\Windows\…`, `D:\…` |

Ajouter des règles manuellement dans le JSON ou via `RuleWriter.add()`.

---

## Résultats AnonyNER

Évaluation sur corpus de dev (20% du corpus d'entraînement, ~5 000 documents). Sources : LogHub, CTU-13, OTRF Windows, Apache Elastic, logs synthétiques multi-formats.

| Métrique | v3.0 (tok2vec) | v3.11 | v3.16 (RoBERTa) | v3.20 → AnonyNER v0.1.0 |
|----------|---------------|-------|-----------------|------------------------|
| F1 global | 82.4% | 88.0% | 95.9% | **96%** |
| Corpus | ~3 000 | ~16 000 | ~22 000 | ~25 000 |
| Labels | 20 | 25 | 27 | **30** |

Les cycles d'amélioration sont documentés sur [nope.breizhland.eu](https://nope.breizhland.eu) :
- [v3.1 — premier bilan par label](https://nope.breizhland.eu/victor-anonyner-v31-bilan)
- [v3.11 — CTU-13 + KernelDriver](https://nope.breizhland.eu/victor-anonyner-v311-nouveaux-datasets)
- [v3.15 — migration RoBERTa, diagnostic FN, +8 points F1](https://nope.breizhland.eu/victor-anonyner-v315-transformer-diagnostic)
- [v3.19 — URL_URI, SCHEDULED_TASK 100%, KEY_FINGERPRINT](https://nope.breizhland.eu/victor-anonyner-v319-url-scheduled-key)

**Interprétation des statuts batch :**
- `clean` — zéro gap résiduel, anonymisation complète
- `partial` — gaps résiduels détectés, relecture recommandée
- `error` — fichier non traitable (encodage inconnu, binaire…)

---

## Limitations connues

**Tokens statiques pour les custom rules** — plusieurs IPs ou hostnames distincts
capturés par la même règle regex reçoivent le même token (`{{IP_PRIVE}}`).
La numérotation séquentielle (`{{IP_001}}`, `{{IP_002}}`) ne s'applique qu'aux
entités détectées par le NER spaCy.

**Modèle de fallback** — sans AnonyNER, le modèle générique `en_core_web_md`
ne détecte pas les entités cyber (IPs, hostnames, CVE…). Les custom rules
fonctionnent dans les deux cas.

## Licence

Ce projet est distribué sous la licence **MIT**. Voir le fichier [LICENSE](LICENSE) pour les détails.