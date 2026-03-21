# Victor

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](https://opensource.org/licenses/AGPL-3.0)
[![Defense Restrictions](https://img.shields.io/badge/Restriction-Defense%20Sector-red.svg)](#licence)

> **Note importante :** Ce logiciel est distribué sous licence **AGPL-3.0**. Son utilisation au sein du secteur de la **défense et de l'armement**, ou par des entités exigeant la confidentialité du code source, nécessite une licence commerciale dérogatoire. Voir la section [Licence](#licence) pour plus de détails.

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

training/               — pipeline d'entraînement AnonyNER (non versionné)
├── logs/               — logs bruts par source (circuit 2)
│   ├── linux/
│   ├── apache/
│   └── windows/
├── scripts/
│   ├── annotate_corpus.py    — circuit 2 : annotation logs bruts + score confiance
│   ├── review_corpus.py      — circuit 2 : revue humaine CLI
│   ├── prepare_spacy_dataset.py
│   └── train_anonyner.py
├── data/               — corpus annotés + compilés
└── models/             — modèles entraînés
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

| Format | Source | Statut | Circuit | Notes |
|--------|--------|--------|---------|-------|
| OPNsense firewall | Réseau | ✅ Bon | 1 | Corpus d'entraînement v3 |
| WireGuard | VPN | ✅ Bon | 1 | Corpus d'entraînement v3 |
| CrowdSec | IDS/IPS | ✅ Bon | 1 | Corpus d'entraînement v3 |
| Linux syslog | Système | ⚠️ Partiel | 2 | Faux positifs sur PID, timestamps — corpus à construire |
| Apache / Nginx | Web | 🔲 Non testé | 2 | |
| Windows Event Log | Système | 🔲 Non testé | 2 | |
| Fortinet / FortiGate | Réseau | 🔲 Non testé | 2 | |
| Stormshield | Réseau | 🔲 Non testé | 2 | |
| Journald (systemd) | Système | 🔲 Non testé | 2 | |
| Auditd | Système | 🔲 Non testé | 2 | |
| Syslog-ng / rsyslog | Agrégateur | 🔲 Non testé | 2 | |
| Kubernetes / containerd | Cloud | 🔲 Non testé | 2 | |

**Légende :**
- ✅ Bon — détection fiable, peu de faux positifs
- ⚠️ Partiel — détection dégradée, corpus circuit 2 recommandé
- 🔲 Non testé — contribution bienvenue (`training/logs/<source>/`)

Pour contribuer un nouveau format : déposer des logs bruts dans `training/logs/<source>/`
et lancer `annotate_corpus.py` (voir [training/README.md](training/README.md)).

---

## Labels NER

**Réseau / Firewall**

| Label | Entités détectées |
|-------|-------------------|
| `IP_ADDRESS` | Adresses IPv4 et IPv6 |
| `IP_SUBNET` | Sous-réseaux CIDR (`10.0.0.0/8`…) |
| `HOSTNAME` | Hostnames et FQDNs internes |
| `INTERFACE` | Interfaces réseau (`eth0`, `wg0`, `en0`…) |
| `MAC_ADDRESS` | Adresses MAC (`aa:bb:cc:dd:ee:ff`) |
| `PORT_NUMBER` | Numéros de port |
| `CVE` | Identifiants CVE (`CVE-YYYY-NNNNN`) |
| `SERVICE_ACCOUNT` | Comptes de service infra (`crowdsec-agent`, `wireguard_peer`…) |
| `FIREWALL_RULE` | Règles et noms de politiques firewall |
| `VPN_USER` | Identifiants utilisateur VPN |

**Linux / Unix**

| Label | Entités détectées |
|-------|-------------------|
| `UNIX_USER` | Utilisateurs OS locaux (`root`, `www-data`, `oracle`, `postgres`…) |
| `PROCESS_NAME` | Processus et daemons (`sshd`, `ftpd`, `cron`, `kernel`, `sudo`…) |
| `FILE_PATH` | Chemins filesystem (`/etc/passwd`, `/var/log/`, `/home/user/`…) |

**Windows**

| Label | Entités détectées |
|-------|-------------------|
| `WIN_USER` | Comptes Windows (`DOMAIN\user`, `user@corp.local`, `Administrator`) |
| `WIN_SID` | Security Identifiers (`S-1-5-21-…`) |
| `WIN_HOST` | Noms de machines Windows (`DESKTOP-AB12CD`, `COMPUTER01$`) |
| `WIN_SERVICE` | Services et processus Windows (`lsass.exe`, `winlogon.exe`, `SYSTEM`) |
| `REGISTRY_KEY` | Clés de registre (`HKLM\SOFTWARE\…`, `HKCU\…`) |

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

## Résultats sur logs réels

Tests réalisés sur des jeux de logs publics issus du projet [LogHub](https://github.com/logpai/loghub).

| Log source | Fichier | Taille | Remplacements | Tokens | Status | Gaps résiduels |
|------------|---------|--------|---------------|--------|--------|----------------|
| Linux syslog | `Linux_2k.log` | 211 KB | 3 287 | 1 676 | partial | 1 |

**Interprétation des statuts :**
- `clean` — zéro gap résiduel, anonymisation complète
- `partial` — gaps résiduels détectés, relecture recommandée
- `error` — fichier non traitable (encodage inconnu, binaire…)

### Analyse qualitative du mapping

L'examen du `batch_mapping.json` révèle des résultats mitigés sur ce format de log :

| Entrée capturée | Token attribué | Verdict |
|-----------------|----------------|---------|
| `sshd(pam_unix)[19937]:` | `{{IFACE_001}}` | ❌ Process+PID → classifié Interface |
| `sshd(pam_unix)[20882` | `{{SVC_ACCOUNT_001}}` | ⚠️ Process+PID → Service Account (approximatif) |
| `14:53:32` | `{{IP_001}}` | ❌ Timestamp → classifié IP |
| `12:13:20` | `{{FW_RULE_002}}` | ❌ Timestamp → classifié Firewall Rule |
| `]:` | `{{MAC_001}}` | ❌ Ponctuation → classifié MAC |
| `=` | `{{VPN_USER_001}}` | ❌ Signe égal → classifié VPN User |
| `uid=0` | `{{PORT_001}}` | ❌ UID root → classifié Port |
| `1` | `{{FW_RULE_001}}` | ❌ Entier → classifié Firewall Rule |
| `rhost=220-135-151-1.hinet-ip.hinet.net` | `{{HOST_001}}` | ⚠️ Correct mais inclut le préfixe `rhost=` |

**Diagnostic :** AnonyNER a été entraîné principalement sur des logs réseau et firewall
(OPNsense, CrowdSec, WireGuard). Les Linux syslogs ont un format structuré différent —
`process(subsystem)[pid]:` — que le modèle ne reconnaît pas nativement. Il projette
les labels familiers (IP, MAC, IFACE) sur des fragments syntaxiques similaires en surface,
produisant de nombreux faux positifs.

**Ce que ce test démontre :**
- Les custom rules (regex RFC1918, CVE, FQDN…) fonctionnent indépendamment du modèle NER
- Le modèle AnonyNER v3 est spécialisé logs réseau/firewall — les logs applicatifs Linux
  nécessitent un enrichissement du corpus d'entraînement
- Le `batch_report.json` + `batch_mapping.json` permettent d'identifier précisément
  les zones à corriger avant d'utiliser les fichiers anonymisés

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

Ce logiciel est distribué sous la licence **GNU Affero General Public License v3.0 (AGPL-3.0)**. 

### Pourquoi l'AGPL-3.0 ?
L'AGPL-3.0 est une licence de "copyleft" fort conçue pour garantir que le code source de toutes les versions modifiées du logiciel soit mis à la disposition de la communauté, même si le logiciel est utilisé uniquement via un réseau (SaaS/Cloud). 

### Utilisation Commerciale et Restrictions
Les entreprises dont les politiques internes interdisent l'utilisation de licences AGPL-3.0 (notamment pour des raisons de confidentialité ou de secret industriel) doivent acquérir une **licence commerciale dérogatoire**.

Le détenteur des droits se réserve le droit de refuser la vente d'une licence commerciale à toute entité dont les activités ne sont pas en adéquation avec les valeurs du projet (notamment les secteurs de la défense et de l'armement).

### Demandes de dérogation
Pour toute demande de licence commerciale dérogatoire ou pour discuter d'un cas d'usage spécifique (secteurs régulés, défense, infrastructure critique), 
👉 [**Ouvrir une demande de licence dérogatoire**](https://github.com/patlegu/victor/issues/new?title=[Licensing+Request]+Nom+de+votre+entité&labels=%E2%9A%96%EF%B8%8F+Licensing+Request&body=Organisation+:+%0ASecteur+:+%0ACas+d'usage+:+%0ARaison+de+la+dérogation+:+)

*Note : Les demandes anonymes ou incomplètes ne seront pas traitées.*