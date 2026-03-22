# Entraînement AnonyNER

Ce répertoire contient les scripts et données pour entraîner ou ré-entraîner
le modèle spaCy **AnonyNER** utilisé par Victor.

AnonyNER est un modèle NER spécialisé sur les entités cyber : adresses IP,
hostnames, CVE, adresses MAC, comptes de service, interfaces réseau, logs
système Linux/Unix et Windows Event Logs.

> **Note :** Ce répertoire est partiellement exclu du dépôt git (`.gitignore`).
> Seul `training/README.md` est versionné. Scripts, données et modèles sont locaux.
> Le modèle pré-entraîné est disponible en release GitHub :
> `pip install https://github.com/patlegu/anonyfiles/releases/download/anonyner-v3.0.0/en_anonyner-3.0.0.tar.gz`

---

## Sources de données

Les corpus d'entraînement sont constitués à partir de logs réels issus des sources suivantes.
Merci de respecter leur licence respective avant toute redistribution.

### LogHub — Jiyuan Chen et al.
Collection de logs système issus de projets open source et d'environnements réels.
Utilisé pour : Linux syslog, SSH, Apache, Nginx, OpenStack, HDFS, Windows CBS.

> Jiyuan Chen, Shilin He, Pinjia He, Zhuangbin Chen, Jinyang Liu, Yintong Huo,
> Michael R. Lyu. *LogHub: A Large Collection of System Log Datasets for AI-driven
> Log Analytics*. IEEE ICWS 2023.
>
> 🔗 https://github.com/logpai/loghub
> 📄 Licence : voir le dépôt (Creative Commons pour la plupart des datasets)

### OTRF Security Datasets
Logs Windows Security Event (EventID 4624, 4625, 4688…) issus de simulations
d'attaques en laboratoire. Utilisé pour : WIN_USER, WIN_SID, WIN_HOST, EVENT_ID.

> Open Threat Research Foundation.
> *Security Datasets Project* — collections of malicious and benign events.
>
> 🔗 https://github.com/OTRF/Security-Datasets
> 📄 Licence : MIT

### Elastic Examples
Jeux de données d'exemple pour la stack Elastic (Kibana, Elasticsearch).
Utilisé pour : logs nginx, syslog, Windows en format structuré.

> Elastic N.V. *Elastic Examples Repository*.
>
> 🔗 https://github.com/elastic/examples
> 📄 Licence : Apache 2.0

---

## Deux circuits d'apprentissage

### Circuit 1 — Auto-apprentissage sur formats connus

Le modèle AnonyNER comprend déjà le format (firewall, CrowdSec, WireGuard).
Les gaps sont des entités manquantes, pas des erreurs de classification.
Le signal est fiable → automation possible avec un SLM léger (CPU).

```
logs (formats connus)
  └─► Anonymizer → ner_gaps
        └─► GapCollector (score fréquence)
              └─► GapValidator (Ollama qwen2.5:1.5b, CPU)
                    ├─► ACCEPT → RuleWriter / AnnotationWriter
                    └─► REJECT → blacklist
```

Géré directement par le package Victor — voir `victor/gap_collector.py`.

### Circuit 2 — Nouveaux formats inconnus

Le modèle ne comprend pas le format (Linux syslog, Apache, Windows Event Log…).
Il projette ses labels sur n'importe quoi → les annotations auto seraient corrompues.
Un LLM externe plus capable (qwen2.5-coder:7b) annote les logs bruts avec un score
de confiance. Les annotations au-dessus du seuil sont auto-acceptées, les autres
sont mises en file de revue humaine (spot-check, pas révision exhaustive).

```
training/logs/<source>/          ← logs bruts déposés ici
  └─► annotate_corpus.py         (Ollama qwen2.5-coder:7b + score confiance)
        ├─► confiance ≥ seuil → <source>_annotated.jsonl  (auto-accept)
        └─► confiance < seuil → <source>_review.jsonl     (revue humaine)
              └─► review_corpus.py  (CLI : accept / edit / skip)
                    └─► <source>_annotated.jsonl
  └─► prepare_spacy_dataset.py → data/ner/train.spacy
  └─► train_anonyner.py          (fine-tuning depuis en_anonyner v3)
```

---

## Structure

```
training/
├── scripts/
│   ├── labels.py                  — source unique des 30 labels NER (à modifier ici uniquement)
│   ├── annotate_corpus.py         — Circuit 2 : annotation logs bruts via Ollama
│   ├── review_corpus.py           — Circuit 2 : revue humaine (CLI)
│   ├── clean_corpus.py            — nettoyage JSONL : labels invalides, doublons, cohérence
│   ├── generate_ner_dataset.py    — génération via Ollama depuis corpus SFT existant
│   ├── generate_ner_synthetic.py  — génération synthétique via Ollama (entités sous-représentées)
│   ├── generate_rare_labels.py    — génération déterministe pour labels rares (sans LLM)
│   ├── extract_ctu13_flows.py     — convertit binetflow CTU-13 → logs lisibles (IP, PORT, PROTOCOL)
│   ├── extract_kerneldriver.py    — convertit syscalls Windows KernelDriver.7z → logs (PROCESS_NAME, FILE_PATH)
│   ├── extract_otrf_windows.py    — extrait événements OTRF Security Datasets → logs préfixés [EventID:N]
│   ├── prepare_spacy_dataset.py   — conversion JSONL → data/ner/train.spacy / dev.spacy
│   └── train_anonyner.py          — fine-tuning spaCy depuis en_anonyner + sauvegarde
├── logs/
│   ├── linux/                     ← déposer les logs Linux ici
│   ├── apache/                    ← déposer les logs Apache ici
│   ├── windows/                   ← déposer les logs Windows ici
│   ├── ctu13/                     ← flows binetflow CTU-13 (Stratosphere IPS)
│   └── malware/                   ← syscalls extraits de KernelDriver.7z
├── data/
│   ├── <source>_annotated.jsonl   — annotations auto-acceptées par source
│   ├── <source>_review.jsonl      — annotations à réviser manuellement
│   ├── <source>_annotation_report.json — statistiques d'annotation
│   ├── corpus_vX.jsonl            — corpus fusionné par version (corpus_v312_full.jsonl = actuel)
│   └── ner/
│       ├── config.cfg             — configuration spaCy (générée automatiquement)
│       ├── train.spacy            — dataset d'entraînement compilé
│       └── dev.spacy              — dataset de validation compilé
└── models/                        — modèles entraînés (gitignored)
    └── anonyner_model/
        ├── model-best/            ← modèle à utiliser en production
        └── model-last/
```

---

## Inventaire des scripts

### `labels.py` — Source unique des labels

Dictionnaire `LABEL_DEFINITIONS` avec pour chaque label : groupe, description, exemples.
Importé par `annotate_corpus.py`, `review_corpus.py`, `clean_corpus.py`.
**Ne jamais définir les labels ailleurs.**

### `annotate_corpus.py` — Annotation via LLM (Circuit 2)

Envoie chaque ligne de log à un LLM Ollama pour extraction NER avec score de confiance.
Route automatiquement : confiance ≥ seuil → `_annotated.jsonl`, sinon → `_review.jsonl`.

```bash
python training/scripts/annotate_corpus.py \
    --source linux --model qwen2.5-coder:7b --sample 500 --threshold 0.80
# ou fichier direct :
python training/scripts/annotate_corpus.py \
    --input training/logs/linux/auth.log --source linux
```

### `review_corpus.py` — Revue humaine (CLI)

Interface CLI pour valider les annotations à confiance insuffisante (`_review.jsonl`).
Commandes : `a`/Entrée=accepter, `e`=éditer label, `d`=supprimer entité, `s`=ignorer, `q`=quitter.
Progression sauvegardée automatiquement.

```bash
python training/scripts/review_corpus.py --source linux
```

### `clean_corpus.py` — Nettoyage et déduplication

Filtre les entités hors `VALID_LABELS_SET`, recalcule `spacy_format`, supprime les doublons sur `text`.
Affiche un rapport des labels supprimés et des enregistrements perdus.

```bash
python training/scripts/clean_corpus.py \
    --inputs data/a.jsonl data/b.jsonl --output data/corpus_clean.jsonl
# Ou en place :
python training/scripts/clean_corpus.py --inputs data/old.jsonl --inplace
```

### `generate_ner_dataset.py` — Génération LLM depuis SFT

Génère des exemples annotés via Ollama à partir de templates de logs existants dans le corpus SFT.
Nécessite Ollama + modèle compatible (qwen2.5-coder:7b ou supérieur).

```bash
python training/scripts/generate_ner_dataset.py --model qwen2.5-coder:7b --count 100
```

### `generate_ner_synthetic.py` — Génération LLM entités rares

Génère des exemples synthétiques via Ollama pour des types d'entités spécifiques (CVE, MAC_ADDRESS…).
Similaire à `generate_ner_dataset.py` mais orienté sur les labels sous-représentés.

```bash
python training/scripts/generate_ner_synthetic.py \
    --output training/data/anonyner_synthetic_new.jsonl
```

### `generate_rare_labels.py` — Génération déterministe (sans LLM)

Génère directement des JSONL annotés pour les labels très rares, sans LLM.
Annotation par templates + `str.find()` — 100% fiable, pas de biais de confiance.
Labels ciblés : `ACTION`, `WIN_GROUP`, `UNIX_GROUP`, `SCHEDULED_TASK`, `ASN`, `FILE_HASH`.

```bash
python training/scripts/generate_rare_labels.py \
    --output training/data/synthetic_rare_labels.jsonl
```

### `extract_ctu13_flows.py` — Convertisseur CTU-13

Convertit les fichiers binetflow CSV du [dataset CTU-13](https://www.stratosphereips.org/datasets-ctu13)
en lignes de logs texte annotables. Expose : `IP_ADDRESS`, `PORT_NUMBER`, `PROTOCOL`.

Format entrée : `SrcAddr,DstAddr,Proto,Sport,Dport,State,...,Label`
Format sortie : `flow: 147.32.84.59:1577 -> 62.107.124.67:6881 proto=TCP state=CON pkts=6 bytes=396`

```bash
python training/scripts/extract_ctu13_flows.py \
    --input /tmp/ctu13_sample.csv \
    --output training/logs/ctu13/ctu13_flows.log --max-lines 5000
```

### `extract_kerneldriver.py` — Convertisseur KernelDriver (Zenodo 1203289)

Extrait les appels système Windows depuis l'archive [Dynamic Malware Analysis](https://zenodo.org/records/1203289).
Structure : `ProcessId/ProcessIdVirusShare500/<sample_id>/<syscall>.txt` — format `Time=,Pid=,MethodName=,ProcessName=`.
Expose : `PROCESS_NAME`, `FILE_PATH`, `PID`. Filtre sur les syscalls `Zw*` pertinents.

Nécessite `py7zr` pour inspecter l'archive, extraction préalable requise pour l'exécution.

```bash
# Après extraction de KernelDriver.7z :
python training/scripts/extract_kerneldriver.py \
    --input /tmp/KernelDriver --output training/logs/malware/kerneldriver.log --max-lines 5000
```

### `extract_otrf_windows.py` — Convertisseur OTRF Security Datasets

Extrait les événements Windows depuis les fichiers JSON [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets).
Préfixe `[EventID:N] [Host:H]` au champ `Message` pour que `annotate_corpus.py` puisse extraire `EVENT_ID` et `WIN_HOST`.
Filtre les EventIDs bruités (Sysmon 7, 12, 13…).

```bash
python training/scripts/extract_otrf_windows.py \
    --input /tmp/Security-Datasets/datasets/atomic/windows \
    --output training/logs/windows/otrf_enriched.log --max-lines 10000
```

### `prepare_spacy_dataset.py` — Compilation JSONL → .spacy

Convertit un ou plusieurs fichiers JSONL annotés au format binaire spaCy.
Utilise le tokeniseur de `en_anonyner` pour assurer la cohérence des offsets.
Split configurable (défaut 80/20).

```bash
python training/scripts/prepare_spacy_dataset.py \
    --input training/data/corpus_v312_full.jsonl \
    --train-out training/data/ner/train.spacy \
    --dev-out training/data/ner/dev.spacy \
    --split 0.2
```

### `train_anonyner.py` — Fine-tuning spaCy (tok2vec ou transformer)

Génère `config.cfg` si absent et lance l'entraînement. Deux modes :

**Mode tok2vec** (défaut) — fine-tuning depuis `en_anonyner`, rapide (~45 min GPU), ~88% F1.
Injecte `source = "en_anonyner"` dans `tok2vec` et `ner`. Requiert CuPy pour le GPU.

**Mode transformer** — RoBERTa-base (ou autre HuggingFace), 5-10× plus lent, ~90%+ F1.
Entraînement depuis zéro avec backbone pré-entraîné. Requiert PyTorch + `spacy-transformers`.

```bash
# Mode tok2vec (défaut)
python training/scripts/train_anonyner.py

# Mode transformer RoBERTa-base
python training/scripts/train_anonyner.py --transformer

# Autre modèle HuggingFace
python training/scripts/train_anonyner.py --transformer --transformer-model distilbert-base-uncased

# Régénérer la config (si changement de mode)
python training/scripts/train_anonyner.py --transformer --force-regen-config
```

---

## Labels supportés

Définis dans `scripts/labels.py` — **source unique à modifier**.
Les scripts `annotate_corpus.py` et `review_corpus.py` importent depuis ce fichier.

**Réseau / Firewall**

| Label | Entités détectées |
|-------|-------------------|
| `IP_ADDRESS` | Adresses IPv4 et IPv6 |
| `IP_SUBNET` | Sous-réseaux CIDR (`10.0.0.0/8`…) |
| `HOSTNAME` | Hostnames et FQDNs internes |
| `DOMAIN` | Noms de domaine externes (`google.com`, `evil.xyz`) |
| `INTERFACE` | Interfaces réseau (`eth0`, `wg0`, `en0`…) |
| `MAC_ADDRESS` | Adresses MAC (`aa:bb:cc:dd:ee:ff`) |
| `PORT_NUMBER` | Numéros de port |
| `PROTOCOL` | Protocoles réseau (`TCP`, `UDP`, `ICMP`) |
| `URL_URI` | URLs et chemins web (`/admin/login.php`) |
| `ACTION` | Actions firewall (`ALLOW`, `DROP`, `DENY`, `PASS`) |
| `CVE` | Identifiants CVE (`CVE-YYYY-NNNNN`) |
| `SERVICE_ACCOUNT` | Comptes de service infra (`crowdsec-agent`, `wireguard_peer`…) |
| `FIREWALL_RULE` | Règles et noms de politiques firewall |
| `VPN_USER` | Identifiants utilisateur VPN |
| `ASN` | Autonomous System Number (`AS13335`) |

**Commun Linux + Windows**

| Label | Entités détectées |
|-------|-------------------|
| `PROCESS_NAME` | Processus et daemons (`sshd`, `lsass.exe`, `cmd.exe`) |
| `PID` | Identifiants de processus (`1045`, `992`) |
| `COMMAND_LINE` | Lignes de commande exécutées |
| `FILE_PATH` | Chemins filesystem (`/etc/passwd`, `C:\Windows\…`) |
| `FILE_HASH` | Empreintes de fichiers (`SHA256:e3b0c44…`) |

**Linux / Unix**

| Label | Entités détectées |
|-------|-------------------|
| `UNIX_USER` | Utilisateurs OS locaux (`root`, `www-data`, `oracle`…) |
| `UNIX_GROUP` | Groupes locaux (`wheel`, `docker`, `sudo`) |

**Windows**

| Label | Entités détectées |
|-------|-------------------|
| `WIN_USER` | Comptes Windows (`DOMAIN\user`, `user@corp.local`) |
| `WIN_GROUP` | Groupes Windows (`Domain Admins`, `Administrators`) |
| `WIN_SID` | Security Identifiers (`S-1-5-21-…`) |
| `WIN_HOST` | Noms de machines Windows (`DESKTOP-AB12CD`, `COMPUTER01$`) |
| `EVENT_ID` | IDs d'événements Windows (`4624`, `4688`) |
| `WIN_SERVICE` | Services Windows (`lanmanserver`, `bits`, `wuauserv`) |
| `REGISTRY_KEY` | Clés de registre (`HKLM\SOFTWARE\…`) |
| `SCHEDULED_TASK` | Tâches planifiées (`\Microsoft\Windows\AppID\…`) |

---

## Circuit 2 — Annoter un nouveau corpus

### Déposer les logs

```bash
cp /path/to/Linux_2k.log training/logs/linux/
```

### Lancer l'annotation

```bash
python training/scripts/annotate_corpus.py \
    --source linux \
    --model qwen2.5-coder:7b \
    --sample 500 \
    --threshold 0.80
```

Résultat :
- `training/data/linux_annotated.jsonl` — annotations à confiance ≥ 0.80 (auto-accept)
- `training/data/linux_review.jsonl` — annotations à confiance < 0.80 (à réviser)
- `training/data/linux_annotation_report.json` — statistiques

### Réviser les annotations douteuses

```bash
python training/scripts/review_corpus.py --source linux
```

Interface CLI ligne par ligne :
- `a` / Entrée → accepter
- `e` → éditer le label (affiche les 30 labels numérotés)
- `d` → supprimer une entité
- `s` → ignorer
- `q` → quitter (progression sauvegardée, reprise possible)

### Compiler et entraîner

```bash
# Conversion JSONL → train.spacy / dev.spacy (dans data/ner/ automatiquement)
python training/scripts/prepare_spacy_dataset.py \
    --input training/data/linux_annotated.jsonl

# Fine-tuning depuis en_anonyner v3
python training/scripts/train_anonyner.py
```

---

## Procédure d'entraînement complète

### Prérequis

```bash
pip install spacy

# AnonyNER v3 — modèle de base pour le fine-tuning et le tokeniseur d'alignement
pip install https://github.com/patlegu/anonyfiles/releases/download/anonyner-v3.0.0/en_anonyner-3.0.0.tar.gz
```

`en_anonyner` intervient à deux niveaux :
- **Tokeniseur d'alignement** dans `prepare_spacy_dataset.py` — même tokeniseur que celui
  utilisé en production, évite les désalignements d'offsets
- **Modèle source pour le fine-tuning** dans `train_anonyner.py` — les composants `tok2vec`
  et `ner` sont chargés depuis `en_anonyner` via `source =`, préservant les acquis
  (OPNsense, CrowdSec, WireGuard) et accélérant la convergence sur les nouveaux formats

### Étape 1 — Générer des données supplémentaires (optionnel)

Si Ollama est disponible, générer de nouveaux exemples à partir de logs bruts :

```bash
# Génération via Ollama (nécessite qwen2.5-coder:7b ou équivalent)
python training/scripts/generate_ner_dataset.py --model qwen2.5-coder:7b --count 100

# Génération synthétique (entités sous-représentées, sans GPU)
python training/scripts/generate_ner_synthetic.py --output training/data/anonyner_synthetic_new.jsonl
```

### Étape 2 — Fusionner et compiler le dataset

```bash
# Combiner plusieurs corpus
cat training/data/linux_annotated.jsonl training/data/windows_annotated.jsonl \
    > training/data/corpus_complet.jsonl

# Convertir JSONL → train.spacy + dev.spacy (split 80/20 par défaut)
python training/scripts/prepare_spacy_dataset.py \
    --input training/data/corpus_complet.jsonl
```

Option `--split` pour ajuster le ratio de validation (défaut : `0.2`).

### Étape 3 — Fine-tuner le modèle

```bash
python training/scripts/train_anonyner.py
```

Le script :
1. Génère `data/ner/config.cfg` si absent (optimisé CPU/efficiency)
2. Injecte `source = "en_anonyner"` dans les sections `[components.tok2vec]` et
   `[components.ner]` — fine-tuning au lieu d'un réentraînement de zéro
3. Détecte le GPU via CuPy et passe `LD_LIBRARY_PATH` au subprocess si disponible
4. Lance `spacy train` avec `data/ner/train.spacy` et `data/ner/dev.spacy`
5. Sauvegarde `model-best` et `model-last` dans `models/anonyner_model/`

> **Note :** Si la config existe déjà d'un run précédent, la supprimer avant de relancer :
> `rm training/data/ner/config.cfg`

#### Comprendre l'affichage pendant l'entraînement

```
E    #       LOSS TOK2VEC  LOSS NER  ENTS_F  ENTS_P  ENTS_R  SCORE
---  ------  ------------  --------  ------  ------  ------  ------
  0       0          7.92     21.27    5.59    4.43    7.56    0.06
  0     200       2346.72   1567.78   68.81   71.84   66.02    0.69
  1    2000       1303.84   3294.82   86.84   85.90   87.79    0.87
```

| Colonne | Signification |
|---|---|
| `E` | Numéro d'époque (passage complet sur le dataset d'entraînement) |
| `#` | Numéro de step (batch) depuis le début |
| `LOSS TOK2VEC` | Perte du composant de représentation contextuelle (tok2vec). Doit diminuer en début d'entraînement. |
| `LOSS NER` | Perte du composant NER. Doit diminuer globalement, des remontées ponctuelles sont normales. |
| `ENTS_F` | **F1-score sur le dev set** — métrique principale. Sauvegardé dans `model-best` à chaque nouveau maximum. |
| `ENTS_P` | Précision sur le dev set — ratio entités prédites correctes / total prédit |
| `ENTS_R` | Rappel sur le dev set — ratio entités correctes trouvées / total attendu. **Métrique critique pour l'anonymisation** (une entité manquée = fuite de donnée). |
| `SCORE` | Score composite spaCy (= `ENTS_F` pour un pipeline NER pur) |

#### Comportements attendus

**Début (epoch 0, steps 0–400)** : forte descente de la loss, F1 progresse vite de ~5% à ~75%. Normal — le modèle s'aligne sur le nouveau corpus depuis `en_anonyner`.

**Milieu (epochs 1–4)** : convergence progressive vers 85–90% F1. Les pertes augmentent en valeur absolue (plus d'examples vus par step) mais le score dev continue de monter. Des oscillations de ±2% F1 entre steps sont normales.

**Fin (early stopping)** : spaCy arrête automatiquement si le score dev ne s'améliore pas pendant N steps consécutifs (`patience` dans `config.cfg`, défaut 1600). Le meilleur modèle (`model-best`) est celui du step avec le SCORE maximal observé — pas forcément le dernier.

**Signaux d'alerte :**
- F1 plafonne sous 70% dès l'epoch 0 → problème de corpus (chevauchements, labels corrompus) — relancer `clean_corpus.py`
- `ENTS_P` ≫ `ENTS_R` (ex. P=95%, R=60%) → le modèle est trop conservateur, corpus trop petit ou entités rares absentes
- `ENTS_R` ≫ `ENTS_P` (ex. R=95%, P=60%) → sur-annotation dans les données d'entraînement, labels ambigus
- Loss NER qui monte indéfiniment sans que F1 progresse → learning rate trop élevé ou corpus mal aligné

### Étape 4 — Tester le modèle entraîné

```python
import spacy

nlp = spacy.load("training/models/anonyner_model/model-best")
doc = nlp("Block IP 192.168.1.10 on fw01.company.local — CVE-2024-12345")
print([(ent.text, ent.label_) for ent in doc.ents])
# → [('192.168.1.10', 'IP_ADDRESS'), ('fw01.company.local', 'HOSTNAME'), ('CVE-2024-12345', 'CVE')]
```

### Étape 5 — Intégrer dans Victor

```python
from victor import Anonymizer

anon = Anonymizer(config={"spacy_model": "training/models/anonyner_model/model-best"})
```

---

## Ajouter ou modifier des labels

Modifier **uniquement** `training/scripts/labels.py` :
- Ajouter le label dans la liste `_NETWORK`, `_COMMON`, `_LINUX` ou `_WINDOWS`
- Mettre à jour le `NER_PROMPT` dans `annotate_corpus.py` pour que le LLM connaisse le nouveau label
- Ajouter une règle regex dans `victor/config/custom_rules_security.json` si le pattern est déterministe

Les scripts `annotate_corpus.py` et `review_corpus.py` importent `VALID_LABELS` et `VALID_LABELS_SET`
depuis `labels.py` — aucune autre modification nécessaire.

---

## Enrichir le corpus avec les gaps Victor

Le `GapCollector` de Victor alimente directement le pipeline d'entraînement.
Les gaps validés (via `GapValidator` ou manuellement) sont exportés en JSONL
compatibles avec `prepare_spacy_dataset.py` :

```python
from victor import GapCollector, AnnotationWriter
from pathlib import Path

collector = GapCollector(data_dir=Path("data"))
ann_writer = AnnotationWriter(data_dir=Path("data/dataset"))

for gap in collector.candidates(min_occurrences=3):
    examples = collector.to_spacy_examples(gap["text"], gap["label"])
    ann_writer.add_examples(examples, label=gap["label"], source_key=f"gap::{gap['label']}")
    collector.accept(gap["text"], gap["label"])

# data/dataset/annotations.json → copier dans training/data/ pour ré-entraîner
```

---

## Politique de versioning

AnonyNER adopte la même convention que les modèles officiels spaCy (`en_core_web_md-3.8.0`) :
la **version majeure est calquée sur spaCy**, les deux chiffres suivants sont propres au modèle.

```
MAJEURE  =  version majeure de spaCy (3.x → 3, 4.x → 4)
MINEURE  =  évolution du modèle : nouveaux labels, nouveau domaine
PATCH    =  réentraînement à périmètre constant
```

| Incrément | Quand | Exemples |
|-----------|-------|---------|
| **PATCH** `3.x.y+1` | Réentraînement sur le même jeu de labels — amélioration du score F, correction de corpus, ajout d'exemples dans les catégories existantes | `v3.1.1`, `v3.1.2` |
| **MINEURE** `3.x+1.0` | Nouveaux labels ajoutés, nouveau format de log supporté, extension vers un nouveau domaine (Linux, Windows, Apache…) | `v3.1.0`, `v3.2.0` |
| **MAJEURE** `X+1.0.0` | Migration vers une nouvelle version majeure de spaCy — implique un réentraînement complet, potentielle incompatibilité de labels ou d'architecture | `v4.0.0` |

> **Exemple :** spaCy 3.8.11 est utilisé. L'ajout des 12 labels Linux/Windows/Common
> justifie `v3.1.0`. La prochaine migration spaCy 4.x donnera `v4.0.0`.

> **Cohérence :** un modèle `en_anonyner-3.x.y` nécessite spaCy 3.x.
> Un modèle `en_anonyner-4.x.y` nécessitera spaCy 4.x.

---

## Publier une nouvelle version

Après validation du modèle, déterminer le numéro de version selon la politique ci-dessus,
puis packager et publier :

```bash
# Remplacer X.Y.Z selon la politique de versioning
VERSION=3.1.0

# Packager le modèle
python -m spacy package training/models/anonyner_model/model-best dist/ \
    --name anonyner --version ${VERSION}

# Créer une release GitHub et uploader le .tar.gz
gh release create anonyner-v${VERSION} dist/en_anonyner-${VERSION}.tar.gz \
    --repo patlegu/anonyfiles \
    --title "AnonyNER v${VERSION}"
```
