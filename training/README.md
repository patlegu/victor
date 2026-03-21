# Entraînement AnonyNER

Ce répertoire contient les scripts et données pour entraîner ou ré-entraîner
le modèle spaCy **AnonyNER** utilisé par Victor.

AnonyNER est un modèle NER spécialisé sur les entités cyber : adresses IP,
hostnames, CVE, adresses MAC, comptes de service, interfaces réseau, etc.

> **Note :** Ce répertoire est exclu du dépôt git (`.gitignore`).
> Le modèle pré-entraîné est disponible en release GitHub :
> `pip install https://github.com/patlegu/anonyfiles/releases/download/anonyner-v3.0.0/en_anonyner-3.0.0.tar.gz`

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
  └─► prepare_spacy_dataset.py → train.spacy → train_anonyner.py
```

---

## Structure

```
training/
├── scripts/
│   ├── annotate_corpus.py         — Circuit 2 : annotation logs bruts via Ollama
│   ├── review_corpus.py           — Circuit 2 : revue humaine (CLI)
│   ├── generate_ner_dataset.py    — génération via Ollama depuis corpus SFT existant
│   ├── generate_ner_synthetic.py  — génération synthétique (entités sous-représentées)
│   ├── prepare_spacy_dataset.py   — conversion JSONL → train.spacy / dev.spacy
│   └── train_anonyner.py          — entraînement spaCy + sauvegarde modèle
├── logs/
│   ├── linux/                     ← déposer les logs Linux ici
│   ├── apache/                    ← déposer les logs Apache ici
│   └── windows/                   ← déposer les logs Windows ici
├── data/
│   ├── anonyner_train.jsonl        — corpus principal (1018 exemples)
│   ├── anonyner_combined_v2.jsonl  — corpus combiné v2 (1997 exemples)
│   ├── anonyner_synthetic_en.jsonl — exemples synthétiques EN (924 exemples)
│   ├── anonyner_synthetic_v2.jsonl — exemples synthétiques v2 (550 exemples)
│   ├── anonyner_extractions_v2.jsonl — extractions réelles v2 (179 exemples)
│   ├── config.cfg                 — configuration spaCy (générée, CPU/efficiency)
│   ├── train.spacy                — dataset d'entraînement compilé
│   └── dev.spacy                  — dataset de validation compilé
└── models/                        — modèles entraînés (gitignored)
```

---

## Format des données (JSONL)

Chaque ligne du corpus est un objet JSON :

```json
{
  "text": "Bloque l'IP 192.168.1.50 sur fw01.company.local",
  "entities": [
    {"text": "192.168.1.50", "label": "IP_ADDRESS"},
    {"text": "fw01.company.local", "label": "HOSTNAME"}
  ],
  "spacy_format": [
    [12, 24, "IP_ADDRESS"],
    [29, 47, "HOSTNAME"]
  ]
}
```

Le champ `spacy_format` contient les offsets caractères `[start, end, label]`
directement utilisables par spaCy.

---

## Labels supportés

| Label | Entités détectées |
|-------|-------------------|
| `IP_ADDRESS` | Adresses IPv4 et IPv6 |
| `HOSTNAME` | Hostnames et FQDNs internes |
| `CVE` | Identifiants CVE (`CVE-YYYY-NNNNN`) |
| `MAC_ADDRESS` | Adresses MAC (`aa:bb:cc:dd:ee:ff`) |
| `INTERFACE` | Interfaces réseau (`eth0`, `wg0`, `en0`…) |
| `SERVICE_ACCOUNT` | Comptes de service (`crowdsec-agent`, `sshd`…) |
| `FIREWALL_RULE` | Règles et noms de politiques firewall |
| `PORT_NUMBER` | Numéros de port |
| `VPN_USER` | Identifiants utilisateur VPN |
| `IP_SUBNET` | Sous-réseaux CIDR |

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
- `e` → éditer le label
- `d` → supprimer une entité
- `s` → ignorer
- `q` → quitter (progression sauvegardée, reprise possible)

### Compiler et entraîner

```bash
python training/scripts/prepare_spacy_dataset.py \
    --input training/data/linux_annotated.jsonl \
    --train-out training/data/train.spacy \
    --dev-out training/data/dev.spacy

python training/scripts/train_anonyner.py
```

---

## Procédure d'entraînement

### Prérequis

```bash
pip install spacy
python -m spacy download en_core_web_md   # tokeniseur pour l'alignement
```

### Étape 1 — Générer des données supplémentaires (optionnel)

Si Ollama est disponible, générer de nouveaux exemples à partir de logs bruts :

```bash
# Génération via Ollama (nécessite qwen2.5-coder:7b ou équivalent)
python scripts/generate_ner_dataset.py --model qwen2.5-coder:7b --count 100

# Génération synthétique (entités sous-représentées, sans GPU)
python scripts/generate_ner_synthetic.py --output data/anonyner_synthetic_new.jsonl
```

Les fichiers JSONL générés s'ajoutent aux corpus existants dans `data/`.

### Étape 2 — Fusionner et compiler le dataset

Concaténer les corpus à utiliser, puis les convertir au format binaire spaCy :

```bash
# Exemple : combiner tous les JSONL en un seul fichier
cat data/anonyner_train.jsonl data/anonyner_synthetic_en.jsonl > data/corpus_complet.jsonl

# Convertir JSONL → train.spacy + dev.spacy (split 80/20 par défaut)
python scripts/prepare_spacy_dataset.py --input data/corpus_complet.jsonl \
    --train-out data/train.spacy \
    --dev-out data/dev.spacy
```

Option `--split` pour ajuster le ratio de validation (défaut : `0.2`).

### Étape 3 — Entraîner le modèle

```bash
python scripts/train_anonyner.py
```

Le script :
1. Génère `data/config.cfg` si absent (optimisé CPU/efficiency)
2. Lance `spacy train` avec les fichiers `train.spacy` et `dev.spacy`
3. Sauvegarde `model-best` et `model-last` dans `models/anonyner_model/`

### Étape 4 — Tester le modèle entraîné

```python
import spacy

nlp = spacy.load("training/models/anonyner_model/model-best")
doc = nlp("Block IP 192.168.1.10 on fw01.company.local — CVE-2024-12345")
print([(ent.text, ent.label_) for ent in doc.ents])
# → [('192.168.1.10', 'IP_ADDRESS'), ('fw01.company.local', 'HOSTNAME'), ('CVE-2024-12345', 'CVE')]
```

### Étape 5 — Intégrer dans Victor

Pointer Victor vers le nouveau modèle :

```python
from victor import Anonymizer

anon = Anonymizer(config={"spacy_model": "training/models/anonyner_model/model-best"})
```

Ou remplacer `models/anonyner_model/model-best` par le modèle entraîné.

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

## Publier une nouvelle version

Après validation du modèle :

```bash
# Packager le modèle
python -m spacy package training/models/anonyner_model/model-best dist/ \
    --name anonyner --version 4.0.0

# Créer une release GitHub et uploader le .tar.gz
gh release create anonyner-v4.0.0 dist/en_anonyner-4.0.0.tar.gz \
    --repo patlegu/anonyfiles \
    --title "AnonyNER v4.0.0"
```
