import spacy
import re
import logging
from functools import lru_cache

logger = logging.getLogger(__name__)

EMAIL_REGEX = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b'

DATE_REGEX = (
    r'\b('
    r'(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4})|'
    r'(?:\d{4}[/-]\d{1,2}[/-]\d{1,2})|'
    r'(?:\d{1,2}\s+[a-zA-Zéûîôâ]+\s+\d{4})|'
    r'(?:le\s+\d{1,2}(?:er)?\s+[a-zA-Zéûîôâ]+\s+\d{4})'
    r')\b'
)
PHONE_REGEX = r'\b(?:\+33|0)[1-9](?:[\s.-]?\d{2}){4}\b'
IBAN_REGEX = r'\b[A-Z]{2}\d{2}[ ]?(?:\d[ ]?){12,26}\b'


@lru_cache(maxsize=2)
def _load_spacy_model_cached(model_name: str):
    """Charge un modèle spaCy avec mise en cache (évite les rechargements)."""
    logger.info("Chargement du modèle spaCy : %s …", model_name)
    try:
        return spacy.load(model_name)
    except Exception as e:
        install_cmd = f"python -m spacy download {model_name}"
        raise RuntimeError(
            f"Impossible de charger le modèle spaCy '{model_name}'. "
            f"Installer avec : {install_cmd}. Erreur : {e}"
        ) from e


class SpaCyEngine:
    def __init__(self, model="fr_core_news_md"):
        self.nlp = _load_spacy_model_cached(model)

    def nlp_doc(self, text):
        """Retourne le doc spaCy (utile pour les offsets)."""
        return self.nlp(text)
