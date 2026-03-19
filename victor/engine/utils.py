from typing import List, Dict, Tuple
from io import StringIO


def apply_positional_replacements(
    text: str,
    entity_replacements: Dict[str, str],
    entities_in_text_block: List[Tuple[str, str, int, int]],
) -> str:
    """
    Applique les remplacements d'entités dans un bloc de texte en respectant leurs positions.
    Gère les remplacements qui changent la longueur du texte.

    Args:
        text: Le bloc de texte original.
        entity_replacements: {texte_original: texte_anonymisé}.
        entities_in_text_block: Liste de (entity_text, label, start_char, end_char).

    Returns:
        Le texte avec les entités remplacées.
    """
    output = StringIO()
    sorted_entities = sorted(entities_in_text_block, key=lambda x: x[2])
    current_original_cursor = 0

    for ent_text, ent_label, ent_start_char, ent_end_char in sorted_entities:
        replacement_value = entity_replacements.get(ent_text, ent_text)
        output.write(text[current_original_cursor:ent_start_char])
        output.write(replacement_value)
        current_original_cursor = ent_end_char

    output.write(text[current_original_cursor:])
    return output.getvalue()
