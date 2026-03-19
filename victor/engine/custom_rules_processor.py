import re
import logging
from typing import List, Dict, Any, Optional

from .audit import AuditLogger

logger = logging.getLogger(__name__)


class CustomRulesProcessor:
    """
    Gère l'application des règles de remplacement personnalisées sur des blocs de texte.
    """

    def __init__(
        self,
        custom_replacement_rules: Optional[List[Dict[str, Any]]],
        audit_logger: AuditLogger,
    ):
        self.custom_rules: List[Dict[str, Any]] = []
        self.audit_logger = audit_logger
        self.custom_replacements_mapping: Dict[str, str] = {}
        self.custom_replacements_count = 0

        if custom_replacement_rules:
            for rule in custom_replacement_rules:
                pattern_str = rule.get("pattern")
                if not pattern_str:
                    continue
                if rule.get("isRegex", False):
                    try:
                        rule["compiled_pattern"] = re.compile(pattern_str, flags=re.IGNORECASE)
                    except re.error as e:
                        logger.warning(
                            "Regex invalide pour la règle '%s': %s — règle ignorée.",
                            pattern_str, e,
                        )
                        continue
                self.custom_rules.append(rule)

        if self.custom_rules:
            logger.debug("CustomRulesProcessor initialisé avec %d règle(s).", len(self.custom_rules))

    def apply_to_block(self, text_block: str) -> str:
        """Applique les règles personnalisées à un bloc de texte."""
        if not self.custom_rules:
            return text_block

        modified_text = text_block
        for rule in self.custom_rules:
            pattern_str = rule.get("pattern")
            replacement = rule.get("replacement", "[CUSTOM_REDACTED]")
            is_regex = rule.get("isRegex", False)
            compiled_pattern: Optional[re.Pattern] = rule.get("compiled_pattern")

            if not pattern_str:
                continue

            try:
                if is_regex and compiled_pattern is not None:
                    def replacer_func(match: re.Match) -> str:
                        original_text = match.group(0)
                        final_replacement = match.expand(replacement)
                        self.audit_logger.log(
                            original_text, final_replacement, "custom_regex", 1,
                            original_text=original_text,
                        )
                        self.custom_replacements_count += 1
                        self.custom_replacements_mapping[original_text] = final_replacement
                        return final_replacement

                    modified_text = compiled_pattern.sub(replacer_func, modified_text)
                else:
                    count = modified_text.count(pattern_str)
                    if count > 0:
                        modified_text = modified_text.replace(pattern_str, replacement)
                        self.audit_logger.log(
                            pattern_str, replacement, "custom_text", count,
                            original_text=pattern_str,
                        )
                        self.custom_replacements_count += count
                        self.custom_replacements_mapping[pattern_str] = replacement
            except re.error as e:
                logger.warning("Regex invalide pour la règle '%s': %s — ignorée.", pattern_str, e)

        return modified_text

    def get_custom_replacements_mapping(self) -> Dict[str, str]:
        return self.custom_replacements_mapping

    def get_custom_replacements_count(self) -> int:
        return self.custom_replacements_count

    def reset(self):
        self.custom_replacements_mapping = {}
        self.custom_replacements_count = 0
