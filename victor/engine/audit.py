class AuditLogger:
    def __init__(self):
        self.entries = {}

    def log(self, pattern, replacement, typ, count, original_text: str = None):
        key = (pattern, replacement, typ)
        if key in self.entries:
            self.entries[key]["count"] += count
        else:
            entry = {
                "pattern": pattern,
                "replacement": replacement,
                "type": typ,
                "count": count,
            }
            if original_text is not None:
                entry["original_text_for_custom_rule"] = original_text
            self.entries[key] = entry

    def summary(self):
        return list(self.entries.values())

    def total(self):
        return sum(e["count"] for e in self.entries.values())

    def reset(self):
        self.entries = {}
