#!/usr/bin/env python3
"""
GODS Engine: parser
Normalizes raw module output into structured findings.
"""
from utils.helpers import C, log

class Parser:
    def __init__(self, raw_results, logger):
        self.raw = raw_results
        self.logger = logger

    def run(self):
        log("PARSER", "Parsing and normalizing results...", C.B)
        parsed = {}
        for module, data in self.raw.items():
            parsed[module] = self._normalize(module, data)
        log("PARSER", "Parsing complete.", C.G)
        return parsed

    def _normalize(self, module, data):
        if not isinstance(data, dict):
            return {"raw": data}
        return data
