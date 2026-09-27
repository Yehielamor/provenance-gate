"""Open prompt-injection classifiers, used as the detection baseline.

Each detector scores *every tool output* the agent reads, the way such
classifiers are deployed in front of an agent. Long outputs are split into
overlapping 512-token windows and the output is flagged if any window is.
"""

from __future__ import annotations

import hashlib

import torch
import yaml
from transformers import AutoModelForSequenceClassification, AutoTokenizer

# name -> (HF model id, label index meaning "injection" is looked up by name)
MODELS = {
    "protectai-v2": ("protectai/deberta-v3-base-prompt-injection-v2", "INJECTION"),
    "deepset": ("deepset/deberta-v3-base-injection", "INJECTION"),
    "prompt-guard-2": ("meta-llama/Llama-Prompt-Guard-2-86M", "LABEL_1"),  # gated on HF
}


class Detector:
    """name "<model>" scores the whole tool output; "<model>/per-item" scores each record of a
    list-shaped output separately (a yoga-class listing flags as a whole but not item by item)."""

    def __init__(self, name: str, threshold: float = 0.5):
        base, _, mode = name.partition("/")
        model_id, label = MODELS[base]
        self.name, self.threshold, self.per_item = name, threshold, mode == "per-item"
        self.tok = AutoTokenizer.from_pretrained(model_id)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_id).eval()
        labels = {v.upper(): int(k) for k, v in self.model.config.id2label.items()}
        self.idx = labels.get(label.upper(), 1)
        self.cache: dict[str, float] = {}

    def score(self, text: str) -> float:
        if self.per_item:
            try:
                data = yaml.safe_load(text)
            except yaml.YAMLError:
                data = None
            if isinstance(data, list) and len(data) > 1:
                return max(self._score(yaml.safe_dump(x, allow_unicode=True)) for x in data)
        return self._score(text)

    @torch.no_grad()
    def _score(self, text: str) -> float:
        """Max injection probability over all 512-token windows of the text."""
        key = hashlib.sha1(text.encode("utf-8", "surrogatepass")).hexdigest()
        if key in self.cache:
            return self.cache[key]
        enc = self.tok(text, truncation=True, max_length=512, stride=64, return_overflowing_tokens=True,
                       padding=True, return_tensors="pt")
        enc.pop("overflow_to_sample_mapping", None)
        best = 0.0
        for i in range(0, enc["input_ids"].shape[0], 16):
            batch = {k: v[i:i + 16] for k, v in enc.items()}
            probs = torch.softmax(self.model(**batch).logits, dim=-1)[:, self.idx]
            best = max(best, float(probs.max()))
        self.cache[key] = best
        return best

    def flags(self, text: str) -> bool:
        return self.score(text) >= self.threshold
