"""A tiny, dependency-free TF-IDF vector store.

Why not embeddings? Determinism and zero setup: the same query always retrieves the same
documents, CI needs no model download, and the whole retriever fits in one screen, so it is
easy to reason about *why* a poisoned document was retrieved. The security properties being
tested (no access control on the index, untrusted text flowing into the prompt) are the same
for TF-IDF and dense embeddings.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable

from redteam.models import Document

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "can",
        "do",
        "for",
        "from",
        "has",
        "have",
        "how",
        "i",
        "in",
        "is",
        "it",
        "its",
        "me",
        "my",
        "of",
        "on",
        "or",
        "our",
        "please",
        "the",
        "their",
        "this",
        "to",
        "was",
        "what",
        "when",
        "which",
        "who",
        "will",
        "with",
        "you",
        "your",
    ]
)


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS and len(t) > 1]


class TfidfIndex:
    def __init__(self, documents: Iterable[Document]) -> None:
        self.documents: list[Document] = list(documents)
        tokenized = [tokenize(f"{d.title or ''} {d.content}") for d in self.documents]
        n_docs = len(self.documents)
        df: Counter[str] = Counter()
        for tokens in tokenized:
            df.update(set(tokens))
        self.idf = {term: math.log((1 + n_docs) / (1 + freq)) + 1.0 for term, freq in df.items()}
        self.vectors = [self._vector(tokens) for tokens in tokenized]

    def _vector(self, tokens: list[str]) -> dict[str, float]:
        counts = Counter(tokens)
        vec = {t: c * self.idf.get(t, 0.0) for t, c in counts.items() if t in self.idf}
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        return {t: v / norm for t, v in vec.items()}

    def search(self, query: str, k: int = 3) -> list[tuple[Document, float]]:
        qvec = self._vector(tokenize(query))
        scored = [
            (doc, sum(w * dvec.get(t, 0.0) for t, w in qvec.items()))
            for doc, dvec in zip(self.documents, self.vectors, strict=True)
        ]
        scored = [s for s in scored if s[1] > 0]
        scored.sort(key=lambda s: s[1], reverse=True)
        return scored[:k]


def format_context(docs: list[Document]) -> str:
    """How retrieved chunks are pasted into the prompt (the vulnerable part: no isolation)."""
    return "\n\n".join(f"[{d.id}] {d.content}" for d in docs)


def augment_user_message(question: str, docs: list[Document]) -> str:
    if not docs:
        return question
    return (
        "Use the following retrieved documents to answer.\n\n"
        f"Retrieved documents:\n{format_context(docs)}\n\n"
        f"Customer question: {question}"
    )
