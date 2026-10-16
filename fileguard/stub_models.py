"""Deterministic stub implementations of the Gatekeeper and answering model.

These are used for tests and CI — they never call an LLM API. Both are
keyword/TF-IDF based and fully deterministic given the same inputs.

The stub Gatekeeper selects relevant Unit objects from the unified index
based on term overlap with the access reason. The stub answering model
generates answers with span citations from the selected units, following
the grounding ladder spec.

Live-model runs are optional smoke tests (config.GATEKEEPER_MODE == "live").
"""

from __future__ import annotations

import re
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Protocol

from fileguard.connector import Unit


# ---------------------------------------------------------------------------
# Span reference (normalised across uploaded files and unified index items)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class UnitSpanRef:
    """A reference to a selected span (unit) in the unified index."""
    platform: str
    container: str
    item_id: str
    unit_id: str
    kind: str
    text: str
    order: int


@dataclass
class GatekeeperResult:
    """Output of the Gatekeeper's span selection."""
    spans: list[UnitSpanRef]
    selection_reason: str
    mode: str = "stub-keyword"


@dataclass
class AnswerResult:
    """Output of the answering model."""
    answer_text: str
    citations: list[UnitSpanRef]
    mode: str = "stub-keyword"


# ---------------------------------------------------------------------------
# Stub Gatekeeper — deterministic term-overlap selection
# ---------------------------------------------------------------------------

def _tokenize(text: str) -> set[str]:
    """Split into lowercase terms > 2 chars."""
    return set(w for w in re.split(r"\W+", text.lower()) if len(w) > 2)


def _tfidf_score(unit_text: str, reason_terms: set[str], df_map: Counter, N: int) -> float:
    """TF-IDF score of a unit against the reason terms.
    Smoothed IDF (1 + log(N/df)) so single-unit items can score above zero —
    raw log(N/df) is 0 when N == df == 1 and such items could never match."""
    terms = Counter(w for w in re.split(r"\W+", unit_text.lower()) if len(w) > 2)
    return sum(
        terms[t] * (1 + math.log(N / max(1, df_map[t])))
        for t in reason_terms if t in terms
    )


def stub_select_spans(
    units: list[Unit],
    reason: str,
    platform: str = "",
    container: str = "",
    item_id: str = "",
    max_spans: int = 5,
) -> GatekeeperResult:
    """Deterministic span selection using TF-IDF term overlap.

    Scores each unit by the sum of tf(t) * log(N / df(t)) for every reason
    term t that appears in the unit. Selects the top-k scoring units above
    zero. Returns an empty selection when nothing matches — this is a
    legitimate "nothing relevant" outcome, never an error.
    """
    if not units or not reason.strip():
        return GatekeeperResult(
            spans=[],
            selection_reason="No units or no reason provided.",
        )

    reason_terms = _tokenize(reason)
    if not reason_terms:
        return GatekeeperResult(
            spans=[],
            selection_reason="Access reason has no usable terms.",
        )

    # Document frequency across all units
    df: Counter[str] = Counter()
    for u in units:
        terms = _tokenize(u.text)
        df.update(terms)

    N = len(units)
    scored: list[tuple[float, int, Unit]] = []
    for i, u in enumerate(units):
        score = _tfidf_score(u.text, reason_terms, df, N)
        scored.append((score, i, u))

    # Sort by score descending, then by order for stability
    scored.sort(key=lambda t: (-t[0], t[1]))

    top_k = min(max_spans, max(1, len(scored) // 3))
    picked = [(s, u) for s, _, u in scored[:top_k] if s > 0]

    if not picked:
        return GatekeeperResult(
            spans=[],
            selection_reason="No units in this item match the access reason.",
        )

    spans = [
        UnitSpanRef(
            platform=platform,
            container=container,
            item_id=item_id,
            unit_id=u.unit_id,
            kind=u.kind,
            text=u.text,
            order=u.order,
        )
        for _, u in picked
    ]
    return GatekeeperResult(
        spans=spans,
        selection_reason=f"Selected {len(spans)} unit(s) by term relevance to the access reason.",
    )


# ---------------------------------------------------------------------------
# Stub answering model — extractive answer with citations
# ---------------------------------------------------------------------------

def _sentence_split(text: str) -> list[str]:
    """Split text into sentences (simple)."""
    parts = re.split(r'(?<=[.!?])\s+', text.strip())
    return [p.strip() for p in parts if p.strip()]


def _sentence_relevance(sentence: str, reason_terms: set[str], df_map: Counter, N: int) -> float:
    """TF-IDF score of a sentence against reason terms."""
    return _tfidf_score(sentence, reason_terms, df_map, N)


def stub_generate_answer(
    spans: list[UnitSpanRef],
    reason: str,
) -> AnswerResult:
    """Generate an extractive answer from the selected spans.

    Picks the most relevant sentences from the selected spans and composes
    them into an answer with citations. Each cited sentence is attributed
    to its source span.

    If no spans are selected, returns an empty answer (the grounding ladder
    will turn this into the generic no-evidence message).
    """
    if not spans:
        return AnswerResult(
            answer_text="",
            citations=[],
        )

    reason_terms = _tokenize(reason)
    if not reason_terms:
        return AnswerResult(
            answer_text="",
            citations=[],
        )

    # Collect all sentences from all spans, track which span each came from
    # Build df across sentences so that terms appearing in many sentences
    # are down-weighted (TF-IDF needs N > 1 to produce non-zero scores).
    sentences: list[tuple[float, str, UnitSpanRef]] = []
    all_sentences: list[str] = []
    for span in spans:
        for sentence in _sentence_split(span.text):
            all_sentences.append(sentence)

    df: Counter[str] = Counter()
    for s in all_sentences:
        df.update(_tokenize(s))
    N = max(len(all_sentences), 2)  # avoid log(1/1)=0 when only 1 sentence

    for span in spans:
        for sentence in _sentence_split(span.text):
            score = _sentence_relevance(sentence, reason_terms, df, N)
            if score > 0:
                sentences.append((score, sentence, span))

    if not sentences:
        # No sentence scored above zero — return first sentence of first span
        first = _sentence_split(spans[0].text)
        if first:
            return AnswerResult(
                answer_text=first[0],
                citations=[spans[0]],
            )
        return AnswerResult(answer_text="", citations=[])

    # Sort by score descending, pick top 3
    sentences.sort(key=lambda t: -t[0])
    top = sentences[:3]

    # Compose answer with inline citation markers
    parts = []
    cited = []
    for i, (_, sentence, span) in enumerate(top):
        parts.append(f"{sentence} [{i+1}]")
        cited.append(span)

    answer = " ".join(parts)
    return AnswerResult(
        answer_text=answer,
        citations=cited,
    )
