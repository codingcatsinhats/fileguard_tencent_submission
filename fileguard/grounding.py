"""Grounding check — the graceful grounding ladder.

The answering model generates an answer with citations from the
Gatekeeper-selected spans. The grounding check verifies that every
claim in the answer is backed by a cited span, then degrades gracefully:

  a. Generate an answer with citations.
  b. Pass: "verified" — every claim is grounded in a cited span.
  c. Fail: delete the failing sentence and re-check.
  d. "pruned" — ≥1 cited sentence remains and ≥50% of original claims
     survive. Return the pruned answer with its surviving citations.
  e. Pruning leaves too little: "excerpts only" — return verbatim span
     excerpts with no composed answer.
  f. Zero permitted spans or zero surviving claims: "generic no-evidence
     message" — identical for "nothing exists" and "nothing may be seen".

The grounding check is a pure function of (answer, citations, spans) —
it never calls an LLM. It uses fuzzy matching (normalized substring) to
verify that each cited sentence appears verbatim in the referenced span.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from fileguard.stub_models import UnitSpanRef, AnswerResult


GroundingLevel = Literal["verified", "pruned", "excerpts_only", "no_evidence"]


@dataclass
class GroundingResult:
    """The result of the grounding ladder."""
    level: GroundingLevel
    answer_text: str
    citations: list[UnitSpanRef]
    pruned_count: int = 0  # number of sentences removed during pruning
    reason: str = ""


GENERIC_NO_EVIDENCE = (
    "No verified information is available to answer this request "
    "with the current access permissions."
)


def _normalize(text: str) -> str:
    """Normalize whitespace and case for fuzzy matching."""
    return re.sub(r"\s+", " ", text).strip().lower()


def _sentence_split(text: str) -> list[str]:
    """Split text into sentences (simple)."""
    parts = re.split(r'(?<=[.!?])\s+', text.strip())
    return [p.strip() for p in parts if p.strip()]


def _strip_citation_markers(text: str) -> str:
    """Remove [1], [2], etc. citation markers from a sentence."""
    return re.sub(r'\s*\[\d+\]\s*', '', text).strip()


def _sentence_grounded(
    sentence: str,
    cited_spans: list[UnitSpanRef],
) -> bool:
    """Check if a sentence is grounded in at least one cited span.

    A sentence is grounded if its normalized form appears as a substring
    of at least one cited span's text (fuzzy matching on whitespace/case).
    """
    sentence_clean = _strip_citation_markers(sentence)
    if not sentence_clean:
        return False
    norm_sentence = _normalize(sentence_clean)
    for span in cited_spans:
        norm_span = _normalize(span.text)
        if norm_sentence in norm_span:
            return True
    return False


def _extract_cited_spans_for_sentence(
    sentence: str,
    all_citations: list[UnitSpanRef],
) -> list[UnitSpanRef]:
    """Extract the spans cited by this sentence's [N] markers."""
    markers = re.findall(r'\[(\d+)\]', sentence)
    if not markers:
        # No explicit markers — try all citations
        return all_citations
    indices = [int(m) - 1 for m in markers if int(m) > 0]
    return [all_citations[i] for i in indices if i < len(all_citations)]


def grounding_check(
    answer: AnswerResult,
    spans: list[UnitSpanRef],
) -> GroundingResult:
    """Run the graceful grounding ladder on an answer.

    Args:
        answer: The answering model's output (text + citations).
        spans: The Gatekeeper-selected spans (the permitted content).

    Returns:
        GroundingResult with the final level, text, and citations.
    """
    # Step f: zero permitted spans → generic no-evidence
    if not spans:
        return GroundingResult(
            level="no_evidence",
            answer_text=GENERIC_NO_EVIDENCE,
            citations=[],
            reason="no spans were permitted for this request",
        )

    # If the answering model produced no text, also no-evidence
    if not answer.answer_text.strip():
        return GroundingResult(
            level="no_evidence",
            answer_text=GENERIC_NO_EVIDENCE,
            citations=[],
            reason="answering model produced no text",
        )

    sentences = _sentence_split(answer.answer_text)
    if not sentences:
        return GroundingResult(
            level="no_evidence",
            answer_text=GENERIC_NO_EVIDENCE,
            citations=[],
            reason="answer contained no sentences",
        )

    # Step a/b: verify — every sentence must be grounded in a cited span
    verified: list[tuple[str, list[UnitSpanRef]]] = []
    unverified: list[str] = []

    for sentence in sentences:
        cited_for_this = _extract_cited_spans_for_sentence(sentence, answer.citations)
        # The cited spans must all be in the permitted spans set
        permitted_cited = [s for s in cited_for_this if s in spans or _span_in_list(s, spans)]
        if not permitted_cited:
            # Fall back: check if the sentence is grounded in ANY permitted span
            permitted_cited = [s for s in spans if _sentence_grounded(sentence, [s])]

        if _sentence_grounded(sentence, permitted_cited if permitted_cited else spans):
            verified.append((sentence, permitted_cited or spans[:1]))
        else:
            unverified.append(sentence)

    # Step b: all sentences grounded → verified
    if not unverified:
        return GroundingResult(
            level="verified",
            answer_text=answer.answer_text,
            citations=answer.citations,
            reason="all claims grounded in cited spans",
        )

    # Step c/d: prune — delete failing sentences, keep grounded ones
    original_count = len(sentences)
    surviving_count = len(verified)

    # ≥1 cited sentence remains AND ≥50% survive → pruned
    if surviving_count >= 1 and surviving_count >= original_count / 2:
        pruned_text = " ".join(s for s, _ in verified)
        pruned_citations = []
        seen_ids = set()
        for _, spans_list in verified:
            for span in spans_list:
                if span.unit_id not in seen_ids:
                    seen_ids.add(span.unit_id)
                    pruned_citations.append(span)
        return GroundingResult(
            level="pruned",
            answer_text=pruned_text,
            citations=pruned_citations,
            pruned_count=len(unverified),
            reason=f"removed {len(unverified)} ungrounded sentence(s)",
        )

    # Step e: pruning leaves too little → excerpts only
    # Return verbatim span excerpts (the full text of each permitted span)
    if surviving_count >= 1:
        excerpts = [s.text for s in spans]
        excerpt_text = " ".join(excerpts)
        return GroundingResult(
            level="excerpts_only",
            answer_text=excerpt_text,
            citations=list(spans),
            pruned_count=len(unverified),
            reason="too few sentences survived pruning; returning verbatim excerpts",
        )

    # Step f: zero surviving claims → generic no-evidence
    return GroundingResult(
        level="no_evidence",
        answer_text=GENERIC_NO_EVIDENCE,
        citations=[],
        pruned_count=len(unverified),
        reason="no claims survived grounding verification",
    )


def _span_in_list(span: UnitSpanRef, spans: list[UnitSpanRef]) -> bool:
    """Check if a span is in a list by unit_id."""
    return any(s.unit_id == span.unit_id for s in spans)
