"""Span Extractor — code only. Turns SpanRefs into verbatim text.

1. hash pin: re-hash the plaintext, compare with the hash pinned at selection
   (mismatch = file changed mid-selection -> reject).
2. verbatim copy: re-parse the plaintext and copy the referenced span bytes.
3. redundancy check: the copied text's normalized fingerprint must appear in
   the normalized full text (belt and braces on top of the re-parse).
"""

import re

from . import parsers, security


class SpanExtractError(Exception):
    pass


SPAN_KIND_BY_DOC_KIND = {"pdf": "page", "xlsx": "cell_range", "docx": "paragraph"}


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def extract_spans(
    plaintext: bytes,
    kind: str,
    doc_id: str,
    pinned_hash: str,
    span_refs: list[dict],
) -> list[dict]:
    actual_hash = security.sha256_hex(plaintext)
    if actual_hash != pinned_hash:
        raise SpanExtractError(
            f"content hash mismatch for {doc_id}: file changed since selection"
        )

    all_spans = parsers.parse_to_spans(plaintext, kind)
    full_normalized = _normalize("\n".join(s.text for s in all_spans))

    out = []
    for ref in span_refs:
        if ref.get("doc_id") != doc_id or ref.get("content_hash") != pinned_hash:
            raise SpanExtractError(f"span ref does not match selected document: {ref}")
        if ref.get("kind") != SPAN_KIND_BY_DOC_KIND[kind]:
            raise SpanExtractError(
                f"span kind {ref.get('kind')!r} is not valid for document kind {kind!r}"
            )
        text = parsers.extract_span(plaintext, kind, ref["kind"], ref["start"], ref["end"])
        if _normalize(text) not in full_normalized:
            raise SpanExtractError(
                f"redundancy check failed for span {ref['start']}..{ref['end']}"
            )
        out.append({
            "kind": ref["kind"],
            "start": ref["start"],
            "end": ref["end"],
            "text": text,
            "doc_id": doc_id,
            "content_hash": pinned_hash,
            "verified": True,
        })
    return out
