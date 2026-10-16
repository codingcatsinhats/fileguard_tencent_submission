# ⚠️ DEV DEMO ONLY — NOT PART OF THE SECURITY PERIMETER

Everything in this folder exists to make the demo inspectable:

- `*.pdf / *.xlsx / *.docx` — the **plaintext originals** of the documents
  served through the **uploads connector** (the fifth connector). They are
  encrypted into the content-addressed Content Store
  (`data/store/<sha256>.bin`); these are the same bytes whose SHA-256 is
  the `file_id` in the metadata DB, so you can verify the pinning yourself.
- `decrypt.py` — demo tool: finds an encrypted file **by name (regex)** in
  the metadata DB, decrypts it from the Content Store, and writes the
  plaintext into this folder.

**These are plaintext copies of access-controlled documents, and decrypted
outputs are written here in the clear.** This folder is for development and
demo only — it must never exist in any real deployment, and nothing in the
product reads from it.

for product testing:
- run: python3 demo-seed/reset-demo.py && python3 scripts/sync_demo.py
- run: uvicorn ui.web:app --port 8000   (then open http://localhost:8000)
- chat: log in as a Company A persona (token-maya, token-lena, …) —
  see the root README for the full token table and demo flows
- Upload-store demo (closed-network corpus): log in as token-alice or token-bob and ask
  about the board compensation spreadsheet

The files in this folder are the closed-network corpus for the
upload-store demo; they are the uploads connector's fixtures.
