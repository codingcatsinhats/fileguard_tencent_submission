"""Upload path + file registry tests — the upload store's fixtures
(plaintext originals live in dev_demo_files/, encrypted into the content
store; dev tooling only, outside the security perimeter)."""

import io
import json
import os
import sys
import tempfile
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="fileguard-upload-")
os.environ["FILEGUARD_DATA_DIR"] = _TMP
os.environ["FILEGUARD_GATEKEEPER_MODE"] = "test"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import ui.web as web  # noqa: E402
from fileguard import db, store  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def seeded():
    from scripts import ingest_demo, seed

    seed.main()
    ingest_demo.main()


@pytest.fixture()
def client():
    return TestClient(web.app)


def _docx_bytes(text="uploaded confidential note"):
    import docx

    d = docx.Document()
    d.add_paragraph(text)
    buf = io.BytesIO()
    d.save(buf)
    return buf.getvalue()


def _login_user(client, token="token-bob"):
    client.post("/login", data={"token": token})


def _upload(client, *, clearance, groups="", display_name="", filename="note.docx",
            data=None, ctype="application/octet-stream", token=None):
    if token:
        _login_user(client, token)
    kwargs = {"data": {"clearance": clearance, "groups": groups,
                       "display_name": display_name},
              "files": {"file": (filename, data or _docx_bytes(), ctype)}}
    return client.post("/upload", **kwargs)


def _login_audit(client, token="audit-token-topsecret"):
    client.post("/audit/login", data={"token": token})


def test_upload_ok_encrypted_hashed_registered(client, seeded):
    _login_user(client)
    data = _docx_bytes()
    r = _upload(client, clearance="confidential", groups="finance",
                display_name="bob_team_note", filename="bob_team_note.docx",
                data=data, ctype="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    assert r.status_code == 200
    assert "Uploaded" in r.text and "Encrypted at rest" in r.text

    # registered in the metadata DB with the right metadata
    conn = db.central()
    row = conn.execute(
        "SELECT file_id, kind, base_clearance, groups FROM files WHERE name LIKE 'bob_team_note%'"
    ).fetchone()
    assert row, "file registered in DB"
    file_id, kind, clearance, groups = row
    assert kind == "docx" and clearance == "confidential"
    assert json.loads(groups) == ["finance"]

    # encrypted at rest, decrypts back byte-identical (hash == file_id)
    assert (store.load_plaintext(file_id) == data)
    from fileguard import config
    assert (Path(config.STORE_DIR) / f"{file_id}.bin").exists()

    # upload logged in the central audit trail
    payloads = [p for (p,) in conn.execute("SELECT payload FROM audit_log")]
    assert any('"event":"upload"' in p.replace(" ", "") and "bob_team_note" in p
               for p in payloads)

    # dev_demo_files must NOT contain the uploaded plaintext
    from fileguard import config
    assert not (config.REPO_ROOT / "dev_demo_files" / "bob_team_note.docx").exists()


def test_upload_above_own_clearance_rejected(client, seeded):
    _login_user(client, "token-bob")  # confidential
    r = _upload(client, clearance="top_secret", filename="leak.docx")
    assert "above your own clearance" in r.text
    conn = db.central()
    rows = conn.execute("SELECT 1 FROM files WHERE name LIKE 'leak%'").fetchall()
    assert not rows


def test_upload_foreign_group_rejected(client, seeded):
    _login_user(client, "token-bob")  # finance only
    r = _upload(client, clearance="confidential", groups="HR")
    assert "not a member of" in r.text


def test_upload_unsupported_type_rejected(client, seeded):
    _login_user(client, "token-bob")
    r = _upload(client, clearance="open", filename="notes.txt", data=b"plain text",
                ctype="text/plain")
    assert "Unsupported file type" in r.text


def test_upload_requires_login(client, seeded):
    r = _upload(client, clearance="open", token="token-bob")
    client.cookies.clear()
    r = client.post("/upload", data={"clearance": "open"},
                    files={"file": ("x.docx", _docx_bytes(), "application/octet-stream")})
    assert r.status_code == 401


def test_duplicate_name_auto_suffixed(client, seeded):
    _login_user(client)
    for i in range(2):
        r = _upload(client, clearance="confidential", groups="finance",
                    display_name="dup_note", filename=f"dup_{i}.docx",
                    data=_docx_bytes(f"dup {i}"))
    assert "Uploaded" in r.text
    conn = db.central()
    names = [n for (n,) in conn.execute(
        "SELECT name FROM files WHERE name LIKE 'dup_note%'")]
    assert len(names) == 2 and any(n.startswith("dup_note_2") for n in names)


# --- sources view (replaced the file registry; uploads are one connector) ----------


def test_sources_view_lists_connectors(client, seeded):
    _login_audit(client, "audit-token-topsecret")
    page = client.get("/audit?view=sources")
    assert "Sources" in page.text
    for platform in ("confluence", "jira", "slack", "drive", "uploads"):
        assert platform in page.text
    assert "employee_handbook.pdf" not in page.text  # per-file rows are gone


def test_sources_standard_auditor_no_file_names(client, seeded):
    _login_user(client, "token-bob")
    _upload(client, clearance="secret", display_name="secret_registry_canary",
            filename="secret_registry_canary.docx")
    client.post("/audit/login", data={"token": "audit-token-standard"})
    page = client.get("/audit?view=sources")
    assert "Sources" in page.text
    assert "secret_registry_canary" not in page.text, "standard auditor must not see names"
    assert "uploads" in page.text  # connector rows are fine — no file detail
