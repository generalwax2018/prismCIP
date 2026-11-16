"""AI drafting against a loopback fake of the Messages API: opt-in, what's sent, human accept."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from tests.test_app import CSRF  # noqa: F401
from app.db import SessionLocal
from app.main import app
from app.models import AiSuggestion, AuditLog, Narrative, Organization, Requirement


class Fake:
    calls: list = []
    reply = "We review vendor remote access paths each quarter. [CONFIRM: reviewer name]"


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Fake.calls.append((self.path, body, self.headers.get("x-api-key"), self.headers.get("anthropic-version")))
        out = json.dumps({"content": [{"type": "text", "text": Fake.reply}], "stop_reason": "end_turn"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


@pytest.fixture()
def ai_server(monkeypatch):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("PRISMCIP_AI_API_KEY", "sk-ant-test")
    monkeypatch.setenv("PRISMCIP_AI_API", f"http://127.0.0.1:{srv.server_port}")
    yield
    srv.shutdown()


def _csrf(c, url="/"):
    return CSRF.search(c.get(url).text).group(1)


def _admin(c):
    c.post("/login", data=dict(csrf=_csrf(c, "/login"), email="admin@coop.test", password="correct-horse-battery"))


def test_ai_off_without_server_key():
    with TestClient(app) as c:
        _admin(c)
        assert "Suggest with AI" not in c.get("/rsaw").text and "AI drafting" not in c.get("/settings").text


def test_ai_rsaw_and_plan_suggestions_need_a_person(ai_server):
    with SessionLocal() as db:
        code = "CIP-003 Att1 S6"
        req = db.query(Requirement).filter_by(code=code).first() or db.query(Requirement).first()
        rid, code = req.id, req.code
    with TestClient(app) as c:
        _admin(c)
        assert "AI drafting" in c.get("/settings").text and "Suggest with AI" not in c.get("/rsaw").text
        assert c.post(f"/ai/rsaw/{rid}", data=dict(csrf=_csrf(c, "/rsaw"))).status_code == 403  # utility hasn't opted in
        c.post("/settings/ai", data=dict(csrf=_csrf(c, "/settings"), ai_enabled="on"))
        assert "Suggest with AI" in c.get("/rsaw").text
        r = c.post(f"/ai/rsaw/{rid}", data=dict(csrf=_csrf(c, "/rsaw")))
        assert "AI suggestion ready" in r.text and "Not yet accepted" in r.text
        path, body, key, ver = Fake.calls[-1]
        assert path == "/v1/messages" and key == "sk-ant-test" and ver == "2023-06-01"
        prompt = body["messages"][0]["content"]
        assert code in prompt and "<records>" in prompt and "@" not in prompt  # emails scrubbed
        assert "invent" in body["system"]
        with SessionLocal() as db:
            sug = db.query(AiSuggestion).filter_by(key=f"rsaw:{code}", status="Pending").one()
            sid = sug.id
            assert not db.query(Narrative).filter_by(key=f"rsaw:{code}", body=Fake.reply).count()
        # accept with an edit
        edited = Fake.reply.replace("[CONFIRM: reviewer name]", "Pat Ops reviews them.")
        r = c.post(f"/ai/suggestions/{sid}/accept", data={"csrf": _csrf(c, "/rsaw"), f"suggestion_{sid}": edited})
        assert "Accepted into your text" in r.text and "CONFIRM" not in r.text.split("Accepted into your text")[1][:80]
        with SessionLocal() as db:
            org_id = db.query(Organization).order_by(Organization.id).first().id
            n = db.query(Narrative).filter_by(org_id=org_id, key=f"rsaw:{code}").one()
            assert n.body == edited
            assert db.get(AiSuggestion, sid).status == "Accepted"
            assert db.query(AuditLog).filter(AuditLog.action == "ai_suggestion_accepted",
                                             AuditLog.detail.like("%with edits%")).count() == 1
        assert "already handled" in c.post(f"/ai/suggestions/{sid}/accept", data=dict(csrf=_csrf(c, "/rsaw"))).text
        # plan section: suggestion uses the typed text, then discard leaves the section alone
        r = c.post("/ai/plan/s1_method", data={"csrf": _csrf(c, "/plan/edit"), "s1_method": "We email staff."})
        assert "AI suggestion ready" in r.text
        assert "We email staff." in Fake.calls[-1][1]["messages"][0]["content"]
        with SessionLocal() as db:
            sid2 = db.query(AiSuggestion).filter_by(key="plan:s1_method", status="Pending").one().id
        c.post(f"/ai/suggestions/{sid2}/discard", data=dict(csrf=_csrf(c, "/plan/edit")))
        with SessionLocal() as db:
            assert db.get(AiSuggestion, sid2).status == "Discarded"
            assert not db.query(Narrative).filter_by(key="plan:s1_method", body=Fake.reply).count()
        assert c.post("/ai/plan/not-a-section", data=dict(csrf=_csrf(c, "/plan/edit"))).status_code == 404
        c.post("/settings/ai", data=dict(csrf=_csrf(c, "/settings")))  # off again for later tests
