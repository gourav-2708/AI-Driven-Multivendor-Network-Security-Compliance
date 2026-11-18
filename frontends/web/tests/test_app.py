# -*- coding: utf-8 -*-
"""
End-to-end tests for the web dashboard, using Flask's test client, a
throw-away SQLite database and the real auditor binary.

    python -m unittest discover -s frontends/web/tests -v

They need the engine to be built (`make`). Nothing here touches MongoDB or
the real data directory: the environment is set before the app is imported.
"""
import io
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent
ROOT = WEB.parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
DATA = Path(tempfile.mkdtemp(prefix="net-audit-test-"))

# A history file written by a version without accounts: the first
# organization must adopt it.
(DATA / "history").mkdir()
(DATA / "history" / "0ldaud1t.json").write_text(json.dumps({
    "meta": {"audit_id": "0ldaud1t", "timestamp": "2025-01-02 03:04:05", "files": ["legacy.cfg"],
             "vendor": "auto", "severity": "low"},
    "report": {"report_type": "device", "hostname": "legacy-device", "vendor": "cisco", "version": "",
               "source": "legacy.cfg", "score": 77, "critical": 0, "high": 2, "medium": 1, "low": 3,
               "findings": []}}), encoding="utf-8")

os.environ.update({
    "MONGODB_URI": "", "NET_AUDIT_DATA_DIR": str(DATA), "NET_AUDIT_SCHEDULER": "0",
    "NET_AUDIT_SECRET_KEY": "test-secret", "NET_AUDIT_INTAKE_ROOT": str(FIXTURES),
    "NET_AUDIT_SIGNUP": "open", "SMTP_HOST": "", "CRON_SECRET": "cron-test-secret",
})
sys.path.insert(0, str(WEB))

import accounts  # noqa: E402
import app as webapp  # noqa: E402
import engine  # noqa: E402
import intake  # noqa: E402
import inventory  # noqa: E402
import notify  # noqa: E402
from storage import store  # noqa: E402

PASSWORD = "correct horse battery"

GOOD = """hostname drift-router
enable secret 9 $9$abcdefghijklmn$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG
service password-encryption
service timestamps log datetime msec
security passwords min-length 14
login block-for 120 attempts 5 within 60
no ip source-route
no cdp run
aaa new-model
ip ssh version 2
banner login # Authorized access only #
logging host 192.0.2.50
logging buffered 16384
ntp authenticate
ntp server 192.0.2.10
ntp server 192.0.2.11
access-list 10 permit 192.0.2.0 0.0.0.255
line vty 0 4
 access-class 10 in
 transport input ssh
"""
WORSE = GOOD.replace(" transport input ssh", " transport input telnet ssh") + \
    "snmp-server community public RO\n"


class Client:
    """A browser session: keeps cookies and sends the CSRF token like the pages do."""

    def __init__(self):
        self.c = webapp.app.test_client()

    def csrf(self):
        with self.c.session_transaction() as s:
            return s.get("csrf", "")

    def get(self, path, **kw):
        return self.c.get(path, **kw)

    def post(self, path, data=None, csrf=True, **kw):
        if csrf and not self.csrf():
            self.c.get("/login")                       # a page view issues the token
        data = dict(data or {})
        if csrf:
            data["_csrf"] = self.csrf()
        return self.c.post(path, data=data, **kw)

    def signup(self, org, email):
        return self.post("/signup", {"organization": org, "email": email, "password": PASSWORD})

    def login(self, email, password=PASSWORD):
        return self.post("/login", {"email": email, "password": password})

    def audit(self, files, **form):
        data = dict(form)
        data["files"] = [(io.BytesIO(body), name) for name, body in files]
        return self.post("/api/audit", data, content_type="multipart/form-data")


def fixture(name):
    return name, (FIXTURES / name).read_bytes()


def config(text, name="drift-router.cfg"):
    return name, text.encode("utf-8")


class DashboardTests(unittest.TestCase):
    """Tests share one database, so they run in name order and build on each other."""

    @classmethod
    def setUpClass(cls):
        if not engine.available():
            raise unittest.SkipTest("auditor binary not built (run make)")
        cls.alice = Client()        # admin of Acme
        cls.mallory = Client()      # admin of another organization
        cls.anon = Client()

    @classmethod
    def tearDownClass(cls):
        store()._db.close()
        shutil.rmtree(DATA, ignore_errors=True)

    # -- accounts ---------------------------------------------------------------
    def test_01_everything_needs_a_login(self):
        for path in ("/", "/devices", "/findings", "/compliance", "/history", "/settings",
                     "/sources", "/alerts", "/reports/executive.pdf", "/results/0ldaud1t",
                     "/controls/pci_dss_4/8.4.1", "/controls/unlock"):
            r = self.anon.get(path)
            self.assertEqual(r.status_code, 302, path)
            self.assertIn("/login", r.headers["Location"], path)
        for path in ("/api/history", "/api/devices", "/api/findings", "/api/compliance",
                     "/api/result/0ldaud1t", "/api/download/0ldaud1t/json",
                     "/api/controls/pci_dss_4/8.4.1"):
            self.assertEqual(self.anon.get(path).status_code, 401, path)
        self.assertEqual(self.anon.c.delete("/api/result/0ldaud1t").status_code, 401)
        self.assertEqual(self.anon.get("/api/health").status_code, 200)

    def test_01b_privacy_policy_is_public(self):
        r = self.anon.get("/privacy")
        self.assertEqual(r.status_code, 200)
        page = r.data.decode()
        for text in ("Privacy policy", "deleted as soon as the audit finishes", "net_audit_session",
                     "salted hash", "not yet published"):
            self.assertIn(text, page)
        self.assertIn('href="/privacy"', self.anon.get("/login").data.decode())
        self.assertIn('href="/privacy"', self.anon.get("/signup").data.decode())
        import config
        old = (config.OPERATOR, config.PRIVACY_CONTACT)
        try:
            config.OPERATOR, config.PRIVACY_CONTACT = "Acme Audit Ltd", "privacy@acme.test"
            page = self.anon.get("/privacy").data.decode()
            self.assertIn("Acme Audit Ltd", page)
            self.assertIn('href="mailto:privacy@acme.test"', page)
            self.assertNotIn("not yet published", page)
            config.PRIVACY_CONTACT = "javascript:alert(1)"            # never becomes a link
            self.assertNotIn("javascript:", self.anon.get("/privacy").data.decode())
        finally:
            config.OPERATOR, config.PRIVACY_CONTACT = old

    def test_02_signup_creates_org_and_adopts_old_history(self):
        r = self.alice.signup("Acme Networks", "alice@acme.test")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.alice.get("/").status_code, 200)
        history = self.alice.get("/api/history").get_json()
        self.assertEqual([h["id"] for h in history], ["0ldaud1t"])      # adopted by the first org
        self.assertEqual(self.alice.get("/results/0ldaud1t").status_code, 200)

    def test_03_signup_rules(self):
        c = Client()
        self.assertEqual(c.post("/signup", {"organization": "X", "email": "x@x.test",
                                            "password": "short"}).status_code, 400)
        self.assertEqual(c.signup("Dup", "alice@acme.test").status_code, 400)
        self.assertEqual(c.post("/signup", {"organization": "X", "email": "y@x.test",
                                            "password": PASSWORD}, csrf=False).status_code, 400)

    def test_04_organizations_are_isolated(self):
        self.assertEqual(self.mallory.signup("Other Org", "mallory@other.test").status_code, 302)
        self.assertEqual(self.mallory.get("/api/history").get_json(), [])
        self.assertEqual(self.mallory.get("/api/result/0ldaud1t").status_code, 404)
        self.assertEqual(self.mallory.get("/api/download/0ldaud1t/json").status_code, 404)
        r = self.mallory.c.delete("/api/result/0ldaud1t", headers={"X-CSRF-Token": self.mallory.csrf()})
        self.assertEqual(r.status_code, 404)
        self.assertIsNotNone(store().get("audits", "0ldaud1t"))

    def test_05_login_redirect_and_lockout(self):
        c = Client()
        r = c.post("/login?next=//evil.example/x", {"email": "alice@acme.test", "password": PASSWORD})
        self.assertEqual(r.headers["Location"], "/")
        c2 = Client()
        r = c2.post("/login?next=/devices", {"email": "alice@acme.test", "password": PASSWORD})
        self.assertEqual(r.headers["Location"], "/devices")

        victim = Client()
        victim.signup("Lock Org", "lock@lock.test")
        attacker = Client()
        for _ in range(5):
            self.assertEqual(attacker.login("lock@lock.test", "wrong password!").status_code, 401)
        r = attacker.login("lock@lock.test", PASSWORD)          # correct, but locked now
        self.assertEqual(r.status_code, 401)
        self.assertIn(b"Too many failed", r.data)

    # -- audits and inventory -----------------------------------------------------
    def test_10_audit_needs_csrf_and_fills_inventory(self):
        name, body = fixture("cisco_sample.cfg")
        r = self.alice.c.post("/api/audit", data={"files": [(io.BytesIO(body), name)]},
                              content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)                    # no CSRF token

        r = self.alice.audit([fixture("cisco_sample.cfg"), fixture("test_05_juniper_secure.conf"),
                              fixture("test_11_paloalto_secure.xml")], severity="critical")
        self.assertEqual(r.status_code, 200, r.data)
        out = r.get_json()
        self.assertEqual(out["inventory"]["devices"], 3)
        self.assertEqual(out["report"]["devices_audited"], 3)
        # The response is filtered to critical; the inventory holds everything.
        shown = {f["severity"] for d in out["report"]["devices"] for f in d["findings"]}
        self.assertEqual(shown, {"CRITICAL"})
        devices = self.alice.get("/api/devices").get_json()
        self.assertEqual({d["hostname"] for d in devices},
                         {"core-router-01", "juniper-srx-secure", "pa-edge-secure"})
        findings = self.alice.get("/api/findings").get_json()
        self.assertIn("HIGH", {f["severity"] for f in findings})
        self.assertTrue(all(f["status"] == "open" for f in findings))
        self.assertTrue(findings[0]["frameworks"]["nist_800_53_r5"] or findings[0]["frameworks"]["pci_dss_4"])
        self.assertEqual(self.mallory.get("/api/devices").get_json(), [])
        self.assertEqual(self.mallory.get("/api/findings").get_json(), [])
        self.assertEqual(os.listdir(DATA / "uploads"), [])       # uploads are never kept

    def test_11_pages_render(self):
        dev = self.alice.get("/api/devices").get_json()[0]
        aid = self.alice.get("/api/history").get_json()[0]["id"]
        for path in ("/", "/devices", "/devices/" + dev["_id"], "/findings", "/findings?status=open&severity=high",
                     "/compliance", "/compliance?fw=pci_dss_4", "/alerts", "/sources", "/settings",
                     "/history", "/results/" + aid):
            r = self.alice.get(path)
            self.assertEqual(r.status_code, 200, path)
        page = self.alice.get("/results/" + aid).data.decode()
        self.assertIn("Controls", page)
        self.assertIn("PCI", page)
        self.assertEqual(self.mallory.get("/devices/" + dev["_id"]).status_code, 302)
        self.assertEqual(self.mallory.get("/results/" + aid).status_code, 302)

    def test_12_downloads(self):
        aid = self.alice.get("/api/history").get_json()[0]["id"]
        csv_text = self.alice.get(f"/api/download/{aid}/csv").data.decode()
        self.assertTrue(csv_text.startswith('"device","vendor","rule_id"'))
        self.assertIn("NIST", csv_text)
        self.assertIn("Controls:", self.alice.get(f"/api/download/{aid}/txt").data.decode())
        self.assertEqual(self.alice.get(f"/api/download/{aid}/pdf").status_code, 404)

    # -- roles and tokens ----------------------------------------------------------
    def test_20_invite_viewer_and_roles(self):
        r = self.alice.post("/settings/users", {"email": "victor@acme.test", "role": "viewer"})
        self.assertEqual(r.status_code, 302)
        page = self.alice.get("/settings").data.decode()
        token = re.search(r"/reset/([\w-]+)", page).group(1)
        self.assertNotIn("/reset/", self.alice.get("/settings").data.decode())   # shown once

        victor = Client()
        self.assertEqual(victor.get("/reset/" + token).status_code, 200)
        r = victor.post("/reset/" + token, {"password": PASSWORD, "confirm": PASSWORD})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(victor.get("/reset/" + token).status_code, 302)          # one use only
        self.assertEqual(victor.login("victor@acme.test").status_code, 302)
        type(self).victor = victor

        self.assertEqual(victor.get("/devices").status_code, 200)                # can read
        self.assertEqual(victor.audit([fixture("cisco_sample.cfg")]).status_code, 403)
        f = victor.get("/api/findings").get_json()[0]
        r = victor.post("/api/findings/" + f["_id"], {"action": "fix"})
        self.assertEqual(r.status_code, 403)
        aid = victor.get("/api/history").get_json()[0]["id"]
        r = victor.c.delete("/api/result/" + aid, headers={"X-CSRF-Token": victor.csrf()})
        self.assertEqual(r.status_code, 403)
        self.assertNotIn(b"Audit log", victor.get("/settings").data)
        self.assertEqual(victor.post("/settings/tokens", {"name": "x", "role": "viewer"}).status_code, 302)
        self.assertEqual(store().count("tokens"), 0)
        self.assertEqual(victor.get("/settings/audit-log.csv").status_code, 302)

    def test_21_last_admin_cannot_be_removed(self):
        me = accounts.find_user("alice@acme.test")
        self.alice.post("/settings/users/" + me["_id"], {"action": "role", "role": "viewer"})
        self.alice.post("/settings/users/" + me["_id"], {"action": "deactivate"})
        me = accounts.find_user("alice@acme.test")
        self.assertEqual((me["role"], me["active"]), ("admin", True))
        other = accounts.find_user("mallory@other.test")                 # not in this organization
        self.alice.post("/settings/users/" + other["_id"], {"action": "deactivate"})
        self.assertTrue(accounts.find_user("mallory@other.test")["active"])

    def test_22_api_tokens(self):
        self.alice.post("/settings/tokens", {"name": "backup job", "role": "auditor"})
        page = self.alice.get("/settings").data.decode()
        token = re.search(r"na_[0-9a-f]{12}_[\w-]+", page).group(0)
        auth = {"Authorization": "Bearer " + token}
        c = webapp.app.test_client()
        name, body = fixture("test_13_arista_secure.cfg")
        r = c.post("/api/audit", data={"files": [(io.BytesIO(body), name)]}, headers=auth,
                   content_type="multipart/form-data")                   # no CSRF needed with a token
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(r.get_json()["report"]["score"], 100)
        self.assertIn("dc1-leaf-secure", {d["hostname"] for d in c.get("/api/devices", headers=auth).get_json()})
        self.assertEqual(c.delete("/api/result/" + r.get_json()["audit_id"], headers=auth).status_code, 403)
        self.assertEqual(c.get("/api/devices", headers={"Authorization": "Bearer na_bad_token"}).status_code, 401)

        doc = store().find("tokens")[0]
        self.assertNotIn(token.split("_", 2)[2], json.dumps(doc))        # only a hash is stored
        self.alice.post(f"/settings/tokens/{doc['_id']}/delete")
        self.assertEqual(c.get("/api/devices", headers=auth).status_code, 401)

    # -- finding workflow ------------------------------------------------------------
    def _finding(self, rule, host="core-router-01"):
        for f in self.alice.get("/api/findings?status=all").get_json():
            if f["rule_id"] == rule and f["hostname"] == host:
                return f
        self.fail(f"no finding {rule} on {host}")

    def _act(self, fid, **form):
        return self.alice.post("/api/findings/" + fid, form)

    def test_30_assign_and_accept_risk(self):
        f = self._finding("AUTH-003")
        r = self._act(f["_id"], action="assign", assignee="victor@acme.test")
        self.assertEqual(r.get_json()["status"], "assigned")
        r = self._act(f["_id"], action="assign", assignee="mallory@other.test")
        self.assertEqual(r.status_code, 400)                             # not a member

        g = self._finding("SVC-002")
        self.assertEqual(self._act(g["_id"], action="accept_risk", reason="short", expires="2099-01-01").status_code, 400)
        self.assertEqual(self._act(g["_id"], action="accept_risk", reason="CDP is needed for the phones",
                                   expires="2001-01-01").status_code, 400)
        self.assertEqual(self._act(g["_id"], action="accept_risk", reason="CDP is needed for the phones",
                                   expires="2099-01-01").status_code, 400)   # more than a year
        from storage import later
        soon = later(days=30)[:10]
        r = self._act(g["_id"], action="accept_risk", reason="CDP is needed for the phones", expires=soon)
        self.assertEqual(r.get_json()["status"], "risk_accepted")
        self.assertEqual(r.get_json()["risk"]["accepted_by"], "alice@acme.test")

    def test_31_risk_acceptance_expires(self):
        g = self._finding("SVC-002")
        g["risk"]["expires_at"] = "2020-01-01T00:00:00Z"
        store().replace("findings", g)
        self.alice.get("/findings")                                      # sweeps expired acceptances
        g = self._finding("SVC-002")
        self.assertEqual(g["status"], "open")
        self.assertEqual(g["history"][-1]["action"], "risk_expired")

    def test_32_fixed_is_verified_or_reopened_by_the_next_audit(self):
        f = self._finding("AUTH-003")
        self.assertEqual(self._act(f["_id"], action="fix", note="telnet removed").get_json()["status"], "fixed")
        out = self.alice.audit([fixture("cisco_sample.cfg")]).get_json()   # same config: still there
        self.assertEqual(out["inventory"]["reopened"], 1)
        f = self._finding("AUTH-003")
        self.assertEqual(f["status"], "assigned")                         # reopened, still Victor's
        self.assertEqual(f["history"][-1]["action"], "reopened")

        # The same device with telnet gone: the finding is verified without anyone touching it.
        name, body = fixture("cisco_sample.cfg")
        fixed = body.replace(b"transport input telnet ssh", b"transport input ssh") \
                    .replace(b"transport input telnet", b"transport input ssh") \
                    .replace(b"transport input all", b"transport input ssh")
        self.assertNotEqual(fixed, body)
        out = self.alice.audit([(name, fixed)]).get_json()
        self.assertGreaterEqual(out["inventory"]["verified"], 1)
        f = self._finding("AUTH-003")
        self.assertEqual(f["status"], "verified")
        self.assertTrue(f["resolved_at"])
        self.assertEqual(self._act(f["_id"], action="fix").status_code, 400)

    def test_33_line_shift_does_not_duplicate_findings(self):
        before = len(self.alice.get("/api/findings?status=all").get_json())
        name, body = fixture("cisco_sample.cfg")
        fixed = body.replace(b"transport input telnet ssh", b"transport input ssh") \
                    .replace(b"transport input telnet", b"transport input ssh") \
                    .replace(b"transport input all", b"transport input ssh")
        shifted = b"! a new comment line at the top\n! and another\n" + fixed
        out = self.alice.audit([(name, shifted)]).get_json()
        self.assertEqual(out["inventory"]["new_findings"], 0)
        self.assertEqual(len(self.alice.get("/api/findings?status=all").get_json()), before)

    # -- drift ---------------------------------------------------------------------
    def test_40_drift_alert_on_score_drop_and_new_critical(self):
        out = self.alice.audit([config(GOOD)]).get_json()
        self.assertEqual(out["inventory"]["alerts"], 0)                   # first audit: nothing to compare
        first = out["report"]["score"]
        out = self.alice.audit([config(WORSE)]).get_json()
        self.assertLess(out["report"]["score"], first)
        self.assertEqual(out["inventory"]["alerts"], 2)
        alerts = self.alice.get("/api/alerts").get_json()
        self.assertEqual({a["kind"] for a in alerts}, {"score_drop", "new_critical"})
        self.assertTrue(all(a["hostname"] == "drift-router" for a in alerts))
        self.assertEqual(self.mallory.get("/api/alerts").get_json(), [])
        self.assertIn(b"nav-badge", self.alice.get("/devices").data)

        dev = [d for d in self.alice.get("/api/devices").get_json() if d["hostname"] == "drift-router"][0]
        detail = self.alice.get("/api/devices/" + dev["_id"]).get_json()
        self.assertEqual([p["score"] for p in detail["trend"]], [first, out["report"]["score"]])
        self.assertEqual(dev["prev_score"], first)
        self.alice.post("/alerts/ack")
        self.assertTrue(all(a["acknowledged"] for a in self.alice.get("/api/alerts").get_json()))

    def test_41_device_details_and_trend(self):
        dev = [d for d in self.alice.get("/api/devices").get_json() if d["hostname"] == "drift-router"][0]
        self.alice.post("/devices/" + dev["_id"], {"site": "Lab", "owner": "Network team"})
        dev = self.alice.get("/api/devices/" + dev["_id"]).get_json()["device"]
        self.assertEqual((dev["site"], dev["owner"]), ("Lab", "Network team"))
        self.assertTrue(self.alice.get("/api/trend").get_json())

    # -- compliance and reports -------------------------------------------------------
    def test_50_compliance_status(self):
        data = {fw["key"]: fw for fw in self.alice.get("/api/compliance").get_json()}
        self.assertEqual(set(data), {"cis_v8", "pci_dss_4", "iso_27001_2022", "nist_800_53_r5"})
        pci = {c["id"]: c for c in data["pci_dss_4"]["controls"]}
        self.assertEqual(pci["2.2.2"]["status"], "fail")                 # default SNMP community
        self.assertEqual(pci["2.2.2"]["rules"], ["SNMP-001"])
        self.assertEqual(pci["8.4.1"]["status"], "not_covered")           # MFA: no rule yet
        self.assertEqual(pci["8.4.1"]["rules"], [])
        counts = data["pci_dss_4"]["counts"]
        self.assertEqual(sum(counts.values()), len(pci))
        self.assertGreater(counts["fail"], 0)
        other = {fw["key"]: fw for fw in self.mallory.get("/api/compliance").get_json()}
        self.assertEqual(other["pci_dss_4"]["counts"]["fail"], 0)        # nothing audited there
        self.assertEqual({c["status"] for c in other["pci_dss_4"]["controls"]},
                         {"not_assessed", "not_covered"})

    def test_51_executive_pdf(self):
        r = self.alice.get("/reports/executive.pdf")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.data.startswith(b"%PDF-1.4"))
        self.assertTrue(r.data.rstrip().endswith(b"%%EOF"))
        self.assertIn(b"Top risks", r.data)
        self.assertIn(b"Acme Networks", r.data)
        empty = self.mallory.get("/reports/executive.pdf")
        self.assertIn(b"No devices have been audited yet", empty.data)

    def test_52_evidence_pack(self):
        r = self.alice.get("/reports/evidence.zip?fw=pci_dss_4")
        self.assertEqual(r.status_code, 200)
        z = zipfile.ZipFile(io.BytesIO(r.data))
        self.assertEqual(set(z.namelist()), {"evidence.pdf", "controls.csv", "findings.csv",
                                             "devices.csv", "README.txt", "manifest.json"})
        manifest = json.loads(z.read("manifest.json"))
        self.assertEqual([f["key"] for f in manifest["frameworks"]], ["pci_dss_4"])
        import hashlib
        for name, digest in manifest["sha256"].items():
            self.assertEqual(hashlib.sha256(z.read(name)).hexdigest(), digest, name)
        findings = z.read("findings.csv").decode("utf-8-sig")
        self.assertIn("first_seen", findings.splitlines()[0])
        self.assertIn("Verified fixed", findings)
        self.assertIn("core-router-01", z.read("controls.csv").decode("utf-8-sig"))
        self.assertTrue(z.read("evidence.pdf").startswith(b"%PDF"))
        all_fw = zipfile.ZipFile(io.BytesIO(self.alice.get("/reports/evidence.zip").data))
        self.assertEqual(len(json.loads(all_fw.read("manifest.json"))["frameworks"]), 4)

    # -- control register ---------------------------------------------------------------
    def _control(self, client, key, cid):
        r = client.get(f"/api/controls/{key}/{cid}")
        self.assertEqual(r.status_code, 200, r.data)
        return r.get_json()

    def _pci(self, client=None):
        data = {fw["key"]: fw for fw in (client or self.alice).get("/api/compliance").get_json()}
        return data["pci_dss_4"], {c["id"]: c for c in data["pci_dss_4"]["controls"]}

    def test_53_register_needs_an_unlocked_admin(self):
        url = "/controls/pci_dss_4/8.4.1"
        form = {"action": "update", "owner": "", "implementation": "implemented"}
        self.assertEqual(self.victor.get(url).status_code, 200)               # viewers can read
        self.assertIn(b"Only an administrator", self.victor.get(url).data)
        self.assertEqual(self.victor.post(url, form).status_code, 302)
        self.assertEqual(self.victor.get("/controls/unlock").status_code, 302)  # admin only
        self.assertEqual(store().count("controls"), 0)

        r = self.alice.post(url, form)                                        # admin, still locked
        self.assertEqual(r.status_code, 302)
        self.assertIn("/controls/unlock", r.headers["Location"])
        self.assertEqual(store().count("controls"), 0)
        self.assertIn(b"Unlock control management", self.alice.get("/compliance").data)

        r = self.alice.post("/controls/unlock?next=" + url, {"password": "not the password"})
        self.assertEqual(r.status_code, 400)
        r = self.alice.post("/controls/unlock?next=" + url, {"password": PASSWORD})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith(url))
        self.assertEqual(accounts.find_user("alice@acme.test")["failed_logins"], 0)
        self.assertIn(b"Lock control management", self.alice.get("/compliance").data)
        r = self.alice.post("/controls/unlock?next=https://evil.test/", {"password": PASSWORD})
        self.assertFalse(r.headers["Location"].startswith("https://evil"))      # stays on this site

        # Locking again takes the edit right away until the next unlock.
        self.assertEqual(self.alice.post("/controls/lock").status_code, 302)
        self.assertEqual(self.alice.post(url, form).status_code, 302)
        self.assertEqual(store().count("controls"), 0)

    def test_54_attest_a_control_no_rule_checks(self):
        from storage import later
        url = "/controls/pci_dss_4/8.4.1"
        self.alice.post("/controls/unlock", {"password": PASSWORD})
        before, ctl = self._pci()
        self.assertEqual(ctl["8.4.1"]["status"], "not_covered")

        bad_owner = {"action": "update", "owner": "mallory@other.test", "implementation": "implemented"}
        self.alice.post(url, bad_owner)                                      # not a member
        self.assertEqual(store().count("controls"), 0)
        review = later(days=90)[:10]
        self.alice.post(url, {"action": "update", "owner": "victor@acme.test",
                              "implementation": "implemented", "next_review": review,
                              "notes": "MFA on the VPN for all admins"})
        c = self._control(self.alice, "pci_dss_4", "8.4.1")
        self.assertEqual((c["register"]["owner"], c["register"]["implementation"]),
                         ("victor@acme.test", "implemented"))
        self.assertEqual(c["status"], "not_covered")                          # no evidence yet

        self.alice.post(url, {"action": "evidence_add", "text": "VPN MFA policy", "link": "javascript:alert(1)"})
        self.assertEqual(self._control(self.alice, "pci_dss_4", "8.4.1")["evidence"], [])
        self.alice.post(url, {"action": "evidence_add", "text": "VPN MFA policy SEC-12",
                              "link": "https://wiki.acme.test/sec-12"})
        c = self._control(self.alice, "pci_dss_4", "8.4.1")
        self.assertEqual(c["status"], "attested")
        self.assertEqual(c["evidence"][0]["by"], "alice@acme.test")
        self.assertEqual([h["action"] for h in c["history"]], ["updated", "evidence_added"])

        after, ctl = self._pci()
        self.assertEqual(ctl["8.4.1"]["status"], "attested")
        self.assertEqual(after["counts"]["attested"], 1)
        self.assertEqual(after["counts"]["not_covered"], before["counts"]["not_covered"] - 1)
        page = self.alice.get("/compliance?fw=pci_dss_4").data
        self.assertIn(b"victor@acme.test", page)
        self.assertIn(b"Attested", page)

        # The other organization sees none of it.
        other = self._control(self.mallory, "pci_dss_4", "8.4.1")
        self.assertEqual((other["status"], other["evidence"], other["register"]["owner"]),
                         ("not_covered", [], ""))

        # Evidence that is removed takes the attestation with it.
        item = c["evidence"][0]["id"]
        self.alice.post(url, {"action": "evidence_remove", "evidence_id": item})
        self.assertEqual(self._control(self.alice, "pci_dss_4", "8.4.1")["status"], "not_covered")
        self.alice.post(url, {"action": "evidence_add", "text": "VPN MFA policy SEC-12"})
        self.assertEqual(self._control(self.alice, "pci_dss_4", "8.4.1")["status"], "attested")

    def test_55_overdue_review_and_not_applicable(self):
        doc = store().get("controls", accounts.find_user("alice@acme.test")["org_id"] + ":pci_dss_4:8.4.1")
        doc["next_review"] = "2020-01-01"
        store().replace("controls", doc)
        c = self._control(self.alice, "pci_dss_4", "8.4.1")
        self.assertEqual(c["status"], "not_covered")                          # overdue: no longer attested
        self.assertTrue(c["register"]["review_overdue"])
        self.alice.post("/controls/pci_dss_4/8.4.1", {"action": "reviewed", "next_review": "2020-02-02"})
        self.assertTrue(self._control(self.alice, "pci_dss_4", "8.4.1")["register"]["review_overdue"])
        from storage import later
        self.alice.post("/controls/pci_dss_4/8.4.1", {"action": "reviewed", "next_review": later(days=180)[:10]})
        c = self._control(self.alice, "pci_dss_4", "8.4.1")
        self.assertEqual(c["status"], "attested")
        self.assertTrue(c["register"]["last_reviewed_at"])

        url = "/controls/pci_dss_4/1.3.2"
        self.alice.post(url, {"action": "update", "implementation": "not_applicable", "na_reason": "short"})
        self.assertEqual(self._control(self.alice, "pci_dss_4", "1.3.2")["status"], "not_covered")
        self.alice.post(url, {"action": "update", "implementation": "not_applicable",
                              "na_reason": "No cardholder data passes through these routers"})
        _, ctl = self._pci()
        self.assertEqual(ctl["1.3.2"]["status"], "not_applicable")

        # A control that a rule checks keeps its audit status, with the owner alongside.
        self.alice.post("/controls/pci_dss_4/2.2.2", {"action": "update", "owner": "alice@acme.test",
                                                       "implementation": "implemented"})
        c = self._control(self.alice, "pci_dss_4", "2.2.2")
        self.assertEqual((c["status"], c["register"]["owner"]), ("fail", "alice@acme.test"))

        self.assertEqual(self.alice.get("/api/controls/pci_dss_4/99.99").status_code, 404)
        self.assertEqual(self.alice.get("/api/controls/nope/8.4.1").status_code, 404)
        log = self.alice.get("/settings/audit-log.csv").data.decode("utf-8-sig")
        for action in ("controls.unlock", "control.update", "control.evidence_add", "control.reviewed"):
            self.assertIn(action, log)

    def test_56_unlock_expires_and_register_is_in_the_evidence_pack(self):
        with self.alice.c.session_transaction() as s:
            s["admin_until"] = "2020-01-01T00:00:00Z"
        r = self.alice.post("/controls/pci_dss_4/8.4.1", {"action": "update", "owner": ""})
        self.assertIn("/controls/unlock", r.headers["Location"])
        self.assertEqual(self._control(self.alice, "pci_dss_4", "8.4.1")["register"]["owner"],
                         "victor@acme.test")

        z = zipfile.ZipFile(io.BytesIO(self.alice.get("/reports/evidence.zip?fw=pci_dss_4").data))
        rows = z.read("controls.csv").decode("utf-8-sig")
        self.assertIn("next_review", rows.splitlines()[0])
        self.assertIn("VPN MFA policy SEC-12", rows)
        self.assertIn("No cardholder data passes through these routers", rows)
        self.assertIn(b"Attested", z.read("evidence.pdf"))
        self.assertTrue(self.alice.get("/reports/executive.pdf").data.startswith(b"%PDF"))

    # -- sources ----------------------------------------------------------------------
    def test_60_source_validation(self):
        base = {"name": "s", "schedule": "daily", "vendor": "auto"}
        bad = [
            dict(base, type="git", location="file:///etc"),
            dict(base, type="git", location="ssh://git@example.com/x.git"),
            dict(base, type="git", location="ext::sh -c id"),
            dict(base, type="git", location="https://user:pw@example.com/x.git"),
            dict(base, type="git", location="https://example.com/x.git", branch="--upload-pack=x"),
            dict(base, type="directory", location=str(DATA)),
            dict(base, type="directory", location="../.."),
            dict(base, type="oxidized", location="ftp://example.com"),
            dict(base, type="git", location="https://example.com/x.git", subdir="../../etc"),
        ]
        for form in bad:
            with self.assertRaises(intake.IntakeError, msg=str(form)):
                intake.validate(form)
        doc = intake.validate(dict(base, type="git", location="https://example.com/net/configs.git",
                                   secret="s3cret"))
        self.assertTrue(doc["next_run_at"])
        self.assertNotIn("secret", intake.public(dict(doc, _id="x")))

    def test_61_directory_source_runs_and_is_scheduled(self):
        r = self.mallory.post("/sources", {"name": "Fixtures", "type": "directory",
                                           "location": str(FIXTURES), "schedule": "daily", "vendor": "auto"})
        self.assertEqual(r.status_code, 302)
        source = store().find("sources")[0]
        self.assertEqual(self.alice.post(f"/sources/{source['_id']}/run").status_code, 302)   # not Alice's
        self.assertIsNone(store().get("sources", source["_id"])["last_run_at"])

        r = self.mallory.post(f"/api/sources/{source['_id']}/run")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertIn("devices audited", r.get_json()["last_message"])
        devices = self.mallory.get("/api/devices").get_json()
        self.assertGreaterEqual(len(devices), 20)                        # every fixture, edge cases too
        self.assertIn("asa-dmz-legacy", {d["hostname"] for d in devices})
        self.assertEqual(os.listdir(DATA / "work"), [])                  # nothing fetched is kept

        # The scheduler picks it up again when it is due.
        store().update("sources", source["_id"], {"next_run_at": "2020-01-01T00:00:00Z"})
        self.assertEqual(self.anon.get("/api/cron").status_code, 401)
        r = self.anon.get("/api/cron", headers={"Authorization": "Bearer cron-test-secret"})
        self.assertEqual(r.get_json()["sources"], 1)
        self.assertGreater(store().get("sources", source["_id"])["next_run_at"], "2026")

    # -- integrations -------------------------------------------------------------------
    def test_70_tickets_and_slack(self):
        calls = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                calls.append((self.path, self.headers.get("Authorization", ""), body))
                reply = {"key": "NET-42"} if "issue" in self.path else \
                    ({"result": {"sys_id": "abc123", "number": "INC0010001"}} if "table" in self.path else {})
                data = json.dumps(reply).encode()
                self.send_response(201 if reply else 200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            r = self.alice.post("/settings/integrations", {
                "slack_webhook": base + "/slack", "alert_emails": "noc@acme.test, not-an-address",
                "jira_url": base, "jira_email": "bot@acme.test", "jira_token": "jira-secret",
                "jira_project": "net", "servicenow_url": base, "servicenow_user": "svc",
                "servicenow_password": "snow-secret"})
            self.assertEqual(r.status_code, 302)
            settings = store().get("orgs", accounts.find_user("alice@acme.test")["org_id"])["settings"]
            self.assertEqual(settings["alert_emails"], ["noc@acme.test"])
            page = self.alice.get("/settings").data.decode()
            self.assertNotIn("jira-secret", page)                         # secrets are never shown again
            self.assertNotIn("snow-secret", page)
            self.assertNotIn(base + "/slack", page)

            # Saving again with empty secret fields keeps them.
            self.alice.post("/settings/integrations", {"jira_url": base, "jira_email": "bot@acme.test",
                                                       "jira_project": "NET", "servicenow_url": base,
                                                       "servicenow_user": "svc"})
            settings = store().get("orgs", accounts.find_user("alice@acme.test")["org_id"])["settings"]
            self.assertEqual(settings["jira"]["token"], "jira-secret")
            self.assertEqual(settings["slack_webhook"], base + "/slack")

            f = self._finding("SNMP-001")
            r = self._act(f["_id"], action="ticket", system="jira")
            self.assertEqual(r.get_json()["ticket"], {"system": "jira", "key": "NET-42",
                                                      "url": base + "/browse/NET-42"})
            path, auth, body = calls[-1]
            self.assertEqual(path, "/rest/api/2/issue")
            self.assertEqual(auth, notify.basic_auth("bot@acme.test", "jira-secret"))
            self.assertEqual(body["fields"]["project"], {"key": "NET"})
            self.assertIn("SNMP-001", body["fields"]["summary"])
            self.assertEqual(self._act(f["_id"], action="ticket", system="jira").status_code, 400)   # already has one

            g = self._finding("ACL-001")
            r = self._act(g["_id"], action="ticket", system="servicenow")
            self.assertEqual(r.get_json()["ticket"]["key"], "INC0010001")
            self.assertEqual(calls[-1][0], "/api/now/table/incident")
            self.assertEqual(calls[-1][2]["urgency"], "1")

            # A drift alert reaches Slack.
            self.alice.audit([config(GOOD)])
            calls.clear()
            self.alice.audit([config(WORSE)])
            slack = [c for c in calls if c[0] == "/slack"]
            self.assertEqual(len(slack), 2)
            self.assertIn("drift-router", slack[0][2]["text"])
        finally:
            server.shutdown()
            server.server_close()

    # -- password reset and audit log ------------------------------------------------------
    def test_80_password_reset_signs_out_other_sessions(self):
        self.assertEqual(self.victor.get("/devices").status_code, 200)
        self.anon.post("/forgot", {"email": "victor@acme.test"})
        self.anon.post("/forgot", {"email": "nobody@nowhere.test"})       # same answer, no account
        user, token = accounts.start_password_reset("victor@acme.test")
        c = Client()
        self.assertEqual(c.post("/reset/" + token, {"password": "a brand new password",
                                                    "confirm": "different"}).status_code, 400)
        self.assertEqual(c.post("/reset/" + token, {"password": "a brand new password",
                                                    "confirm": "a brand new password"}).status_code, 302)
        self.assertEqual(self.victor.get("/devices").status_code, 302)    # old session is dead
        self.assertEqual(Client().login("victor@acme.test").status_code, 401)
        self.assertEqual(Client().login("victor@acme.test", "a brand new password").status_code, 302)

    def test_81_deactivated_user_is_signed_out(self):
        c = Client()
        c.login("victor@acme.test", "a brand new password")
        self.assertEqual(c.get("/devices").status_code, 200)
        victor = accounts.find_user("victor@acme.test")
        self.alice.post("/settings/users/" + victor["_id"], {"action": "deactivate"})
        self.assertEqual(c.get("/devices").status_code, 302)
        self.assertEqual(Client().login("victor@acme.test", "a brand new password").status_code, 401)

    def test_82_audit_log_records_who_did_what(self):
        org_id = accounts.find_user("alice@acme.test")["org_id"]
        actions = {e["action"] for e in store().find("audit_log", {"org_id": org_id})}
        for expected in ("org.create", "audit.adopt", "login", "audit.run", "audit.view", "audit.export",
                         "user.invite", "token.create", "token.revoke", "finding.assign",
                         "finding.accept_risk", "finding.fix", "finding.ticket", "device.update",
                         "report.export", "integrations.update", "user.deactivate", "alert.ack"):
            self.assertIn(expected, actions)
        csv_text = self.alice.get("/settings/audit-log.csv").data.decode("utf-8-sig")
        self.assertIn("alice@acme.test", csv_text)
        other = store().find("audit_log", {"org_id": accounts.find_user("mallory@other.test")["org_id"]})
        self.assertFalse(any(e["user"] == "alice@acme.test" for e in other))

    def test_83_admin_deletes_audit_and_device(self):
        aid = self.alice.get("/api/history").get_json()[0]["id"]
        r = self.alice.c.delete("/api/result/" + aid, headers={"X-CSRF-Token": self.alice.csrf()})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.alice.get("/api/result/" + aid).status_code, 404)
        dev = [d for d in self.alice.get("/api/devices").get_json() if d["hostname"] == "drift-router"][0]
        self.alice.post(f"/devices/{dev['_id']}/delete")
        self.assertEqual(self.alice.get("/api/devices/" + dev["_id"]).status_code, 404)
        self.assertFalse(inventory.findings(dev["org_id"], device_id=dev["_id"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
