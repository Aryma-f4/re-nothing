#!/usr/bin/env python3
"""Self-check for flagr: login, targets, batch submit, dedupe, archive, retry."""
import base64
import json
import os
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

os.environ["FLAGR_HOME"] = tempfile.mkdtemp(prefix="flagr-test-")
import flagr  # noqa: E402  (HOME read at import time)


def fake_jwt():
    b64 = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'HS256'})}.{b64({'exp': 9999999999})}.sig"


class Mock(BaseHTTPRequestHandler):
    seen_flags = set()
    calls = []

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        payload = json.loads(self.rfile.read(n) or b"{}")
        Mock.calls.append((self.path, payload))
        if self.path == "/api/login":
            if payload.get("username") == "u" and payload.get("password") == "p":
                return self._send(200, {"access_token": fake_jwt()})
            return self._send(401, {"msg": "bad creds"})
        if self.path == "/api/flag":
            if self.headers.get("Authorization") != f"Bearer {fake_jwt()}":
                return self._send(401, {"msg": "unauthorized"})
            given = payload["flag"]
            flags = given if isinstance(given, list) else [given]
            res = []
            for f in flags:
                if f.endswith("{bad}"):
                    res.append("invalid")
                elif f in Mock.seen_flags:
                    res.append("duplicate")
                else:
                    Mock.seen_flags.add(f)
                    res.append("accepted")
            return self._send(200, {"results": res})
        self._send(404, {})

    def do_GET(self):
        if self.path == "/api/user":
            if self.headers.get("Authorization") != f"Bearer {fake_jwt()}":
                return self._send(401, {"msg": "unauthorized"})
            return self._send(200, [
                {"id": 1, "username": "Opponent", "vpn_ip": "10.13.37.1"},
                {"id": 7, "username": "u", "vpn_ip": "10.13.37.7"},
            ])
        self._send(404, {})


class FlagrTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Mock)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        flagr.ensure()
        for d in (flagr.INBOX, flagr.ARCH):
            for f in d.glob("*"):
                f.unlink()
        for f in (flagr.SEEN_F,):
            if f.exists():
                f.unlink()
        Mock.seen_flags.clear()
        Mock.calls.clear()
        self.cfg = {"base": f"http://127.0.0.1:{self.port}", "username": "u",
                    "password": "p", "token": "", "token_exp": 0, "interval": 60}

    def test_extract_flags(self):
        noisy = "leak -> GEMASTIK{abc123} and GEMASTIK{def-456}\nnoise line\n"
        self.assertEqual(flagr.extract_flags(noisy),
                         ["GEMASTIK{abc123}", "GEMASTIK{def-456}"])
        self.assertEqual(flagr.extract_flags("plain GEMASTIK{x} tail"), ["GEMASTIK{x}"])

    def test_submit_dedupe_archive(self):
        (flagr.INBOX / "a.txt").write_text("GEMASTIK{one}\nGEMASTIK{two}\nGEMASTIK{bad}\n")
        auth = flagr.Auth(self.cfg, lambda m: None)
        logs = []
        stats = flagr.process(self.cfg, auth, logs.append)
        self.assertEqual(stats["accepted"], 2)
        self.assertEqual(stats["invalid"], 1)
        self.assertTrue(any(m.startswith("  accepted: ") for m in logs))
        self.assertTrue(any("submit done:" in m and "accepted=2" in m for m in logs))
        self.assertEqual(list(flagr.INBOX.glob("*.txt")), [])
        self.assertEqual(len(list(flagr.ARCH.glob("*"))), 1)

        # same flags again -> all deduped, zero network submissions for flags
        (flagr.INBOX / "b.txt").write_text("GEMASTIK{one}\n")
        before = len(Mock.calls)
        stats2 = flagr.process(self.cfg, auth, lambda m: None)
        self.assertEqual(stats2["new"], 0)
        self.assertEqual(len(Mock.calls), before)
        self.assertEqual(list(flagr.INBOX.glob("*.txt")), [])

    def test_mass_exploit_runner(self):
        self.cfg["teams"] = [{"name": "Alpha", "ip": "10.0.0.2", "self": False},
                             {"name": "Own", "ip": "10.0.0.1", "self": False}]
        self.cfg["own_ip"] = "10.0.0.1"
        self.cfg["services"] = [{"name": "web", "port": 30000},
                                {"name": "pwn", "port": 30001}]
        self.cfg["exploits"] = {
            "web": "printf 'GEMASTIK{web_{port}}\\n'",
            "pwn": "printf 'GEMASTIK{pwn_{ip}}'",
        }
        self.cfg["concurrency"] = 4
        self.cfg["exploit_timeout"] = 5
        logs = []
        stats = flagr.run_all(self.cfg, flagr.Auth(self.cfg, lambda m: None), logs.append)
        self.assertEqual(stats["targets"], 2, "own team must be skipped")
        self.assertEqual(stats["flags"], 2)
        self.assertEqual(stats["submitted"], 2)
        self.assertTrue(any("flags=1" in m for m in logs))
        self.assertTrue(any("submit done:" in m for m in logs))

    def test_sync_teams_and_batch_single_flag(self):
        auth = flagr.Auth(self.cfg, lambda m: None)
        teams = flagr.fetch_teams(self.cfg, auth)
        self.assertEqual(len(teams), 2)
        self.assertTrue(teams[1]["self"])
        self.assertFalse(teams[0]["self"])
        self.assertEqual(flagr._normalize({"results": [{"flag": "GEMASTIK{x}",
                         "status": "accepted"}]}, ["GEMASTIK{x}"])[0]["result"], "accepted")
        (flagr.INBOX / "one.txt").write_text("GEMASTIK{single}\n")
        result = flagr.process(self.cfg, auth, lambda m: None)
        self.assertEqual(result["accepted"], 1)
        self.assertEqual(Mock.calls[-1][1]["flag"], ["GEMASTIK{single}"])

    def test_parsers(self):
        self.assertEqual(flagr.parse_teams("A 10.0.0.2\n! Me 10.0.0.1\n# c\n").__len__(), 2)
        self.assertTrue(flagr.parse_teams("! Me 10.0.0.1")[0]["self"])
        self.assertEqual(flagr.parse_services("web 30000\nbad\n"), [{"name": "web", "port": 30000}])
        self.assertEqual(flagr.parse_exploits("web = run {url}\n# x\n"),
                         {"web": "run {url}"})
        self.assertEqual(flagr.render_cmd("a {ip}:{port} {url} {team}",
                                          "T", "1.2.3.4", "web", 80),
                         "a 1.2.3.4:80 http://1.2.3.4:80 T")

    def test_token_auth_and_normalize(self):
        tok = fake_jwt()
        self.assertEqual(flagr.normalize_token(f'  Bearer "{tok}"\n'), tok)
        self.assertEqual(flagr.normalize_token(tok), tok)

        cfg = dict(self.cfg)
        sub, exp = flagr.store_token(cfg, "Bearer " + tok)
        self.assertEqual(cfg["token"], tok)
        self.assertEqual(exp, 9999999999)
        with self.assertRaises(ValueError):
            flagr.store_token(dict(self.cfg), "not-a-jwt")

        self.cfg["username"] = ""
        self.cfg["password"] = ""
        self.cfg["token"] = tok
        self.cfg["token_exp"] = 9999999999
        (flagr.INBOX / "t.txt").write_text("GEMASTIK{tokonly}\n")
        Mock.calls.clear()
        stats = flagr.process(self.cfg, flagr.Auth(self.cfg, lambda m: None), lambda m: None)
        self.assertEqual(stats["accepted"], 1)
        self.assertFalse(any(p == "/api/login" for p, _ in Mock.calls),
                         "token-only auth must not call /api/login")

    def test_tool_defaults_merge(self):
        cfg = flagr.merge_tools({"tulip": {"start": "custom"}})
        self.assertIn("ataka", cfg)
        self.assertEqual(cfg["tulip"]["start"], "custom")
        self.assertEqual(cfg["tulip"]["url"], "http://localhost:3000")
        for name in ("ataka", "yampa", "tulip"):
            self.assertGreater(len(flagr.TOOL_GUIDES[name]), 200, name)

    def test_tool_setup_checks(self):
        tool = {"dir": "", "start": "printf ready", "extra": "printf ready",
                "stop": "", "url": "http://localhost:3000"}
        self.assertIn("choose the repository directory",
                      flagr.tool_config_issues("tulip", tool, "start"))
        self.assertEqual(flagr.tool_config_issues("ataka", tool, "start"), [])
        self.assertEqual(flagr.tool_config_issues("ataka", tool, "stop"), [])
        tool["dir"] = "/does/not/exist/flagr"
        self.assertTrue(any("directory does not exist" in issue for issue in
                            flagr.tool_config_issues("tulip", tool, "check")))
        tool["url"] = "javascript:alert(1)"
        self.assertTrue(any("Web UI URL" in issue for issue in
                            flagr.tool_config_issues("ataka", tool, "url")))
        tool["start"] = "atk exploit ls"
        with patch("flagr.shutil.which", return_value=None):
            self.assertIn("atk executable is not on PATH",
                          flagr.tool_config_issues("ataka", tool, "start"))

    def test_tools_catch_and_stop(self):
        got = []
        cfg = dict(self.cfg)
        script = flagr.HOME / "emit_tool_flag.py"
        script.write_text("import time\nprint('GEMASTIK{toolflag}', flush=True)\ntime.sleep(30)\n")
        argv = [sys.executable, "-u", str(script)]
        command = subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)
        cfg["tools"] = {"demo": {"dir": "", "start": command,
                                 "stop": "", "extra": "", "url": "", "catch": True}}
        tm = flagr.Tools(cfg, lambda m: None, submit=got.extend)
        self.assertTrue(tm.start("demo"))
        for _ in range(30):
            if got:
                break
            time.sleep(0.1)
        self.assertIn("GEMASTIK{toolflag}", got)
        self.assertTrue(tm.running("demo"))
        tm.stop("demo")
        for _ in range(30):
            if not tm.running("demo"):
                break
            time.sleep(0.1)
        self.assertFalse(tm.running("demo"))
        self.assertEqual(tm.status("demo"), "stopped")

    def test_retry_keeps_flags_on_server_error(self):
        self.cfg["base"] = "http://127.0.0.1:1"  # nothing listening
        (flagr.INBOX / "c.txt").write_text("GEMASTIK{keepme}\n")
        stats = flagr.process(self.cfg, flagr.Auth(self.cfg, lambda m: None), lambda m: None)
        self.assertIsNotNone(stats["error"])
        self.assertEqual(len(list(flagr.INBOX.glob("*.txt"))), 1, "flags must survive failure")


if __name__ == "__main__":
    unittest.main(verbosity=2)
