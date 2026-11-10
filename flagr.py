#!/usr/bin/env python3
"""flagr - minimal attack/defense flag submitter (Python 3 stdlib only).

Modes:
  flagr                          GUI (Submit / Mass exploit / Tools tabs)
  flagr push 'GEMASTIK{...}' ... queue flag(s) for the background submitter
  flagr submit 'GEMASTIK{...}' ...  one-shot submit now
  flagr exploit                  run all configured exploits once, submit flags
  flagr token 'eyJ...'           save a bearer JWT copied from the Team page
  flagr login                    save username/password and fetch a token

Exploits just run `flagr push FLAG` (or drop a .txt file into
~/.flagr/inbox/). The background loop drains the inbox, dedupes, batches
(<=200 per request) and POSTs /api/flag with the bearer token, refreshing
the JWT automatically.

Env: FLAGR_HOME overrides ~/.flagr
"""
import argparse
import base64
import getpass
import json
import os
import queue
import re
import signal
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.error
import urllib.request
from pathlib import Path

# GUI apps launched from Finder/Explorer get a minimal PATH; restore the
# usual tool locations so docker/atk resolve from the Tools tab.
def _ensure_path():
    if os.name == "nt":
        return
    extra = ["/opt/homebrew/bin", "/usr/local/bin", str(Path.home() / ".local" / "bin")]
    cur = os.environ.get("PATH", "").split(os.pathsep)
    add = [p for p in extra if os.path.isdir(p) and p not in cur]
    if add:
        os.environ["PATH"] = os.pathsep.join(add + cur)


_ensure_path()

HOME = Path(os.environ.get("FLAGR_HOME", Path.home() / ".flagr"))
CFG_F = HOME / "config.json"
INBOX = HOME / "inbox"
ARCH = HOME / "archive"
SEEN_F = HOME / "seen.json"
EV_F = HOME / "events.jsonl"

TOOL_DEFAULTS = {
    "ataka": {
        "dir": "", "start": "atk exploit runlocal --all-targets",
        "stop": "", "extra": "atk exploit ls", "url": "", "catch": True,
    },
    "yampa": {
        "dir": "", "start": "docker compose up -d",
        "stop": "docker compose down", "extra": "./lint-rules.sh && ./reload.sh",
        "url": "", "catch": False,
    },
    "tulip": {
        "dir": "", "start": "docker compose up -d --build",
        "stop": "docker compose down", "extra": "", "url": "http://localhost:3000",
        "catch": False,
    },
}

DEFAULT_CFG = {
    "base": "https://gemastik19-finals.siberlab.id",
    "username": "",
    "password": "",
    "token": "",
    "token_exp": 0,
    "interval": 60,
    "teams": [],
    "services": [],
    "exploits": {},
    "concurrency": 8,
    "exploit_timeout": 20,
    "exploit_interval": 180,
    "tools": {k: dict(v) for k, v in TOOL_DEFAULTS.items()},
}


def merge_tools(stored):
    stored = stored if isinstance(stored, dict) else {}
    out = {}
    for name, default in TOOL_DEFAULTS.items():
        t = dict(default)
        if isinstance(stored.get(name), dict):
            t.update(stored[name])
        out[name] = t
    for name, t in stored.items():
        if name not in out and isinstance(t, dict):
            out[name] = t
    return out

FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,64}\{[^{}\s]{1,512}\}")

_PROCESS_LOCK = threading.Lock()
_SAVE_LOCK = threading.Lock()


def ensure():
    for d in (HOME, INBOX, ARCH):
        d.mkdir(parents=True, exist_ok=True)


def load_cfg():
    ensure()
    try:
        stored = json.loads(CFG_F.read_text())
    except (FileNotFoundError, ValueError):
        stored = {}
    cfg = dict(DEFAULT_CFG)
    if isinstance(stored, dict):
        cfg.update(stored)
    cfg["tools"] = merge_tools(stored.get("tools") if isinstance(stored, dict) else None)
    return cfg


def save_cfg(cfg):
    ensure()
    with _SAVE_LOCK:
        tmp = CFG_F.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, indent=2))
        os.replace(tmp, CFG_F)
        try:
            os.chmod(CFG_F, 0o600)
        except OSError:
            pass


def event(kind, msg, **kw):
    rec = {"t": time.strftime("%Y-%m-%dT%H:%M:%S"), "kind": kind, "msg": msg, **kw}
    try:
        with EV_F.open("a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def make_logger(sink=print):
    def log(msg):
        event("log", str(msg))
        try:
            sink(str(msg))
        except Exception:
            pass
    return log


class ApiError(Exception):
    def __init__(self, status, body):
        super().__init__(f"HTTP {status}: {body[:300]}")
        self.status = status
        self.body = body


class Api:
    def __init__(self, base):
        self.base = base.rstrip("/")

    def _post(self, path, payload, token=None):
        req = urllib.request.Request(
            self.base + path, data=json.dumps(payload).encode(), method="POST"
        )
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                raw = r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            raise ApiError(e.code, e.read().decode("utf-8", "replace")) from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise ApiError(0, str(e)) from None
        try:
            return json.loads(raw) if raw.strip() else {}
        except ValueError:
            raise ApiError(0, "non-JSON response: " + raw[:300]) from None

    def login(self, username, password):
        return self._post("/api/login", {"username": username, "password": password})

    def submit(self, token, flags):
        payload = flags[0] if len(flags) == 1 else list(flags)
        return self._post("/api/flag", {"flag": payload}, token=token)


def normalize_token(raw):
    """Accept a bare JWT or a copied 'Bearer ...' header."""
    t = (raw or "").strip()
    if t.lower().startswith("bearer "):
        t = t[7:]
    t = t.strip().strip('"').strip("'")
    return "".join(t.split())


def jwt_payload(token):
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}


def jwt_exp(token):
    try:
        return int(jwt_payload(token).get("exp", 0))
    except (TypeError, ValueError):
        return 0


def store_token(cfg, raw):
    """Validate and persist a bearer JWT. Returns (subject, exp) or raises ValueError."""
    tok = normalize_token(raw)
    if tok.count(".") != 2:
        raise ValueError("expected a JWT with three dot-separated parts")
    exp = jwt_exp(tok)
    if not exp:
        raise ValueError("cannot read 'exp' from token payload")
    left = int(exp - time.time())
    if left <= 0:
        raise ValueError("token already expired - grab a fresh one from the Team page")
    cfg["token"] = tok
    cfg["token_exp"] = exp
    save_cfg(cfg)
    return jwt_payload(tok).get("sub") or "?", exp


class Auth:
    """Owns the bearer token; re-logs in when missing, expired or rejected."""

    def __init__(self, cfg, log=print):
        self.cfg = cfg
        self.log = log
        self.lock = threading.Lock()

    def invalidate(self):
        with self.lock:
            self.cfg["token"] = ""
            self.cfg["token_exp"] = 0
            save_cfg(self.cfg)

    def token(self, force=False):
        with self.lock:
            tok = self.cfg.get("token") or ""
            exp = self.cfg.get("token_exp") or jwt_exp(tok)
            if tok and not force and exp > time.time() + 60:
                return tok
            user = self.cfg.get("username") or ""
            pw = self.cfg.get("password") or ""
            if not (user and pw):
                raise ApiError(0, "no credentials: paste a bearer token or set username/password")
            resp = Api(self.cfg["base"]).login(user, pw)
            tok = resp.get("access_token") or ""
            if not tok:
                raise ApiError(0, "login returned no access_token: " + json.dumps(resp)[:200])
            self.cfg["token"] = tok
            self.cfg["token_exp"] = jwt_exp(tok)
            save_cfg(self.cfg)
            self.log(f"logged in as {user}")
            return tok


def extract_flags(text):
    """Pull flags out of noisy exploit output. Falls back to brace-only tokens."""
    found = FLAG_RE.findall(text or "")
    if found:
        return found
    out = []
    for line in (text or "").splitlines():
        s = line.strip()
        if "{" in s and "}" in s and " " not in s:
            out.append(s)
    return out


def load_seen():
    try:
        return set(json.loads(SEEN_F.read_text()))
    except Exception:
        return set()


def save_seen(seen):
    with _SAVE_LOCK:
        tmp = SEEN_F.with_suffix(".tmp")
        tmp.write_text(json.dumps(sorted(seen)))
        os.replace(tmp, SEEN_F)


def _archive(f, tag="ok"):
    try:
        name = f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}-{tag}-{f.name}"
        f.rename(ARCH / name)
    except OSError:
        pass


def read_inbox():
    """Return (flags, files). Files with no recognizable flag are archived."""
    flags, files = [], []
    for f in sorted(INBOX.glob("*.txt")):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        found = extract_flags(text)
        if found:
            flags += found
            files.append(f)
        else:
            _archive(f, "bad")
    return flags, files


def _normalize(resp, batch):
    rows = resp.get("results")
    if not isinstance(rows, list):
        if len(batch) > 1 and ("result" not in resp and "status" not in resp):
            return [{"flag": f, "result": "unknown", "raw": resp} for f in batch]
        rows = [resp]
    out = []
    for i, r in enumerate(rows):
        flag = batch[i] if i < len(batch) else ""
        if isinstance(r, str):
            out.append({"flag": flag, "result": r})
        elif isinstance(r, dict):
            out.append({
                "flag": r.get("flag") or flag,
                "result": r.get("result") or r.get("status") or "?",
                "raw": r,
            })
        else:
            out.append({"flag": flag, "result": str(r)})
    return out


def process(cfg, auth, log=print, extra=None):
    """Drain inbox (+extra flags), dedupe, submit in batches <=200. Returns stats."""
    with _PROCESS_LOCK:
        api = Api(cfg["base"])
        flags, files = read_inbox()
        if extra:
            flags += list(extra)
        seen = load_seen()
        todo = []
        for f in flags:
            if f not in seen and f not in todo:
                todo.append(f)
        stats = {"new": len(todo), "accepted": 0, "duplicate": 0,
                 "invalid": 0, "own": 0, "unknown": 0, "error": None}
        if not todo:
            for f in files:
                _archive(f)
            return stats

        for i in range(0, len(todo), 200):
            batch = todo[i:i + 200]
            resp = None
            for attempt in (0, 1):
                try:
                    token = auth.token(force=attempt == 1)
                    resp = api.submit(token, batch)
                    break
                except ApiError as e:
                    if e.status in (401, 403) and attempt == 0:
                        auth.invalidate()
                        continue
                    stats["error"] = str(e)
                    break
            if resp is None:
                break
            counts = {}
            for row in _normalize(resp, batch):
                res = (row.get("result") or "").lower()
                if res in ("accepted", "duplicate", "invalid", "own"):
                    seen.add(row["flag"])
                    stats[res] += 1
                    counts[res] = counts.get(res, 0) + 1
                else:
                    stats["unknown"] += 1
                    counts["unknown"] = counts.get("unknown", 0) + 1
            save_seen(seen)
            log(f"batch {len(batch)}: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

        if stats["error"] is None:
            for f in files:
                _archive(f)
        else:
            log(f"submit error: {stats['error']} (flags kept for retry)")
        return stats


class Loop(threading.Thread):
    """Runs fn() every cfg[interval_key] seconds until stopped."""

    def __init__(self, name, cfg, interval_key, fn, log=print):
        super().__init__(daemon=True)
        self.name = name
        self.cfg = cfg
        self.interval_key = interval_key
        self.fn = fn
        self.log = log
        self.stop = threading.Event()

    def run(self):
        self.log(f"{self.name} started (every {int(self.cfg.get(self.interval_key, 60))}s)")
        while not self.stop.is_set():
            try:
                self.fn()
            except Exception as e:  # keep the loop alive
                self.log(f"{self.name} tick failed: {e}")
            self.stop.wait(max(5, int(self.cfg.get(self.interval_key, 60))))
        self.log(f"{self.name} stopped")


class Tools:
    """Start/stop external tool stacks (ataka, yampa, tulip) and catch their flags.

    ataka prints stolen flags; with catch=True they are batched and submitted.
    yampa/tulip are docker stacks; `start` returns immediately, the `stop`
    command tears the containers down.
    """

    def __init__(self, cfg, log=print, submit=None):
        self.cfg = cfg
        self.log = log
        self.submit = submit
        self.procs = {}
        self.lock = threading.Lock()
        self._pending = []
        self._timer = None

    def _conf(self, name):
        return self.cfg.setdefault("tools", {}).setdefault(name, {})

    def running(self, name):
        p = self.procs.get(name)
        return p is not None and p.poll() is None

    def status(self, name):
        p = self.procs.get(name)
        if p is None:
            return "stopped"
        rc = p.poll()
        return f"running pid {p.pid}" if rc is None else f"exited rc={rc}"

    def _spawn(self, name, cmd, cwd, catch, track):
        try:
            p = subprocess.Popen(cmd, shell=True, cwd=cwd or None,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, bufsize=1, start_new_session=True)
        except Exception as e:
            self.log(f"[{name}] spawn failed: {e}")
            return None
        if track:
            self.procs[name] = p
        threading.Thread(target=self._pump, args=(name, p, catch, track), daemon=True).start()
        return p

    def _pump(self, name, p, catch, track):
        try:
            if p.stdout:
                for line in p.stdout:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    self.log(f"[{name}] {line}")
                    if catch:
                        flags = extract_flags(line)
                        if flags:
                            self._catch_flags(flags)
        finally:
            rc = p.wait()
            try:
                if p.stdout:
                    p.stdout.close()
            except Exception:
                pass
            if track:
                with self.lock:
                    if self.procs.get(name) is p:
                        self.procs.pop(name, None)
            self.log(f"[{name}] exited rc={rc}")

    def _catch_flags(self, flags):
        if not self.submit:
            return
        with self.lock:
            self._pending.extend(flags)
            if self._timer is None:
                self._timer = threading.Timer(1.5, self._flush)
                self._timer.daemon = True
                self._timer.start()

    def _flush(self):
        with self.lock:
            flags, self._pending = self._pending, []
            self._timer = None
        if flags:
            self.log(f"tools: submitting {len(flags)} caught flag(s)")
            try:
                self.submit(flags)
            except Exception as e:
                self.log(f"tools: submit failed: {e}")

    def start(self, name):
        t = self._conf(name)
        cmd = (t.get("start") or "").strip()
        if not cmd:
            self.log(f"[{name}] no start command")
            return False
        if self.running(name):
            self.log(f"[{name}] already running")
            return False
        self.log(f"[{name}] start: {cmd}")
        return self._spawn(name, cmd, t.get("dir"), bool(t.get("catch")), True) is not None

    def run_once(self, name, cmd=None):
        t = self._conf(name)
        cmd = (cmd if cmd is not None else (t.get("extra") or "")).strip()
        if not cmd:
            self.log(f"[{name}] no command to run")
            return False
        self.log(f"[{name}] run: {cmd}")
        return self._spawn(name, cmd, t.get("dir"), bool(t.get("catch")), False) is not None

    def stop(self, name):
        t = self._conf(name)
        p = self.procs.get(name)
        alive = p is not None and p.poll() is None
        stop_cmd = (t.get("stop") or "").strip()
        if not alive and not stop_cmd:
            self.log(f"[{name}] not running")
            return False
        if alive:
            self._kill(name)
        if stop_cmd:
            self.run_once(name, stop_cmd)
        return True

    def _kill(self, name):
        p = self.procs.get(name)
        if not p or p.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except Exception:
            try:
                p.terminate()
            except Exception:
                pass

    def terminate_all(self):
        for name in list(self.procs):
            self._kill(name)


# ------------------------------------------------- mass exploit runner
#
# No built-in exploits: pwn/web/crypto/rev differ per service. Point each
# service at your own script. It gets {ip} {port} {team} {url} substituted,
# plus TARGET_IP/TARGET_PORT/TARGET_TEAM/SERVICE/TARGET_URL env vars, and
# just prints flags; the runner extracts them and submits.

PLACEHOLDERS = ("ip", "port", "team", "service", "url")


def render_cmd(cmd, team, ip, service, port):
    vals = {"ip": ip, "port": str(port), "team": team,
            "service": service, "url": f"http://{ip}:{port}"}
    for k in PLACEHOLDERS:
        cmd = cmd.replace("{" + k + "}", vals[k])
    return cmd


def _run_one(team, ip, service, port, cmd, timeout):
    env = dict(os.environ)
    env.update({"TARGET_IP": ip, "TARGET_PORT": str(port), "TARGET_TEAM": team,
                "SERVICE": service, "TARGET_URL": f"http://{ip}:{port}"})
    try:
        p = subprocess.run(render_cmd(cmd, team, ip, service, port), shell=True,
                           capture_output=True, text=True, timeout=timeout, env=env)
        out = (p.stdout or "") + "\n" + (p.stderr or "")
        return {"team": team, "service": service, "port": port,
                "flags": extract_flags(out), "rc": p.returncode, "error": None}
    except subprocess.TimeoutExpired:
        return {"team": team, "service": service, "port": port,
                "flags": [], "rc": -1, "error": "timeout"}
    except Exception as e:
        return {"team": team, "service": service, "port": port,
                "flags": [], "rc": -1, "error": str(e)}


def run_all(cfg, auth, log=print):
    """Run every (team, service) exploit in parallel, then submit found flags."""
    teams = [t for t in cfg.get("teams", []) if not t.get("self")]
    services = cfg.get("services", [])
    exploits = cfg.get("exploits", {})
    tasks = []
    for t in teams:
        for s in services:
            cmd = (exploits.get(s.get("name", "")) or "").strip()
            if cmd:
                tasks.append((t.get("name", "?"), t.get("ip", ""),
                              s.get("name", "?"), int(s.get("port", 0)), cmd))
    stats = {"targets": len(tasks), "flags": 0, "submitted": 0, "error": None}
    if not tasks:
        log("exploit: no tasks (fill teams / services / exploits)")
        return stats

    conc = max(1, int(cfg.get("concurrency", 8)))
    timeout = max(1, int(cfg.get("exploit_timeout", 20)))
    log(f"exploit: {len(tasks)} tasks, concurrency {conc}, timeout {timeout}s")

    found = []
    with ThreadPoolExecutor(max_workers=conc) as ex:
        futs = [ex.submit(_run_one, *task, timeout) for task in tasks]
        for fut in as_completed(futs):
            r = fut.result()
            if r["error"]:
                log(f"  {r['team']} {r['service']}:{r['port']} error: {r['error']}")
            else:
                log(f"  {r['team']} {r['service']}:{r['port']} rc={r['rc']} flags={len(r['flags'])}")
            found += r["flags"]

    stats["flags"] = len(found)
    if found:
        sub = process(cfg, auth, log, extra=found)
        stats["submitted"] = sub.get("accepted", 0) + sub.get("duplicate", 0)
        stats["error"] = sub.get("error")
    else:
        log("exploit: no flags found this run")
    return stats


def parse_teams(text):
    out = []
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        own = s.startswith("!")
        if own:
            s = s[1:].strip()
        parts = s.split()
        if len(parts) < 2:
            continue
        out.append({"name": " ".join(parts[:-1]), "ip": parts[-1], "self": own})
    return out


def dump_teams(teams):
    return "\n".join(("! " if t.get("self") else "") + f"{t.get('name', '')} {t.get('ip', '')}"
                     for t in teams)


def parse_services(text):
    out = []
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        try:
            out.append({"name": parts[0], "port": int(parts[1])})
        except (IndexError, ValueError):
            continue
    return out


def dump_services(services):
    return "\n".join(f"{s.get('name', '')} {s.get('port', '')}" for s in services)


def parse_exploits(text):
    out = {}
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        name, cmd = s.split("=", 1)
        if name.strip():
            out[name.strip()] = cmd.strip()
    return out


def dump_exploits(exploits):
    return "\n".join(f"{k} = {v}" for k, v in exploits.items())


def make_queued_flags(flags):
    ensure()
    p = INBOX / f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex}.txt"
    tmp = p.with_suffix(".tmp")
    tmp.write_text("\n".join(flags) + "\n")
    os.replace(tmp, p)
    return p


# ---------------------------------------------------------------- CLI


def cmd_push(args):
    ensure()
    flags = extract_flags(" ".join(args.flags)) or list(args.flags)
    p = make_queued_flags(flags)
    print(f"queued {len(flags)} flag(s) -> {p}")


def cmd_submit(args):
    cfg = load_cfg()
    flags = extract_flags(" ".join(args.flags)) or list(args.flags)
    stats = process(cfg, Auth(cfg, print), print, extra=flags)
    print(json.dumps(stats))


def cmd_login(args):
    cfg = load_cfg()
    cfg["base"] = (args.base or cfg["base"]).rstrip("/")
    if getattr(args, "token", None):
        try:
            sub, exp = store_token(cfg, args.token)
        except ValueError as e:
            raise SystemExit(f"token rejected: {e}")
        print(f"token saved: {sub} (valid {max(0, int(exp - time.time())) // 60}m)")
        return
    user = args.username or input("username: ").strip()
    pw = args.password or getpass.getpass("password: ")
    cfg["username"] = user
    cfg["password"] = pw
    cfg["token"] = ""
    cfg["token_exp"] = 0
    save_cfg(cfg)
    auth = Auth(cfg, print)
    auth.token(force=True)
    print(f"token saved (exp in {max(0, int(cfg['token_exp'] - time.time())) // 60}m)")


def cmd_token(args):
    cfg = load_cfg()
    try:
        sub, exp = store_token(cfg, args.token)
    except ValueError as e:
        raise SystemExit(f"token rejected: {e}")
    print(f"token saved: {sub} (valid {max(0, int(exp - time.time())) // 60}m)")


def cmd_exploit(args):
    cfg = load_cfg()
    stats = run_all(cfg, Auth(cfg, print), print)
    print(json.dumps(stats))


# ---------------------------------------------------------------- GUI


def run_gui():
    try:
        import tkinter as tk
        from tkinter import ttk, scrolledtext, filedialog
    except ImportError:
        raise SystemExit(
            "tkinter is missing in this Python build.\n"
            "Try: python3.14 flagr.py   (or `brew install python-tk@3.14`)\n"
            "CLI still works here: flagr push / submit / login"
        )

    cfg = load_cfg()
    ui_q = queue.Queue()
    log = make_logger(ui_q.put)
    auth = Auth(cfg, log)
    tools_mgr = Tools(cfg, log, submit=lambda flags: process(cfg, auth, log, extra=flags))

    root = tk.Tk()
    root.title("flagr - GEMASTIK flag submitter")
    root.geometry(cfg.get("geometry") or "1020x860")
    root.minsize(960, 740)

    ws = root.tk.call("tk", "windowingsystem")
    mono = ("Menlo", 11) if ws == "aqua" else ("Consolas", 10) if ws == "win32" else ("DejaVu Sans Mono", 10)

    outer = ttk.Frame(root, padding=8)
    outer.pack(fill="both", expand=True)
    outer.columnconfigure(0, weight=1)
    outer.rowconfigure(0, weight=1)

    paned = ttk.Panedwindow(outer, orient="vertical")
    paned.grid(row=0, column=0, sticky="nsew")

    nb = ttk.Notebook(paned)
    try:
        paned.add(nb, weight=5)
    except tk.TclError:
        paned.add(nb)

    # ---------- tab: submit ----------
    tab1 = ttk.Frame(nb, padding=8)
    nb.add(tab1, text="Submit")
    tab1.columnconfigure(1, weight=1)
    tab1.columnconfigure(3, weight=1)
    tab1.rowconfigure(6, weight=1)

    base_var = tk.StringVar(value=cfg["base"])
    user_var = tk.StringVar(value=cfg["username"])
    pass_var = tk.StringVar(value=cfg["password"])
    int_var = tk.IntVar(value=int(cfg.get("interval", 60)))
    token_var = tk.StringVar(value=cfg.get("token") or "")

    ttk.Label(tab1, text="Platform URL").grid(row=0, column=0, sticky="w", pady=2)
    ttk.Entry(tab1, textvariable=base_var).grid(row=0, column=1, columnspan=3, sticky="ew", pady=2)

    ttk.Label(tab1, text="Username").grid(row=1, column=0, sticky="w", pady=2)
    ttk.Entry(tab1, textvariable=user_var).grid(row=1, column=1, sticky="ew", pady=2)
    ttk.Label(tab1, text="Password").grid(row=1, column=2, sticky="e", padx=(8, 4))
    ttk.Entry(tab1, textvariable=pass_var, show="*").grid(row=1, column=3, sticky="ew", pady=2)

    def save_fields():
        cfg["base"] = base_var.get().strip().rstrip("/") or cfg["base"]
        cfg["username"] = user_var.get().strip()
        cfg["password"] = pass_var.get()
        try:
            cfg["interval"] = max(10, int(int_var.get()))
        except (tk.TclError, ValueError):
            cfg["interval"] = 60
        save_cfg(cfg)

    def do_login():
        save_fields()

        def work():
            try:
                auth.invalidate()
                auth.token(force=True)
                log(f"login ok as {cfg['username']} (interval {cfg['interval']}s)")
            except Exception as e:
                log(f"login failed: {e}")
        threading.Thread(target=work, daemon=True).start()

    def copy_token():
        tok = normalize_token(token_var.get()) or cfg.get("token") or ""
        if not tok:
            log("no token yet - paste one or login first")
            return
        root.clipboard_clear()
        root.clipboard_append(tok)
        log("token copied to clipboard")

    def save_token():
        try:
            sub, exp = store_token(cfg, token_var.get())
        except ValueError as e:
            log(f"token rejected: {e}")
            return
        token_var.set(cfg["token"])
        log(f"token saved: {sub} · valid {max(0, int(exp - time.time())) // 60}m")

    token_row = ttk.Frame(tab1)
    token_row.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(4, 0))
    ttk.Label(token_row, text="Bearer token").pack(side="left")
    ttk.Entry(token_row, textvariable=token_var, show="*").pack(
        side="left", fill="x", expand=True, padx=(6, 6))
    ttk.Button(token_row, text="Save token", command=save_token).pack(side="left")
    ttk.Button(token_row, text="Copy token", command=copy_token).pack(side="left", padx=(6, 0))

    auth_row = ttk.Frame(tab1)
    auth_row.grid(row=3, column=0, columnspan=4, sticky="ew", pady=4)
    ttk.Button(auth_row, text="Login / refresh token", command=do_login).pack(side="left")
    int_box = ttk.Spinbox(auth_row, from_=10, to=3600, width=8, textvariable=int_var,
                          command=lambda: (save_fields(), None))
    int_box.pack(side="right")
    ttk.Label(auth_row, text="Submit every (s)").pack(side="right", padx=(0, 6))
    int_box.bind("<FocusOut>", lambda _e: save_fields())

    sub_btn = ttk.Button(tab1, text="Start background submitter")
    sub_btn.grid(row=4, column=0, columnspan=2, sticky="w", pady=4)

    ttk.Label(
        tab1,
        text=f"Inbox: {INBOX}/*.txt  (`flagr push FLAG` or drop a file)",
        foreground="#555", wraplength=520, justify="left",
    ).grid(row=4, column=2, columnspan=2, sticky="e")

    ttk.Label(tab1, text="Flags (paste, one per line or noisy output)").grid(
        row=5, column=0, columnspan=4, sticky="w", pady=(8, 2))
    flags_text = scrolledtext.ScrolledText(tab1, height=8, wrap="word", font=mono, width=30)
    flags_text.grid(row=6, column=0, columnspan=4, sticky="nsew", pady=2)

    def submit_now():
        save_fields()
        flags = extract_flags(flags_text.get("1.0", "end"))
        if not flags:
            log("no flags found in the text box")
            return
        flags_text.delete("1.0", "end")

        def work():
            try:
                process(cfg, auth, log, extra=flags)
            except Exception as e:
                log(f"submit failed: {e}")
        threading.Thread(target=work, daemon=True).start()

    def flush_inbox():
        save_fields()
        threading.Thread(target=lambda: process(cfg, auth, log), daemon=True).start()

    action_row = ttk.Frame(tab1)
    action_row.grid(row=7, column=0, columnspan=4, sticky="w", pady=(2, 8))
    ttk.Button(action_row, text="Submit now", command=submit_now).pack(side="left")
    ttk.Button(action_row, text="Flush inbox", command=flush_inbox).pack(side="left", padx=(6, 0))
    ttk.Label(action_row, text="Ctrl+Enter submits", foreground="#555").pack(
        side="left", padx=(12, 0))

    for seq in ("<Control-Return>", "<Command-Return>"):
        flags_text.bind(seq, lambda _e: (submit_now(), "break")[1])

    # ---------- tab: mass exploit ----------
    tab2 = ttk.Frame(nb, padding=8)
    nb.add(tab2, text="Mass exploit")
    tab2.columnconfigure(0, weight=1)
    tab2.columnconfigure(1, weight=1)
    tab2.rowconfigure(1, weight=1)
    tab2.rowconfigure(3, weight=1)

    ttk.Label(tab2, text="Teams  (name ip per line;  prefix ! to mark your own)").grid(
        row=0, column=0, sticky="w")
    ttk.Label(tab2, text="Services  (name port per line)").grid(
        row=0, column=1, sticky="w", padx=(8, 0))

    teams_text = scrolledtext.ScrolledText(tab2, height=6, wrap="none", font=mono, width=30)
    teams_text.grid(row=1, column=0, sticky="nsew", pady=2)
    teams_text.insert("1.0", dump_teams(cfg.get("teams", [])))
    services_text = scrolledtext.ScrolledText(tab2, height=6, wrap="none", font=mono, width=30)
    services_text.grid(row=1, column=1, sticky="nsew", padx=(8, 0), pady=2)
    services_text.insert("1.0", dump_services(cfg.get("services", [])))

    ttk.Label(tab2, text="Exploits  (service = your command; "
                         "{ip} {port} {team} {url} + TARGET_* env are set)").grid(
        row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))
    exploit_text = scrolledtext.ScrolledText(tab2, height=6, wrap="none", font=mono, width=30)
    exploit_text.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=2)
    exploit_text.insert("1.0", dump_exploits(cfg.get("exploits", {})))

    ttk.Label(
        tab2,
        text="e.g.  web = python3 exploits/web.py {url}   |   "
             "pwn = python3 exploits/pwn.py {ip} {port}   |   "
             "cry / rev = your script; print flags to stdout",
        foreground="#555", wraplength=820, justify="left",
    ).grid(row=4, column=0, columnspan=2, sticky="w")

    mass_var = tk.StringVar()
    ttk.Label(tab2, textvariable=mass_var).grid(
        row=5, column=0, columnspan=2, sticky="w", pady=(4, 0))

    def refresh_mass_counts():
        mass_var.set(f"{len(cfg.get('teams', []))} teams · "
                     f"{len(cfg.get('services', []))} services · "
                     f"{len(cfg.get('exploits', {}))} exploits configured")

    refresh_mass_counts()

    ctl = ttk.Frame(tab2)
    ctl.grid(row=6, column=0, columnspan=2, sticky="w", pady=(6, 0))
    conc_var = tk.IntVar(value=int(cfg.get("concurrency", 8)))
    cto_var = tk.IntVar(value=int(cfg.get("exploit_timeout", 20)))
    eint_var = tk.IntVar(value=int(cfg.get("exploit_interval", 180)))

    ttk.Label(ctl, text="Concurrency").pack(side="left")
    ttk.Spinbox(ctl, from_=1, to=64, width=5, textvariable=conc_var).pack(side="left", padx=(2, 14))
    ttk.Label(ctl, text="Timeout (s)").pack(side="left")
    ttk.Spinbox(ctl, from_=1, to=600, width=5, textvariable=cto_var).pack(side="left", padx=(2, 14))
    ttk.Label(ctl, text="Auto every (s)").pack(side="left")
    ttk.Spinbox(ctl, from_=10, to=3600, width=6, textvariable=eint_var).pack(side="left", padx=(2, 0))

    act = ttk.Frame(tab2)
    act.grid(row=7, column=0, columnspan=2, sticky="w", pady=(4, 0))

    def save_exploit():
        cfg["teams"] = parse_teams(teams_text.get("1.0", "end"))
        cfg["services"] = parse_services(services_text.get("1.0", "end"))
        cfg["exploits"] = parse_exploits(exploit_text.get("1.0", "end"))
        for key, var, default in (("concurrency", conc_var, 8),
                                  ("exploit_timeout", cto_var, 20),
                                  ("exploit_interval", eint_var, 180)):
            try:
                cfg[key] = max(1, int(var.get()))
            except (tk.TclError, ValueError):
                cfg[key] = default
        save_cfg(cfg)
        log(f"saved: {len(cfg['teams'])} teams, {len(cfg['services'])} services, "
            f"{len(cfg['exploits'])} exploits")
        refresh_mass_counts()
        return cfg

    def run_now():
        save_exploit()
        threading.Thread(target=lambda: run_all(cfg, auth, log), daemon=True).start()

    ttk.Button(act, text="Save", command=save_exploit).pack(side="left", padx=(0, 6))
    ttk.Button(act, text="Run all now", command=run_now).pack(side="left", padx=(0, 6))
    exploit_btn = ttk.Button(act, text="Start auto exploit")
    exploit_btn.pack(side="left")
    exploit_btn.config(command=lambda: toggle_loop("exploit", exploit_btn,
                                                   "Start auto exploit", "Stop auto exploit"))

    # ---------- tab: tools (ataka / yampa / tulip) ----------
    tab3 = ttk.Frame(nb, padding=0)
    nb.add(tab3, text="Tools")
    tab3.columnconfigure(0, weight=1)
    tab3.rowconfigure(0, weight=1)

    canvas = tk.Canvas(tab3, highlightthickness=0, borderwidth=0,
                       background=ttk.Style().lookup("TFrame", "background"))
    vsb = ttk.Scrollbar(tab3, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=vsb.set)
    canvas.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")

    inner = ttk.Frame(canvas, padding=8)
    inner.columnconfigure(0, weight=1)
    win = canvas.create_window((0, 0), window=inner, anchor="nw")
    inner.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win, width=e.width))

    def on_wheel(e):
        w = canvas.winfo_containing(e.x_root, e.y_root)
        p = w
        while p is not None and p is not canvas:
            p = p.master
        if p is not canvas:
            return
        if getattr(e, "num", None) == 4:
            canvas.yview_scroll(-1, "units")
        elif getattr(e, "num", None) == 5:
            canvas.yview_scroll(1, "units")
        else:
            canvas.yview_scroll(-1 if getattr(e, "delta", 0) > 0 else 1, "units")

    root.bind_all("<MouseWheel>", on_wheel)
    root.bind_all("<Button-4>", on_wheel)
    root.bind_all("<Button-5>", on_wheel)
    for idx, key in enumerate(("1", "2", "3")):
        root.bind(f"<Control-Key-{key}>", lambda _e, i=idx: nb.select(i))

    ttk.Label(
        inner,
        text="Start/stop external stacks. Ataka: `atk` player-cli on PATH. "
             "Yampa/Tulip: docker compose + repo dir. "
             "`catch flags` auto-submits flags printed by the tool.",
        foreground="#555", wraplength=900, justify="left",
    ).grid(row=0, column=0, sticky="w", pady=(0, 4))

    tool_status = {}
    tool_vars = {}

    def tool_save(name):
        tv, cv = tool_vars[name]
        t = cfg.setdefault("tools", {}).setdefault(name, {})
        for k, var in tv.items():
            t[k] = var.get().strip()
        t["catch"] = bool(cv.get())
        save_cfg(cfg)
        return t

    for i, name in enumerate(cfg.get("tools", {}).keys()):
        t = cfg["tools"][name]
        lf = ttk.LabelFrame(inner, text=name.capitalize(), padding=4)
        lf.grid(row=i + 1, column=0, sticky="ew", pady=2)
        lf.columnconfigure(1, weight=1)

        tv = {k: tk.StringVar(value=t.get(k, "")) for k in ("dir", "start", "stop", "extra", "url")}
        cv = tk.BooleanVar(value=bool(t.get("catch")))
        tool_vars[name] = (tv, cv)

        def add_row(r, label, key, tv=tv, lf=lf):
            ttk.Label(lf, text=label).grid(row=r, column=0, sticky="w", padx=(0, 4))
            ttk.Entry(lf, textvariable=tv[key]).grid(row=r, column=1, sticky="ew")

        add_row(0, "dir", "dir")
        add_row(1, "start", "start")
        add_row(2, "stop", "stop")
        add_row(3, "extra", "extra")

        btns = ttk.Frame(lf)
        btns.grid(row=0, column=2, rowspan=2, sticky="ne", padx=(6, 0))

        def mk(parent, text, fn):
            ttk.Button(parent, text=text, command=fn).pack(side="left", padx=1)

        def choose_dir(n=name, tv=tv):
            cur = tv["dir"].get().strip() or os.path.expanduser("~")
            path = filedialog.askdirectory(initialdir=cur, title=f"{n} directory")
            if path:
                tv["dir"].set(path)
                tool_save(n)

        mk(btns, "Browse", choose_dir)
        mk(btns, "Start", lambda n=name: (tool_save(n), tools_mgr.start(n)))
        mk(btns, "Stop", lambda n=name: (tool_save(n), tools_mgr.stop(n)))
        mk(btns, "Run extra", lambda n=name: (tool_save(n), tools_mgr.run_once(n)))

        def open_url(n=name):
            url = (tool_save(n).get("url") or "").strip()
            if not url:
                log(f"[{n}] no url configured")
                return
            import webbrowser
            log(f"[{n}] opening {url}")
            webbrowser.open(url)

        mk(btns, "Open UI", open_url)

        foot = ttk.Frame(lf)
        foot.grid(row=3, column=2, sticky="e", padx=(6, 0))
        ttk.Checkbutton(foot, text="catch flags", variable=cv,
                        command=lambda n=name: tool_save(n)).pack(side="left")
        lbl = ttk.Label(foot, text="stopped", foreground="#666")
        lbl.pack(side="left", padx=(8, 0))
        tool_status[name] = lbl

    # ---------- shared log ----------
    log_frame = ttk.Frame(paned)
    log_frame.columnconfigure(0, weight=1)
    log_frame.rowconfigure(1, weight=1)
    try:
        paned.add(log_frame, weight=1)
    except tk.TclError:
        paned.add(log_frame)

    log_head = ttk.Frame(log_frame)
    log_head.grid(row=0, column=0, sticky="ew")
    log_head.columnconfigure(1, weight=1)
    ttk.Label(log_head, text="Log").grid(row=0, column=0, sticky="w")
    autoscroll = tk.BooleanVar(value=True)

    def clear_log():
        logbox.configure(state="normal")
        logbox.delete("1.0", "end")
        logbox.configure(state="disabled")

    ttk.Button(log_head, text="Clear", command=clear_log).grid(row=0, column=1, sticky="e")
    ttk.Checkbutton(log_head, text="auto-scroll", variable=autoscroll).grid(
        row=0, column=2, sticky="e", padx=(8, 0))

    logbox = scrolledtext.ScrolledText(log_frame, height=10, state="disabled",
                                       wrap="word", font=mono, width=30)
    logbox.grid(row=1, column=0, sticky="nsew")

    # ---------- background loops ----------
    loops = {}

    def toggle_loop(kind, btn, start_label, stop_label):
        w = loops.get(kind)
        if w and w.is_alive():
            w.stop.set()
            loops.pop(kind, None)
            btn.config(text=start_label)
            return
        if kind == "submit":
            save_fields()
            w = Loop("submitter", cfg, "interval", lambda: process(cfg, auth, log), log)
        else:
            save_exploit()
            w = Loop("mass-exploit", cfg, "exploit_interval",
                     lambda: run_all(cfg, auth, log), log)
        loops[kind] = w
        w.start()
        btn.config(text=stop_label)

    sub_btn.config(command=lambda: toggle_loop("submit", sub_btn,
                                               "Start background submitter",
                                               "Stop background submitter"))

    # ---------- status bar ----------
    status_bar = ttk.Frame(outer, padding=(2, 5))
    status_bar.grid(row=1, column=0, sticky="ew", pady=(6, 0))
    status_bar.columnconfigure(2, weight=1)
    state = {
        "token": ttk.Label(status_bar, text="token: none", foreground="#a60"),
        "inbox": ttk.Label(status_bar, text="inbox: 0"),
        "loops": ttk.Label(status_bar,
                           text="submitter: off · exploit loop: off · tools up: 0"),
    }
    state["token"].grid(row=0, column=0, sticky="w")
    ttk.Separator(status_bar, orient="vertical").grid(row=0, column=1, sticky="ns", padx=8)
    state["inbox"].grid(row=0, column=2, sticky="w")
    state["loops"].grid(row=0, column=3, sticky="e")

    def append_log(msg):
        logbox.configure(state="normal")
        logbox.insert("end", f"{time.strftime('%H:%M:%S')} {msg}\n")
        try:
            if int(logbox.index("end-1c").split(".")[0]) > 3000:
                logbox.delete("1.0", "1200.0")
        except Exception:
            pass
        if autoscroll.get():
            logbox.see("end")
        logbox.configure(state="disabled")

    scan = {"at": 0.0, "n": 0}

    def refresh_status():
        for name, lbl in tool_status.items():
            s = tools_mgr.status(name)
            color = "#0a0" if s.startswith("running") else "#a60" if s.startswith("exited") else "#666"
            lbl.config(text=s, foreground=color)

        now = time.time()
        if now - scan["at"] > 1.0:
            scan["at"] = now
            try:
                scan["n"] = len(list(INBOX.glob("*.txt")))
            except OSError:
                scan["n"] = 0
        left = max(0, int((cfg.get("token_exp") or 0) - now))
        has_token = bool(cfg.get("token"))
        token_txt = f"token: {left // 60}m{left % 60:02d}s" if has_token and left else "token: none"
        state["token"].config(text=token_txt,
                              foreground="#0a0" if token_txt != "token: none" else "#a60")
        state["inbox"].config(text=f"inbox: {scan['n']}")
        running_tools = sum(1 for n in tool_status if tools_mgr.running(n))
        state["loops"].config(
            text=f"submitter: {'on' if 'submit' in loops else 'off'} · "
                 f"exploit loop: {'on' if 'exploit' in loops else 'off'} · "
                 f"tools up: {running_tools}")

    def pump():
        try:
            while True:
                append_log(ui_q.get_nowait())
        except queue.Empty:
            pass
        refresh_status()
        root.after(200, pump)

    def on_close():
        cfg["geometry"] = root.geometry()
        try:
            cfg["sash"] = paned.sashpos(0) / max(1, paned.winfo_height())
        except tk.TclError:
            pass
        try:
            save_cfg(cfg)
        except Exception:
            pass
        for w in list(loops.values()):
            w.stop.set()
        tools_mgr.terminate_all()
        root.destroy()

    def place_sash():
        try:
            h = paned.winfo_height()
            frac = float(cfg.get("sash") or 0.68)
            hi = max(430, h - 150)
            paned.sashpos(0, max(380, min(int(h * frac), hi)))
        except (tk.TclError, ValueError):
            pass

    if os.environ.get("FLAGR_GUI_TAB"):
        try:
            nb.select(int(os.environ["FLAGR_GUI_TAB"]))
        except (ValueError, tk.TclError):
            pass

    root.protocol("WM_DELETE_WINDOW", on_close)
    pump()
    root.after(60, place_sash)
    root.mainloop()


def main():
    p = argparse.ArgumentParser(prog="flagr", description="minimal attack/defense flag submitter")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("push", help="queue flag(s) for the background submitter")
    sp.add_argument("flags", nargs="+")
    sp.set_defaults(fn=cmd_push)

    ss = sub.add_parser("submit", help="submit flag(s) immediately")
    ss.add_argument("flags", nargs="+")
    ss.set_defaults(fn=cmd_submit)

    sl = sub.add_parser("login", help="save credentials and fetch a token")
    sl.add_argument("--base")
    sl.add_argument("--username")
    sl.add_argument("--password")
    sl.add_argument("--token", help="use a bearer JWT directly instead of logging in")
    sl.set_defaults(fn=cmd_login)

    st = sub.add_parser("token", help="save a bearer JWT (from the Team page)")
    st.add_argument("token")
    st.set_defaults(fn=cmd_token)

    se = sub.add_parser("exploit", help="run all configured exploits once and submit flags")
    se.set_defaults(fn=cmd_exploit)

    sub.add_parser("gui", help="open the GUI (default)").set_defaults(fn=lambda a: run_gui())

    args = p.parse_args()
    fn = getattr(args, "fn", None)
    if fn is None:
        run_gui()
    else:
        fn(args)


if __name__ == "__main__":
    main()
