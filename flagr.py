#!/usr/bin/env python3
"""flagr - attack/defense flag submitter (Python 3 + requests).

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
import ipaddress
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse
from pathlib import Path
import requests

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

TOOL_GUIDES = {
    "ataka": """Ataka - centralized exploit runner (OpenAttackDefenseTools)

SETUP (once)
1. Download the player-cli from the ataka API container (port 8000), per its README.
2. Save it and make it executable:
     macOS/Linux:  ~/.local/bin/atk        chmod +x ~/.local/bin/atk
     Windows:      C:\\Users\\<you>\\.local\\bin\\atk   (run with `python atk` if needed)
3. After the server's ctfconfig changes:  atk reload
4. Sanity check:  atk exploit ls

IN FLAGR (Tools tab)
  dir    empty (CLI is global), or your exploit folder if you use `atk exploit new`
  start  atk exploit runlocal --all-targets     (runs until Stop)
  stop   empty -> flagr just terminates the process
  extra  atk exploit ls  |  atk flag ids  |  atk exploit logs -n 3
  Open UI  none (CLI only)
  catch flags  ON -> flags printed by ataka are submitted to GEMASTIK

NOTES
- Local mode (`runlocal`) attacks the NOP team by default; --all-targets hits real targets.
- Centralized mode runs exploits on the ataka server, which already submits to the game
  server itself; with `catch` ON you may just see duplicates (harmless).
- Ataka exploits receive TARGET_IP and TARGET_EXTRA (JSON). That is separate from the
  {ip} {port} placeholders used by flagr's own Mass exploit runner.
- `atk exploit upload` deploys a job; `atk exploit logs <id>` follows its output.
""",
    "yampa": """Yampa - MITM proxy between the game network and your vulnbox

SETUP (once)
1. git clone https://github.com/OpenAttackDefenseTools/yampa
2. cd yampa && ./generate-env.sh
3. Edit .env: proxied ports/services, plugin and rules directories.
4. Docker Desktop must be running (docker compose v2).

IN FLAGR (Tools tab)
  dir    the yampa repo folder (use Browse)
  start  docker compose up -d
  stop   docker compose down
  extra  ./lint-rules.sh && ./reload.sh      (reload plugins without restart)
  Open UI  none (yampa is a proxy)
  catch flags  OFF (it is not a flag source)

NOTES
- `docker compose up -d` exits right away, so the status shows "exited rc=0" even though
  the containers keep running. To verify: set extra to `docker compose ps` and Run extra,
  or run `docker compose logs -f` for live output.
- Plugins live in ./plugins, rules in ./rules; reload with the extra command.
- filter_plugin.py is always active; with empty rules it forwards traffic unchanged.
- Wrappers (e.g. TLS) survive plugin reloads, by design.
""",
    "tulip": """Tulip - flow analyzer for traffic from your services

SETUP (once)
1. git clone https://github.com/OpenAttackDefenseTools/tulip
2. cd tulip && cp .env.example .env
3. Edit .env: TRAFFIC_DIR_HOST, TICK_START, TICK_LENGTH, FLAG_REGEX
   (e.g. GEMASTIK\\{[^}]+\\})
4. Edit services/api/configurations.py: vm_ip and the services list (name + port).
5. Docker Desktop must be running.

IN FLAGR (Tools tab)
  dir    the tulip repo folder (use Browse)
  start  docker compose up -d --build
  stop   docker compose down
  extra  docker compose logs --tail=50 assembler
  Open UI  http://localhost:3000
  catch flags  OFF (analyze traffic; it is not a submitter)

GET TRAFFIC IN
- On the vulnbox, rotate captures:
    tcpdump -i eth0 -G 180 -w "traffic_%H:%M:%S.pcap" port <service port>
- Copy them to the machine running tulip, into TRAFFIC_DIR_HOST:
    rsync -avz -e ssh --progress root@<vulnbox>:/pcaps ./pcaps
- The assembler uses inotify and ingests new pcaps automatically.

TIP
- If services/api/configurations.py changes later, rebuild just the api:
    docker compose up --build -d api
""",
}

DEFAULT_CFG = {
    "base": "https://gemastik19-finals.siberlab.id",
    "username": "",
    "password": "",
    "token": "",
    "token_exp": 0,
    "interval": 60,
    "teams": [],
    "own_ip": "",
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


def tool_config_issues(name, tool, action="check"):
    """Return actionable setup problems without running an external command."""
    issues = []
    directory = (tool.get("dir") or "").strip()
    if action in ("check", "start", "extra"):
        if name in ("yampa", "tulip") and not directory:
            issues.append("choose the repository directory")
        elif directory and not Path(directory).is_dir():
            issues.append(f"directory does not exist: {directory}")
    field = {"start": "start", "extra": "extra"}.get(action)
    if field and not (tool.get(field) or "").strip():
        issues.append(f"{field} command is empty")
    if action == "check" and not (tool.get("start") or "").strip():
        issues.append("start command is empty")
    command = (tool.get("extra") if action == "extra" else tool.get("start")) or ""
    executable = command.strip().split(maxsplit=1)[0] if command.strip() else ""
    if action in ("check", "start", "extra") and executable in ("atk", "docker"):
        if shutil.which(executable) is None:
            issues.append(f"{executable} executable is not on PATH")
    url = (tool.get("url") or "").strip()
    if action == "url" and not url:
        issues.append("Web UI URL is empty")
    if url and action in ("check", "url"):
        try:
            parsed = urllib.parse.urlsplit(url)
            valid_url = parsed.scheme in ("http", "https") and bool(parsed.hostname)
        except ValueError:
            valid_url = False
        if not valid_url:
            issues.append("Web UI URL must start with http:// or https://")
    return issues

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

    def _request(self, method, path, payload=None, token=None):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            resp = requests.request(method, self.base + path, json=payload,
                                    headers=headers, timeout=20)
        except requests.RequestException as e:
            raise ApiError(0, str(e)) from None
        raw = resp.text
        if resp.status_code >= 400:
            raise ApiError(resp.status_code, raw) from None
        try:
            return json.loads(raw) if raw.strip() else {}
        except ValueError:
            raise ApiError(0, "non-JSON response: " + raw[:300]) from None

    def _post(self, path, payload, token=None):
        return self._request("POST", path, payload, token)

    def login(self, username, password):
        return self._post("/api/login", {"username": username, "password": password})

    def submit(self, token, flags):
        return self._post("/api/flag", {"flag": list(flags)}, token=token)

    def users(self, token):
        return self._request("GET", "/api/user", token=token)


def _short(text, limit=30):
    text = str(text)
    return text if len(text) <= limit else text[:limit - 3] + "..."


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

        batches = (len(todo) + 199) // 200
        log(f"submit: {len(todo)} new flag(s) in {batches} batch(es)")
        detail = 0

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
                    if detail < 40:
                        log(f"  {res}: {_short(row['flag'], 60)}")
                        detail += 1
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
        total = len(todo)
        if total > 40:
            log(f"  ... {total - 40} more result line(s) not shown")
        summary = (f"submit done: accepted={stats['accepted']} duplicate={stats['duplicate']} "
                   f"invalid={stats['invalid']} own={stats['own']} unknown={stats['unknown']}")
        if stats["error"]:
            summary += f" error={_short(stats['error'], 120)}"
        log(summary)
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
        next_run = time.monotonic()
        while not self.stop.is_set():
            if self.stop.wait(max(0, next_run - time.monotonic())):
                break
            try:
                self.fn()
            except Exception as e:  # keep the loop alive
                self.log(f"{self.name} tick failed: {e}")
            interval = max(5, int(self.cfg.get(self.interval_key, 60)))
            next_run += interval
            while next_run <= time.monotonic():
                next_run += interval
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
        if os.name == "nt":
            # Commands run through cmd.exe; terminate its child processes too.
            try:
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               check=True)
                return
            except (OSError, subprocess.CalledProcessError):
                pass
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
                "flags": extract_flags(out), "rc": p.returncode, "error": None,
                "tail": out[-800:]}
    except subprocess.TimeoutExpired:
        return {"team": team, "service": service, "port": port,
                "flags": [], "rc": -1, "error": "timeout"}
    except Exception as e:
        return {"team": team, "service": service, "port": port,
                "flags": [], "rc": -1, "error": str(e)}


def run_all(cfg, auth, log=print):
    """Run every (team, service) exploit in parallel, submitting results promptly."""
    own_name = jwt_payload(cfg.get("token") or "").get("sub") or cfg.get("username") or ""
    own_ip = cfg.get("own_ip") or ""
    teams = [t for t in cfg.get("teams", []) if not t.get("self")
             and t.get("name") != own_name and t.get("ip") != own_ip]
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

    pending = []
    last_submit = 0.0

    def submit_pending():
        nonlocal last_submit
        if not pending:
            return
        sub = process(cfg, auth, log, extra=pending)
        stats["submitted"] += sub.get("accepted", 0) + sub.get("duplicate", 0)
        stats["error"] = sub.get("error") or stats["error"]
        if sub.get("error"):
            make_queued_flags(pending)
            log(f"exploit: {len(pending)} flag(s) queued for retry")
        pending.clear()
        last_submit = time.monotonic()

    with ThreadPoolExecutor(max_workers=conc) as ex:
        futs = [ex.submit(_run_one, *task, timeout) for task in tasks]
        for fut in as_completed(futs):
            r = fut.result()
            where = f"{r['team']} {r['service']}:{r['port']}"
            if r["error"]:
                log(f"  {where} error: {r['error']}")
            elif r["flags"]:
                shown = ", ".join(_short(f, 34) for f in r["flags"][:3])
                more = "" if len(r["flags"]) <= 3 else f" (+{len(r['flags']) - 3} more)"
                log(f"  {where} rc={r['rc']} flags={len(r['flags'])}: {shown}{more}")
            else:
                log(f"  {where} rc={r['rc']} flags=0")
                for line in (r.get("tail") or "").strip().splitlines()[-3:]:
                    log(f"    {_short(line, 200)}")
            stats["flags"] += len(r["flags"])
            pending.extend(r["flags"])
            if pending and (len(pending) >= 20 or time.monotonic() - last_submit >= 1):
                submit_pending()

    submit_pending()
    if not stats["flags"]:
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


def fetch_teams(cfg, auth):
    """Read live targets from the scoring API and identify our own box."""
    api = Api(cfg["base"])
    for attempt in (0, 1):
        try:
            token = auth.token(force=bool(attempt))
            rows = api.users(token)
            break
        except ApiError as e:
            if e.status in (401, 403) and not attempt:
                auth.invalidate()
                continue
            raise
    if not isinstance(rows, list):
        raise ValueError("/api/user did not return a team list")
    own_name = jwt_payload(token).get("sub") or cfg.get("username") or ""
    own_ip = cfg.get("own_ip") or ""
    teams = []
    seen_ips = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        name, ip = str(row.get("username") or "").strip(), str(row.get("vpn_ip") or "").strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not name or ip in seen_ips:
            continue
        seen_ips.add(ip)
        teams.append({"name": name, "ip": ip,
                      "self": bool((own_name and name == own_name) or (own_ip and ip == own_ip))})
    if not any(t["self"] for t in teams):
        raise ValueError("own team not found; set username or Own VPN IP before syncing")
    return teams


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
    root.title("flagr · Attack & Defense console")
    root.geometry(cfg.get("geometry") or "1100x820")
    root.minsize(900, 680)

    ws = root.tk.call("tk", "windowingsystem")
    mono = ("Menlo", 11) if ws == "aqua" else ("Consolas", 10) if ws == "win32" else ("DejaVu Sans Mono", 10)
    ui_font = ("Helvetica Neue", 11) if ws == "aqua" else ("Segoe UI", 10) if ws == "win32" else ("DejaVu Sans", 10)
    bg, surface, text_color = "#f2f5fa", "#ffffff", "#172337"
    muted, accent, good, warn = "#64748b", "#245cb4", "#16734d", "#a85d08"
    style = ttk.Style(root)
    style.theme_use("clam")
    root.configure(background=bg)
    style.configure("TFrame", background=bg)
    style.configure("TLabel", background=bg, foreground=text_color, font=ui_font)
    style.configure("TButton", font=ui_font, padding=(11, 7), background=surface,
                    foreground=text_color, bordercolor="#ced8e7", lightcolor=surface,
                    darkcolor=surface, relief="solid", borderwidth=1)
    style.map("TButton", background=[("active", "#e9f0fb"), ("pressed", "#dce8f9")])
    style.configure("Accent.TButton", background=accent, foreground="white", padding=(12, 8),
                    bordercolor=accent, lightcolor=accent, darkcolor=accent, relief="flat")
    style.map("Accent.TButton", background=[("active", "#174990"), ("disabled", "#a8b6cb")],
              foreground=[("disabled", "#e4eaf3")])
    style.configure("TEntry", padding=6, fieldbackground=surface, bordercolor="#ced8e7",
                    lightcolor="#ced8e7", darkcolor="#ced8e7")
    style.configure("TSpinbox", padding=5, fieldbackground=surface, bordercolor="#ced8e7")
    style.configure("TCheckbutton", background=bg, foreground=text_color, font=ui_font)
    style.configure("TNotebook", background=bg, borderwidth=0)
    style.configure("TNotebook.Tab", font=(ui_font[0], ui_font[1], "bold"),
                    padding=(18, 10), background="#e5ebf4", bordercolor=bg)
    style.map("TNotebook.Tab", background=[("selected", surface), ("active", "#edf3fb")],
              foreground=[("selected", accent)])
    style.configure("TLabelframe", background=surface, bordercolor="#dce4ef", relief="solid", padding=10)
    style.configure("TLabelframe.Label", background=surface, foreground=text_color,
                    font=(ui_font[0], ui_font[1], "bold"))
    style.configure("Card.TFrame", background=surface)
    style.configure("Card.TLabel", background=surface, foreground=text_color, font=ui_font)
    style.configure("Card.TCheckbutton", background=surface, foreground=text_color, font=ui_font)
    style.map("Card.TCheckbutton", background=[("active", surface)])
    style.configure("Muted.TLabel", background=bg, foreground=muted, font=ui_font)
    style.configure("CardMuted.TLabel", background=surface, foreground=muted, font=ui_font)
    style.configure("Title.TLabel", background=bg, foreground=text_color,
                    font=(ui_font[0], 19, "bold"))
    style.configure("Section.TLabel", background=surface, foreground=text_color,
                    font=(ui_font[0], ui_font[1], "bold"))

    def style_text(widget):
        widget.configure(background=surface, foreground=text_color,
                         insertbackground=text_color, selectbackground="#c8dcfa",
                         selectforeground=text_color, relief="flat", padx=8, pady=7,
                         highlightthickness=1, highlightbackground="#dce4ef",
                         highlightcolor=accent)

    outer = ttk.Frame(root, padding=12)
    outer.pack(fill="both", expand=True)
    outer.columnconfigure(0, weight=1)
    outer.rowconfigure(1, weight=1)

    header = ttk.Frame(outer)
    header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
    header.columnconfigure(0, weight=1)
    ttk.Label(header, text="flagr", style="Title.TLabel").grid(row=0, column=0, sticky="w")
    ttk.Label(header, text="Flag submission, mass exploits, and external tools in one workspace",
              style="Muted.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 0))
    headline_status = ttk.Label(header, text="Ready", style="Muted.TLabel")
    headline_status.grid(row=0, column=1, rowspan=2, sticky="e")

    paned = ttk.Panedwindow(outer, orient="vertical")
    paned.grid(row=1, column=0, sticky="nsew")

    nb = ttk.Notebook(paned)
    try:
        paned.add(nb, weight=5)
    except tk.TclError:
        paned.add(nb)

    # ---------- tab: submit ----------
    tab1 = ttk.Frame(nb, padding=12)
    nb.add(tab1, text="Submit")
    tab1.columnconfigure(0, weight=1)
    tab1.rowconfigure(0, weight=3, minsize=230)
    tab1.rowconfigure(1, weight=2, minsize=105)

    settings_frame = ttk.Frame(tab1)
    settings_frame.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
    settings_frame.columnconfigure(0, weight=1)
    settings_frame.rowconfigure(0, weight=1)
    settings_canvas = tk.Canvas(settings_frame, highlightthickness=0,
                                borderwidth=0, background=bg)
    settings_scroll = ttk.Scrollbar(settings_frame, orient="vertical",
                                     command=settings_canvas.yview)
    settings_canvas.configure(yscrollcommand=settings_scroll.set)
    settings_canvas.grid(row=0, column=0, sticky="nsew")
    settings_scroll.grid(row=0, column=1, sticky="ns")
    settings_body = ttk.Frame(settings_canvas)
    settings_body.columnconfigure(0, weight=1)
    settings_win = settings_canvas.create_window((0, 0), window=settings_body, anchor="nw")
    settings_body.bind("<Configure>", lambda _e: settings_canvas.configure(
        scrollregion=settings_canvas.bbox("all")))
    settings_canvas.bind("<Configure>", lambda e: settings_canvas.itemconfigure(
        settings_win, width=e.width))

    connection = ttk.LabelFrame(settings_body, text="Platform & authentication", padding=12)
    connection.grid(row=0, column=0, sticky="ew")
    connection.columnconfigure(1, weight=1)
    connection.columnconfigure(3, weight=1)
    flag_card = ttk.LabelFrame(tab1, text="Flag queue", padding=12)
    flag_card.grid(row=0, column=0, sticky="nsew")
    flag_card.columnconfigure(0, weight=1)
    flag_card.rowconfigure(2, weight=1, minsize=100)

    base_var = tk.StringVar(value=cfg["base"])
    user_var = tk.StringVar(value=cfg["username"])
    pass_var = tk.StringVar(value=cfg["password"])
    int_var = tk.IntVar(value=int(cfg.get("interval", 60)))
    token_var = tk.StringVar(value=cfg.get("token") or "")

    ttk.Label(connection, text="Platform URL", style="Card.TLabel").grid(
        row=0, column=0, sticky="w", padx=(0, 10), pady=4)
    ttk.Entry(connection, textvariable=base_var).grid(
        row=0, column=1, columnspan=3, sticky="ew", pady=4)

    ttk.Label(connection, text="Username", style="Card.TLabel").grid(
        row=1, column=0, sticky="w", padx=(0, 10), pady=4)
    ttk.Entry(connection, textvariable=user_var).grid(row=1, column=1, sticky="ew", pady=4)
    ttk.Label(connection, text="Password", style="Card.TLabel").grid(
        row=1, column=2, sticky="e", padx=(12, 8))
    ttk.Entry(connection, textvariable=pass_var, show="*").grid(row=1, column=3, sticky="ew", pady=4)

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

    token_row = ttk.Frame(connection, style="Card.TFrame")
    token_row.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(5, 0))
    ttk.Label(token_row, text="Bearer token", style="Card.TLabel").pack(side="left", padx=(0, 8))
    ttk.Entry(token_row, textvariable=token_var, show="*").pack(
        side="left", fill="x", expand=True, padx=(6, 6))
    ttk.Button(token_row, text="Save token", command=save_token).pack(side="left")
    ttk.Button(token_row, text="Copy token", command=copy_token).pack(side="left", padx=(6, 0))

    auth_row = ttk.Frame(connection, style="Card.TFrame")
    auth_row.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(10, 0))
    ttk.Button(auth_row, text="Login / refresh token", command=do_login).pack(side="left")
    int_box = ttk.Spinbox(auth_row, from_=10, to=3600, width=8, textvariable=int_var,
                          command=lambda: (save_fields(), None))
    int_box.pack(side="right")
    ttk.Label(auth_row, text="Submit every (s)", style="Card.TLabel").pack(
        side="right", padx=(0, 6))
    int_box.bind("<FocusOut>", lambda _e: save_fields())

    ttk.Label(
        flag_card, text="Paste flags or noisy exploit output below. Recognized flags are queued before submission.",
        style="CardMuted.TLabel", wraplength=800, justify="left",
    ).grid(row=0, column=0, sticky="w", pady=(0, 8))
    flags_text = scrolledtext.ScrolledText(flag_card, height=7, wrap="word", font=mono, width=30)
    flags_text.grid(row=2, column=0, sticky="nsew")
    style_text(flags_text)

    def submit_now():
        save_fields()
        flags = extract_flags(flags_text.get("1.0", "end"))
        if not flags:
            log("no flags found in the text box")
            return
        try:
            make_queued_flags(flags)
        except OSError as e:
            log(f"could not queue flags: {e}")
            return
        flags_text.delete("1.0", "end")
        log(f"queued {len(flags)} flag(s) for submission")

        def work():
            try:
                process(cfg, auth, log)
            except Exception as e:
                log(f"submit failed: {e}")
        threading.Thread(target=work, daemon=True).start()

    def flush_inbox():
        save_fields()
        threading.Thread(target=lambda: process(cfg, auth, log), daemon=True).start()

    action_row = ttk.Frame(flag_card, style="Card.TFrame")
    action_row.grid(row=1, column=0, sticky="ew", pady=(0, 10))
    ttk.Button(action_row, text="Submit now", style="Accent.TButton", command=submit_now).pack(side="left")
    ttk.Button(action_row, text="Flush inbox", command=flush_inbox).pack(side="left", padx=(6, 0))
    ttk.Label(action_row, text="Ctrl+Enter submits", style="CardMuted.TLabel").pack(
        side="right", padx=(12, 0))
    sub_btn = ttk.Button(action_row, text="Start background submitter")
    sub_btn.pack(side="left", padx=(6, 0))

    for seq in ("<Control-Return>", "<Command-Return>"):
        flags_text.bind(seq, lambda _e: (submit_now(), "break")[1])

    # ---------- tab: mass exploit ----------
    tab2 = ttk.Frame(nb, padding=12)
    nb.add(tab2, text="Mass exploit")
    tab2.columnconfigure(0, weight=1)
    tab2.columnconfigure(1, weight=1)
    tab2.rowconfigure(0, weight=1)
    target_card = ttk.LabelFrame(tab2, text="Targets", padding=12)
    target_card.grid(row=0, column=0, sticky="nsew", padx=(0, 5), pady=(0, 10))
    target_card.columnconfigure(0, weight=1)
    target_card.columnconfigure(1, weight=1)
    target_card.rowconfigure(1, weight=1, minsize=115)

    ttk.Label(target_card, text="Teams · name IP · ! marks own",
              style="Card.TLabel", wraplength=240).grid(row=0, column=0, sticky="w")
    ttk.Label(target_card, text="Services · name port", style="Card.TLabel").grid(
        row=0, column=1, sticky="w", padx=(10, 0))

    teams_text = scrolledtext.ScrolledText(target_card, height=5, wrap="none", font=mono, width=30)
    teams_text.grid(row=1, column=0, sticky="nsew", pady=2)
    style_text(teams_text)
    teams_text.insert("1.0", dump_teams(cfg.get("teams", [])))
    own_ip_var = tk.StringVar(value=cfg.get("own_ip") or "")
    team_actions = ttk.Frame(target_card, style="Card.TFrame")
    team_actions.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(6, 0))
    ttk.Label(team_actions, text="Own VPN IP", style="Card.TLabel").pack(side="left")
    ttk.Entry(team_actions, textvariable=own_ip_var, width=15).pack(side="left", padx=(6, 10))
    sync_btn = ttk.Button(team_actions, text="Sync teams from API")
    sync_btn.pack(side="left")
    services_text = scrolledtext.ScrolledText(target_card, height=5, wrap="none", font=mono, width=30)
    services_text.grid(row=1, column=1, sticky="nsew", padx=(10, 0), pady=2)
    style_text(services_text)
    services_text.insert("1.0", dump_services(cfg.get("services", [])))

    exploit_card = ttk.LabelFrame(tab2, text="Exploit commands", padding=12)
    exploit_card.grid(row=0, column=1, sticky="nsew", padx=(5, 0), pady=(0, 10))
    exploit_card.columnconfigure(0, weight=1)
    exploit_card.rowconfigure(1, weight=1, minsize=115)
    ttk.Label(exploit_card, text="One per line: service = command · {ip} {port} {team} {url} supported",
              style="Card.TLabel", wraplength=375).grid(row=0, column=0, sticky="w")
    exploit_text = scrolledtext.ScrolledText(exploit_card, height=5, wrap="none", font=mono, width=30)
    exploit_text.grid(row=1, column=0, sticky="nsew", pady=2)
    style_text(exploit_text)
    exploit_text.insert("1.0", dump_exploits(cfg.get("exploits", {})))

    ttk.Label(
        exploit_card, text="Example: web = python3 exploits/web.py {url} · Print flags to stdout",
        style="CardMuted.TLabel", wraplength=375, justify="left",
    ).grid(row=2, column=0, sticky="w", pady=(5, 0))

    mass_var = tk.StringVar()
    runner_card = ttk.LabelFrame(tab2, text="Runner", padding=12)
    runner_card.grid(row=1, column=0, columnspan=2, sticky="ew")
    ttk.Label(runner_card, textvariable=mass_var, style="CardMuted.TLabel").grid(
        row=0, column=0, sticky="w")

    def refresh_mass_counts():
        mass_var.set(f"{len(cfg.get('teams', []))} teams · "
                     f"{len(cfg.get('services', []))} services · "
                     f"{len(cfg.get('exploits', {}))} exploits configured")

    refresh_mass_counts()

    ctl = ttk.Frame(runner_card, style="Card.TFrame")
    ctl.grid(row=1, column=0, sticky="w", pady=(9, 0))
    conc_var = tk.IntVar(value=int(cfg.get("concurrency", 8)))
    cto_var = tk.IntVar(value=int(cfg.get("exploit_timeout", 20)))
    eint_var = tk.IntVar(value=int(cfg.get("exploit_interval", 180)))

    ttk.Label(ctl, text="Concurrency", style="Card.TLabel").pack(side="left")
    ttk.Spinbox(ctl, from_=1, to=64, width=5, textvariable=conc_var).pack(side="left", padx=(2, 14))
    ttk.Label(ctl, text="Timeout (s)", style="Card.TLabel").pack(side="left")
    ttk.Spinbox(ctl, from_=1, to=600, width=5, textvariable=cto_var).pack(side="left", padx=(2, 14))
    ttk.Label(ctl, text="Auto every (s)", style="Card.TLabel").pack(side="left")
    ttk.Spinbox(ctl, from_=10, to=3600, width=6, textvariable=eint_var).pack(side="left", padx=(2, 0))

    act = ttk.Frame(runner_card, style="Card.TFrame")
    act.grid(row=2, column=0, sticky="w", pady=(10, 0))

    def save_exploit():
        save_fields()
        cfg["teams"] = parse_teams(teams_text.get("1.0", "end"))
        cfg["own_ip"] = own_ip_var.get().strip()
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

    def sync_teams():
        save_fields()
        cfg["own_ip"] = own_ip_var.get().strip()
        sync_btn.config(state="disabled")

        def work():
            try:
                teams = fetch_teams(cfg, auth)
            except Exception as e:
                log(f"team sync failed: {e}")
                root.after(0, lambda: sync_btn.config(state="normal"))
                return

            def apply():
                cfg["teams"] = teams
                save_cfg(cfg)
                teams_text.delete("1.0", "end")
                teams_text.insert("1.0", dump_teams(teams))
                refresh_mass_counts()
                sync_btn.config(state="normal")
                log(f"team sync: {len(teams) - 1} opponents + own team")

            root.after(0, apply)

        threading.Thread(target=work, daemon=True).start()

    sync_btn.config(command=sync_teams)

    def run_now():
        save_exploit()
        threading.Thread(target=lambda: run_all(cfg, auth, log), daemon=True).start()

    ttk.Button(act, text="Save", command=save_exploit).pack(side="left", padx=(0, 6))
    ttk.Button(act, text="Run all now", style="Accent.TButton", command=run_now).pack(side="left", padx=(0, 6))
    exploit_btn = ttk.Button(act, text="Start auto exploit")
    exploit_btn.pack(side="left")
    exploit_btn.config(command=lambda: toggle_loop("exploit", exploit_btn,
                                                   "Start auto exploit", "Stop auto exploit"))
    ttk.Label(runner_card,
              text="Connect WireGuard first. Use each service port from Challenges; "
                   "180 s repeats every round and submits flags as they arrive.",
              style="CardMuted.TLabel", wraplength=800).grid(
                  row=3, column=0, sticky="w", pady=(8, 0))

    # ---------- tab: tools (ataka / yampa / tulip) ----------
    tab3 = ttk.Frame(nb, padding=12)
    nb.add(tab3, text="Tools")
    tab3.columnconfigure(0, weight=1)
    tab3.rowconfigure(1, weight=1)
    ttk.Label(tab3, text="External tools", style="Title.TLabel").grid(
        row=0, column=0, sticky="w", pady=(0, 8))
    tool_nb = ttk.Notebook(tab3)
    tool_nb.grid(row=1, column=0, sticky="nsew")
    tool_canvases = []

    def on_wheel(e):
        w = root.winfo_containing(e.x_root, e.y_root)
        if isinstance(w, tk.Text):
            return
        p = w
        while p is not None and p is not settings_canvas and p not in tool_canvases:
            p = p.master
        if p is not settings_canvas and p not in tool_canvases:
            return
        if getattr(e, "num", None) == 4:
            p.yview_scroll(-1, "units")
        elif getattr(e, "num", None) == 5:
            p.yview_scroll(1, "units")
        else:
            p.yview_scroll(-1 if getattr(e, "delta", 0) > 0 else 1, "units")

    root.bind_all("<MouseWheel>", on_wheel)
    root.bind_all("<Button-4>", on_wheel)
    root.bind_all("<Button-5>", on_wheel)
    for idx, key in enumerate(("1", "2", "3")):
        root.bind(f"<Control-Key-{key}>", lambda _e, i=idx: nb.select(i))

    tool_status = {}
    tool_vars = {}
    tool_feedback = {}

    def tool_save(name):
        tv, cv = tool_vars[name]
        t = cfg.setdefault("tools", {}).setdefault(name, {})
        for k, var in tv.items():
            t[k] = var.get().strip()
        t["catch"] = bool(cv.get())
        save_cfg(cfg)
        return t

    def open_guide(name):
        win = tk.Toplevel(root)
        win.title(f"{name.capitalize()} - guide")
        win.geometry("760x560")
        win.transient(root)
        frame = ttk.Frame(win, padding=12)
        frame.pack(fill="both", expand=True)
        bar = ttk.Frame(frame)
        bar.pack(side="bottom", fill="x", pady=(8, 0))
        ttk.Button(bar, text="Close", command=win.destroy).pack(side="right")
        txt = scrolledtext.ScrolledText(frame, wrap="word", font=mono)
        txt.pack(fill="both", expand=True)
        style_text(txt)
        txt.insert("1.0", TOOL_GUIDES.get(name, "No guide for this tool."))
        txt.configure(state="disabled")
        txt.focus_set()

    for i, name in enumerate(cfg.get("tools", {}).keys()):
        t = cfg["tools"][name]
        page = ttk.Frame(tool_nb)
        tool_nb.add(page, text=name.capitalize())
        page.columnconfigure(0, weight=1)
        page.rowconfigure(0, weight=1)
        tool_canvas = tk.Canvas(page, highlightthickness=0, borderwidth=0, background=bg)
        tool_scroll = ttk.Scrollbar(page, orient="vertical", command=tool_canvas.yview)
        tool_canvas.configure(yscrollcommand=tool_scroll.set)
        tool_canvas.grid(row=0, column=0, sticky="nsew")
        tool_scroll.grid(row=0, column=1, sticky="ns")
        tool_canvases.append(tool_canvas)
        tool_inner = ttk.Frame(tool_canvas, padding=12)
        tool_inner.columnconfigure(0, weight=1)
        tool_win = tool_canvas.create_window((0, 0), window=tool_inner, anchor="nw")
        tool_inner.bind("<Configure>", lambda _e, c=tool_canvas: c.configure(
            scrollregion=c.bbox("all")))
        tool_canvas.bind("<Configure>", lambda e, c=tool_canvas, w=tool_win: c.itemconfigure(
            w, width=e.width))
        summary = {
            "ataka": "Run exploits through the Ataka player CLI.",
            "yampa": "Manage the Yampa traffic proxy with Docker Compose.",
            "tulip": "Run the Tulip traffic analysis dashboard.",
        }.get(name, "Configure and run this external tool.")
        ttk.Label(tool_inner, text=summary, style="Muted.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 10))
        lf = ttk.LabelFrame(tool_inner, text=f"{name.capitalize()} configuration", padding=12)
        lf.grid(row=1, column=0, sticky="ew")
        lf.columnconfigure(1, weight=1)

        tv = {k: tk.StringVar(value=t.get(k, "")) for k in ("dir", "start", "stop", "extra", "url")}
        cv = tk.BooleanVar(value=bool(t.get("catch")))
        tool_vars[name] = (tv, cv)

        def add_row(r, label, key, tv=tv, lf=lf):
            ttk.Label(lf, text=label, style="Card.TLabel").grid(
                row=r, column=0, sticky="w", padx=(0, 10), pady=3)
            ttk.Entry(lf, textvariable=tv[key]).grid(row=r, column=1, sticky="ew", pady=3)

        add_row(0, "Working directory", "dir")
        add_row(1, "Start command", "start")
        add_row(2, "Stop command", "stop")
        add_row(3, "Extra command", "extra")
        add_row(4, "Web UI URL", "url")

        def choose_dir(n=name, tv=tv):
            cur = tv["dir"].get().strip() or os.path.expanduser("~")
            path = filedialog.askdirectory(initialdir=cur, title=f"{n} directory")
            if path:
                tv["dir"].set(path)
                tool_save(n)

        ttk.Button(lf, text="Browse…", command=choose_dir).grid(
            row=0, column=2, sticky="w", padx=(8, 0))

        feedback = ttk.Label(lf, text="Edit settings, then Save or Check setup",
                             style="CardMuted.TLabel")
        feedback.grid(row=5, column=0, columnspan=2, sticky="w", pady=(9, 0))
        tool_feedback[name] = feedback

        def report_issues(n, action):
            issues = tool_config_issues(n, tool_save(n), action)
            label = tool_feedback[n]
            if issues:
                message = "; ".join(issues)
                label.config(text=message, foreground=warn)
                log(f"[{n}] setup: {message}")
                return False
            label.config(text="Setup looks ready", foreground=good)
            return True

        def run_tool_action(n, action):
            if not report_issues(n, action):
                return
            if action == "start":
                tools_mgr.start(n)
            elif action == "stop":
                tools_mgr.stop(n)
            elif action == "extra":
                tools_mgr.run_once(n)

        btns = ttk.Frame(lf, style="Card.TFrame")
        btns.grid(row=1, column=2, rowspan=4, sticky="nsew", padx=(12, 0))
        for col in range(2):
            btns.columnconfigure(col, weight=1)

        def mk(parent, label, fn, row, col, primary=False):
            ttk.Button(parent, text=label, command=fn,
                       style="Accent.TButton" if primary else "TButton").grid(
                           row=row, column=col, sticky="ew", padx=(0, 6), pady=(0, 6))

        mk(btns, "Start", lambda n=name: run_tool_action(n, "start"), 0, 0, primary=True)
        mk(btns, "Stop", lambda n=name: run_tool_action(n, "stop"), 0, 1)
        mk(btns, "Run extra", lambda n=name: run_tool_action(n, "extra"), 1, 0)
        mk(btns, "Save", lambda n=name: (tool_save(n),
                                         tool_feedback[n].config(text="Settings saved", foreground=good)), 2, 0)
        mk(btns, "Check setup", lambda n=name: report_issues(n, "check"), 2, 1)
        mk(btns, "Guide", lambda n=name: open_guide(n), 3, 0)

        def open_url(n=name):
            if not report_issues(n, "url"):
                return
            url = cfg["tools"][n]["url"]
            import webbrowser
            log(f"[{n}] opening {url}")
            webbrowser.open(url)

        mk(btns, "Open UI", open_url, 1, 1)

        foot = ttk.Frame(lf, style="Card.TFrame")
        foot.grid(row=5, column=2, sticky="e", padx=(12, 0))
        ttk.Checkbutton(foot, text="catch flags", variable=cv,
                        style="Card.TCheckbutton",
                        command=lambda n=name: tool_save(n)).pack(side="top", anchor="e")
        lbl = ttk.Label(foot, text="● Stopped", style="CardMuted.TLabel")
        lbl.pack(side="top", anchor="e", pady=(6, 0))
        tool_status[name] = lbl

    # ---------- shared log ----------
    log_frame = ttk.LabelFrame(paned, text="Activity", padding=10)
    log_frame.columnconfigure(0, weight=1)
    log_frame.rowconfigure(1, weight=1)
    try:
        paned.add(log_frame, weight=1)
    except tk.TclError:
        paned.add(log_frame)

    log_head = ttk.Frame(log_frame, style="Card.TFrame")
    log_head.grid(row=0, column=0, sticky="ew")
    log_head.columnconfigure(1, weight=1)
    ttk.Label(log_head, text="Latest submission and tool output", style="CardMuted.TLabel").grid(
        row=0, column=0, sticky="w")
    autoscroll = tk.BooleanVar(value=True)

    def clear_log():
        logbox.configure(state="normal")
        logbox.delete("1.0", "end")
        logbox.configure(state="disabled")

    ttk.Button(log_head, text="Clear", command=clear_log).grid(row=0, column=1, sticky="e")
    ttk.Checkbutton(log_head, text="auto-scroll", variable=autoscroll).grid(
        row=0, column=2, sticky="e", padx=(8, 0))

    logbox = scrolledtext.ScrolledText(log_frame, height=5, state="disabled",
                                       wrap="word", font=mono, width=30)
    logbox.grid(row=1, column=0, sticky="nsew")
    style_text(logbox)
    logbox.tag_configure("time", foreground=muted)
    logbox.tag_configure("success", foreground=good)
    logbox.tag_configure("warning", foreground=warn)

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
    status_bar = ttk.Frame(outer, padding=(12, 9), style="Card.TFrame")
    status_bar.grid(row=2, column=0, sticky="ew", pady=(8, 0))
    status_bar.columnconfigure(2, weight=1)
    state = {
        "token": ttk.Label(status_bar, text="token: none", style="Card.TLabel", foreground=warn),
        "inbox": ttk.Label(status_bar, text="inbox: 0", style="Card.TLabel"),
        "loops": ttk.Label(status_bar,
                           text="submitter: off · exploit loop: off · tools up: 0",
                           style="Card.TLabel"),
    }
    state["token"].grid(row=0, column=0, sticky="w")
    ttk.Separator(status_bar, orient="vertical").grid(row=0, column=1, sticky="ns", padx=8)
    state["inbox"].grid(row=0, column=2, sticky="w")
    state["loops"].grid(row=0, column=3, sticky="e")

    def append_log(msg):
        logbox.configure(state="normal")
        logbox.insert("end", time.strftime("%H:%M:%S") + "  ", "time")
        lower = msg.lower()
        tag = "warning" if any(word in lower for word in ("failed", "error", "invalid", "rejected")) else (
            "success" if any(word in lower for word in ("accepted", "saved", "login ok")) else None)
        if tag:
            logbox.insert("end", msg + "\n", tag)
        else:
            logbox.insert("end", msg + "\n")
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
            color = good if s.startswith("running") else warn if s.startswith("exited") else muted
            lbl.config(text=f"● {s.capitalize()}", foreground=color)

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
                              foreground=good if token_txt != "token: none" else warn)
        state["inbox"].config(text=f"inbox: {scan['n']}")
        running_tools = sum(1 for n in tool_status if tools_mgr.running(n))
        active_loops = sum(w.is_alive() and not w.stop.is_set() for w in loops.values())
        headline_status.config(text=f"{active_loops} automation(s) active  ·  {running_tools} tool(s) running",
                               foreground=good if active_loops or running_tools else muted)
        state["loops"].config(
            text=f"submitter: {'on' if 'submit' in loops and loops['submit'].is_alive() and not loops['submit'].stop.is_set() else 'off'} · "
                 f"exploit loop: {'on' if 'exploit' in loops and loops['exploit'].is_alive() and not loops['exploit'].stop.is_set() else 'off'} · "
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
            frac = float(cfg.get("sash") or 0.82)
            hi = max(430, h - 100)
            paned.sashpos(0, max(380, min(int(h * frac), hi)))
        except (tk.TclError, ValueError):
            pass

    if os.environ.get("FLAGR_GUI_TAB"):
        try:
            initial_tab = int(os.environ["FLAGR_GUI_TAB"])
            if 0 <= initial_tab < nb.index("end"):
                root.after(100, lambda: nb.select(initial_tab))
        except ValueError:
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
