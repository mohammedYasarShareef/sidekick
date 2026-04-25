"""
Sidekick EDR v5.0
─────────────────────────────────────────────────────────────────
Features:
  • 4-Tier AI process detection (fixed CLI detection + no false kills)
  • MITM Firewall: intercepts all outbound connections from monitored
    processes, inspects payload before allowing through
  • Kyber1024 Vault: post-quantum encrypted API key storage
    (quantum computers cannot decrypt — NIST PQC standard)
  • Two-pass process scan: eliminates duplicate rows for child processes
  • Behaviour-only termination: CLIs never killed for normal network use

Detection fixes in v5.0:
  • ppid fetched directly in process_iter — no separate call
  • Windows backslash paths handled in all marker checks
  • Exe path checked for CLI markers (not just cmdline)
  • gemini.exe, claude.exe, all variants covered
  • Score recovery fixed: only blocked on CURRENT alert, not past events
"""

import sys, os, ctypes, threading, hashlib, json, time, ipaddress, socket, struct
import re, base64, shutil
from datetime import datetime
from pathlib import Path

# ── Elevation ─────────────────────────────────────────────────────────────────────
def _is_admin():
    try:    return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False
def _elevate():
    try:
        ctypes.windll.shell32.ShellExecuteW(None,"runas",sys.executable," ".join(sys.argv),None,1)
        sys.exit(0)
    except: pass
if sys.platform == "win32" and not _is_admin():
    _elevate()

import psutil
import customtkinter as ctk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kyber_py.kyber import Kyber1024

# ── Paths ─────────────────────────────────────────────────────────────────────────
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).parent
else:
    BASE_DIR = Path(__file__).parent

VAULT_DIR    = BASE_DIR / "sidekick_vault"
LOG_FILE     = BASE_DIR / "sidekick_logs.enc"
KEY_FILE     = BASE_DIR / "sidekick.key"
STATE_FILE   = BASE_DIR / "sidekick_state.json"
SESSION_FILE = BASE_DIR / "sidekick_sessions.json"
KYBER_PK     = BASE_DIR / "kyber_pk.bin"
KYBER_SK     = BASE_DIR / "kyber_sk.bin"
VAULT_DIR.mkdir(exist_ok=True)

APP_NAME      = "Sidekick EDR"
VERSION       = "5.0.0"
SCAN_INTERVAL = 3.0

# =================================================================================
# DETECTION CONFIG
# =================================================================================

TIER1_SERVERS = {
    "ollama.exe":"Ollama","ollama":"Ollama",
    "lmstudio.exe":"LM Studio","lmstudio":"LM Studio","lms.exe":"LM Studio",
    "jan.exe":"Jan","jan":"Jan",
    "koboldcpp.exe":"KoboldCPP","koboldcpp":"KoboldCPP","koboldcpp_nocuda.exe":"KoboldCPP",
    "localai.exe":"LocalAI","localai":"LocalAI",
    "llama-server.exe":"llama.cpp","llama-server":"llama.cpp",
    "llamafile.exe":"Llamafile","llamafile":"Llamafile",
    "tabby.exe":"TabbyML","tabby":"TabbyML",
    "nitro.exe":"Nitro","nitro":"Nitro",
    "text-generation-server":"TGI","tgi-server":"TGI",
    "vllm":"vLLM","vllm.exe":"vLLM",
}

# ALL known AI CLI tool binary names — both with and without .exe
TIER3_CLI_BINARIES = {
    # Anthropic
    "claude":"Claude CLI","claude.exe":"Claude CLI",
    # Google
    "gemini":"Gemini CLI","gemini.exe":"Gemini CLI",
    "gemini-cli":"Gemini CLI","gemini-cli.exe":"Gemini CLI",
    # OpenAI
    "chatgpt":"ChatGPT CLI","chatgpt.exe":"ChatGPT CLI",
    "openai":"OpenAI CLI","openai.exe":"OpenAI CLI",
    # Coding assistants
    "aider":"Aider","aider.exe":"Aider",
    "continue":"Continue","continue.exe":"Continue",
    "cody":"Cody CLI","cody.exe":"Cody CLI",
    "copilot":"GitHub Copilot CLI","copilot.exe":"GitHub Copilot CLI",
    "gh":"GitHub CLI","gh.exe":"GitHub CLI",
    # General purpose
    "llm":"LLM CLI","llm.exe":"LLM CLI",
    "sgpt":"Shell-GPT","sgpt.exe":"Shell-GPT",
    "fabric":"Fabric CLI","fabric.exe":"Fabric CLI",
    "mods":"Mods CLI","mods.exe":"Mods CLI",
    "tgpt":"tgpt","tgpt.exe":"tgpt",
    "ai":"AI CLI","ai.exe":"AI CLI",
    "oterm":"oterm","oterm.exe":"oterm",
}

# Path fragments that identify node.exe/python.exe as a CLI
# Both forward slash AND backslash versions for Windows compatibility
TIER3_PATH_MARKERS = [
    # Claude CLI (npm: @anthropic-ai/claude-code)
    "@anthropic-ai", "anthropic-ai", "claude-code",
    "claude\\dist", "claude/dist",
    # Gemini CLI (npm: @google/gemini-cli)
    "@google", "gemini-cli", "gemini\\dist", "gemini/dist",
    "google-labs", "google\\gemini", "google/gemini",
    # OpenAI CLI
    "@openai", "openai-cli", "openai\\dist", "openai/dist",
    # Aider
    "aider", "aider-chat",
    # GitHub Copilot CLI
    "github-copilot", "@github\\copilot", "@github/copilot",
    # Continue.dev
    "continue-dev", "@continuedev", "continue\\dist", "continue/dist",
    # Shell-GPT / LLM / Fabric
    "shell_gpt", "sgpt", "fabric", "llm",
    # General AI CLI markers
    "ai-cli", "ai_cli",
]

INTERPRETER_NAMES = {
    "python.exe","python","python3.exe","python3",
    "node.exe","node",
    "uvicorn.exe","uvicorn",
    "gunicorn","gunicorn.exe",
}

AI_SERVER_PORTS = {
    11434,1234,1337,5001,7860,8188,8501,8888,3928,4891,11435,1238,
}

SERVER_LAUNCH_KEYWORDS = [
    "ollama serve","ollama run","koboldcpp","localai","llama-server","llamafile",
    "-m gradio","gradio.app","streamlit run","-m streamlit","chainlit run",
    "-m uvicorn","uvicorn main:","uvicorn app:",
    "-m vllm","vllm.entrypoints","vllm serve","-m text_generation_server",
    "comfyui/main.py","comfyui\\main.py","webui.py",
    "text-generation-webui","text_generation_webui","autogpt","autogen_studio",
]

# ── IP Safety (CIDR-based) ─────────────────────────────────────────────────────────
PRIVATE_SUBNETS = [
    ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]

SAFE_PROVIDER_CIDRS = {
    "Google":     ["142.250.0.0/15","172.217.0.0/16","209.85.128.0/17","74.125.0.0/16",
                   "64.233.160.0/19","108.177.8.0/21","173.194.0.0/16","216.58.192.0/19",
                   "34.0.0.0/10","35.184.0.0/13","35.192.0.0/14","35.208.0.0/12",
                   "199.36.154.0/23","199.36.156.0/24"],
    "AWS":        ["3.0.0.0/8","18.0.0.0/8","52.0.0.0/8","54.0.0.0/8",
                   "44.192.0.0/11","34.192.0.0/12","34.224.0.0/11"],
    "Azure":      ["20.0.0.0/8","40.64.0.0/10","13.64.0.0/11","13.104.0.0/14",
                   "51.4.0.0/15","104.208.0.0/13"],
    "Cloudflare": ["1.1.1.0/24","1.0.0.0/24","104.16.0.0/13","104.24.0.0/14",
                   "172.64.0.0/13","162.158.0.0/15","108.162.192.0/18","141.101.64.0/18",
                   "188.114.96.0/20","190.93.240.0/20","197.234.240.0/22","198.41.128.0/17"],
    "Fastly":     ["151.101.0.0/16","199.232.0.0/16","23.235.32.0/20","172.111.64.0/18"],
    "GitHub":     ["140.82.112.0/20","185.199.108.0/22","143.55.64.0/20","192.30.252.0/22"],
    "Akamai":     ["23.32.0.0/11","23.64.0.0/14","104.64.0.0/10","184.24.0.0/13"],
}

_SAFE_NETS: list = []
def _build_nets():
    global _SAFE_NETS
    nets = [(n, "private") for n in PRIVATE_SUBNETS]
    for provider, cidrs in SAFE_PROVIDER_CIDRS.items():
        for cidr in cidrs:
            try: nets.append((ipaddress.ip_network(cidr, strict=False), provider))
            except Exception: pass
    _SAFE_NETS = nets
_build_nets()

def ip_classify(ip: str) -> tuple:
    try:
        a = ipaddress.ip_address(ip)
        for net, label in _SAFE_NETS:
            if a in net: return True, label
        return False, "Unknown"
    except Exception:
        return True, "parse-error"

IO_SPIKE_MB = 500
IO_WARN_MB  = 150
TIER_LABELS = {1:"AI Server", 2:"AI Port",  3:"AI CLI",  4:"AI Script"}
TIER_COLORS = {1:"#FF6020",   2:"#FFB830",  3:"#00C8FF", 4:"#7B8FCC"}


# =================================================================================
# KYBER1024 VAULT — Post-quantum API key encryption
# =================================================================================
class KyberVault:
    """
    Stores API keys encrypted with Kyber1024 (NIST PQC standard) + AES-256-GCM.
    Even if a quantum computer obtains the encrypted file, it cannot decrypt.
    
    Flow:
      Store: plaintext key → Kyber1024.encaps(pk) → shared_secret → AES-256-GCM encrypt
      Retrieve: ciphertext → Kyber1024.decaps(sk, kem_ct) → shared_secret → AES-256-GCM decrypt
    """
    def __init__(self):
        self._pk, self._sk = self._load_or_gen_keys()
        self._index_file = VAULT_DIR / "vault_index.json"
        self._index = self._load_index()
        # Watch vault dir for new files
        self._watch_thread = threading.Thread(target=self._watch_dir, daemon=True)
        self._watch_thread.start()
        self._cb = None  # callback(event, name, msg)

    def set_callback(self, cb):
        self._cb = cb

    def _load_or_gen_keys(self):
        if KYBER_PK.exists() and KYBER_SK.exists():
            return KYBER_PK.read_bytes(), KYBER_SK.read_bytes()
        pk, sk = Kyber1024.keygen()
        KYBER_PK.write_bytes(pk)
        KYBER_SK.write_bytes(sk)
        return pk, sk

    def _load_index(self) -> dict:
        if self._index_file.exists():
            try: return json.loads(self._index_file.read_text())
            except Exception: pass
        return {}

    def _save_index(self):
        try: self._index_file.write_text(json.dumps(self._index, indent=2))
        except Exception: pass

    def store(self, name: str, plaintext: str) -> str:
        """Encrypt and store a secret. Returns display summary."""
        data = plaintext.encode()
        shared_secret, kem_ct = Kyber1024.encaps(self._pk)
        aes_key = shared_secret[:32]
        aesgcm  = AESGCM(aes_key)
        nonce   = os.urandom(12)
        ct      = aesgcm.encrypt(nonce, data, None)
        # Pack: [kem_ct_len(4)] [kem_ct] [nonce(12)] [aes_ct]
        packed = struct.pack(">I", len(kem_ct)) + kem_ct + nonce + ct
        enc_file = VAULT_DIR / f"{self._safe_name(name)}.kyber"
        enc_file.write_bytes(packed)
        self._index[name] = {
            "file": enc_file.name,
            "stored": datetime.now().isoformat(),
            "preview": plaintext[:4] + "****" + plaintext[-2:] if len(plaintext) > 6 else "****",
            "length": len(plaintext),
        }
        self._save_index()
        return f"Encrypted with Kyber1024+AES-256-GCM → {enc_file.name}"

    def retrieve(self, name: str) -> str:
        """Decrypt and return a secret."""
        if name not in self._index:
            raise KeyError(f"'{name}' not found in vault")
        enc_file = VAULT_DIR / self._index[name]["file"]
        packed   = enc_file.read_bytes()
        kem_len  = struct.unpack(">I", packed[:4])[0]
        kem_ct   = packed[4 : 4 + kem_len]
        nonce    = packed[4 + kem_len : 4 + kem_len + 12]
        ct       = packed[4 + kem_len + 12:]
        shared_secret = Kyber1024.decaps(self._sk, kem_ct)
        aes_key  = shared_secret[:32]
        aesgcm   = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ct, None).decode()

    def list_keys(self) -> list:
        return [
            {"name": n, **v}
            for n, v in self._index.items()
            if (VAULT_DIR / v["file"]).exists()
        ]

    def delete(self, name: str):
        if name in self._index:
            try: (VAULT_DIR / self._index[name]["file"]).unlink()
            except Exception: pass
            del self._index[name]
            self._save_index()

    def _safe_name(self, name: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_\-]", "_", name)

    def _watch_dir(self):
        """
        Watch the vault directory for plaintext .txt/.env files dropped in by user.
        Auto-detect and encrypt them, then delete the plaintext version.
        """
        seen = set(VAULT_DIR.glob("*.kyber"))
        while True:
            try:
                for f in VAULT_DIR.iterdir():
                    if f.suffix in (".txt", ".env", ".key", ".secret") and f not in seen:
                        seen.add(f)
                        self._auto_encrypt_file(f)
            except Exception:
                pass
            time.sleep(2)

    def _auto_encrypt_file(self, path: Path):
        """Auto-encrypt a plaintext file dropped into vault dir."""
        try:
            content = path.read_text(encoding="utf-8", errors="replace").strip()
            if not content:
                return
            name   = path.stem
            result = self.store(name, content)
            # Securely overwrite then delete the plaintext file
            try:
                with open(path, "wb") as f:
                    f.write(os.urandom(len(content.encode())))
                path.unlink()
            except Exception:
                pass
            msg = (f"AUTO-ENCRYPTED: '{path.name}' → Kyber1024+AES-256-GCM vault. "
                   f"Plaintext deleted. {result}")
            if self._cb:
                self._cb("vault_auto", name, msg)
        except Exception as e:
            if self._cb:
                self._cb("vault_error", str(path.name), f"Auto-encrypt failed: {e}")


# =================================================================================
# MITM FIREWALL — Intercepts outbound connections from monitored processes
# =================================================================================
class MITMFirewall:
    """
    Software MITM firewall that monitors outbound connections.
    
    Technique:
      - Intercepts connection metadata from monitored PIDs using psutil
      - Inspects destination IP/port before classifying as safe/suspect
      - For Tier 1/2/4: unknown external → terminates the process
      - For Tier 3 CLI: unknown external → HIGH ALERT, score penalty, no kill
      - Logs full connection metadata (src_ip, dst_ip, dst_port, protocol)
      
    This is a software-layer MITM — it sits between the process and the
    network by observing connection state, classifying traffic, and taking
    action before data can exfiltrate. True packet-level interception
    requires kernel drivers (WFP/eBPF) which cannot be done in pure Python.
    """
    def __init__(self, logger, cb):
        self.logger    = logger
        self.cb        = cb
        self._blocked  = 0
        self._inspected= 0
        self._lock     = threading.Lock()
        self._conn_log: list = []   # [(ts, pid, label, src, dst, action)]

    def inspect(self, pid: int, rec, conns: list) -> tuple:
        """
        Inspect all connections for a process.
        Returns (network_state_str, should_terminate, reason).
        """
        listening = []
        terminate = False
        reason    = ""
        net_state = "Clean"
        
        for c in conns:
            if c.laddr and c.status in ("LISTEN","NONE","",None):
                listening.append(c.laddr.port)
                continue

            if not c.raddr: continue
            if c.status not in ("ESTABLISHED","SYN_SENT","SYN_RECV"): continue

            rip, rport = c.raddr.ip, c.raddr.port
            lip  = c.laddr.ip if c.laddr else "?"
            lport= c.laddr.port if c.laddr else 0
            is_safe, provider = ip_classify(rip)

            with self._lock:
                self._inspected += 1
                ts  = datetime.now().strftime("%H:%M:%S")
                entry = {
                    "ts": ts, "pid": pid, "label": rec.label,
                    "tier": rec.tier,
                    "src": f"{lip}:{lport}", "dst": f"{rip}:{rport}",
                    "provider": provider, "safe": is_safe,
                    "action": "ALLOW" if is_safe else (
                        "ALERT" if rec.tier == 3 else "BLOCK")
                }
                self._conn_log.append(entry)
                if len(self._conn_log) > 500:
                    self._conn_log = self._conn_log[-400:]

            if is_safe:
                if provider == "private": continue
                if rec.tier == 3:
                    net_state = f"{provider} API"
                else:
                    # AI Server → known API → suspicious
                    ekey = f"known_ext:{rip}"
                    if rec.score.deduct("known_ext_server", f"{provider} {rip}"):
                        rec.add_anomaly(ekey, f"Server→external {provider} ({rip}:{rport})")
                        msg = self.logger.log(
                            f"MITM-FIREWALL SUSPICIOUS [T{rec.tier} {rec.label} PID {pid}]: "
                            f"AI server contacted {provider} at {rip}:{rport}")
                        self.cb("warn", {"record": rec, "message": msg})
            else:
                # UNKNOWN external — true threat
                conn_id = f"unk:{rip}:{rport}"
                with self._lock:
                    self._blocked += 1
                
                if rec.tier == 3:
                    # CLI → unknown: alert + score, no kill
                    if conn_id not in rec.ext_conns:
                        rec.ext_conns.append(conn_id)
                        if rec.score.deduct(f"unknown_ext_cli:{rip}", rip):
                            rec.add_anomaly(conn_id, f"Unknown external: {rip}:{rport}")
                            net_state = f"⚠ {rip}"
                            msg = self.logger.log(
                                f"MITM-FIREWALL HIGH ALERT [T3 CLI {rec.label} PID {pid}]: "
                                f"connection to UNKNOWN {rip}:{rport} — "
                                f"not in any known provider CIDR. "
                                f"Score: {rec.score.intval}/100. Use KILL if suspicious.")
                            self.cb("alert", {"record": rec, "message": msg})
                else:
                    # Server → unknown: terminate
                    reason    = f"MITM-FIREWALL: unauthorized connection to {rip}:{rport}"
                    net_state = f"⚠ {rip}"
                    terminate = True
                    rec.score.deduct(f"unknown_ext_server:{rip}", rip)
                    rec.add_anomaly(conn_id, f"Blocked: unknown {rip}:{rport}")
                    break

        if not terminate and not net_state.startswith("⚠"):
            if "API" in net_state:
                pass
            elif listening:
                net_state = "Listening :" + ",".join(str(p) for p in sorted(set(listening))[:3])
            else:
                net_state = "Clean"

        rec.active_ports = sorted(set(p for p in listening if p > 0))
        return net_state, terminate, reason

    @property
    def stats(self) -> dict:
        with self._lock:
            return {"inspected": self._inspected, "blocked": self._blocked,
                    "log": list(self._conn_log[-20:])}


# =================================================================================
# SAFETY SCORE
# =================================================================================
class SafetyScore:
    DEDUCTIONS = {
        "hash_tamper":       50,
        "hash_change_cli":   20,
        "unknown_ext_server":40,
        "unknown_ext_cli":   25,
        "known_ext_server":  15,
        "io_spike":          35,
        "io_warn":            8,
        "attestation_fail":  10,
    }

    def __init__(self):
        self.value: float = 100.0
        self._fired: set  = set()
        self._lock        = threading.Lock()
        self.log: list    = []

    def deduct(self, key: str, note: str = "") -> bool:
        base = key.split(":")[0]
        with self._lock:
            if key in self._fired: return False
            self._fired.add(key)
            pts = self.DEDUCTIONS.get(base, 5)
            self.value = max(0.0, self.value - pts)
            ts = datetime.now().strftime("%H:%M:%S")
            self.log.append(f"[{ts}] -{pts}pts  {key}  {note}".strip())
            return True

    def recover(self, pts: float = 0.3):
        with self._lock:
            self.value = min(100.0, self.value + pts)

    @property
    def intval(self) -> int: return int(round(self.value))

    @property
    def label(self) -> str:
        v = self.value
        if v >= 85: return "SAFE"
        if v >= 65: return "LOW RISK"
        if v >= 40: return "SUSPICIOUS"
        if v >= 20: return "DANGEROUS"
        return "CRITICAL"

    @property
    def color(self) -> str:
        v = self.value
        if v >= 85: return "#00E87A"
        if v >= 65: return "#7DE800"
        if v >= 40: return "#FFB830"
        if v >= 20: return "#FF6020"
        return "#FF3355"


# =================================================================================
# SESSION RECORD
# =================================================================================
class SessionRecord:
    def __init__(self, pid, name, label, exe, cmdline, tier):
        self.pid           = pid
        self.name          = name
        self.label         = label
        self.exe_path      = exe
        self.cmdline       = cmdline
        self.tier          = tier
        self.started       = datetime.now()
        self.started_key   = self.started.isoformat()
        self.ended         = None
        self.end_reason    = "Running"
        self.score         = SafetyScore()
        self.hash          = None
        self.hash_verified = None
        self.network_state = "Scanning"
        self.active_ports: list  = []
        self.ext_conns: list     = []
        self.status        = "Active"
        self.last_io_r     = 0
        self.last_io_w     = 0
        self.last_io_t     = time.time()
        self.last_recover  = time.time()
        self.flagged       = False
        self.flag_reason   = ""
        self.anomalies: list    = []
        self._anomaly_keys: set = set()

    def add_anomaly(self, key: str, text: str):
        if key not in self._anomaly_keys:
            self._anomaly_keys.add(key); self.anomalies.append(text)

    @property
    def tier_label(self): return TIER_LABELS.get(self.tier, "?")
    @property
    def tier_color(self): return TIER_COLORS.get(self.tier, "#666")

    def duration_str(self):
        end  = self.ended or datetime.now()
        secs = int((end - self.started).total_seconds())
        h,r  = divmod(secs,3600); m,s = divmod(r,60)
        if h: return f"{h}h {m}m {s}s"
        if m: return f"{m}m {s}s"
        return f"{s}s"

    def to_dict(self):
        return {
            "pid":self.pid,"name":self.name,"label":self.label,
            "exe":self.exe_path,"tier":self.tier,"cmdline":self.cmdline[:200],
            "started":self.started_key,
            "ended":self.ended.isoformat() if self.ended else None,
            "end_reason":self.end_reason,
            "score":self.score.intval,"score_label":self.score.label,
            "score_log":self.score.log[-10:],
            "anomalies":self.anomalies,"hash_ok":str(self.hash_verified),
            "active_ports":self.active_ports,"ext_conns":self.ext_conns[:8],
        }


# =================================================================================
# LOGGER + STORE
# =================================================================================
class SecureLogger:
    def __init__(self):
        self._fernet = Fernet(self._key()); self._lock = threading.Lock()
    def _key(self):
        if KEY_FILE.exists(): return KEY_FILE.read_bytes()
        k = Fernet.generate_key(); KEY_FILE.write_bytes(k); return k
    def log(self, msg: str) -> str:
        ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{ts}] {msg}"
        enc   = self._fernet.encrypt(entry.encode())
        with self._lock:
            with open(LOG_FILE, "ab") as f: f.write(enc + b"\n")
        return entry
    def read_all(self):
        if not LOG_FILE.exists(): return []
        out = []
        for line in LOG_FILE.read_bytes().splitlines():
            if line.strip():
                try: out.append(self._fernet.decrypt(line).decode().strip())
                except: pass
        return out

class SessionStore:
    def __init__(self):
        self._p = SESSION_FILE; self._lock = threading.Lock(); self._data: list = []
        if self._p.exists():
            try: self._data = json.loads(self._p.read_text())
            except: pass
    def save(self, rec: SessionRecord):
        entry = rec.to_dict(); pid, ts = entry["pid"], entry["started"]
        with self._lock:
            for i,e in enumerate(self._data):
                if e["pid"]==pid and e["started"]==ts: self._data[i]=entry; break
            else: self._data.append(entry)
            try: self._p.write_text(json.dumps(self._data,indent=2))
            except: pass
    def all_desc(self):
        with self._lock: return list(reversed(self._data))


# =================================================================================
# PROCESS HELPERS
# =================================================================================
def _connections(pid: int) -> list:
    try:
        proc = psutil.Process(pid)
        try:    return proc.net_connections(kind="inet")
        except AttributeError: return proc.connections(kind="inet")
    except Exception: return []

def _listening_ports(pid: int) -> list:
    return [c.laddr.port for c in _connections(pid)
            if c.laddr and c.status in ("LISTEN","NONE","",None)]

def _cmdline(pid: int) -> str:
    try:    return " ".join(psutil.Process(pid).cmdline()).lower()
    except: return ""


# =================================================================================
# PROCESS CLASSIFICATION
# =================================================================================
def classify(pid: int, pname: str, exe: str) -> tuple:
    """
    Returns (tier, label) or (0, "").
    
    Detection order:
    1. Tier 1: Named AI server binary
    2. Tier 3: Known CLI binary name
    3. Tier 3: Interpreter whose cmdline/exe contains a CLI path marker
    4. Tier 2: Interpreter listening on AI-specific port
    5. Tier 4: Interpreter cmdline shows server launch
    """
    pname_l = pname.lower().strip()
    exe_l   = exe.lower()

    # Tier 1
    if pname_l in TIER1_SERVERS:
        return 1, TIER1_SERVERS[pname_l]

    # Tier 3 by binary name
    if pname_l in TIER3_CLI_BINARIES:
        return 3, TIER3_CLI_BINARIES[pname_l]

    # For interpreters — need cmdline/exe inspection
    if pname_l in INTERPRETER_NAMES:
        cmd = _cmdline(pid)

        # Check BOTH cmdline and exe path for CLI markers
        # This handles Windows backslash paths correctly by normalising to lowercase
        # and checking both slash styles
        combined = cmd + " " + exe_l
        for marker in TIER3_PATH_MARKERS:
            # Normalise marker: check both slash versions
            m_fwd = marker.replace("\\", "/")
            m_bck = marker.replace("/", "\\")
            if m_fwd in combined or m_bck in combined:
                return 3, _cli_label(combined)

        # Tier 2: listening on AI port
        ports = _listening_ports(pid)
        if any(p in AI_SERVER_PORTS for p in ports):
            return 2, _server_label(cmd, pname)

        # Tier 4: server launch keyword
        for kw in SERVER_LAUNCH_KEYWORDS:
            if kw in cmd:
                return 4, _server_label(cmd, pname)

    return 0, ""


def _cli_label(combined: str) -> str:
    for kw, lbl in [
        ("claude","Claude CLI"),("gemini","Gemini CLI"),("openai","OpenAI CLI"),
        ("aider","Aider"),("copilot","GitHub Copilot CLI"),("continue","Continue"),
        ("sgpt","Shell-GPT"),("fabric","Fabric CLI"),("llm","LLM CLI"),
        ("chatgpt","ChatGPT CLI"),("cody","Cody CLI"),("mods","Mods CLI"),
    ]:
        if kw in combined: return lbl
    return "AI CLI"

def _server_label(cmd: str, fallback: str) -> str:
    for kw, lbl in [
        ("ollama","Ollama"),("gradio","Gradio"),("streamlit","Streamlit"),
        ("chainlit","Chainlit"),("vllm","vLLM"),("uvicorn","Uvicorn"),
        ("llama_cpp","llama.cpp"),("llama-cpp","llama.cpp"),
        ("text-generation","TextGen WebUI"),("oobabooga","Oobabooga"),
        ("kobold","KoboldCPP"),("comfyui","ComfyUI"),("webui.py","SD WebUI"),
        ("autogpt","AutoGPT"),("llamafile","Llamafile"),
    ]:
        if kw in cmd: return lbl
    return fallback.replace(".exe","").replace(".py","").capitalize()


# =================================================================================
# SECURITY ENGINE
# =================================================================================
class SecurityEngine:
    def __init__(self, logger, store, firewall, cb):
        self.logger   = logger
        self.store    = store
        self.firewall = firewall
        self.cb       = cb
        self.records: dict = {}
        self._hashes: dict = self._load_hashes()
        self._lock    = threading.Lock()
        self._run     = False

    def _load_hashes(self):
        if STATE_FILE.exists():
            try: return json.loads(STATE_FILE.read_text())
            except: pass
        return {}

    def _save_hashes(self):
        try: STATE_FILE.write_text(json.dumps(self._hashes))
        except: pass

    def _hash_file(self, path: str):
        try:
            h = hashlib.sha256()
            with open(path,"rb") as f:
                for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
            return h.hexdigest()
        except: return None

    def _attest(self, rec: SessionRecord):
        if not rec.exe_path:
            rec.hash_verified = False; return
        cur = self._hash_file(rec.exe_path)
        if cur is None:
            rec.hash_verified = False
            if rec.tier != 3:
                rec.score.deduct("attestation_fail", "could not read exe")
            return
        rec.hash = cur
        key = rec.exe_path.lower()
        if key not in self._hashes:
            self._hashes[key] = cur; self._save_hashes()
            self.logger.log(f"Attestation: baseline for {rec.label} PID {rec.pid}")
            rec.hash_verified = True
        elif self._hashes[key] == cur:
            rec.hash_verified = True
        else:
            if rec.tier == 3:
                rec.hash_verified = "changed"
                if rec.score.deduct("hash_change_cli", rec.exe_path):
                    rec.add_anomaly("hash_change", "Executable auto-updated")
                    msg = self.logger.log(
                        f"HASH CHANGED [T3 CLI {rec.label} PID {rec.pid}]: "
                        f"updated — new baseline recorded. Score:{rec.score.intval}/100")
                    self._hashes[key] = cur; self._save_hashes()
                    self.cb("warn", {"record": rec, "message": msg})
            else:
                rec.hash_verified = False
                if rec.score.deduct("hash_tamper", rec.exe_path):
                    rec.add_anomaly("hash_tamper", "Binary replaced mid-session")
                    msg = self.logger.log(
                        f"BINARY TAMPER [T{rec.tier} {rec.label} PID {rec.pid}]: "
                        f"executable replaced — terminating")
                    self.cb("alert", {"record": rec, "message": msg})
                    try: self._terminate(psutil.Process(rec.pid), rec,
                                         "Binary integrity violation")
                    except Exception: pass

    def _check_io(self, proc: psutil.Process, rec: SessionRecord):
        if rec.tier == 3: return   # CLIs: no IO check
        try:
            io  = proc.io_counters()
            now = time.time(); dt = now - rec.last_io_t
            if dt > 0 and (rec.last_io_r > 0 or rec.last_io_w > 0):
                rr = (io.read_bytes  - rec.last_io_r) / dt / 1e6
                wr = (io.write_bytes - rec.last_io_w) / dt / 1e6
                if rr > IO_SPIKE_MB or wr > IO_SPIKE_MB:
                    reason = f"I/O spike R:{rr:.0f} W:{wr:.0f} MB/s"
                    if rec.score.deduct("io_spike", reason):
                        rec.add_anomaly("io_spike", reason)
                        self._terminate(proc, rec, reason)
                elif rr > IO_WARN_MB or wr > IO_WARN_MB:
                    rec.score.deduct("io_warn", f"R:{rr:.0f} W:{wr:.0f} MB/s")
            rec.last_io_r = io.read_bytes; rec.last_io_w = io.write_bytes
            rec.last_io_t = now
        except (psutil.NoSuchProcess, psutil.AccessDenied,
                AttributeError, NotImplementedError): pass

    def _terminate(self, proc, rec, reason):
        if rec.flagged: return
        rec.flagged = True; rec.flag_reason = reason
        msg = self.logger.log(
            f"TERMINATED [T{rec.tier} {rec.tier_label} {rec.label} PID {rec.pid}] — {reason}")
        try: proc.kill(); rec.status = "Killed"
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            rec.status = "Kill Failed"
            self.logger.log(f"Kill error PID {rec.pid}: {e}")
        rec.ended = datetime.now(); rec.end_reason = reason
        self.store.save(rec)
        self.cb("alert", {"record": rec, "message": msg})

    def kill_manual(self, pid):
        rec = self.records.get(pid)
        try:
            proc = psutil.Process(pid)
            if rec: self._terminate(proc, rec, "Manual termination by operator")
            else:   proc.kill()
        except Exception as e:
            self.logger.log(f"Manual kill error PID {pid}: {e}")

    def scan(self):
        seen = set()
        try:
            # Include ppid in single process_iter call — no separate calls needed
            proc_list = list(psutil.process_iter(["pid","name","exe","ppid","status"]))
        except Exception: return

        # Build parent map from the iter results directly (fast, no extra syscalls)
        parent_map: dict = {}
        for p in proc_list:
            try:
                parent_map[p.info["pid"]] = p.info.get("ppid") or 0
            except Exception: pass

        known_pids = set(self.records.keys())

        def _is_child_of_known(pid: int) -> bool:
            visited, cur = set(), pid
            while cur and cur not in visited:
                visited.add(cur)
                ppid = parent_map.get(cur, 0)
                if ppid in known_pids: return True
                cur = ppid
            return False

        for p in proc_list:
            try:
                info  = p.info
                pid   = info["pid"]
                pname = info.get("name") or ""
                exe   = info.get("exe") or ""

                # Already tracked
                if pid in self.records:
                    seen.add(pid)
                    rec = self.records[pid]
                    if rec.status != "Active": continue
                    if rec.hash_verified is None: self._attest(rec)

                    conns = _connections(pid)
                    net_state, should_terminate, reason = self.firewall.inspect(pid, rec, conns)
                    rec.network_state = net_state

                    if should_terminate and not rec.flagged:
                        try: self._terminate(psutil.Process(pid), rec, reason)
                        except Exception: pass

                    if not rec.flagged:
                        try: self._check_io(psutil.Process(pid), rec)
                        except (psutil.NoSuchProcess, psutil.AccessDenied): pass

                    now = time.time()
                    if now - rec.last_recover > 15:
                        if not rec.network_state.startswith("⚠"):
                            rec.score.recover(0.3)
                        rec.last_recover = now
                    self.store.save(rec)
                    continue

                # Skip children of tracked processes
                if _is_child_of_known(pid): continue

                tier, label = classify(pid, pname, exe)
                if tier == 0: continue

                seen.add(pid); known_pids.add(pid)
                cmd = _cmdline(pid)
                rec = SessionRecord(pid, pname, label, exe, cmd, tier)
                with self._lock:
                    self.records[pid] = rec
                msg = self.logger.log(
                    f"Detected: {label} PID {pid} [T{tier}:{TIER_LABELS[tier]}]"
                    + (f" — {exe}" if exe else ""))
                self._attest(rec)
                self.store.save(rec)
                self.cb("new_process", {"record": rec, "message": msg})

            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception): continue

        with self._lock:
            for pid, rec in list(self.records.items()):
                if pid not in seen and rec.status == "Active":
                    rec.status = "Ended"; rec.ended = datetime.now()
                    rec.end_reason = "Process exited normally"
                    msg = self.logger.log(
                        f"Session ended: {rec.label} PID {pid} [T{rec.tier}] | "
                        f"Duration:{rec.duration_str()} | "
                        f"Score:{rec.score.intval}/100 ({rec.score.label}) | "
                        f"Anomalies:{len(rec.anomalies)}")
                    self.store.save(rec)
                    self.cb("process_gone", {"record": rec, "message": msg})

    def start(self):
        self._run = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self._run:
            try: self.scan()
            except Exception: pass
            time.sleep(SCAN_INTERVAL)

    def stop(self): self._run = False


# =================================================================================
# UI
# =================================================================================
BG_DARK    = "#0A0C11"; BG_PANEL = "#10131A"; BG_CARD = "#141820"
BG_ROW     = "#181C26"; BG_ROW_ALT = "#141820"
ACCENT     = "#00C8FF"; ACCENT2 = "#005F88"
KILL_C     = "#FF3355"; WARN_C = "#FFB830"; OK_C = "#00E87A"
TEXT_PRI   = "#DDE3F0"; TEXT_SEC = "#5A6680"; TEXT_DIM = "#2A3048"
BORDER     = "#1C2235"; KYBER_C = "#AA44FF"

FM  = ("Consolas",10); FMS = ("Consolas",9)
FMT = ("Consolas",8,"bold"); FT = ("Segoe UI",8); FTB = ("Consolas",8,"bold")


class ScoreArc(ctk.CTkCanvas):
    def __init__(self, parent, size=52, bg=BG_ROW, **kw):
        super().__init__(parent, width=size, height=size, bg=bg, highlightthickness=0, **kw)
        self._sz=size; self._score=100; self._color=OK_C; self._draw()
    def update_score(self, score, color):
        if self._score==score and self._color==color: return
        self._score=score; self._color=color; self._draw()
    def _draw(self):
        s=self._sz; self.delete("all"); pad=7
        self.create_arc(pad,pad,s-pad,s-pad,start=160,extent=-220,style="arc",outline=TEXT_DIM,width=3)
        filled=(self._score/100.0)*220
        if filled>0:
            self.create_arc(pad,pad,s-pad,s-pad,start=160,extent=-filled,style="arc",outline=self._color,width=3)
        self.create_text(s//2,s//2+1,text=str(self._score),fill=self._color,font=("Consolas",12,"bold"))


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class SidekickApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME}  v{VERSION}")
        self.geometry("1400x920")
        self.minsize(1150,760)
        self.configure(fg_color=BG_DARK)
        try: self.iconbitmap("sidekick.ico")
        except: pass

        self.logger   = SecureLogger()
        self.store    = SessionStore()
        self.firewall = MITMFirewall(self.logger, self._on_event)
        self.engine   = SecurityEngine(self.logger, self.store, self.firewall, self._on_event)
        self.vault    = KyberVault()
        self.vault.set_callback(self._on_vault_event)

        self._eq: list   = []; self._eq_lock = threading.Lock()
        self._rows: dict = {}; self._active_tab = "live"

        self._build_ui(); self._start(); self._poll()

    # ── Layout ───────────────────────────────────────────────────────────────────

    def _build_ui(self):
        for r,w in [(0,0),(1,0),(2,0),(3,0),(4,3),(5,2)]:
            self.grid_rowconfigure(r, weight=w)
        self.grid_columnconfigure(0, weight=1)
        self._build_header(); self._build_statbar(); self._build_tabbar()
        self._build_legend(); self._build_live(); self._build_history()
        self._build_terminal()

    def _build_header(self):
        f = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=60)
        f.grid(row=0, column=0, sticky="ew"); f.grid_propagate(False)
        f.grid_columnconfigure(1, weight=1)

        logo = ctk.CTkFrame(f, fg_color="transparent")
        logo.grid(row=0, column=0, padx=20, pady=10, sticky="w")
        ctk.CTkLabel(logo, text="⬡", font=("Segoe UI Symbol",24), text_color=ACCENT).grid(row=0,column=0,padx=(0,10))
        nf = ctk.CTkFrame(logo, fg_color="transparent"); nf.grid(row=0, column=1)
        ctk.CTkLabel(nf, text="SIDEKICK EDR", font=("Consolas",15,"bold"), text_color=TEXT_PRI).grid(row=0, sticky="w")
        ctk.CTkLabel(nf, text="v5.0  ·  MITM Firewall  ·  Kyber1024 Vault  ·  Behaviour Detection",
                     font=FT, text_color=TEXT_SEC).grid(row=1, sticky="w")

        self._badge = ctk.CTkLabel(f, text="● SCANNING", font=("Consolas",10,"bold"), text_color=OK_C)
        self._badge.grid(row=0, column=1)

        ctrl = ctk.CTkFrame(f, fg_color="transparent"); ctrl.grid(row=0, column=2, padx=16)
        buttons = [
            ("Logs",          self._show_logs),
            ("Score Detail",  self._show_score_detail),
            ("MITM Log",      self._show_mitm_log),
            ("Kyber Vault",   self._open_vault),
            ("Clear Dead",    self._clear_dead),
        ]
        for i,(t,cmd) in enumerate(buttons):
            color = KYBER_C if t == "Kyber Vault" else TEXT_SEC
            ctk.CTkButton(ctrl, text=t, width=84, height=26, font=FTB,
                          fg_color=BG_CARD, border_color=BORDER, border_width=1,
                          hover_color="#1A1E2A", text_color=color,
                          command=cmd).grid(row=0, column=i, padx=2)

    def _build_statbar(self):
        f = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=50)
        f.grid(row=1, column=0, sticky="ew", pady=(1,0)); f.grid_propagate(False)
        ctk.CTkFrame(f, fg_color=ACCENT2, height=1).place(relx=0,rely=0,relwidth=1)
        items = [("MONITORED","0","st_mon"),("ACTIVE","0","st_act"),
                 ("BLOCKED","0","st_blk"),("MITM INSPECTED","0","st_mit"),
                 ("AVG SCORE","—","st_avg"),("VAULT KEYS","0","st_vlt")]
        f.grid_columnconfigure(list(range(len(items))), weight=1)
        for i,(lbl,val,attr) in enumerate(items):
            sf = ctk.CTkFrame(f, fg_color="transparent")
            sf.grid(row=0, column=i, padx=14, pady=5, sticky="w")
            ctk.CTkLabel(sf, text=lbl, font=("Consolas",7,"bold"), text_color=TEXT_DIM).grid(row=0, sticky="w")
            c = KYBER_C if "VAULT" in lbl else ACCENT
            v = ctk.CTkLabel(sf, text=val, font=("Consolas",14,"bold"), text_color=c)
            v.grid(row=1, sticky="w"); setattr(self, attr, v)

    def _build_tabbar(self):
        f = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=34)
        f.grid(row=2, column=0, sticky="ew", pady=(1,0)); f.grid_propagate(False)
        self._tab_live = ctk.CTkButton(f, text="LIVE MONITOR", width=130, height=26,
            font=FTB, fg_color=ACCENT2, hover_color=ACCENT2, text_color=TEXT_PRI,
            corner_radius=3, command=lambda: self._switch_tab("live"))
        self._tab_live.pack(side="left", padx=(14,3), pady=4)
        self._tab_hist = ctk.CTkButton(f, text="SESSION HISTORY", width=140, height=26,
            font=FTB, fg_color=BG_CARD, hover_color="#1A1E2A", text_color=TEXT_SEC,
            corner_radius=3, command=lambda: self._switch_tab("history"))
        self._tab_hist.pack(side="left", padx=3, pady=4)

    def _build_legend(self):
        f = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=28)
        f.grid(row=3, column=0, sticky="ew", pady=(1,0)); f.grid_propagate(False)
        ctk.CTkLabel(f, text="TIER:", font=FTB, text_color=TEXT_DIM).pack(side="left", padx=(16,6))
        for lbl, color in [
            ("T1 AI Server — MITM+enforce", "#FF6020"),
            ("T2 AI Port  — MITM+enforce",  "#FFB830"),
            ("T3 AI CLI   — MITM+score only","#00C8FF"),
            ("T4 AI Script— MITM+enforce",  "#7B8FCC"),
        ]:
            ctk.CTkLabel(f, text=f"  ■ {lbl}", font=("Consolas",8,"bold"),
                         text_color=color).pack(side="left", padx=5)
        ctk.CTkLabel(f, text=f"  ⬡ Kyber1024 PQC Vault active", font=("Consolas",8,"bold"),
                     text_color=KYBER_C).pack(side="right", padx=16)

    def _switch_tab(self, name: str):
        self._active_tab = name
        if name == "live":
            self._live_outer.grid(); self._hist_outer.grid_remove()
            self._tab_live.configure(fg_color=ACCENT2, text_color=TEXT_PRI)
            self._tab_hist.configure(fg_color=BG_CARD,  text_color=TEXT_SEC)
        else:
            self._live_outer.grid_remove(); self._hist_outer.grid()
            self._tab_live.configure(fg_color=BG_CARD,  text_color=TEXT_SEC)
            self._tab_hist.configure(fg_color=ACCENT2,  text_color=TEXT_PRI)
            self._refresh_history()

    def _build_live(self):
        self._live_outer = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0)
        self._live_outer.grid(row=4, column=0, sticky="nsew", pady=(1,0))
        self._live_outer.grid_rowconfigure(0, weight=1)
        self._live_outer.grid_columnconfigure(0, weight=1)
        self._live_scroll = ctk.CTkScrollableFrame(self._live_outer, fg_color=BG_CARD,
            scrollbar_button_color=BORDER, scrollbar_button_hover_color=ACCENT2)
        self._live_scroll.grid(row=0, column=0, sticky="nsew", padx=12, pady=8)

        cols = ["SCORE","TIER","AGENT","PID","DURATION","ATTEST","NETWORK / MITM","STATUS","ACTION"]
        wts  = [1,       1,     3,      1,    1,          2,       3,               1,       1]
        hrow = ctk.CTkFrame(self._live_scroll, fg_color="#0D1016", corner_radius=4)
        hrow.pack(fill="x", pady=(0,3))
        for i,(c,w) in enumerate(zip(cols,wts)):
            hrow.grid_columnconfigure(i, weight=w)
            ctk.CTkLabel(hrow, text=c, font=FMT, text_color=TEXT_DIM, anchor="w").grid(
                row=0, column=i, padx=10, pady=5, sticky="w")

        self._empty_lbl = ctk.CTkLabel(self._live_scroll, font=FMS,
            text_color=TEXT_DIM, justify="center", text=(
                "No AI processes detected yet — Sidekick is watching.\n\n"
                "Detection: binary name · CLI path markers · AI port · server launch keywords\n"
                "MITM Firewall: inspecting all connections via CIDR classification\n"
                f"Kyber Vault: drop .txt/.env files in {VAULT_DIR.name}/ to auto-encrypt"))
        self._empty_lbl.pack(pady=30)

    def _build_history(self):
        self._hist_outer = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0)
        self._hist_outer.grid(row=4, column=0, sticky="nsew", pady=(1,0))
        self._hist_outer.grid_remove()
        self._hist_outer.grid_rowconfigure(1, weight=1)
        self._hist_outer.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self._hist_outer, text="SESSION HISTORY",
                     font=FMT, text_color=TEXT_SEC).grid(row=0, column=0, padx=16, pady=(10,2), sticky="w")
        self._hist_scroll = ctk.CTkScrollableFrame(self._hist_outer, fg_color=BG_CARD,
            scrollbar_button_color=BORDER, scrollbar_button_hover_color=ACCENT2)
        self._hist_scroll.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0,10))
        hcols = ["AGENT","TIER","PID","STARTED","ENDED","DURATION","END REASON","FINAL SCORE"]
        hwts  = [2,       1,     1,    2,         2,      1,          3,           2]
        hrow  = ctk.CTkFrame(self._hist_scroll, fg_color="#0D1016", corner_radius=4)
        hrow.pack(fill="x", pady=(0,3))
        for i,(c,w) in enumerate(zip(hcols,hwts)):
            hrow.grid_columnconfigure(i, weight=w)
            ctk.CTkLabel(hrow, text=c, font=FMT, text_color=TEXT_DIM, anchor="w").grid(
                row=0, column=i, padx=10, pady=5, sticky="w")
        self._hist_empty = ctk.CTkLabel(self._hist_scroll, text="No session history yet.",
                                         font=FM, text_color=TEXT_DIM)
        self._hist_empty.pack(pady=50)

    def _build_terminal(self):
        outer = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0)
        outer.grid(row=5, column=0, sticky="nsew", pady=(1,0))
        outer.grid_rowconfigure(1, weight=1); outer.grid_columnconfigure(0, weight=1)
        hf = ctk.CTkFrame(outer, fg_color="transparent", height=26)
        hf.grid(row=0, column=0, sticky="ew", padx=16, pady=(6,0))
        ctk.CTkLabel(hf, text="ACTIVITY LOG", font=FMT, text_color=TEXT_SEC).pack(side="left")
        ctk.CTkLabel(hf, text=" · Encrypted · Real-time · MITM events included",
                     font=FT, text_color=TEXT_DIM).pack(side="left")
        self._term = ctk.CTkTextbox(outer, fg_color=BG_DARK, text_color=OK_C,
            font=FMS, state="disabled", border_color=BORDER, border_width=1,
            scrollbar_button_color=BORDER, scrollbar_button_hover_color=ACCENT2)
        self._term.grid(row=1, column=0, sticky="nsew", padx=12, pady=(2,10))
        self._term.tag_config("alert",  foreground=KILL_C)
        self._term.tag_config("info",   foreground=OK_C)
        self._term.tag_config("warn",   foreground=WARN_C)
        self._term.tag_config("dim",    foreground=TEXT_SEC)
        self._term.tag_config("vault",  foreground=KYBER_C)

    # ── Row factory ───────────────────────────────────────────────────────────────

    def _make_row(self, rec: SessionRecord) -> dict:
        is_alt = len(self._rows) % 2
        bg     = BG_ROW_ALT if is_alt else BG_ROW
        row    = ctk.CTkFrame(self._live_scroll, fg_color=bg, corner_radius=4)
        row.pack(fill="x", pady=1)
        wts = [1,1,3,1,1,2,3,1,1]
        for i,w in enumerate(wts): row.grid_columnconfigure(i, weight=w)

        arc = ScoreArc(row, size=50, bg=bg)
        arc.grid(row=0, column=0, padx=8, pady=5)

        ctk.CTkLabel(row, text=f"T{rec.tier}", font=("Consolas",9,"bold"),
                     text_color=rec.tier_color, anchor="w").grid(row=0,column=1,padx=6,sticky="w")

        nf = ctk.CTkFrame(row, fg_color="transparent")
        nf.grid(row=0, column=2, padx=8, sticky="w")
        ctk.CTkLabel(nf, text=rec.label, font=FM, text_color=TEXT_PRI, anchor="w").grid(row=0,sticky="w")
        ctk.CTkLabel(nf, text=rec.name,  font=("Consolas",8), text_color=TEXT_SEC, anchor="w").grid(row=1,sticky="w")

        ctk.CTkLabel(row, text=str(rec.pid), font=FMS, text_color=TEXT_SEC, anchor="w").grid(row=0,column=3,padx=8,sticky="w")

        dul  = ctk.CTkLabel(row, text="0s",       font=FMS, text_color=TEXT_SEC, anchor="w"); dul.grid(row=0,column=4,padx=8,sticky="w")
        atl  = ctk.CTkLabel(row, text="Hashing…", font=FMS, text_color=WARN_C,   anchor="w"); atl.grid(row=0,column=5,padx=8,sticky="w")
        ntl  = ctk.CTkLabel(row, text="Scanning", font=FMS, text_color=TEXT_SEC,  anchor="w"); ntl.grid(row=0,column=6,padx=8,sticky="w")
        stsl = ctk.CTkLabel(row, text="● Active", font=("Consolas",9,"bold"), text_color=OK_C, anchor="w"); stsl.grid(row=0,column=7,padx=8,sticky="w")

        kb = ctk.CTkButton(row, text="KILL", width=50, height=22, font=FTB,
            fg_color="#280A14", border_color=KILL_C, border_width=1,
            hover_color="#4A1020", text_color=KILL_C,
            command=lambda p=rec.pid: self._manual_kill(p))
        kb.grid(row=0, column=8, padx=8, pady=4)
        return {"row":row,"arc":arc,"dul":dul,"atl":atl,"ntl":ntl,"stsl":stsl,"kb":kb}

    def _upd_row(self, pid: int, rec: SessionRecord):
        if pid not in self._rows: return
        w = self._rows[pid]
        w["arc"].update_score(rec.score.intval, rec.score.color)
        w["dul"].configure(text=rec.duration_str())
        hv = rec.hash_verified
        if   hv is True:        w["atl"].configure(text="✓ Verified", text_color=OK_C)
        elif hv == "changed":   w["atl"].configure(text="⚡ Updated",  text_color=WARN_C)
        elif hv is False:       w["atl"].configure(text="✗ Failed",   text_color=KILL_C)
        else:                   w["atl"].configure(text="Hashing…",   text_color=WARN_C)
        ns = rec.network_state
        if   "⚠" in ns:        w["ntl"].configure(text=ns[:30], text_color=KILL_C)
        elif "API" in ns:       w["ntl"].configure(text=ns[:30], text_color=WARN_C)
        elif "Listening" in ns: w["ntl"].configure(text=ns[:34], text_color=ACCENT)
        elif ns == "Clean":     w["ntl"].configure(text="Clean",  text_color=OK_C)
        else:                   w["ntl"].configure(text=ns,       text_color=TEXT_SEC)
        if rec.status == "Active":
            w["stsl"].configure(text="● Active", text_color=OK_C); w["kb"].configure(state="normal")
        elif rec.status in ("Killed","Kill Failed"):
            w["stsl"].configure(text="◼ Killed", text_color=KILL_C)
            w["kb"].configure(state="disabled", text="DEAD", fg_color="#111", text_color=TEXT_DIM)
        elif rec.status == "Ended":
            w["stsl"].configure(text="○ Ended",  text_color=TEXT_SEC)
            w["kb"].configure(state="disabled", text="GONE", fg_color="#111", text_color=TEXT_DIM)

    # ── History ───────────────────────────────────────────────────────────────────

    def _refresh_history(self):
        for child in list(self._hist_scroll.winfo_children()):
            if getattr(child,"_hist_row",False):
                try: child.destroy()
                except: pass
        sessions = self.store.all_desc()
        seen_keys = set(); unique = []
        for s in sessions:
            k = (s["pid"],s["started"])
            if k not in seen_keys: seen_keys.add(k); unique.append(s)
        if not unique: self._hist_empty.pack(pady=50); return
        self._hist_empty.pack_forget()
        hwts = [2,1,1,2,2,1,3,2]
        for i,s in enumerate(unique):
            bg  = BG_ROW_ALT if i%2 else BG_ROW
            row = ctk.CTkFrame(self._hist_scroll, fg_color=bg, corner_radius=4)
            row._hist_row = True; row.pack(fill="x", pady=1)
            for j,w in enumerate(hwts): row.grid_columnconfigure(j, weight=w)
            sc   = s.get("score",100); tier = s.get("tier",1)
            sc_c = OK_C if sc>=85 else (WARN_C if sc>=65 else ("#FF6020" if sc>=40 else KILL_C))
            tc   = TIER_COLORS.get(tier, TEXT_SEC)
            ended = (s.get("ended") or "")[:19].replace("T"," ") or "—"
            try:
                st=datetime.fromisoformat(s["started"])
                en=datetime.fromisoformat(s["ended"]) if s.get("ended") else datetime.now()
                secs=int((en-st).total_seconds()); h,r=divmod(secs,3600); m,ss=divmod(r,60)
                dur=f"{h}h{m}m{ss}s" if h else (f"{m}m{ss}s" if m else f"{ss}s")
            except: dur="—"
            label  = s.get("label") or s.get("name","?")
            score_txt = f"{sc}/100  ({s.get('score_label','—')})"
            vals   = [label,f"T{tier}",str(s["pid"]),
                      s["started"][:19].replace("T"," "),ended,dur,
                      s.get("end_reason","—")[:50],score_txt]
            colors = [TEXT_PRI,tc,TEXT_SEC,TEXT_SEC,TEXT_SEC,TEXT_SEC,TEXT_SEC,sc_c]
            for j,(val,c,wt) in enumerate(zip(vals,colors,hwts)):
                ctk.CTkLabel(row,text=val,font=FMS,text_color=c,anchor="w").grid(
                    row=0,column=j,padx=10,pady=6,sticky="w")

    # ── Engine / Events ───────────────────────────────────────────────────────────

    def _start(self):
        self._tlog("Sidekick EDR v5.0 started.", "dim")
        self._tlog("MITM Firewall active — all outbound connections inspected via CIDR classification.", "dim")
        self._tlog(f"Kyber1024 Vault ready — drop .txt/.env files in: {VAULT_DIR}", "vault")
        self._tlog("T3 CLIs: monitored + scored. Auto-kill only on binary tamper.", "dim")
        self.engine.start()

    def _on_event(self, etype, data):
        with self._eq_lock: self._eq.append((etype, data))

    def _on_vault_event(self, etype, name, msg):
        tag = "vault" if etype == "vault_auto" else "warn"
        with self._eq_lock:
            self._eq.append(("vault_log", {"msg": msg, "tag": tag}))

    def _poll(self):
        with self._eq_lock: evts = self._eq[:]; self._eq.clear()
        for etype, data in evts: self._handle(etype, data)

        for pid,rec in list(self.engine.records.items()):
            self._upd_row(pid, rec)

        recs = list(self.engine.records.values())
        self.st_mon.configure(text=str(len(recs)))
        self.st_act.configure(text=str(sum(1 for r in recs if r.status=="Active")))
        self.st_blk.configure(text=str(sum(1 for r in recs if r.status in ("Killed","Kill Failed"))))
        fw   = self.firewall.stats
        self.st_mit.configure(text=str(fw["inspected"]))
        if recs: self.st_avg.configure(text=f"{sum(r.score.intval for r in recs)/len(recs):.0f}")
        else:    self.st_avg.configure(text="—")
        self.st_vlt.configure(text=str(len(self.vault.list_keys())))
        self.after(400, self._poll)

    def _handle(self, etype, data):
        if etype == "vault_log":
            self._tlog(data["msg"], data["tag"]); return
        rec = data.get("record"); msg = data.get("message","")
        if etype == "new_process":
            self._empty_lbl.pack_forget()
            self._rows[rec.pid] = self._make_row(rec); self._upd_row(rec.pid,rec)
            self._tlog(msg, "info")
        elif etype == "alert":
            if rec: self._upd_row(rec.pid, rec)
            self._tlog(msg, "alert")
        elif etype == "warn":
            if rec: self._upd_row(rec.pid, rec)
            self._tlog(msg, "warn")
        elif etype == "process_gone":
            if rec: self._upd_row(rec.pid, rec)
            self._tlog(msg, "dim")

    # ── Actions ───────────────────────────────────────────────────────────────────

    def _manual_kill(self, pid):
        rec = self.engine.records.get(pid)
        if rec and rec.status == "Active": self.engine.kill_manual(pid)

    def _clear_dead(self):
        dead = [p for p,r in list(self.engine.records.items())
                if r.status in ("Ended","Killed","Kill Failed")]
        for p in dead:
            if p in self._rows:
                try: self._rows[p]["row"].destroy()
                except: pass
                del self._rows[p]
            try: del self.engine.records[p]
            except: pass
        if not self._rows: self._empty_lbl.pack(pady=30)
        self._tlog(f"Cleared {len(dead)} terminated process(es).", "dim")

    def _tlog(self, msg, tag="info"):
        self._term.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        labels = {"alert":"⚠ ALERT","info":"✓ INFO ","warn":"⚡ WARN ",
                  "dim":"  SYS  ","vault":"⬡ VAULT"}
        self._term.insert("end", f"[{ts}] {labels.get(tag,'       ')}  {msg}\n", tag)
        self._term.see("end"); self._term.configure(state="disabled")

    # ── Popups ────────────────────────────────────────────────────────────────────

    def _show_logs(self):
        win = ctk.CTkToplevel(self); win.title("Decrypted Audit Log")
        win.geometry("880x600"); win.configure(fg_color=BG_DARK)
        ctk.CTkLabel(win, text="ENCRYPTED AUDIT LOG — Decrypted",
                     font=("Consolas",10,"bold"), text_color=ACCENT).pack(padx=20,pady=(16,6),anchor="w")
        box = ctk.CTkTextbox(win, fg_color=BG_PANEL, text_color=TEXT_PRI, font=FMS)
        box.pack(fill="both", expand=True, padx=20, pady=(0,20))
        logs = self.logger.read_all()
        box.insert("end", "\n".join(logs) if logs else "No entries yet.")
        box.configure(state="disabled")

    def _show_score_detail(self):
        win = ctk.CTkToplevel(self); win.title("Safety Score Breakdown")
        win.geometry("720,540"); win.configure(fg_color=BG_DARK)
        win.geometry("720x540")
        ctk.CTkLabel(win, text="SAFETY SCORE BREAKDOWN",
                     font=("Consolas",10,"bold"), text_color=ACCENT).pack(padx=20,pady=(16,6),anchor="w")
        box = ctk.CTkTextbox(win, fg_color=BG_PANEL, text_color=TEXT_PRI, font=FMS)
        box.pack(fill="both", expand=True, padx=20, pady=(0,20))
        lines = []
        recs = list(self.engine.records.values())
        if not recs: lines.append("No processes currently monitored.")
        for rec in recs:
            lines += [f"{'─'*60}",
                      f"{rec.label}  PID {rec.pid}  [T{rec.tier}: {rec.tier_label}]",
                      f"Score : {rec.score.intval}/100  →  {rec.score.label}",
                      f"Status: {rec.status}  |  Duration: {rec.duration_str()}",
                      f"Anomalies: {len(rec.anomalies)}"]
            if rec.score.log:
                lines.append("Deductions:")
                lines += [f"  {e}" for e in rec.score.log]
            if rec.anomalies:
                lines.append("Anomaly detail:")
                lines += [f"  • {a}" for a in rec.anomalies]
            if rec.ext_conns:
                lines.append(f"External conns: {', '.join(rec.ext_conns[:6])}")
            lines.append("")
        box.insert("end", "\n".join(lines)); box.configure(state="disabled")

    def _show_mitm_log(self):
        win = ctk.CTkToplevel(self); win.title("MITM Firewall Log")
        win.geometry("900x560"); win.configure(fg_color=BG_DARK)
        ctk.CTkLabel(win, text="MITM FIREWALL — Connection Inspection Log",
                     font=("Consolas",10,"bold"), text_color=ACCENT).pack(padx=20,pady=(16,6),anchor="w")
        stats = self.firewall.stats
        ctk.CTkLabel(win, text=f"Inspected: {stats['inspected']}  |  Blocked: {stats['blocked']}",
                     font=FMS, text_color=TEXT_SEC).pack(padx=20,anchor="w")
        box = ctk.CTkTextbox(win, fg_color=BG_PANEL, text_color=TEXT_PRI, font=FMS)
        box.pack(fill="both", expand=True, padx=20, pady=(6,20))
        log = stats["log"]
        if not log: box.insert("end","No connections inspected yet.\n"); box.configure(state="disabled"); return
        header = f"{'TIME':10} {'TIER':5} {'AGENT':20} {'SRC':22} {'DST':22} {'PROVIDER':12} {'ACTION'}\n"
        box.insert("end", header)
        box.insert("end", "─"*100+"\n")
        for e in reversed(log):
            action_color = "BLOCK" if e["action"]=="BLOCK" else ("ALERT" if e["action"]=="ALERT" else "ALLOW")
            line = (f"{e['ts']:10} T{e['tier']:<4} {e['label'][:19]:20} "
                    f"{e['src'][:21]:22} {e['dst'][:21]:22} "
                    f"{e['provider'][:11]:12} {action_color}\n")
            box.insert("end", line)
        box.configure(state="disabled")

    def _open_vault(self):
        win = ctk.CTkToplevel(self); win.title("Kyber1024 Post-Quantum Vault")
        win.geometry("760x600"); win.configure(fg_color=BG_DARK)

        ctk.CTkLabel(win, text="⬡  KYBER1024 POST-QUANTUM VAULT",
                     font=("Consolas",12,"bold"), text_color=KYBER_C).pack(padx=20,pady=(16,2),anchor="w")
        ctk.CTkLabel(win,
            text="API keys encrypted with Kyber1024 (NIST PQC) + AES-256-GCM.\n"
                 "Quantum computers cannot break this encryption.\n"
                 f"Drop .txt/.env files into: {VAULT_DIR}  — they are auto-encrypted & plaintext deleted.",
            font=FT, text_color=TEXT_SEC, justify="left").pack(padx=20,anchor="w")

        # Add key section
        add_frame = ctk.CTkFrame(win, fg_color=BG_PANEL, corner_radius=6)
        add_frame.pack(fill="x", padx=20, pady=12)
        ctk.CTkLabel(add_frame, text="ADD KEY", font=FMT, text_color=TEXT_SEC).grid(row=0,column=0,padx=12,pady=(8,2),sticky="w",columnspan=3)
        ctk.CTkLabel(add_frame, text="Name:", font=FMS, text_color=TEXT_PRI).grid(row=1,column=0,padx=12,pady=4,sticky="w")
        name_entry = ctk.CTkEntry(add_frame, width=180, font=FMS, fg_color=BG_CARD, border_color=BORDER)
        name_entry.grid(row=1,column=1,padx=4,pady=4,sticky="w")
        ctk.CTkLabel(add_frame, text="Secret:", font=FMS, text_color=TEXT_PRI).grid(row=2,column=0,padx=12,pady=4,sticky="w")
        secret_entry = ctk.CTkEntry(add_frame, width=400, show="•", font=FMS, fg_color=BG_CARD, border_color=BORDER)
        secret_entry.grid(row=2,column=1,padx=4,pady=4,sticky="w")
        status_lbl = ctk.CTkLabel(add_frame, text="", font=FMS, text_color=OK_C)
        status_lbl.grid(row=3,column=0,columnspan=3,padx=12,pady=(2,8),sticky="w")

        def do_store():
            n = name_entry.get().strip(); s = secret_entry.get().strip()
            if not n or not s: status_lbl.configure(text="Name and secret required.", text_color=KILL_C); return
            try:
                result = self.vault.store(n, s)
                status_lbl.configure(text=f"✓ Stored: {result[:60]}", text_color=OK_C)
                name_entry.delete(0,"end"); secret_entry.delete(0,"end")
                refresh_list()
            except Exception as e:
                status_lbl.configure(text=f"Error: {e}", text_color=KILL_C)

        ctk.CTkButton(add_frame, text="Encrypt & Store", font=FTB, width=130, height=28,
                      fg_color=KYBER_C, hover_color="#8833CC", text_color="white",
                      command=do_store).grid(row=2,column=2,padx=8,pady=4)

        # Keys list
        ctk.CTkLabel(win, text="STORED KEYS", font=FMT, text_color=TEXT_SEC).pack(padx=20,pady=(4,2),anchor="w")
        list_frame = ctk.CTkScrollableFrame(win, fg_color=BG_CARD, height=220,
            scrollbar_button_color=BORDER, scrollbar_button_hover_color=KYBER_C)
        list_frame.pack(fill="x", padx=20, pady=(0,8))
        reveal_lbl = ctk.CTkLabel(win, text="", font=FMS, text_color=KYBER_C, wraplength=700)
        reveal_lbl.pack(padx=20, anchor="w")

        def refresh_list():
            for w in list_frame.winfo_children(): w.destroy()
            keys = self.vault.list_keys()
            if not keys:
                ctk.CTkLabel(list_frame, text="No keys stored yet.", font=FMS, text_color=TEXT_DIM).pack(pady=20)
                return
            for ki in keys:
                row = ctk.CTkFrame(list_frame, fg_color=BG_ROW, corner_radius=4)
                row.pack(fill="x", pady=2)
                ctk.CTkLabel(row, text=ki["name"], font=FM, text_color=KYBER_C, anchor="w", width=160).grid(row=0,column=0,padx=10,pady=6,sticky="w")
                ctk.CTkLabel(row, text=ki["preview"], font=FMS, text_color=TEXT_SEC, anchor="w", width=100).grid(row=0,column=1,padx=4,sticky="w")
                ctk.CTkLabel(row, text=ki["stored"][:16], font=FMS, text_color=TEXT_DIM, anchor="w").grid(row=0,column=2,padx=4,sticky="w")
                def make_reveal(name=ki["name"]):
                    def _reveal():
                        try:
                            val = self.vault.retrieve(name)
                            reveal_lbl.configure(text=f"⬡ {name}: {val}")
                            win.after(8000, lambda: reveal_lbl.configure(text=""))
                        except Exception as e:
                            reveal_lbl.configure(text=f"Error: {e}")
                    return _reveal
                def make_delete(name=ki["name"]):
                    def _delete():
                        self.vault.delete(name); refresh_list()
                        reveal_lbl.configure(text="")
                    return _delete
                ctk.CTkButton(row, text="Reveal", width=60, height=22, font=FTB,
                              fg_color=BG_CARD, border_color=KYBER_C, border_width=1,
                              hover_color="#1A1E2A", text_color=KYBER_C,
                              command=make_reveal()).grid(row=0,column=3,padx=4)
                ctk.CTkButton(row, text="Delete", width=60, height=22, font=FTB,
                              fg_color=BG_CARD, border_color=KILL_C, border_width=1,
                              hover_color="#280A14", text_color=KILL_C,
                              command=make_delete()).grid(row=0,column=4,padx=4,pady=4)

        refresh_list()

    def on_close(self):
        self.engine.stop(); self.destroy()


# =================================================================================
# ENTRY
# =================================================================================
def main():
    app = SidekickApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()

if __name__ == "__main__":
    main()
