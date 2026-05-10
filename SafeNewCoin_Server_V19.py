

import os
import json
import time
import uuid
import hmac
import base64
import shutil
import zipfile
import secrets
import hashlib
import sqlite3
import tempfile
import threading
import traceback
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from flask import Flask, jsonify, request, render_template_string

APP_NAME = "SafeNewCoin"
APP_VERSION = "V20 SERVER FIXED"
COIN_SYMBOL = "SNC"

MAX_SUPPLY = 52_000_000.0
INITIAL_REWARD = 1.0
MIN_REWARD = 0.0001
HALVING_INTERVAL = 1_000_000
DEFAULT_DIFFICULTY = 1
INACTIVE_DELETE_DAYS = 730
INACTIVE_GRACE_DAYS = 30
TOKEN_EXPIRE_SECONDS = 60 * 60 * 24 * 30

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "safe_newcoin_server_data"
USER_DATA_DIR = DATA_DIR / "users"
BACKUP_DIR = DATA_DIR / "backups"
DB_FILE = DATA_DIR / "server_v20_fixed.db"
LOG_FILE = DATA_DIR / "server_v20_fixed.log"

for d in [DATA_DIR, USER_DATA_DIR, BACKUP_DIR]:
    d.mkdir(parents=True, exist_ok=True)

SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET_KEY_SAFE_NEWCOIN_V20_FIXED")
PORT = int(os.environ.get("PORT", "8788"))
SERVER_LOCK = threading.RLock()


def now() -> int:
    return int(time.time())


def ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def stable_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def log_line(msg: str) -> None:
    line = f"[{ts()}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name, suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass


def atomic_json(path: Path, data: Any) -> None:
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2))


def make_user_id() -> str:
    return "USER_" + uuid.uuid4().hex[:16]


def make_address(public_key: str) -> str:
    return "SNC_" + sha256_text("ADDR:" + public_key)[:40]


def make_wallet() -> Dict[str, Any]:
    private_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
    public_key = sha256_text("PUBLIC:" + private_key)
    return {
        "address": make_address(public_key),
        "public_key": public_key,
        "private_key_hash": sha256_text(private_key),
        "created_at": now(),
    }


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 150_000)
    return f"pbkdf2_sha256$150000${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds, salt, digest_hex = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), int(rounds))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def make_token(user_id: str) -> str:
    raw = f"{user_id}:{now()}:{secrets.token_hex(24)}"
    sig = hmac.new(SECRET_KEY.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{raw}:{sig}".encode("utf-8")).decode("utf-8").rstrip("=")


def parse_token(token: str) -> Optional[str]:
    try:
        pad = "=" * (-len(token) % 4)
        decoded = base64.urlsafe_b64decode((token + pad).encode("utf-8")).decode("utf-8")
        user_id, issued, nonce, sig = decoded.split(":", 3)
        raw = f"{user_id}:{issued}:{nonce}"
        expected = hmac.new(SECRET_KEY.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if now() - int(issued) > TOKEN_EXPIRE_SECONDS:
            return None
        return user_id
    except Exception:
        return None


def get_bearer_token() -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return ""


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.executescript("""
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_login_at INTEGER NOT NULL,
            inactive_delete_agreed INTEGER NOT NULL DEFAULT 0,
            inactive_delete_days INTEGER NOT NULL DEFAULT 730,
            grace_days INTEGER NOT NULL DEFAULT 30,
            delete_warning_at INTEGER DEFAULT 0,
            scheduled_delete_at INTEGER DEFAULT 0,
            deleted_at INTEGER DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'ACTIVE'
        );

        CREATE TABLE IF NOT EXISTS wallets (
            user_id TEXT PRIMARY KEY,
            address TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            private_key_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS balances (
            address TEXT PRIMARY KEY,
            balance REAL NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS blocks (
            block_index INTEGER PRIMARY KEY,
            previous_hash TEXT NOT NULL,
            block_time INTEGER NOT NULL,
            miner_address TEXT NOT NULL,
            reward REAL NOT NULL,
            difficulty INTEGER NOT NULL,
            loop_count INTEGER NOT NULL,
            nonce TEXT NOT NULL,
            seed TEXT NOT NULL,
            proof TEXT NOT NULL,
            block_hash TEXT UNIQUE NOT NULL,
            tx_count INTEGER NOT NULL DEFAULT 0,
            raw_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS transactions (
            tx_hash TEXT PRIMARY KEY,
            tx_type TEXT NOT NULL,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            amount REAL NOT NULL,
            fee REAL NOT NULL,
            created_at INTEGER NOT NULL,
            block_index INTEGER DEFAULT -1,
            raw_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS mining_submits (
            submit_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            address TEXT NOT NULL,
            submitted_at INTEGER NOT NULL,
            accepted INTEGER NOT NULL,
            reason TEXT NOT NULL,
            block_index INTEGER DEFAULT -1,
            nonce TEXT DEFAULT '0',
            proof TEXT DEFAULT '0'
        );

        CREATE TABLE IF NOT EXISTS server_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """)
        conn.commit()


def state_get(key: str, default: str = "") -> str:
    with db() as conn:
        row = conn.execute("SELECT value FROM server_state WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default


def state_set(key: str, value: str) -> None:
    with db() as conn:
        conn.execute("INSERT OR REPLACE INTO server_state(key,value) VALUES(?,?)", (key, value))
        conn.commit()


class ProofEngine:
    def target(self, difficulty: int) -> int:
        difficulty = max(1, min(15, int(difficulty)))
        return 1 << max(1, 64 - difficulty * 4)

    def seed_for_block(self, index: int, previous_hash: str) -> int:
        return int(sha256_text(f"{index}:{previous_hash}")[:16], 16)

    def mix64_loop(self, x: int, loop_count: int) -> int:
        x &= 0xFFFFFFFFFFFFFFFF
        for _ in range(int(loop_count)):
            x ^= 0x9E3779B97F4A7C15
            x = (x * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
            x ^= (x >> 27)
            x = (x * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
            x ^= (x >> 31)
        return x & 0xFFFFFFFFFFFFFFFF

    def proof_value(self, seed: int, nonce: int, loop_count: int) -> int:
        return self.mix64_loop(seed ^ nonce, loop_count)


PROOF = ProofEngine()


def calc_reward(height: int) -> float:
    halvings = height // HALVING_INTERVAL
    reward = INITIAL_REWARD / (2 ** halvings)
    return max(MIN_REWARD, round(reward, 8))


def calc_block_hash(block: Dict[str, Any]) -> str:
    temp = dict(block)
    temp.pop("hash", None)
    return sha256_text(stable_json(temp))


def last_block() -> Optional[sqlite3.Row]:
    with db() as conn:
        return conn.execute("SELECT * FROM blocks ORDER BY block_index DESC LIMIT 1").fetchone()


def current_height() -> int:
    row = last_block()
    return int(row["block_index"]) if row else 0


def last_hash() -> str:
    row = last_block()
    return str(row["block_hash"]) if row else "GENESIS"


def total_supply() -> float:
    with db() as conn:
        row = conn.execute("SELECT COALESCE(SUM(reward),0) AS s FROM blocks").fetchone()
        return round(float(row["s"] or 0), 8)


def next_reward() -> float:
    remaining = MAX_SUPPLY - total_supply()
    if remaining <= 0:
        return 0.0
    return min(calc_reward(current_height() + 1), remaining)


def current_difficulty() -> int:
    try:
        return max(1, min(15, int(state_get("difficulty", str(DEFAULT_DIFFICULTY)))))
    except Exception:
        return DEFAULT_DIFFICULTY


def supply_based_difficulty() -> int:
    return max(1, min(15, 1 + int((total_supply() / MAX_SUPPLY) * 14)))


def create_genesis_if_needed() -> None:
    if last_block() is not None:
        return
    genesis = {
        "index": 0,
        "previous": "GENESIS",
        "time": now(),
        "miner": "GENESIS",
        "reward": 0.0,
        "difficulty": 1,
        "loop_count": 1,
        "nonce": 0,
        "seed": 0,
        "proof": 0,
        "transactions": [],
    }
    genesis["hash"] = calc_block_hash(genesis)
    with db() as conn:
        conn.execute(
            "INSERT INTO blocks(block_index,previous_hash,block_time,miner_address,reward,difficulty,loop_count,nonce,seed,proof,block_hash,tx_count,raw_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (0, "GENESIS", genesis["time"], "GENESIS", 0.0, 1, 1, "0", "0", "0", genesis["hash"], 0, stable_json(genesis))
        )
        conn.commit()
    log_line("제네시스 블록 생성 완료")


def get_current_user() -> Tuple[Optional[sqlite3.Row], Optional[Dict[str, Any]]]:
    token = get_bearer_token()
    user_id = parse_token(token)
    if not user_id:
        return None, {"ok": False, "reason": "로그인이 필요합니다."}
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE user_id=? AND deleted_at=0", (user_id,)).fetchone()
        if not user:
            return None, {"ok": False, "reason": "사용자를 찾을 수 없습니다."}
        if user["status"] not in ["ACTIVE", "DELETE_SCHEDULED"]:
            return None, {"ok": False, "reason": f"계정 상태 오류: {user['status']}"}
        return user, None


def user_wallet(user_id: str) -> Optional[sqlite3.Row]:
    with db() as conn:
        return conn.execute("SELECT * FROM wallets WHERE user_id=?", (user_id,)).fetchone()


def write_user_folder(user_id: str, wallet: Dict[str, Any], meta: Dict[str, Any]) -> None:
    folder = USER_DATA_DIR / user_id
    folder.mkdir(parents=True, exist_ok=True)
    atomic_json(folder / "wallet_public.json", wallet)
    atomic_json(folder / "user_meta.json", meta)


def balance_of(address: str) -> float:
    with db() as conn:
        row = conn.execute("SELECT balance FROM balances WHERE address=?", (address,)).fetchone()
        return round(float(row["balance"]), 8) if row else 0.0


def set_balance(conn: sqlite3.Connection, address: str, value: float) -> None:
    conn.execute("INSERT OR REPLACE INTO balances(address,balance) VALUES(?,?)", (address, round(float(value), 8)))


def add_balance(conn: sqlite3.Connection, address: str, delta: float) -> None:
    row = conn.execute("SELECT balance FROM balances WHERE address=?", (address,)).fetchone()
    cur = float(row["balance"]) if row else 0.0
    set_balance(conn, address, cur + float(delta))


def tx_hash(tx: Dict[str, Any]) -> str:
    temp = dict(tx)
    temp.pop("hash", None)
    return sha256_text(stable_json(temp))


def make_transfer(sender: str, receiver: str, amount: float, fee: float = 0.001) -> Dict[str, Any]:
    tx = {
        "type": "TRANSFER",
        "sender": sender,
        "receiver": receiver,
        "amount": round(float(amount), 8),
        "fee": round(float(fee), 8),
        "time": now(),
        "nonce": secrets.randbits(64),
    }
    tx["hash"] = tx_hash(tx)
    return tx


def validate_transfer(tx: Dict[str, Any]) -> Tuple[bool, str]:
    if not str(tx.get("sender", "")).startswith("SNC_"):
        return False, "송신 주소 오류"
    if not str(tx.get("receiver", "")).startswith("SNC_"):
        return False, "수신 주소 오류"
    try:
        amount = float(tx["amount"])
        fee = float(tx["fee"])
    except Exception:
        return False, "금액 형식 오류"
    if amount <= 0:
        return False, "금액은 0보다 커야 합니다."
    if fee < 0:
        return False, "수수료 오류"
    if tx_hash(tx) != tx["hash"]:
        return False, "TX 해시 불일치"
    if balance_of(tx["sender"]) < amount + fee:
        return False, "잔액 부족"
    return True, "OK"


def build_block_from_submit(miner_address: str, nonce: int, proof: int, loop_count: int) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    index = current_height() + 1
    previous = last_hash()
    difficulty = current_difficulty()
    seed = PROOF.seed_for_block(index, previous)
    reward = next_reward()

    if reward <= 0:
        return False, "MAX_SUPPLY_REACHED", None

    expected_proof = PROOF.proof_value(seed, int(nonce), int(loop_count))
    if int(proof) != int(expected_proof):
        return False, "proof 불일치", None

    target = PROOF.target(difficulty)
    if int(proof) >= target:
        return False, "난이도 조건 실패", None

    block = {
        "index": index,
        "previous": previous,
        "time": now(),
        "miner": miner_address,
        "reward": reward,
        "difficulty": difficulty,
        "loop_count": int(loop_count),
        "nonce": int(nonce),
        "seed": int(seed),
        "proof": int(proof),
        "transactions": [],
    }
    block["hash"] = calc_block_hash(block)
    return True, "OK", block


def commit_block(block: Dict[str, Any]) -> Tuple[bool, str]:
    with SERVER_LOCK:
        latest = last_block()
        if latest and block["previous"] != latest["block_hash"]:
            return False, "이전 해시가 현재 서버 체인과 다릅니다. 다시 채굴해야 합니다."
        if total_supply() + float(block["reward"]) > MAX_SUPPLY:
            return False, "총 발행량 초과"
        with db() as conn:
            try:
                conn.execute(
                    "INSERT INTO blocks(block_index,previous_hash,block_time,miner_address,reward,difficulty,loop_count,nonce,seed,proof,block_hash,tx_count,raw_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        int(block["index"]),
                        block["previous"],
                        int(block["time"]),
                        block["miner"],
                        float(block["reward"]),
                        int(block["difficulty"]),
                        int(block["loop_count"]),
                        str(block["nonce"]),
                        str(block["seed"]),
                        str(block["proof"]),
                        block["hash"],
                        len(block.get("transactions", [])),
                        stable_json(block),
                    )
                )
                add_balance(conn, block["miner"], float(block["reward"]))
                conn.commit()
            except sqlite3.IntegrityError:
                return False, "중복 블록"
        new_diff = supply_based_difficulty()
        state_set("difficulty", str(new_diff))
        log_line(f"블록 승인: height={block['index']} miner={block['miner']} reward={block['reward']} diff={new_diff}")
        return True, "ACCEPTED"


def inactive_cleanup_scan() -> Dict[str, Any]:
    now_ts = now()
    warned = 0
    deleted = 0
    with db() as conn:
        rows = conn.execute("SELECT * FROM users WHERE deleted_at=0 AND inactive_delete_agreed=1").fetchall()
        for u in rows:
            inactive_limit = int(u["last_login_at"]) + int(u["inactive_delete_days"]) * 86400
            scheduled_delete_at = int(u["scheduled_delete_at"] or 0)
            if now_ts >= inactive_limit and scheduled_delete_at <= 0:
                scheduled = now_ts + int(u["grace_days"]) * 86400
                conn.execute("UPDATE users SET status='DELETE_SCHEDULED', delete_warning_at=?, scheduled_delete_at=? WHERE user_id=?", (now_ts, scheduled, u["user_id"]))
                warned += 1
            elif scheduled_delete_at > 0 and now_ts >= scheduled_delete_at:
                conn.execute("UPDATE users SET status='DELETED', deleted_at=? WHERE user_id=?", (now_ts, u["user_id"]))
                deleted += 1
        conn.commit()
    return {"ok": True, "scheduled": warned, "deleted": deleted}


def cleanup_loop() -> None:
    while True:
        try:
            inactive_cleanup_scan()
        except Exception as e:
            log_line(f"cleanup error: {e}")
        time.sleep(3600)


def create_full_backup() -> Dict[str, Any]:
    backup_name = f"SafeNewCoin_ServerBackup_V20_FIXED_{now()}"
    work_dir = BACKUP_DIR / backup_name
    work_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    if DB_FILE.exists():
        shutil.copy2(DB_FILE, work_dir / DB_FILE.name)
        copied.append(DB_FILE.name)
    if LOG_FILE.exists():
        shutil.copy2(LOG_FILE, work_dir / LOG_FILE.name)
        copied.append(LOG_FILE.name)
    if USER_DATA_DIR.exists():
        shutil.copytree(USER_DATA_DIR, work_dir / "users", dirs_exist_ok=True)
        copied.append("users/")
    meta = {"app": APP_NAME, "version": APP_VERSION, "created_at": now(), "height": current_height(), "last_hash": last_hash(), "total_supply": total_supply(), "copied": copied}
    atomic_json(work_dir / "backup_meta.json", meta)
    zip_path = BACKUP_DIR / f"{backup_name}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in work_dir.rglob("*"):
            if p.is_file():
                z.write(p, arcname=str(p.relative_to(work_dir)))
    return {"ok": True, "backup_dir": str(work_dir), "zip_file": str(zip_path), "meta": meta}


def migration_mode_enabled() -> bool:
    return state_get("migration_mode", "0") == "1"


HTML = r'''
<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>SafeNewCoin Server V20 FIXED</title>
<style>body{margin:0;background:#07111f;color:#edf6ff;font-family:Arial,Malgun Gothic,sans-serif}.wrap{max-width:1200px;margin:0 auto;padding:24px}.hero,.card{border:1px solid rgba(255,255,255,.12);border-radius:22px;background:rgba(255,255,255,.07);padding:20px;margin-top:16px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.metric{font-size:30px;font-weight:900}.muted{color:#9bb0c8}.console{white-space:pre-wrap;background:#02060b;color:#9cffc7;border-radius:14px;padding:14px;min-height:220px;font-family:Consolas,monospace;font-size:12px}.btn{border:0;border-radius:12px;padding:12px 16px;font-weight:800;background:#4f7cff;color:white;cursor:pointer}@media(max-width:800px){.grid{grid-template-columns:1fr}}</style></head><body><div class="wrap"><div class="hero"><h1>SafeNewCoin Server V20 FIXED</h1><p class="muted">DB TEXT 저장 / 500 오류 방지 / 서버 검증형 온라인 구조</p></div><div class="grid"><div class="card"><div class="muted">HEIGHT</div><div id="height" class="metric">0</div></div><div class="card"><div class="muted">SUPPLY</div><div id="supply" class="metric">0</div></div><div class="card"><div class="muted">DIFFICULTY</div><div id="difficulty" class="metric">1</div></div><div class="card"><div class="muted">USERS</div><div id="users" class="metric">0</div></div></div><div class="card"><button class="btn" onclick="refresh()">새로고침</button> <button class="btn" onclick="backup()">백업</button><div id="box" class="console">loading</div></div></div><script>async function api(u,o){const r=await fetch(u,o);return await r.json()}function j(x){return JSON.stringify(x,null,2)}async function refresh(){const s=await api('/api/status');height.textContent=s.height;supply.textContent=s.total_supply;difficulty.textContent=s.difficulty;users.textContent=s.users;box.textContent=j(s)}async function backup(){box.textContent=j(await api('/api/admin/backup/full',{method:'POST'}))}setInterval(refresh,2000);refresh()</script></body></html>
'''

app = Flask(__name__)


def json_error(reason: str, status: int = 500):
    log_line(f"ERROR: {reason}")
    return jsonify({"ok": False, "reason": reason}), status


@app.errorhandler(Exception)
def handle_exception(e):
    tb = traceback.format_exc()
    log_line(tb)
    return jsonify({"ok": False, "reason": str(e), "traceback_tail": tb[-2000:]}), 500


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/status")
def api_status():
    with db() as conn:
        user_count = conn.execute("SELECT COUNT(*) AS c FROM users WHERE deleted_at=0").fetchone()["c"]
        tx_count = conn.execute("SELECT COUNT(*) AS c FROM transactions").fetchone()["c"]
        submit_count = conn.execute("SELECT COUNT(*) AS c FROM mining_submits").fetchone()["c"]
    return jsonify({"ok": True, "app": APP_NAME, "version": APP_VERSION, "height": current_height(), "last_hash": last_hash(), "difficulty": current_difficulty(), "total_supply": total_supply(), "max_supply": MAX_SUPPLY, "next_reward": next_reward(), "users": user_count, "transactions": tx_count, "mining_submits": submit_count, "migration_mode": migration_mode_enabled(), "db_file": str(DB_FILE), "time": now()})


@app.route("/api/auth/register", methods=["POST"])
def api_register():
    if migration_mode_enabled():
        return jsonify({"ok": False, "reason": "서버 이전 모드입니다."}), 503
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    agreed = bool(data.get("inactive_delete_agreed", False))
    if len(username) < 3:
        return jsonify({"ok": False, "reason": "아이디는 3글자 이상이어야 합니다."})
    if len(username) > 32:
        return jsonify({"ok": False, "reason": "아이디는 32글자 이하이어야 합니다."})
    if len(password) < 6:
        return jsonify({"ok": False, "reason": "비밀번호는 6글자 이상이어야 합니다."})
    if not agreed:
        return jsonify({"ok": False, "reason": "장기 미접속 자동 삭제 정책에 동의해야 가입할 수 있습니다."})
    user_id = make_user_id()
    wallet = make_wallet()
    created = now()
    with SERVER_LOCK:
        try:
            with db() as conn:
                conn.execute("INSERT INTO users(user_id,username,password_hash,created_at,last_login_at,inactive_delete_agreed,inactive_delete_days,grace_days,status) VALUES(?,?,?,?,?,?,?,?,?)", (user_id, username, hash_password(password), created, created, 1, INACTIVE_DELETE_DAYS, INACTIVE_GRACE_DAYS, "ACTIVE"))
                conn.execute("INSERT INTO wallets(user_id,address,public_key,private_key_hash,created_at) VALUES(?,?,?,?,?)", (user_id, wallet["address"], wallet["public_key"], wallet["private_key_hash"], created))
                conn.execute("INSERT OR IGNORE INTO balances(address,balance) VALUES(?,0)", (wallet["address"],))
                conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({"ok": False, "reason": "이미 존재하는 아이디입니다."})
    write_user_folder(user_id, wallet, {"user_id": user_id, "username": username, "created_at": created})
    token = make_token(user_id)
    log_line(f"회원가입 완료: {username} / {wallet['address']}")
    return jsonify({"ok": True, "user_id": user_id, "username": username, "address": wallet["address"], "token": token})


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=? AND deleted_at=0", (username,)).fetchone()
        if not user or not verify_password(password, user["password_hash"]):
            return jsonify({"ok": False, "reason": "아이디 또는 비밀번호가 틀렸습니다."})
        conn.execute("UPDATE users SET last_login_at=?, status='ACTIVE', delete_warning_at=0, scheduled_delete_at=0 WHERE user_id=?", (now(), user["user_id"]))
        conn.commit()
    wallet = user_wallet(user["user_id"])
    return jsonify({"ok": True, "token": make_token(user["user_id"]), "user_id": user["user_id"], "username": username, "address": wallet["address"] if wallet else "", "balance": balance_of(wallet["address"]) if wallet else 0})


@app.route("/api/me")
def api_me():
    user, err = get_current_user()
    if err:
        return jsonify(err), 401
    wallet = user_wallet(user["user_id"])
    return jsonify({"ok": True, "user_id": user["user_id"], "username": user["username"], "status": user["status"], "wallet": {"address": wallet["address"] if wallet else "", "balance": balance_of(wallet["address"]) if wallet else 0}})


@app.route("/api/wallet/balance")
def api_wallet_balance():
    user, err = get_current_user()
    if err:
        return jsonify(err), 401
    wallet = user_wallet(user["user_id"])
    if not wallet:
        return jsonify({"ok": False, "reason": "지갑 없음"})
    return jsonify({"ok": True, "address": wallet["address"], "balance": balance_of(wallet["address"])})


@app.route("/api/mining/job")
def api_mining_job():
    user, err = get_current_user()
    if err:
        return jsonify(err), 401
    wallet = user_wallet(user["user_id"])
    loop_count = int(request.args.get("loop_count", "192"))
    index = current_height() + 1
    previous = last_hash()
    difficulty = current_difficulty()
    seed = PROOF.seed_for_block(index, previous)
    return jsonify({"ok": True, "job": {"index": index, "previous": previous, "difficulty": difficulty, "target": PROOF.target(difficulty), "seed": seed, "loop_count": loop_count, "miner": wallet["address"], "reward": next_reward(), "server_time": now()}})


@app.route("/api/mining/submit", methods=["POST"])
def api_mining_submit():
    try:
        if migration_mode_enabled():
            return jsonify({"ok": False, "reason": "서버 이전 모드입니다."}), 503
        user, err = get_current_user()
        if err:
            return jsonify(err), 401
        wallet = user_wallet(user["user_id"])
        if not wallet:
            return jsonify({"ok": False, "reason": "지갑 없음"})
        data = request.get_json(silent=True) or {}
        nonce = int(data.get("nonce", 0))
        proof = int(data.get("proof", 0))
        loop_count = int(data.get("loop_count", 192))
        ok, reason, block = build_block_from_submit(wallet["address"], nonce, proof, loop_count)
        accepted = 0
        block_index = -1
        if ok and block:
            ok2, reason2 = commit_block(block)
            ok = ok2
            reason = reason2
            if ok2:
                accepted = 1
                block_index = int(block["index"])
        submit_id = "SUBMIT_" + uuid.uuid4().hex
        with db() as conn:
            conn.execute("INSERT INTO mining_submits(submit_id,user_id,address,submitted_at,accepted,reason,block_index,nonce,proof) VALUES(?,?,?,?,?,?,?,?,?)", (submit_id, user["user_id"], wallet["address"], now(), accepted, reason, block_index, str(nonce), str(proof)))
            conn.commit()
        return jsonify({"ok": bool(accepted), "reason": reason, "submit_id": submit_id, "block": block if accepted else None, "balance": balance_of(wallet["address"])})
    except Exception as e:
        tb = traceback.format_exc()
        log_line(tb)
        return jsonify({"ok": False, "reason": str(e), "traceback_tail": tb[-2000:]}), 500


@app.route("/api/tx/send", methods=["POST"])
def api_tx_send():
    if migration_mode_enabled():
        return jsonify({"ok": False, "reason": "서버 이전 모드입니다."}), 503
    user, err = get_current_user()
    if err:
        return jsonify(err), 401
    wallet = user_wallet(user["user_id"])
    data = request.get_json(silent=True) or {}
    amount = float(data.get("amount", 0))
    tx = make_transfer(wallet["address"], str(data.get("receiver", "")).strip(), amount)
    ok, reason = validate_transfer(tx)
    if not ok:
        return jsonify({"ok": False, "reason": reason, "tx": tx})
    with SERVER_LOCK:
        with db() as conn:
            try:
                add_balance(conn, tx["sender"], -float(tx["amount"]) - float(tx["fee"]))
                add_balance(conn, tx["receiver"], float(tx["amount"]))
                conn.execute("INSERT INTO transactions(tx_hash,tx_type,sender,receiver,amount,fee,created_at,block_index,raw_json) VALUES(?,?,?,?,?,?,?,?,?)", (tx["hash"], tx["type"], tx["sender"], tx["receiver"], tx["amount"], tx["fee"], tx["time"], -1, stable_json(tx)))
                conn.commit()
            except sqlite3.IntegrityError:
                return jsonify({"ok": False, "reason": "중복 거래"})
    return jsonify({"ok": True, "reason": "TX_ACCEPTED", "tx": tx, "balance": balance_of(wallet["address"])})


@app.route("/api/tx/history")
def api_tx_history():
    user, err = get_current_user()
    if err:
        return jsonify(err), 401
    wallet = user_wallet(user["user_id"])
    address = wallet["address"]
    with db() as conn:
        rows = conn.execute("SELECT * FROM transactions WHERE sender=? OR receiver=? ORDER BY created_at DESC LIMIT 100", (address, address)).fetchall()
    return jsonify({"ok": True, "address": address, "transactions": [dict(r) for r in rows]})


@app.route("/api/explorer/search")
def api_explorer_search():
    q = str(request.args.get("q", "")).strip()
    result = {"blocks": [], "transactions": []}
    with db() as conn:
        if not q:
            rows = conn.execute("SELECT * FROM blocks ORDER BY block_index DESC LIMIT 25").fetchall()
            result["blocks"] = [json.loads(r["raw_json"]) for r in rows]
            return jsonify(result)
        if q.isdigit():
            row = conn.execute("SELECT * FROM blocks WHERE block_index=?", (int(q),)).fetchone()
            if row:
                result["blocks"].append(json.loads(row["raw_json"]))
        rows = conn.execute("SELECT * FROM blocks WHERE block_hash LIKE ? OR miner_address LIKE ? ORDER BY block_index DESC LIMIT 50", (f"%{q}%", f"%{q}%")).fetchall()
        for r in rows:
            b = json.loads(r["raw_json"])
            if b not in result["blocks"]:
                result["blocks"].append(b)
        txs = conn.execute("SELECT * FROM transactions WHERE tx_hash LIKE ? OR sender LIKE ? OR receiver LIKE ? ORDER BY created_at DESC LIMIT 100", (f"%{q}%", f"%{q}%", f"%{q}%")).fetchall()
        result["transactions"] = [dict(r) for r in txs]
    return jsonify(result)


@app.route("/api/admin/inactive_cleanup", methods=["POST"])
def api_admin_cleanup():
    return jsonify(inactive_cleanup_scan())


@app.route("/api/admin/backup/full", methods=["POST"])
def api_admin_backup():
    return jsonify(create_full_backup())


@app.route("/api/admin/migration", methods=["POST"])
def api_admin_migration():
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled", False))
    state_set("migration_mode", "1" if enabled else "0")
    return jsonify({"ok": True, "migration_mode": enabled})


def boot() -> None:
    init_db()
    create_genesis_if_needed()
    if not state_get("difficulty"):
        state_set("difficulty", str(DEFAULT_DIFFICULTY))
    threading.Thread(target=cleanup_loop, daemon=True).start()
    log_line(f"{APP_NAME} {APP_VERSION} started")
    log_line(f"DB: {DB_FILE}")


boot()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
