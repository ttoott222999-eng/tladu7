# ============================================================
# SafeNewCoin Server V19
# 서버 전용 코드
#
# 기능:
# - Flask 서버
# - 회원가입 / 로그인
# - 비밀번호 해시 저장
# - 토큰 로그인
# - 유저별 고유 ID 관리
# - 장기 미접속 자동 삭제 동의
# - 2년 미접속 + 30일 유예 삭제 정책
# - 지갑 자동 생성
# - 잔액 / 거래 / 블록 저장
# - 클라이언트 채굴 결과 제출 API
# - 서버 검증 후 보상 지급
# - 송금 API
# - 블록 탐색 API
# - 전체 백업 / 마이그레이션 모드
#
# 실행:
#   python SafeNewCoin_Server_V19.py
#
# 설치:
#   pip install flask
#
# Render 실행 명령 예:
#   gunicorn SafeNewCoin_Server_V19:app
#
# Render 환경변수 추천:
#   SECRET_KEY=원하는_긴_랜덤문자
#   PORT=10000
# ============================================================

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
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, request, render_template_string


# ============================================================
# 기본 설정
# ============================================================

APP_NAME = "SafeNewCoin"
APP_VERSION = "V19 SERVER ONLINE"
COIN_SYMBOL = "SNC"

MAX_SUPPLY = 52_000_000.0
INITIAL_REWARD = 1.0
MIN_REWARD = 0.0001
HALVING_INTERVAL = 1_000_000
DEFAULT_DIFFICULTY = 1
TARGET_BLOCK_TIME = 3.0

INACTIVE_DELETE_DAYS = 730          # 2년
INACTIVE_GRACE_DAYS = 30            # 삭제 전 유예 30일
TOKEN_EXPIRE_SECONDS = 60 * 60 * 24 * 30

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "safe_newcoin_server_data"
USER_DATA_DIR = DATA_DIR / "users"
BACKUP_DIR = DATA_DIR / "backups"
MIGRATION_DIR = DATA_DIR / "migration"
DB_FILE = DATA_DIR / "server_v19.db"
LOG_FILE = DATA_DIR / "server_v19.log"

for d in [DATA_DIR, USER_DATA_DIR, BACKUP_DIR, MIGRATION_DIR]:
    d.mkdir(parents=True, exist_ok=True)

SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET_KEY_SAFE_NEWCOIN_V19")
PORT = int(os.environ.get("PORT", "8788"))

SERVER_LOCK = threading.RLock()


# ============================================================
# 공통 유틸
# ============================================================

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
    address = make_address(public_key)
    return {
        "address": address,
        "public_key": public_key,
        "private_key_hash": sha256_text(private_key),
        "created_at": now(),
        "warning": "서버형 V19에서는 private_key 원문을 서버 DB에 저장하지 않습니다."
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
    token = base64.urlsafe_b64encode(f"{raw}:{sig}".encode("utf-8")).decode("utf-8").rstrip("=")
    return token


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


# ============================================================
# DB
# ============================================================

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
            created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
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
            nonce INTEGER NOT NULL,
            seed INTEGER NOT NULL,
            proof INTEGER NOT NULL,
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
            nonce INTEGER DEFAULT 0,
            proof INTEGER DEFAULT 0
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


# ============================================================
# Proof / Block 검증
# ============================================================

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
    value = state_get("difficulty", str(DEFAULT_DIFFICULTY))
    try:
        return max(1, min(15, int(value)))
    except Exception:
        return DEFAULT_DIFFICULTY


def supply_based_difficulty() -> int:
    current = total_supply()
    diff = 1 + int((current / MAX_SUPPLY) * 14)
    return max(1, min(15, diff))


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
            (0, "GENESIS", genesis["time"], "GENESIS", 0.0, 1, 1, 0, 0, 0, genesis["hash"], 0, stable_json(genesis))
        )
        conn.commit()
    log_line("제네시스 블록 생성 완료")


# ============================================================
# 인증 / 사용자 관리
# ============================================================

def get_current_user() -> Tuple[Optional[sqlite3.Row], Optional[Dict[str, Any]]]:
    token = get_bearer_token()
    user_id = parse_token(token)
    if not user_id:
        return None, {"ok": False, "reason": "로그인이 필요합니다."}
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE user_id=? AND deleted_at=0", (user_id,)).fetchone()
        if not user:
            return None, {"ok": False, "reason": "사용자를 찾을 수 없습니다."}
        if user["status"] != "ACTIVE":
            return None, {"ok": False, "reason": f"계정 상태가 ACTIVE가 아닙니다: {user['status']}"}
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


# ============================================================
# 거래
# ============================================================

def tx_hash(tx: Dict[str, Any]) -> str:
    temp = dict(tx)
    temp.pop("hash", None)
    temp.pop("signature", None)
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
    for k in ["sender", "receiver", "amount", "fee", "time", "nonce", "hash"]:
        if k not in tx:
            return False, f"TX 필드 없음: {k}"
    if not str(tx["sender"]).startswith("SNC_"):
        return False, "송신 주소 오류"
    if not str(tx["receiver"]).startswith("SNC_"):
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


# ============================================================
# 채굴 제출 / 블록 생성
# ============================================================

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
                        int(block["index"]), block["previous"], int(block["time"]), block["miner"],
                        float(block["reward"]), int(block["difficulty"]), int(block["loop_count"]),
                        int(block["nonce"]), int(block["seed"]), int(block["proof"]), block["hash"],
                        len(block.get("transactions", [])), stable_json(block)
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


# ============================================================
# 장기 미접속 자동 삭제
# ============================================================

def inactive_cleanup_scan() -> Dict[str, Any]:
    now_ts = now()
    warned = 0
    deleted = 0
    targets = []

    with db() as conn:
        rows = conn.execute("SELECT * FROM users WHERE deleted_at=0 AND inactive_delete_agreed=1").fetchall()
        for u in rows:
            last_login = int(u["last_login_at"])
            inactive_days = int(u["inactive_delete_days"])
            grace_days = int(u["grace_days"])
            delete_warning_at = int(u["delete_warning_at"] or 0)
            scheduled_delete_at = int(u["scheduled_delete_at"] or 0)

            inactive_limit = last_login + inactive_days * 86400
            if now_ts >= inactive_limit and scheduled_delete_at <= 0:
                scheduled = now_ts + grace_days * 86400
                conn.execute(
                    "UPDATE users SET status='DELETE_SCHEDULED', delete_warning_at=?, scheduled_delete_at=? WHERE user_id=?",
                    (now_ts, scheduled, u["user_id"])
                )
                warned += 1
                targets.append({"user_id": u["user_id"], "action": "DELETE_SCHEDULED"})

            elif scheduled_delete_at > 0 and now_ts >= scheduled_delete_at:
                conn.execute(
                    "UPDATE users SET status='DELETED', deleted_at=? WHERE user_id=?",
                    (now_ts, u["user_id"])
                )
                deleted += 1
                targets.append({"user_id": u["user_id"], "action": "DELETED"})

                user_folder = USER_DATA_DIR / u["user_id"]
                if user_folder.exists():
                    trash = BACKUP_DIR / f"deleted_user_{u['user_id']}_{now_ts}"
                    try:
                        shutil.move(str(user_folder), str(trash))
                    except Exception:
                        pass

        conn.commit()

    if warned or deleted:
        log_line(f"장기 미접속 정리: scheduled={warned}, deleted={deleted}")
    return {"ok": True, "scheduled": warned, "deleted": deleted, "targets": targets}


def cleanup_loop() -> None:
    while True:
        try:
            inactive_cleanup_scan()
            time.sleep(3600)
        except Exception as e:
            log_line(f"cleanup error: {e}")
            time.sleep(3600)


# ============================================================
# 백업 / 서버 이전
# ============================================================

def create_full_backup() -> Dict[str, Any]:
    backup_name = f"SafeNewCoin_ServerBackup_V19_{now()}"
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

    meta = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "created_at": now(),
        "created_text": ts(),
        "height": current_height(),
        "last_hash": last_hash(),
        "total_supply": total_supply(),
        "copied": copied,
        "migration_note": "새 서버에 코드 배포 후 DB와 users 폴더를 복원하면 이전 가능합니다."
    }
    atomic_json(work_dir / "backup_meta.json", meta)

    zip_path = BACKUP_DIR / f"{backup_name}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in work_dir.rglob("*"):
            if p.is_file():
                z.write(p, arcname=str(p.relative_to(work_dir)))

    return {"ok": True, "backup_dir": str(work_dir), "zip_file": str(zip_path), "meta": meta}


def migration_mode_enabled() -> bool:
    return state_get("migration_mode", "0") == "1"


# ============================================================
# HTML 관리 페이지
# ============================================================

HTML = r'''
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SafeNewCoin Server V19</title>
<style>
:root{--bg:#07111f;--card:rgba(255,255,255,.07);--line:rgba(255,255,255,.12);--text:#edf6ff;--muted:#9bb0c8;--blue:#4f7cff;--green:#19bf72;--red:#ff4d4d;--orange:#ff9f1c}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0%,#1e3458,#07111f 45%,#02060b);color:var(--text);font-family:Arial,Malgun Gothic,sans-serif}.wrap{max-width:1380px;margin:0 auto;padding:22px}.hero{display:flex;justify-content:space-between;gap:14px;align-items:center;border:1px solid var(--line);border-radius:26px;padding:24px;background:linear-gradient(135deg,rgba(79,124,255,.22),rgba(25,191,114,.12));box-shadow:0 20px 50px rgba(0,0,0,.25)}h1{margin:0;font-size:34px}p{color:var(--muted)}.grid{display:grid;gap:14px}.g4{grid-template-columns:repeat(4,1fr)}.g3{grid-template-columns:repeat(3,1fr)}.g2{grid-template-columns:repeat(2,1fr)}.card{border:1px solid var(--line);border-radius:22px;padding:17px;background:var(--card)}.card b{display:block;color:var(--muted);font-size:12px;margin-bottom:8px}.card strong{font-size:25px}.section{margin-top:18px}.badge{padding:10px 14px;border-radius:999px;background:rgba(255,255,255,.12);font-weight:800}.on{background:rgba(25,191,114,.22);color:#91ffc7}.off{background:rgba(255,159,28,.2);color:#ffd38a}.btn{border:0;border-radius:14px;padding:12px 16px;background:var(--blue);color:white;font-weight:800;cursor:pointer}.green{background:var(--green)}.red{background:var(--red)}.orange{background:var(--orange);color:#241500}.input{width:100%;padding:13px;border-radius:14px;border:1px solid var(--line);background:rgba(255,255,255,.07);color:white}.console{height:260px;overflow:auto;white-space:pre-wrap;background:#02060b;border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:14px;color:#b8ffd3;font-family:Consolas,monospace;font-size:12px}.row{display:flex;gap:10px;flex-wrap:wrap}@media(max-width:900px){.g4,.g3,.g2{grid-template-columns:1fr}.hero{flex-direction:column;align-items:flex-start}}
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <div><h1>SafeNewCoin Server V19</h1><p>회원가입 / 로그인 / DB / 서버 검증 / 장기 미접속 삭제 / 서버 이전 백업</p></div>
    <div class="row"><span id="health" class="badge on">SERVER</span><span id="migration" class="badge off">MIGRATION OFF</span></div>
  </div>

  <div class="section grid g4">
    <div class="card"><b>블록 높이</b><strong id="height">0</strong></div>
    <div class="card"><b>총 발행량</b><strong id="supply">0</strong></div>
    <div class="card"><b>난이도</b><strong id="difficulty">1</strong></div>
    <div class="card"><b>회원 수</b><strong id="users">0</strong></div>
  </div>

  <div class="section grid g2">
    <div class="card">
      <h2>회원가입 테스트</h2>
      <input id="regUser" class="input" placeholder="아이디"><br><br>
      <input id="regPass" class="input" placeholder="비밀번호" type="password"><br><br>
      <label><input id="agree" type="checkbox"> 2년 미접속 + 30일 유예 후 자동 삭제에 동의합니다.</label><br><br>
      <button class="btn green" onclick="register()">회원가입</button>
      <div id="regBox" class="console">대기</div>
    </div>
    <div class="card">
      <h2>로그인 테스트</h2>
      <input id="loginUser" class="input" placeholder="아이디"><br><br>
      <input id="loginPass" class="input" placeholder="비밀번호" type="password"><br><br>
      <button class="btn green" onclick="login()">로그인</button>
      <button class="btn" onclick="me()">내 정보</button>
      <div id="loginBox" class="console">토큰 없음</div>
    </div>
  </div>

  <div class="section grid g2">
    <div class="card">
      <h2>관리 기능</h2>
      <div class="row">
        <button class="btn orange" onclick="cleanup()">장기 미접속 검사</button>
        <button class="btn green" onclick="backup()">전체 백업</button>
        <button class="btn red" onclick="migrationOn()">마이그레이션 ON</button>
        <button class="btn" onclick="migrationOff()">마이그레이션 OFF</button>
      </div>
      <div id="adminBox" class="console">관리 대기</div>
    </div>
    <div class="card">
      <h2>블록 탐색</h2>
      <input id="q" class="input" placeholder="주소 / 해시 / 블록번호"><br><br>
      <button class="btn" onclick="search()">검색</button>
      <div id="searchBox" class="console">최근 블록</div>
    </div>
  </div>

  <div class="section card">
    <h2>서버 상태</h2>
    <div id="statusBox" class="console">로드중</div>
  </div>
</div>
<script>
let TOKEN='';
async function api(url,opt={}){opt.headers=opt.headers||{};if(TOKEN)opt.headers['Authorization']='Bearer '+TOKEN;const r=await fetch(url,opt);return await r.json();}
function j(x){return JSON.stringify(x,null,2)}
async function refresh(){const s=await api('/api/status');height.textContent=s.height;supply.textContent=s.total_supply;difficulty.textContent=s.difficulty;users.textContent=s.users;statusBox.textContent=j(s);migration.textContent=s.migration_mode?'MIGRATION ON':'MIGRATION OFF';migration.className='badge '+(s.migration_mode?'on':'off')}
async function register(){const r=await api('/api/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:regUser.value,password:regPass.value,inactive_delete_agreed:agree.checked})});regBox.textContent=j(r);refresh()}
async function login(){const r=await api('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:loginUser.value,password:loginPass.value})});if(r.token)TOKEN=r.token;loginBox.textContent=j(r);refresh()}
async function me(){const r=await api('/api/me');loginBox.textContent=j(r)}
async function cleanup(){const r=await api('/api/admin/inactive_cleanup',{method:'POST'});adminBox.textContent=j(r);refresh()}
async function backup(){const r=await api('/api/admin/backup/full',{method:'POST'});adminBox.textContent=j(r);refresh()}
async function migrationOn(){const r=await api('/api/admin/migration',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:true})});adminBox.textContent=j(r);refresh()}
async function migrationOff(){const r=await api('/api/admin/migration',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:false})});adminBox.textContent=j(r);refresh()}
async function search(){const r=await api('/api/explorer/search?q='+encodeURIComponent(q.value));searchBox.textContent=j(r)}
setInterval(refresh,2000);refresh();
</script>
</body>
</html>
'''


# ============================================================
# Flask API
# ============================================================

app = Flask(__name__)


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/status")
def api_status():
    with db() as conn:
        user_count = conn.execute("SELECT COUNT(*) AS c FROM users WHERE deleted_at=0").fetchone()["c"]
        tx_count = conn.execute("SELECT COUNT(*) AS c FROM transactions").fetchone()["c"]
        submit_count = conn.execute("SELECT COUNT(*) AS c FROM mining_submits").fetchone()["c"]
    return jsonify({
        "ok": True,
        "app": APP_NAME,
        "version": APP_VERSION,
        "height": current_height(),
        "last_hash": last_hash(),
        "difficulty": current_difficulty(),
        "total_supply": total_supply(),
        "max_supply": MAX_SUPPLY,
        "next_reward": next_reward(),
        "users": user_count,
        "transactions": tx_count,
        "mining_submits": submit_count,
        "migration_mode": migration_mode_enabled(),
        "inactive_policy": {
            "delete_days": INACTIVE_DELETE_DAYS,
            "grace_days": INACTIVE_GRACE_DAYS
        },
        "time": now()
    })


@app.route("/api/auth/register", methods=["POST"])
def api_register():
    if migration_mode_enabled():
        return jsonify({"ok": False, "reason": "서버 이전 모드입니다. 신규 가입이 일시 중지되었습니다."}), 503

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    agreed = bool(data.get("inactive_delete_agreed", False))

    if not username or len(username) < 3:
        return jsonify({"ok": False, "reason": "아이디는 3글자 이상이어야 합니다."})
    if len(username) > 32:
        return jsonify({"ok": False, "reason": "아이디는 32글자 이하이어야 합니다."})
    if not password or len(password) < 6:
        return jsonify({"ok": False, "reason": "비밀번호는 6글자 이상이어야 합니다."})
    if not agreed:
        return jsonify({"ok": False, "reason": "장기 미접속 자동 삭제 정책에 동의해야 가입할 수 있습니다."})

    user_id = make_user_id()
    wallet = make_wallet()
    created = now()

    with SERVER_LOCK:
        try:
            with db() as conn:
                conn.execute(
                    "INSERT INTO users(user_id,username,password_hash,created_at,last_login_at,inactive_delete_agreed,inactive_delete_days,grace_days,status) VALUES(?,?,?,?,?,?,?,?,?)",
                    (user_id, username, hash_password(password), created, created, 1, INACTIVE_DELETE_DAYS, INACTIVE_GRACE_DAYS, "ACTIVE")
                )
                conn.execute(
                    "INSERT INTO wallets(user_id,address,public_key,private_key_hash,created_at) VALUES(?,?,?,?,?)",
                    (user_id, wallet["address"], wallet["public_key"], wallet["private_key_hash"], created)
                )
                conn.execute("INSERT OR IGNORE INTO balances(address,balance) VALUES(?,0)", (wallet["address"],))
                conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({"ok": False, "reason": "이미 존재하는 아이디입니다."})

    write_user_folder(user_id, wallet, {
        "user_id": user_id,
        "username": username,
        "created_at": created,
        "inactive_delete_agreed": True,
        "inactive_delete_days": INACTIVE_DELETE_DAYS,
        "grace_days": INACTIVE_GRACE_DAYS
    })

    token = make_token(user_id)
    log_line(f"회원가입 완료: {username} / {user_id} / {wallet['address']}")
    return jsonify({
        "ok": True,
        "user_id": user_id,
        "username": username,
        "address": wallet["address"],
        "token": token,
        "inactive_policy": "2년 미접속 + 30일 유예 후 자동 삭제"
    })


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=? AND deleted_at=0", (username,)).fetchone()
        if not user or not verify_password(password, user["password_hash"]):
            return jsonify({"ok": False, "reason": "아이디 또는 비밀번호가 틀렸습니다."})
        if user["status"] == "DELETED":
            return jsonify({"ok": False, "reason": "삭제된 계정입니다."})

        conn.execute(
            "UPDATE users SET last_login_at=?, status='ACTIVE', delete_warning_at=0, scheduled_delete_at=0 WHERE user_id=?",
            (now(), user["user_id"])
        )
        conn.commit()

    wallet = user_wallet(user["user_id"])
    token = make_token(user["user_id"])
    log_line(f"로그인: {username} / {user['user_id']}")
    return jsonify({
        "ok": True,
        "token": token,
        "user_id": user["user_id"],
        "username": username,
        "address": wallet["address"] if wallet else "",
        "balance": balance_of(wallet["address"]) if wallet else 0
    })


@app.route("/api/me")
def api_me():
    user, err = get_current_user()
    if err:
        return jsonify(err), 401
    wallet = user_wallet(user["user_id"])
    return jsonify({
        "ok": True,
        "user_id": user["user_id"],
        "username": user["username"],
        "status": user["status"],
        "created_at": user["created_at"],
        "last_login_at": user["last_login_at"],
        "inactive_delete_agreed": bool(user["inactive_delete_agreed"]),
        "scheduled_delete_at": user["scheduled_delete_at"],
        "wallet": {
            "address": wallet["address"] if wallet else "",
            "balance": balance_of(wallet["address"]) if wallet else 0
        }
    })


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
    index = current_height() + 1
    previous = last_hash()
    difficulty = current_difficulty()
    loop_count = int(request.args.get("loop_count", "192"))
    seed = PROOF.seed_for_block(index, previous)
    return jsonify({
        "ok": True,
        "job": {
            "index": index,
            "previous": previous,
            "difficulty": difficulty,
            "target": PROOF.target(difficulty),
            "seed": seed,
            "loop_count": loop_count,
            "miner": wallet["address"],
            "reward": next_reward(),
            "server_time": now()
        }
    })


@app.route("/api/mining/submit", methods=["POST"])
def api_mining_submit():
    if migration_mode_enabled():
        return jsonify({"ok": False, "reason": "서버 이전 모드입니다. 채굴 제출이 일시 중지되었습니다."}), 503

    user, err = get_current_user()
    if err:
        return jsonify(err), 401
    wallet = user_wallet(user["user_id"])
    if not wallet:
        return jsonify({"ok": False, "reason": "지갑 없음"})

    data = request.get_json(silent=True) or {}
    try:
        nonce = int(data.get("nonce", 0))
        proof = int(data.get("proof", 0))
        loop_count = int(data.get("loop_count", 192))
    except Exception:
        return jsonify({"ok": False, "reason": "nonce/proof 형식 오류"})

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
        conn.execute(
            "INSERT INTO mining_submits(submit_id,user_id,address,submitted_at,accepted,reason,block_index,nonce,proof) VALUES(?,?,?,?,?,?,?,?,?)",
            (submit_id, user["user_id"], wallet["address"], now(), accepted, reason, block_index, nonce, proof)
        )
        conn.commit()

    return jsonify({
        "ok": bool(accepted),
        "reason": reason,
        "submit_id": submit_id,
        "block": block if accepted else None,
        "balance": balance_of(wallet["address"])
    })


@app.route("/api/tx/send", methods=["POST"])
def api_tx_send():
    if migration_mode_enabled():
        return jsonify({"ok": False, "reason": "서버 이전 모드입니다. 송금이 일시 중지되었습니다."}), 503

    user, err = get_current_user()
    if err:
        return jsonify(err), 401
    wallet = user_wallet(user["user_id"])
    if not wallet:
        return jsonify({"ok": False, "reason": "지갑 없음"})

    data = request.get_json(silent=True) or {}
    receiver = str(data.get("receiver", "")).strip()
    try:
        amount = float(data.get("amount", 0))
    except Exception:
        return jsonify({"ok": False, "reason": "금액 오류"})

    tx = make_transfer(wallet["address"], receiver, amount)
    ok, reason = validate_transfer(tx)
    if not ok:
        return jsonify({"ok": False, "reason": reason, "tx": tx})

    with SERVER_LOCK:
        with db() as conn:
            try:
                add_balance(conn, tx["sender"], -float(tx["amount"]) - float(tx["fee"]))
                add_balance(conn, tx["receiver"], float(tx["amount"]))
                conn.execute(
                    "INSERT INTO transactions(tx_hash,tx_type,sender,receiver,amount,fee,created_at,block_index,raw_json) VALUES(?,?,?,?,?,?,?,?,?)",
                    (tx["hash"], tx["type"], tx["sender"], tx["receiver"], tx["amount"], tx["fee"], tx["time"], -1, stable_json(tx))
                )
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
        rows = conn.execute(
            "SELECT * FROM transactions WHERE sender=? OR receiver=? ORDER BY created_at DESC LIMIT 100",
            (address, address)
        ).fetchall()
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
    log_line(f"마이그레이션 모드 변경: {'ON' if enabled else 'OFF'}")
    return jsonify({"ok": True, "migration_mode": enabled})


# ============================================================
# 시작
# ============================================================

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
