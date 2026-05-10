# ============================================================
# SafeNewCoin GPU Integrated V16 -> V18
# 파일명: SafeNewCoin_GPU_Integrated_V18.py
#
# V8 GPU CUDA 커널 + V15 지갑/체인/송금/총량/네트워크 준비 UI 통합
# 실제 GPU mode일 때 GPU로 nonce 탐색
# CUDA 실패 시 CPU fallback
#
# 실행:
#   python SafeNewCoin_GPU_Integrated_V18.py
#
# 필수:
#   python -m pip install flask
#
# GPU 채굴용:
#   NVIDIA Driver
#   python -m pip install numpy cuda-python
# ============================================================

import os
import sys
import json
import time
import uuid
import base64
import atexit
import shutil
import zipfile
import secrets
import hashlib
import tempfile
import threading
import subprocess
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, request, render_template_string


CUDA_AVAILABLE = False
CUDA_ERROR = ""

try:
    import numpy as np
    from cuda.bindings import driver as cuda
    from cuda.bindings import nvrtc
    CUDA_AVAILABLE = True
except Exception as e:
    CUDA_AVAILABLE = False
    CUDA_ERROR = str(e)


APP_NAME = "SafeNewCoin"
APP_VERSION = "V18 SUPPLY DIFFICULTY"
APP_FILE_NAME = "SafeNewCoin_GPU_Integrated_V18.py"
COIN_SYMBOL = "SNC"

MAX_SUPPLY = 52_000_000
HALVING_INTERVAL = 1_000_000
INITIAL_REWARD = 1.0
MIN_REWARD = 0.0001

DEFAULT_DIFFICULTY = 1
TARGET_BLOCK_TIME = 3.0

LOCAL_HOST = "127.0.0.1"
LOCAL_PORT = 8787

THREADS_PER_BLOCK = 256
CPU_BATCH = 100_000

DEFAULT_GPU_BLOCKS = 16_384
DEFAULT_LOOP_COUNT = 192
MAX_GPU_TEMP = 65
TARGET_GPU_UTIL = 55


def get_app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


APP_DIR = get_app_dir()
os.chdir(APP_DIR)

DATA_DIR = APP_DIR / "safe_newcoin_data"
CHAIN_DIR = DATA_DIR / "chain"
WALLET_DIR = DATA_DIR / "wallet"
BACKUP_DIR = DATA_DIR / "backup"
EXPORT_DIR = DATA_DIR / "wallet_backup"

CONFIG_FILE = DATA_DIR / "config_v16.json"
STATE_FILE = DATA_DIR / "state_v16.json"
CHAIN_FILE = CHAIN_DIR / "chain_v16.jsonl"
SNAPSHOT_FILE = CHAIN_DIR / "chain_snapshot_v16.json"
TRANSACTION_FILE = DATA_DIR / "transactions_v16.jsonl"
MEMPOOL_FILE = DATA_DIR / "mempool_v16.json"
NETWORK_FILE = DATA_DIR / "network_v16.json"
LOG_FILE = DATA_DIR / "safe_newcoin_v16.log"

for d in [DATA_DIR, CHAIN_DIR, WALLET_DIR, BACKUP_DIR, EXPORT_DIR]:
    d.mkdir(parents=True, exist_ok=True)


def now() -> int:
    return int(time.time())


def ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def stable_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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


def append_jsonl(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(stable_json(data) + "\n")
        f.flush()
        os.fsync(f.fileno())


def read_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default


def log_line(msg: str) -> None:
    line = f"[{ts()}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def parse_int(value: str, default: int = 0) -> int:
    try:
        return int(str(value).replace("%", "").strip().split(",")[0])
    except Exception:
        return default


def run_cmd(args: List[str]) -> str:
    try:
        return subprocess.check_output(args, stderr=subprocess.DEVNULL).decode(errors="ignore").strip()
    except Exception:
        return ""


DEFAULT_CONFIG = {
    "version": APP_VERSION,
    "network_mode": False,
    "server_url": "",
    "auto_open_browser": True,
    "target_block_time": TARGET_BLOCK_TIME,
    "difficulty": DEFAULT_DIFFICULTY,
    "max_supply": MAX_SUPPLY,
    "halving_interval": HALVING_INTERVAL,
    "gpu_mode_enabled": True,
    "gpu_blocks": DEFAULT_GPU_BLOCKS,
    "loop_count": DEFAULT_LOOP_COUNT,
    "target_gpu_util": TARGET_GPU_UTIL,
    "max_gpu_temp": MAX_GPU_TEMP,
    "auto_tune": True,
    "log_mined_blocks": True,
}


def load_config() -> Dict[str, Any]:
    cfg = read_json(CONFIG_FILE, DEFAULT_CONFIG.copy())
    changed = False
    for k, v in DEFAULT_CONFIG.items():
        if k not in cfg:
            cfg[k] = v
            changed = True
    if changed or not CONFIG_FILE.exists():
        atomic_json(CONFIG_FILE, cfg)
    return cfg


def save_config(cfg: Dict[str, Any]) -> None:
    atomic_json(CONFIG_FILE, cfg)


CONFIG = load_config()


PRIVATE_KEY_FILE = WALLET_DIR / "private_v16.key"
PUBLIC_KEY_FILE = WALLET_DIR / "public_v16.key"
WALLET_FILE = WALLET_DIR / "wallet_v16.json"
RECOVERY_FILE = WALLET_DIR / "recovery_v16.json"


class WalletManager:
    def __init__(self):
        self.lock = threading.RLock()
        self.wallet = self.load_or_create_wallet()

    def create_private_key(self) -> str:
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")

    def public_from_private(self, private_key: str) -> str:
        return sha256_text("PUBLIC:" + private_key)

    def address_from_public(self, public_key: str) -> str:
        return "SNC_" + sha256_text("ADDR:" + public_key)[:40]

    def load_or_create_wallet(self) -> Dict[str, Any]:
        with self.lock:
            if WALLET_FILE.exists():
                try:
                    data = json.loads(WALLET_FILE.read_text(encoding="utf-8"))
                    if PRIVATE_KEY_FILE.exists():
                        log_line(f"지갑 로드 완료: {data.get('address', '')}")
                        return data
                except Exception:
                    try:
                        shutil.copy2(WALLET_FILE, BACKUP_DIR / f"broken_wallet_v16_{now()}.json")
                    except Exception:
                        pass

            private_key = self.create_private_key()
            public_key = self.public_from_private(private_key)
            address = self.address_from_public(public_key)

            wallet = {
                "version": APP_VERSION,
                "created": now(),
                "address": address,
                "public_key": public_key,
                "private_key_hash": sha256_text(private_key),
            }

            PRIVATE_KEY_FILE.write_text(private_key, encoding="utf-8")
            PUBLIC_KEY_FILE.write_text(public_key, encoding="utf-8")
            atomic_json(WALLET_FILE, wallet)
            log_line(f"새 지갑 생성: {address}")
            return wallet

    def get_private_key(self) -> str:
        return PRIVATE_KEY_FILE.read_text(encoding="utf-8").strip()

    def get_address(self) -> str:
        return self.wallet.get("address", "")

    def sign(self, payload: Dict[str, Any]) -> str:
        return sha256_text(stable_json(payload) + ":" + self.get_private_key())

    def create_recovery_key(self) -> str:
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")

    def create_backup_package(self) -> Dict[str, Any]:
        recovery_key = self.create_recovery_key()
        recovery_data = {
            "created": now(),
            "address": self.get_address(),
            "recovery_key": recovery_key,
            "version": APP_VERSION,
            "warning": "private.key는 절대 공유하지 마세요.",
        }
        atomic_json(RECOVERY_FILE, recovery_data)

        backup_file = EXPORT_DIR / f"SafeNewCoin_WalletBackup_V16_{now()}.zip"
        with zipfile.ZipFile(backup_file, "w", zipfile.ZIP_DEFLATED) as z:
            for p in [WALLET_FILE, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, RECOVERY_FILE, SNAPSHOT_FILE]:
                if p.exists():
                    z.write(p, arcname=p.name)

        return {"ok": True, "backup_file": str(backup_file), "recovery_key": recovery_key}

    def status(self) -> Dict[str, Any]:
        return {
            "address": self.get_address(),
            "wallet_exists": WALLET_FILE.exists(),
            "private_key": PRIVATE_KEY_FILE.exists(),
            "public_key": PUBLIC_KEY_FILE.exists(),
            "recovery_file": RECOVERY_FILE.exists(),
            "backup_dir": str(EXPORT_DIR),
        }


WALLET = WalletManager()


class TransactionManager:
    def __init__(self):
        self.lock = threading.RLock()
        self.mempool: List[Dict[str, Any]] = read_json(MEMPOOL_FILE, [])
        self.history: List[Dict[str, Any]] = self.load_history()

    def load_history(self) -> List[Dict[str, Any]]:
        result = []
        if TRANSACTION_FILE.exists():
            with open(TRANSACTION_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        result.append(json.loads(line.strip()))
                    except Exception:
                        pass
        return result[-1000:]

    def tx_hash(self, tx: Dict[str, Any]) -> str:
        temp = dict(tx)
        temp.pop("hash", None)
        temp.pop("signature", None)
        return sha256_text(stable_json(temp))

    def create_tx(self, sender: str, receiver: str, amount: float, fee: float = 0.001) -> Dict[str, Any]:
        tx = {
            "type": "TRANSFER",
            "sender": sender,
            "receiver": receiver,
            "amount": float(amount),
            "fee": float(fee),
            "time": now(),
            "nonce": secrets.randbits(64),
        }
        tx["hash"] = self.tx_hash(tx)
        tx["signature"] = WALLET.sign(tx) if sender == WALLET.get_address() else "EXTERNAL_UNSIGNED"
        return tx

    def validate_tx(self, tx: Dict[str, Any], balance_lookup=None) -> Tuple[bool, str]:
        for k in ["sender", "receiver", "amount", "fee", "time", "nonce", "hash"]:
            if k not in tx:
                return False, f"TX 필드 없음: {k}"

        if not str(tx["sender"]).startswith("SNC_"):
            return False, "송신 주소 오류"
        if not str(tx["receiver"]).startswith("SNC_"):
            return False, "수신 주소 오류"

        try:
            amount = float(tx["amount"])
            fee = float(tx.get("fee", 0))
        except Exception:
            return False, "금액 형식 오류"

        if amount <= 0:
            return False, "금액 오류"
        if fee < 0:
            return False, "수수료 오류"
        if self.tx_hash(tx) != tx["hash"]:
            return False, "TX 해시 불일치"

        if balance_lookup:
            if balance_lookup(tx["sender"]) < amount + fee:
                return False, "잔액 부족"

        return True, "OK"

    def add_tx(self, tx: Dict[str, Any], balance_lookup=None) -> Tuple[bool, str]:
        with self.lock:
            ok, reason = self.validate_tx(tx, balance_lookup)
            if not ok:
                return False, reason

            for t in self.mempool:
                if t.get("hash") == tx.get("hash"):
                    return False, "중복 거래"

            self.mempool.append(tx)
            atomic_json(MEMPOOL_FILE, self.mempool)
            return True, "TX_ACCEPTED"

    def pop_for_block(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.lock:
            txs = self.mempool[:limit]
            self.mempool = self.mempool[limit:]
            atomic_json(MEMPOOL_FILE, self.mempool)
            return txs

    def commit_txs(self, txs: List[Dict[str, Any]]) -> None:
        with self.lock:
            for tx in txs:
                append_jsonl(TRANSACTION_FILE, tx)
                self.history.append(tx)
            self.history = self.history[-1000:]

    def status(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "pool_count": len(self.mempool),
                "history_count": len(self.history),
                "pool": self.mempool[-30:],
                "history": self.history[-50:],
            }


TX = TransactionManager()


CUDA_KERNEL = r'''
extern "C" __global__
void mine_kernel(
    unsigned long long seed,
    unsigned long long start_nonce,
    unsigned long long target,
    unsigned int loop_count,
    unsigned long long *found_nonce,
    unsigned int *found
)
{
    unsigned long long idx = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned long long nonce = start_nonce + idx;
    unsigned long long x = seed ^ nonce;

    for (unsigned int i = 0; i < loop_count; i++)
    {
        x ^= 0x9E3779B97F4A7C15ULL;
        x *= 0xBF58476D1CE4E5B9ULL;
        x ^= (x >> 27);
        x *= 0x94D049BB133111EBULL;
        x ^= (x >> 31);
    }

    if (x < target)
    {
        if (atomicCAS(found, 0, 1) == 0)
        {
            found_nonce[0] = nonce;
        }
    }
}
'''


class CPUMixMiner:
    def mix64_loop(self, x: int, loop_count: int) -> int:
        x &= 0xFFFFFFFFFFFFFFFF
        for _ in range(loop_count):
            x ^= 0x9E3779B97F4A7C15
            x = (x * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
            x ^= (x >> 27)
            x = (x * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
            x ^= (x >> 31)
        return x & 0xFFFFFFFFFFFFFFFF

    def mine_batch(self, seed: int, start_nonce: int, target: int, blocks: int, loop_count: int) -> Optional[int]:
        for i in range(CPU_BATCH):
            nonce = start_nonce + i
            x = self.mix64_loop(seed ^ nonce, loop_count)
            if x < target:
                return nonce
        return None


class CUDAMixMiner:
    def __init__(self):
        if not CUDA_AVAILABLE:
            raise RuntimeError(f"cuda-python not installed: {CUDA_ERROR}")

        self.ctx = None
        self.device = None
        self.kernel = None
        self.module = None
        self.d_nonce = None
        self.d_found = None
        self.gpu_info = {}
        self.init_cuda()

    def check_cuda(self, result, name):
        err = result[0]
        if err != cuda.CUresult.CUDA_SUCCESS:
            raise RuntimeError(f"{name} failed: {err}")
        return result[1:] if len(result) > 1 else ()

    def check_nvrtc(self, result, name):
        err = result[0]
        if err != nvrtc.nvrtcResult.NVRTC_SUCCESS:
            raise RuntimeError(f"{name} failed: {err}")
        return result[1:] if len(result) > 1 else ()

    def device_info(self, dev, index: int):
        name, = self.check_cuda(cuda.cuDeviceGetName(100, dev), f"name {index}")
        major, = self.check_cuda(cuda.cuDeviceGetAttribute(cuda.CUdevice_attribute.CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, dev), f"major {index}")
        minor, = self.check_cuda(cuda.cuDeviceGetAttribute(cuda.CUdevice_attribute.CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, dev), f"minor {index}")
        mp, = self.check_cuda(cuda.cuDeviceGetAttribute(cuda.CUdevice_attribute.CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT, dev), f"mp {index}")
        mem, = self.check_cuda(cuda.cuDeviceTotalMem(dev), f"mem {index}")

        return {
            "index": index,
            "name": name.decode(errors="ignore").strip(),
            "arch": f"sm_{major}{minor}",
            "major": int(major),
            "minor": int(minor),
            "mp": int(mp),
            "memory_mb": int(mem // (1024 * 1024)),
            "score": int(mp) * 100000 + int(mem // (1024 * 1024)),
        }

    def choose_gpu(self):
        self.check_cuda(cuda.cuInit(0), "cuInit")
        count, = self.check_cuda(cuda.cuDeviceGetCount(), "cuDeviceGetCount")
        if count <= 0:
            raise RuntimeError("CUDA device not found")

        devices = []
        for i in range(count):
            dev, = self.check_cuda(cuda.cuDeviceGet(i), f"cuDeviceGet {i}")
            info = self.device_info(dev, i)
            devices.append((i, dev, info))

        devices.sort(key=lambda x: x[2]["score"], reverse=True)
        return devices[0], [x[2] for x in devices]

    def init_cuda(self):
        (best_i, best_dev, best_info), all_devices = self.choose_gpu()
        self.device = best_dev
        self.gpu_info = dict(best_info)
        self.gpu_info["devices"] = all_devices

        arch = best_info["arch"].encode()

        self.ctx, = self.check_cuda(cuda.cuCtxCreate(cuda.CUctxCreateParams(), 0, self.device), "cuCtxCreate")
        self.check_cuda(cuda.cuCtxSetCurrent(self.ctx), "cuCtxSetCurrent init")

        prog, = self.check_nvrtc(nvrtc.nvrtcCreateProgram(CUDA_KERNEL.encode(), b"mine_kernel.cu", 0, [], []), "nvrtcCreateProgram")

        opts = [b"--gpu-architecture=" + arch, b"--std=c++14"]
        err, = nvrtc.nvrtcCompileProgram(prog, len(opts), opts)

        _, log_size = nvrtc.nvrtcGetProgramLogSize(prog)
        if log_size > 1:
            buf = bytearray(log_size)
            nvrtc.nvrtcGetProgramLog(prog, buf)
            compile_log = bytes(buf).decode(errors="ignore").strip()
            if compile_log:
                log_line("[NVRTC LOG]\n" + compile_log)

        if err != nvrtc.nvrtcResult.NVRTC_SUCCESS:
            raise RuntimeError(f"NVRTC compile failed: {err}")

        cubin_size, = self.check_nvrtc(nvrtc.nvrtcGetCUBINSize(prog), "nvrtcGetCUBINSize")
        cubin = bytearray(cubin_size)
        self.check_nvrtc(nvrtc.nvrtcGetCUBIN(prog, cubin), "nvrtcGetCUBIN")

        self.module, = self.check_cuda(cuda.cuModuleLoadData(bytes(cubin)), "cuModuleLoadData")
        self.kernel, = self.check_cuda(cuda.cuModuleGetFunction(self.module, b"mine_kernel"), "cuModuleGetFunction")
        self.d_nonce, = self.check_cuda(cuda.cuMemAlloc(8), "cuMemAlloc nonce")
        self.d_found, = self.check_cuda(cuda.cuMemAlloc(4), "cuMemAlloc found")

        log_line(f"GPU Miner Ready: index={best_i} / {best_info['name']} / arch={best_info['arch']}")

    def mine_batch(self, seed: int, start_nonce: int, target: int, blocks: int, loop_count: int) -> Optional[int]:
        import ctypes

        self.check_cuda(cuda.cuCtxSetCurrent(self.ctx), "cuCtxSetCurrent")

        zero = np.array([0], dtype=np.uint32)
        self.check_cuda(cuda.cuMemcpyHtoD(self.d_found, zero.ctypes.data, 4), "cuMemcpyHtoD found")

        seed_arg = ctypes.c_ulonglong(seed)
        nonce_arg = ctypes.c_ulonglong(start_nonce)
        target_arg = ctypes.c_ulonglong(target)
        loop_arg = ctypes.c_uint(loop_count)

        nonce_ptr = ctypes.c_void_p(int(self.d_nonce))
        found_ptr = ctypes.c_void_p(int(self.d_found))

        params = (ctypes.c_void_p * 6)(
            ctypes.cast(ctypes.byref(seed_arg), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(nonce_arg), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(target_arg), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(loop_arg), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(nonce_ptr), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(found_ptr), ctypes.c_void_p),
        )

        self.check_cuda(
            cuda.cuLaunchKernel(
                self.kernel,
                int(blocks), 1, 1,
                THREADS_PER_BLOCK, 1, 1,
                0, cuda.CUstream(0), params, 0
            ),
            "cuLaunchKernel"
        )

        self.check_cuda(cuda.cuCtxSynchronize(), "cuCtxSynchronize")

        found = np.zeros(1, dtype=np.uint32)
        self.check_cuda(cuda.cuMemcpyDtoH(found.ctypes.data, self.d_found, 4), "cuMemcpyDtoH found")

        if found[0]:
            result = np.zeros(1, dtype=np.uint64)
            self.check_cuda(cuda.cuMemcpyDtoH(result.ctypes.data, self.d_nonce, 8), "cuMemcpyDtoH nonce")
            return int(result[0])

        return None


class ProofEngine:
    def __init__(self):
        self.lock = threading.RLock()
        self.gpu_error = ""
        self.gpu = None
        self.cpu = CPUMixMiner()
        self.mode = "CPU"
        self.nonce_hashes = 0
        self.work_hashes = 0
        self.started = time.time()
        self.last_batch = 0

        if CONFIG.get("gpu_mode_enabled", True):
            try:
                self.gpu = CUDAMixMiner()
                self.mode = "GPU"
            except Exception as e:
                self.gpu_error = str(e)
                self.mode = "CPU"
                log_line(f"GPU unavailable, fallback to CPU: {e}")

    def target(self, difficulty: int) -> int:
        difficulty = max(1, min(15, int(difficulty)))
        return 1 << max(1, 64 - difficulty * 4)

    def seed_for_block(self, index: int, previous: str) -> int:
        return int(sha256_text(f"{index}:{previous}")[:16], 16)

    def proof_value_cpu(self, seed: int, nonce: int, loop_count: int) -> int:
        return self.cpu.mix64_loop(seed ^ nonce, loop_count)

    def mine_nonce(self, seed: int, difficulty: int, loop_count: int, blocks: int) -> Tuple[int, int, float]:
        target = self.target(difficulty)
        nonce = 0
        batch = THREADS_PER_BLOCK * int(blocks) if self.mode == "GPU" else CPU_BATCH
        start = time.time()

        while True:
            with self.lock:
                engine = self.gpu if self.mode == "GPU" and self.gpu is not None else self.cpu
                mode = self.mode

            found = engine.mine_batch(seed, nonce, target, int(blocks), int(loop_count))

            self.nonce_hashes += batch
            self.work_hashes += batch * int(loop_count)
            self.last_batch = batch

            if found is not None:
                elapsed = max(0.0001, time.time() - start)
                return int(found), self.proof_value_cpu(seed, int(found), loop_count), elapsed

            nonce += batch

            if mode == "CPU" and nonce > 50_000_000:
                raise RuntimeError("CPU_LOOP_LIMIT")

    def status(self) -> Dict[str, Any]:
        elapsed = max(time.time() - self.started, 1)
        gpu_info = {}
        if self.gpu is not None:
            gpu_info = self.gpu.gpu_info

        return {
            "mode": self.mode,
            "gpu_error": self.gpu_error,
            "nonce_hashes": self.nonce_hashes,
            "work_hashes": self.work_hashes,
            "nonce_speed": self.nonce_hashes / elapsed,
            "work_speed": self.work_hashes / elapsed,
            "last_batch": self.last_batch,
            "gpu_info": gpu_info,
        }


PROOF = ProofEngine()


def calc_reward(height: int) -> float:
    halvings = height // HALVING_INTERVAL
    reward = INITIAL_REWARD / (2 ** halvings)
    return max(MIN_REWARD, round(reward, 8))


def calc_block_hash(block: Dict[str, Any]) -> str:
    temp = dict(block)
    temp.pop("hash", None)
    return sha256_text(stable_json(temp))


def validate_block(block: Dict[str, Any], prev: Optional[Dict[str, Any]], seen_hashes: set) -> Tuple[bool, str]:
    for k in ["index", "previous", "time", "miner", "reward", "difficulty", "loop_count", "nonce", "seed", "proof", "transactions", "hash"]:
        if k not in block:
            return False, f"필수값 없음: {k}"

    try:
        index = int(block["index"])
        difficulty = int(block["difficulty"])
        reward = float(block["reward"])
        nonce = int(block["nonce"])
        seed = int(block["seed"])
        proof = int(block["proof"])
        loop_count = int(block["loop_count"])
        block_time = int(block["time"])
    except Exception:
        return False, "숫자 필드 오류"

    if index < 0:
        return False, "블록 번호 오류"
    if difficulty < 1 or difficulty > 15:
        return False, "난이도 범위 오류"
    if reward < 0 or reward > INITIAL_REWARD:
        return False, "보상값 오류"
    if not str(block["miner"]).startswith("SNC_"):
        return False, "지갑 주소 오류"
    if block["hash"] in seen_hashes:
        return False, "중복 블록 해시"
    if calc_block_hash(block) != block["hash"]:
        return False, "해시 불일치"

    if prev is None:
        if index != 0:
            return False, "제네시스 오류"
    else:
        if index != int(prev["index"]) + 1:
            return False, "블록 번호 순서 오류"
        if block["previous"] != prev["hash"]:
            return False, "이전 해시 연결 오류"
        if block_time < int(prev["time"]) - 120:
            return False, "시간 역행 오류"

        expected_seed = PROOF.seed_for_block(index, block["previous"])
        if seed != expected_seed:
            return False, "seed 불일치"

        expected_proof = PROOF.proof_value_cpu(seed, nonce, loop_count)
        if proof != expected_proof:
            return False, "proof 불일치"

        target = PROOF.target(difficulty)
        if proof >= target:
            return False, "난이도 조건 실패"

    return True, "OK"


class Blockchain:
    def __init__(self):
        self.lock = threading.RLock()
        self.blocks: List[Dict[str, Any]] = []
        self.seen_hashes = set()
        self.stats = {
            "health": "INIT",
            "repair_count": 0,
            "duplicate_rejects": 0,
            "invalid_rejects": 0,
            "safe_save_count": 0,
            "last_safe_save": 0,
            "last_error": "",
            "last_block_time": 0.0,
            "difficulty": max(1, min(15, int(CONFIG.get("difficulty", DEFAULT_DIFFICULTY)))),
            "logs": [],
        }
        self.load_or_repair()
        atexit.register(self.safe_shutdown)

    def log(self, msg: str) -> None:
        with self.lock:
            line = f"[{time.strftime('%H:%M:%S')}] {msg}"
            self.stats["logs"].append(line)
            self.stats["logs"] = self.stats["logs"][-150:]
            log_line(msg)

    def load_chain_file(self) -> List[Dict[str, Any]]:
        blocks = []
        if not CHAIN_FILE.exists():
            return blocks
        with open(CHAIN_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    blocks.append(json.loads(line))
                except Exception:
                    break
        return blocks

    def validate_chain(self, blocks: List[Dict[str, Any]]) -> Tuple[bool, int, str]:
        seen = set()
        prev = None
        for i, b in enumerate(blocks):
            ok, reason = validate_block(b, prev, seen)
            if not ok:
                return False, i, reason
            seen.add(b["hash"])
            prev = b
        return True, len(blocks), "OK"

    def rewrite_chain(self, blocks: List[Dict[str, Any]]) -> None:
        atomic_write(CHAIN_FILE, "".join(stable_json(b) + "\n" for b in blocks))

    def load_or_repair(self) -> None:
        with self.lock:
            blocks = self.load_chain_file()
            ok, good_count, reason = self.validate_chain(blocks)

            if not ok:
                self.stats["repair_count"] += 1
                if CHAIN_FILE.exists():
                    try:
                        shutil.copy2(CHAIN_FILE, BACKUP_DIR / f"broken_chain_v16_{now()}.jsonl")
                    except Exception:
                        pass
                blocks = blocks[:good_count]
                self.rewrite_chain(blocks)
                self.stats["health"] = "REPAIRED"
                self.log(f"체인 자동 복구: {reason} / 정상 {good_count}개")
            else:
                self.stats["health"] = "OK"
                self.log("체인 검증 완료")

            self.blocks = blocks
            self.seen_hashes = {b["hash"] for b in blocks}
            if not self.blocks:
                self.create_genesis()
            self.safe_snapshot()

    def create_genesis(self) -> None:
        genesis = {
            "index": 0,
            "previous": "GENESIS",
            "time": now(),
            "miner": WALLET.get_address(),
            "reward": 0,
            "difficulty": 1,
            "loop_count": int(CONFIG.get("loop_count", DEFAULT_LOOP_COUNT)),
            "nonce": 0,
            "seed": 0,
            "proof": 0,
            "transactions": [],
        }
        genesis["hash"] = calc_block_hash(genesis)
        append_jsonl(CHAIN_FILE, genesis)
        self.blocks.append(genesis)
        self.seen_hashes.add(genesis["hash"])
        self.log("제네시스 블록 생성")

    def current_height(self) -> int:
        return int(self.blocks[-1]["index"]) if self.blocks else 0

    def last_hash(self) -> str:
        return self.blocks[-1]["hash"] if self.blocks else "GENESIS"

    def total_supply(self) -> float:
        return round(sum(float(b.get("reward", 0)) for b in self.blocks), 8)

    def balance_of(self, address: str) -> float:
        balance = 0.0
        for b in self.blocks:
            if b.get("miner") == address:
                balance += float(b.get("reward", 0))
            for tx in b.get("transactions", []):
                if tx.get("sender") == address:
                    balance -= float(tx.get("amount", 0)) + float(tx.get("fee", 0))
                if tx.get("receiver") == address:
                    balance += float(tx.get("amount", 0))
        return round(balance, 8)

    def next_reward(self) -> float:
        remaining = MAX_SUPPLY - self.total_supply()
        if remaining <= 0:
            return 0.0
        return min(calc_reward(self.current_height() + 1), remaining)

    def auto_adjust_difficulty(self) -> int:
        if len(self.blocks) < 40:
            return int(self.stats["difficulty"])

        recent = self.blocks[-40:]
        times = [int(b["time"]) for b in recent]
        span = max(1, times[-1] - times[0])
        avg = span / max(1, len(times) - 1)

        target_time = float(CONFIG.get("target_block_time", TARGET_BLOCK_TIME))
        difficulty = int(self.stats["difficulty"])

        if avg < target_time * 0.50 and difficulty < 15:
            difficulty += 1
            self.log(f"난이도 자동 상승: 평균 {avg:.2f}s -> {difficulty}")
        elif avg > target_time * 2.0 and difficulty > 1:
            difficulty -= 1
            self.log(f"난이도 자동 하락: 평균 {avg:.2f}s -> {difficulty}")

        difficulty = max(1, min(15, difficulty))
        self.stats["difficulty"] = difficulty
        self.stats["last_block_time"] = avg
        CONFIG["difficulty"] = difficulty
        save_config(CONFIG)
        return difficulty

    def supply_based_difficulty(self, current_supply: float) -> int:
        if MAX_SUPPLY <= 0:
            return 1
        diff = 1 + int((current_supply / MAX_SUPPLY) * 14)
        return max(1, min(15, diff))

    def add_block(self, block: Dict[str, Any]) -> Tuple[bool, str]:
        with self.lock:
            if block.get("hash") in self.seen_hashes:
                self.stats["duplicate_rejects"] += 1
                return False, "중복 블록"

            prev = self.blocks[-1] if self.blocks else None
            ok, reason = validate_block(block, prev, self.seen_hashes)
            if not ok:
                self.stats["invalid_rejects"] += 1
                self.stats["last_error"] = reason
                self.log(f"비정상 블록 차단: {reason}")
                return False, reason

            if self.total_supply() + float(block.get("reward", 0)) > MAX_SUPPLY:
                return False, "총 발행량 초과"

            append_jsonl(CHAIN_FILE, block)
            self.blocks.append(block)
            self.seen_hashes.add(block["hash"])
            TX.commit_txs(block.get("transactions", []))
            
            self.stats["difficulty"] = self.supply_based_difficulty(
                self.total_supply()
            )

            CONFIG["difficulty"] = self.stats["difficulty"]

            save_config(CONFIG)
            self.light_save()

            if len(self.blocks) % 100 == 0:
                self.safe_snapshot()

            return True, "ACCEPTED"

    def mine_block_once(self) -> Tuple[bool, str, Optional[Dict[str, Any]], float]:
        with self.lock:
            reward = self.next_reward()
            if reward <= 0:
                return False, "MAX_SUPPLY_REACHED", None, 0.0

            index = self.current_height() + 1
            previous = self.last_hash()
            difficulty = int(self.stats["difficulty"])
            loop_count = int(CONFIG.get("loop_count", DEFAULT_LOOP_COUNT))
            blocks = int(CONFIG.get("gpu_blocks", DEFAULT_GPU_BLOCKS))
            seed = PROOF.seed_for_block(index, previous)
            txs = TX.pop_for_block(100)

        try:
            nonce, proof, elapsed = PROOF.mine_nonce(seed, difficulty, loop_count, blocks)
        except Exception as e:
            self.stats["last_error"] = str(e)
            return False, str(e), None, 0.0

        block = {
            "index": index,
            "previous": previous,
            "time": now(),
            "miner": WALLET.get_address(),
            "reward": reward,
            "difficulty": difficulty,
            "loop_count": loop_count,
            "nonce": nonce,
            "seed": seed,
            "proof": proof,
            "transactions": txs,
            "mined_by": PROOF.mode,
        }
        block["hash"] = calc_block_hash(block)

        ok, reason = self.add_block(block)
        self.stats["last_block_time"] = elapsed
        return ok, reason, block, elapsed

    def safe_snapshot(self) -> None:
        data = {
            "saved_at": now(),
            "height": self.current_height(),
            "last_hash": self.last_hash(),
            "difficulty": self.stats["difficulty"],
            "total_supply": self.total_supply(),
            "my_balance": self.balance_of(WALLET.get_address()),
            "block_count": len(self.blocks),
        }
        atomic_json(SNAPSHOT_FILE, data)
        self.stats["safe_save_count"] += 1
        self.stats["last_safe_save"] = now()

    def light_save(self) -> None:
        atomic_json(STATE_FILE, self.status())

    def safe_shutdown(self) -> None:
        try:
            self.safe_snapshot()
            self.light_save()
            self.log("종료 전 안전 저장 완료")
        except Exception:
            pass

    def supply_status(self) -> Dict[str, Any]:
        current = self.total_supply()
        remaining = max(0.0, MAX_SUPPLY - current)
        percent = current / MAX_SUPPLY * 100 if MAX_SUPPLY else 0
        return {
            "max_supply": MAX_SUPPLY,
            "current_supply": current,
            "remaining_supply": round(remaining, 8),
            "progress_percent": round(percent, 6),
            "next_reward": self.next_reward(),
            "next_halving": ((self.current_height() // HALVING_INTERVAL) + 1) * HALVING_INTERVAL,
        }

    def status(self) -> Dict[str, Any]:
        with self.lock:
            size_mb = CHAIN_FILE.stat().st_size / 1024 / 1024 if CHAIN_FILE.exists() else 0
            return {
                "app": APP_NAME,
                "version": APP_VERSION,
                "file_name": APP_FILE_NAME,
                "health": self.stats["health"],
                "height": self.current_height(),
                "difficulty": self.stats["difficulty"],
                "address": WALLET.get_address(),
                "balance": self.balance_of(WALLET.get_address()),
                "total_supply": self.total_supply(),
                "max_supply": MAX_SUPPLY,
                "last_hash": self.last_hash(),
                "last_block_time": self.stats["last_block_time"],
                "chain_file_mb": round(size_mb, 3),
                "repair_count": self.stats["repair_count"],
                "duplicate_rejects": self.stats["duplicate_rejects"],
                "invalid_rejects": self.stats["invalid_rejects"],
                "safe_save_count": self.stats["safe_save_count"],
                "last_safe_save": self.stats["last_safe_save"],
                "last_error": self.stats["last_error"],
                "logs": self.stats["logs"][-100:],
                "recent_blocks": self.blocks[-25:],
            }


CHAIN = Blockchain()


class HardwareMonitor:
    def __init__(self):
        self.lock = threading.RLock()
        self.gpu_name = "CPU fallback"
        self.gpu_temp = 0
        self.gpu_util = 0
        self.gpu_vram = "CPU"
        self.gpu_available = False
        self.detect_gpu()
        threading.Thread(target=self.loop, daemon=True).start()

    def detect_gpu(self):
        name = run_cmd(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"])
        if name:
            with self.lock:
                self.gpu_name = name.splitlines()[0].strip()
                self.gpu_available = True
                self.gpu_vram = run_cmd(["nvidia-smi", "--query-gpu=memory.used,memory.total", "--format=csv,noheader,nounits"]) or "Unknown"

    def loop(self):
        while True:
            try:
                with self.lock:
                    available = self.gpu_available
                if available:
                    temp = parse_int(run_cmd(["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"]))
                    util = parse_int(run_cmd(["nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"]))
                    vram = run_cmd(["nvidia-smi", "--query-gpu=memory.used,memory.total", "--format=csv,noheader,nounits"]) or "Unknown"
                    with self.lock:
                        self.gpu_temp = temp
                        self.gpu_util = util
                        self.gpu_vram = vram

                        if temp >= 65:
                            run_cmd([
                                "nvidia-smi",
                                "-pl",
                                "300"
                            ])
                time.sleep(1)
            except Exception:
                time.sleep(2)

    def status(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "gpu_available": self.gpu_available,
                "gpu_name": self.gpu_name,
                "gpu_temp": self.gpu_temp,
                "gpu_util": self.gpu_util,
                "gpu_vram": self.gpu_vram,
            }


HW = HardwareMonitor()


class MinerController:
    def __init__(self):
        self.lock = threading.RLock()
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.last_result = "IDLE"
        self.blocks_found = 0
        self.block_speed = 0.0
        self.started_at = 0.0

    def start(self):
        with self.lock:
            if self.running:
                return
            self.running = True
            self.started_at = time.time()
            self.thread = threading.Thread(target=self.loop, daemon=True)
            self.thread.start()
            CHAIN.log("채굴 시작")

    def stop(self):
        with self.lock:
            self.running = False
            CHAIN.safe_snapshot()
            CHAIN.log("채굴 정지")

    def loop(self):
        while True:
            with self.lock:
                if not self.running:
                    break

            ok, reason, block, elapsed = CHAIN.mine_block_once()

            with self.lock:
                if ok and block:
                    self.blocks_found += 1
                    self.last_result = f"BLOCK {block['index']} OK / {block.get('mined_by', PROOF.mode)}"
                    if CONFIG.get("log_mined_blocks", True):
                        CHAIN.log(f"채굴 성공: 높이 {block['index']} / 보상 {block['reward']} {COIN_SYMBOL} / {block.get('mined_by', PROOF.mode)} / {elapsed:.4f}s")
                else:
                    self.last_result = reason
                    CHAIN.log(f"채굴 오류/대기: {reason}")

                self.block_speed = round(1.0 / max(elapsed, 0.001), 4)

            if not ok:
                time.sleep(0.3)

    def status(self) -> Dict[str, Any]:
        hw = HW.status()
        proof = PROOF.status()
        with self.lock:
            return {
                "running": self.running,
                "mode": proof["mode"],
                "last_result": self.last_result,
                "blocks_found": self.blocks_found,
                "block_speed": self.block_speed,
                "uptime": round(time.time() - self.started_at, 1) if self.started_at else 0,
                "gpu_error": proof["gpu_error"],
                "nonce_speed": proof["nonce_speed"],
                "work_speed": proof["work_speed"],
                "nonce_hashes": proof["nonce_hashes"],
                "work_hashes": proof["work_hashes"],
                "last_batch": proof["last_batch"],
                "gpu_info": proof["gpu_info"],
                "gpu_blocks": CONFIG.get("gpu_blocks", DEFAULT_GPU_BLOCKS),
                "loop_count": CONFIG.get("loop_count", DEFAULT_LOOP_COUNT),
                "target_gpu_util": CONFIG.get("target_gpu_util", TARGET_GPU_UTIL),
                "max_gpu_temp": CONFIG.get("max_gpu_temp", MAX_GPU_TEMP),
                **hw,
            }


MINER = MinerController()


class NetworkManager:
    def __init__(self):
        self.lock = threading.RLock()
        self.enabled = bool(CONFIG.get("network_mode", False))
        self.server_url = str(CONFIG.get("server_url", ""))
        self.last_sync = 0
        self.last_error = ""
        self.last_status = "LOCAL MODE"
        self.node_id = self.load_node_id()

    def load_node_id(self) -> str:
        data = read_json(NETWORK_FILE, {})
        if "node_id" not in data:
            data["node_id"] = "NODE_" + uuid.uuid4().hex[:16]
            atomic_json(NETWORK_FILE, data)
        return data["node_id"]

    def set_mode(self, enabled: bool, server_url: str = "") -> Dict[str, Any]:
        with self.lock:
            self.enabled = bool(enabled)
            if server_url:
                self.server_url = server_url
            CONFIG["network_mode"] = self.enabled
            CONFIG["server_url"] = self.server_url
            save_config(CONFIG)
            self.last_status = "NETWORK READY" if self.enabled else "LOCAL MODE"
            CHAIN.log(f"네트워크 모드 변경: {self.last_status}")
            return self.status()

    def connection_test(self) -> Dict[str, Any]:
        with self.lock:
            if not self.enabled:
                return {"ok": False, "status": "NETWORK OFF"}
            if not self.server_url:
                return {"ok": False, "status": "SERVER URL EMPTY"}
            self.last_status = "SERVER CONFIGURED"
            self.last_sync = now()
            return {"ok": True, "status": "READY_ONLY", "message": "서버 URL 저장됨. 서버 API 제작 후 실제 동기화 가능."}

    def export_sync_payload(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "address": WALLET.get_address(),
            "height": CHAIN.current_height(),
            "last_hash": CHAIN.last_hash(),
            "total_supply": CHAIN.total_supply(),
            "mempool": TX.mempool[-100:],
            "recent_blocks": CHAIN.blocks[-20:],
            "time": now(),
        }

    def status(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "enabled": self.enabled,
                "mode": "NETWORK" if self.enabled else "LOCAL",
                "server_url": self.server_url,
                "node_id": self.node_id,
                "last_sync": self.last_sync,
                "last_error": self.last_error,
                "last_status": self.last_status,
            }


NETWORK = NetworkManager()


def run_full_backup() -> Dict[str, Any]:
    target = BACKUP_DIR / f"FullBackup_V16_{now()}"
    target.mkdir(parents=True, exist_ok=True)

    copied = []
    for p in [CHAIN_FILE, SNAPSHOT_FILE, WALLET_FILE, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, RECOVERY_FILE, TRANSACTION_FILE, MEMPOOL_FILE, CONFIG_FILE, LOG_FILE]:
        if p.exists():
            try:
                shutil.copy2(p, target / p.name)
                copied.append(p.name)
            except Exception:
                pass

    meta = {"app": APP_NAME, "version": APP_VERSION, "address": WALLET.get_address(), "height": CHAIN.current_height(), "time": ts(), "copied": copied}
    atomic_json(target / "backup_meta.json", meta)

    zip_path = BACKUP_DIR / f"SafeNewCoin_FullBackup_V16_{now()}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in target.iterdir():
            z.write(p, arcname=p.name)

    return {"ok": True, "backup_dir": str(target), "zip_file": str(zip_path), "copied": copied}


HTML = r'''
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SafeNewCoin GPU V18</title>
<style>
:root{--bg:#07111f;--text:#edf6ff;--muted:#9bb0c8;--blue:#4f7cff;--green:#18b86b;--orange:#ff9f1c;--red:#ff4d4d;--line:rgba(255,255,255,.1)}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0%,#1e3458,#07111f 42%,#03070d);color:var(--text);font-family:Arial,Apple SD Gothic Neo,Malgun Gothic,sans-serif}button,input{font-family:inherit}.wrap{max-width:1450px;margin:0 auto;padding:22px}.hero{display:flex;justify-content:space-between;gap:18px;align-items:center;padding:24px;border-radius:28px;background:linear-gradient(135deg,rgba(79,124,255,.18),rgba(24,184,107,.12));border:1px solid var(--line);box-shadow:0 20px 60px rgba(0,0,0,.3)}.hero h1{margin:0;font-size:34px}.hero p{margin:8px 0 0;color:var(--muted)}.badge{display:inline-flex;align-items:center;padding:9px 14px;border-radius:999px;background:rgba(255,255,255,.12);font-weight:800}.badge.on{background:rgba(24,184,107,.22);color:#8bffbf}.badge.off{background:rgba(255,159,28,.18);color:#ffd08c}.grid{display:grid;gap:14px}.g4{grid-template-columns:repeat(4,minmax(0,1fr))}.g3{grid-template-columns:repeat(3,minmax(0,1fr))}.g2{grid-template-columns:repeat(2,minmax(0,1fr))}.card{padding:18px;border-radius:22px;background:linear-gradient(180deg,rgba(255,255,255,.07),rgba(255,255,255,.035));border:1px solid var(--line);box-shadow:0 12px 34px rgba(0,0,0,.2)}.card b{display:block;color:var(--muted);font-size:12px;margin-bottom:8px}.card strong{font-size:25px}.section{margin-top:18px}.section h2{margin:0 0 12px;font-size:22px}.row{display:flex;gap:10px;flex-wrap:wrap}.btn{border:0;border-radius:14px;padding:12px 16px;background:var(--blue);color:white;font-weight:800;cursor:pointer}.btn.green{background:var(--green)}.btn.orange{background:var(--orange);color:#1e1300}.btn.red{background:var(--red)}.btn:hover{filter:brightness(1.12)}.input{width:100%;padding:13px;border-radius:14px;border:1px solid var(--line);background:rgba(255,255,255,.06);color:white;outline:none}.console{height:230px;overflow:auto;white-space:pre-wrap;padding:14px;border-radius:16px;background:#02060b;color:#b8ffd3;font-family:Consolas,monospace;font-size:12px;border:1px solid rgba(255,255,255,.08)}.progress{height:28px;border-radius:999px;background:rgba(255,255,255,.12);overflow:hidden}.fill{height:100%;width:0%;background:linear-gradient(90deg,#18b86b,#9dffba);transition:.4s}@media(max-width:1100px){.g4{grid-template-columns:repeat(2,minmax(0,1fr))}.g3{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:700px){.hero{flex-direction:column;align-items:flex-start}.g4,.g3,.g2{grid-template-columns:1fr}.hero h1{font-size:26px}}
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <div><h1>SafeNewCoin GPU V18</h1><p>총 채굴량 기반 난이도 / GPU 지속 채굴 / 난이도 폭증 제거 / GPU 65도 유지</p></div>
    <div class="row"><span id="modeBadge" class="badge off">LOCAL</span><span id="mineBadge" class="badge off">MINER OFF</span><span id="engineBadge" class="badge off">CPU</span><span id="healthBadge" class="badge on">OK</span></div>
  </div>

  <div class="section grid g4">
    <div class="card"><b>잔액</b><strong id="balance">0 SNC</strong></div>
    <div class="card"><b>블록 높이</b><strong id="height">0</strong></div>
    <div class="card"><b>난이도</b><strong id="difficulty">0</strong></div>
    <div class="card"><b>블록 속도</b><strong id="blockSpeed">0 blk/s</strong></div>
  </div>

  <div class="section grid g4">
    <div class="card"><b>Nonce 속도</b><strong id="nonceSpeed">0 H/s</strong></div>
    <div class="card"><b>Work 속도</b><strong id="workSpeed">0 H/s</strong></div>
    <div class="card"><b>GPU 사용률</b><strong id="gpuUtil">0%</strong></div>
    <div class="card"><b>GPU 온도</b><strong id="gpuTemp">0℃</strong></div>
  </div>

  <div class="section grid g3">
    <div class="card"><h2>채굴 제어</h2><div class="row"><button class="btn green" onclick="minerStart()">채굴 시작</button><button class="btn red" onclick="minerStop()">채굴 정지</button><button class="btn orange" onclick="mineOnce()">1블록 테스트</button></div><div class="console" id="minerBox">대기중</div></div>
    <div class="card"><h2>GPU 상태</h2><div class="grid g2"><div class="card"><b>GPU</b><strong id="gpuName">-</strong></div><div class="card"><b>VRAM</b><strong id="gpuVram">-</strong></div><div class="card"><b>Blocks</b><strong id="gpuBlocks">0</strong></div><div class="card"><b>Loop</b><strong id="loopCount">0</strong></div></div></div>
    <div class="card"><h2>지갑</h2><input id="myAddress" class="input" readonly><div class="row" style="margin-top:10px"><button class="btn" onclick="walletBackup()">지갑 백업</button><button class="btn orange" onclick="fullBackup()">전체 백업</button><button class="btn green" onclick="copyAddress()">주소 복사</button></div><div class="console" id="walletBox">지갑 준비</div></div>
  </div>

  <div class="section grid g2">
    <div class="card"><h2>송금</h2><div class="grid g2"><input id="txReceiver" class="input" placeholder="받는 주소 SNC_..."><input id="txAmount" class="input" type="number" placeholder="금액"></div><div class="row" style="margin-top:10px"><button class="btn green" onclick="sendTX()">송금 실행</button></div><div class="console" id="txBox">거래 대기</div></div>
    <div class="card"><h2>블록 탐색</h2><div class="grid g2"><input id="searchQ" class="input" placeholder="블록번호 / 해시 / 주소 / 거래 검색"><button class="btn" onclick="searchExplorer()">검색</button></div><div class="console" id="explorerBox">최근 블록 표시</div></div>
  </div>

  <div class="section grid g2">
    <div class="card"><h2>총 발행량</h2><div class="grid g3"><div class="card"><b>최대</b><strong>52,000,000</strong></div><div class="card"><b>현재</b><strong id="currentSupply">0</strong></div><div class="card"><b>남은 수량</b><strong id="remainSupply">0</strong></div></div><div class="progress" style="margin-top:15px"><div id="supplyFill" class="fill"></div></div><div id="supplyPercent" style="text-align:right;margin-top:8px;font-weight:800">0%</div></div>
    <div class="card"><h2>네트워크 준비</h2><input id="serverUrl" class="input" placeholder="서버 주소 예: http://127.0.0.1:8788"><div class="row" style="margin-top:10px"><button class="btn green" onclick="networkOn()">네트워크 ON</button><button class="btn red" onclick="networkOff()">로컬 OFF</button><button class="btn orange" onclick="networkTest()">연결 테스트</button></div><div class="console" id="networkBox">기본값 LOCAL MODE</div></div>
  </div>

  <div class="section card"><h2>시스템 로그</h2><div class="console" id="logBox">로그 대기</div></div>
</div>

<script>
async function api(url,opt){const r=await fetch(url,opt);return await r.json();}
function fmt(n){return Number(n||0).toLocaleString();}
function fmtHash(h){h=Number(h||0);if(h>1000000)return (h/1000000).toFixed(2)+' MH/s';if(h>1000)return (h/1000).toFixed(2)+' KH/s';return h.toFixed(0)+' H/s';}
function j(x){return JSON.stringify(x,null,2);}
async function refresh(){
  const s=await api('/api/status'); const m=await api('/api/miner/status'); const tx=await api('/api/tx/status'); const net=await api('/api/network/status'); const supply=await api('/api/supply/status');
  balance.textContent=fmt(s.balance)+' SNC'; height.textContent=fmt(s.height); difficulty.textContent=s.difficulty; blockSpeed.textContent=fmt(m.block_speed)+' blk/s'; myAddress.value=s.address;
  nonceSpeed.textContent=fmtHash(m.nonce_speed); workSpeed.textContent=fmtHash(m.work_speed); gpuUtil.textContent=(m.gpu_util||0)+'%'; gpuTemp.textContent=(m.gpu_temp||0)+'℃';
  gpuName.textContent=m.gpu_name||'-'; gpuVram.textContent=m.gpu_vram||'-'; gpuBlocks.textContent=fmt(m.gpu_blocks); loopCount.textContent=fmt(m.loop_count);
  healthBadge.textContent=s.health; healthBadge.className='badge '+(s.health==='OK'?'on':'off');
  mineBadge.textContent=m.running?'MINER ON':'MINER OFF'; mineBadge.className='badge '+(m.running?'on':'off');
  modeBadge.textContent=net.mode; modeBadge.className='badge '+(net.enabled?'on':'off');
  engineBadge.textContent=m.mode; engineBadge.className='badge '+(m.mode==='GPU'?'on':'off');
  minerBox.textContent=j(m); txBox.textContent=j(tx); explorerBox.textContent=j(s.recent_blocks||[]); networkBox.textContent=j(net); logBox.textContent=(s.logs||[]).join('\n');
  currentSupply.textContent=fmt(supply.current_supply); remainSupply.textContent=fmt(supply.remaining_supply); supplyFill.style.width=(supply.progress_percent||0)+'%'; supplyPercent.textContent=(supply.progress_percent||0).toFixed(6)+'% MINED';
}
async function minerStart(){await api('/api/miner/start',{method:'POST'});refresh();}
async function minerStop(){await api('/api/miner/stop',{method:'POST'});refresh();}
async function mineOnce(){const r=await api('/api/miner/mine_once',{method:'POST'});minerBox.textContent=j(r);refresh();}
async function walletBackup(){const r=await api('/api/wallet/backup',{method:'POST'});walletBox.textContent=j(r);refresh();}
async function fullBackup(){const r=await api('/api/backup/full',{method:'POST'});walletBox.textContent=j(r);refresh();}
function copyAddress(){myAddress.select();document.execCommand('copy');walletBox.textContent='주소 복사 완료';}
async function sendTX(){const receiver=txReceiver.value; const amount=parseFloat(txAmount.value||'0'); const r=await api('/api/tx/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({receiver,amount})}); txBox.textContent=j(r); refresh();}
async function searchExplorer(){const q=searchQ.value; const r=await api('/api/explorer/search?q='+encodeURIComponent(q)); explorerBox.textContent=j(r);}
async function networkOn(){const r=await api('/api/network/set',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:true,server_url:serverUrl.value})});networkBox.textContent=j(r);refresh();}
async function networkOff(){const r=await api('/api/network/set',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:false})});networkBox.textContent=j(r);refresh();}
async function networkTest(){const r=await api('/api/network/test',{method:'POST'});networkBox.textContent=j(r);refresh();}
setInterval(refresh,1500);refresh();
</script>
</body>
</html>
'''


app = Flask(__name__)


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/status")
def api_status():
    return jsonify(CHAIN.status())


@app.route("/api/miner/status")
def api_miner_status():
    return jsonify(MINER.status())


@app.route("/api/miner/start", methods=["POST"])
def api_miner_start():
    MINER.start()
    return jsonify({"ok": True, "status": "MINING_ON"})


@app.route("/api/miner/stop", methods=["POST"])
def api_miner_stop():
    MINER.stop()
    return jsonify({"ok": True, "status": "MINING_OFF"})


@app.route("/api/miner/mine_once", methods=["POST"])
def api_miner_once():
    ok, reason, block, elapsed = CHAIN.mine_block_once()
    return jsonify({"ok": ok, "reason": reason, "elapsed": elapsed, "block": block})


@app.route("/api/wallet/status")
def api_wallet_status():
    return jsonify(WALLET.status())


@app.route("/api/wallet/backup", methods=["POST"])
def api_wallet_backup():
    return jsonify(WALLET.create_backup_package())


@app.route("/api/backup/full", methods=["POST"])
def api_full_backup():
    return jsonify(run_full_backup())


@app.route("/api/tx/status")
def api_tx_status():
    return jsonify(TX.status())


@app.route("/api/tx/send", methods=["POST"])
def api_tx_send():
    data = request.get_json(silent=True) or {}
    sender = WALLET.get_address()
    receiver = str(data.get("receiver", "")).strip()

    try:
        amount = float(data.get("amount", 0))
    except Exception:
        return jsonify({"ok": False, "reason": "금액 오류"})

    tx = TX.create_tx(sender, receiver, amount, fee=0.001)
    ok, reason = TX.add_tx(tx, CHAIN.balance_of)
    return jsonify({"ok": ok, "reason": reason, "tx": tx})


@app.route("/api/explorer/search")
def api_explorer_search():
    q = str(request.args.get("q", "")).strip()
    result = {"blocks": [], "transactions": []}

    if not q:
        result["blocks"] = CHAIN.blocks[-25:]
        return jsonify(result)

    for b in CHAIN.blocks[-1000:]:
        raw = json.dumps(b, ensure_ascii=False)
        if q in raw or q == str(b.get("index", "")):
            result["blocks"].append(b)

    for tx in TX.history[-1000:] + TX.mempool[-1000:]:
        raw = json.dumps(tx, ensure_ascii=False)
        if q in raw:
            result["transactions"].append(tx)

    return jsonify(result)


@app.route("/api/supply/status")
def api_supply_status():
    return jsonify(CHAIN.supply_status())


@app.route("/api/network/status")
def api_network_status():
    return jsonify(NETWORK.status())


@app.route("/api/network/set", methods=["POST"])
def api_network_set():
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled", False))
    server_url = str(data.get("server_url", "")).strip()
    return jsonify(NETWORK.set_mode(enabled, server_url))


@app.route("/api/network/test", methods=["POST"])
def api_network_test():
    return jsonify(NETWORK.connection_test())


@app.route("/api/network/export")
def api_network_export():
    return jsonify(NETWORK.export_sync_payload())


def open_browser_later():
    time.sleep(1.0)
    if CONFIG.get("auto_open_browser", True):
        try:
            webbrowser.open(f"http://{LOCAL_HOST}:{LOCAL_PORT}")
        except Exception:
            pass


def main():
    log_line(f"{APP_NAME} {APP_VERSION} started")
    log_line(f"APP DIR: {APP_DIR}")
    log_line(f"ADDRESS: {WALLET.get_address()}")
    log_line(f"PROOF MODE: {PROOF.mode}")
    if PROOF.gpu_error:
        log_line(f"GPU ERROR: {PROOF.gpu_error}")
    log_line(f"WEB UI: http://{LOCAL_HOST}:{LOCAL_PORT}")

    threading.Thread(target=open_browser_later, daemon=True).start()
    app.run(host=LOCAL_HOST, port=LOCAL_PORT, debug=False, threaded=True)


if __name__ == "__main__":
    main()
