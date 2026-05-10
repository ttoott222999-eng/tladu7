# ============================================================
# SafeNewCoin Client V19
# PC 설치형 클라이언트 코드
#
# 역할:
# - 서버 로그인 / 회원가입
# - 서버 지갑 / 잔액 조회
# - 서버에서 채굴 작업(job) 받아오기
# - 내 PC CPU/GPU로 nonce 탐색
# - 채굴 결과를 서버에 제출
# - 송금 / 거래내역 / 서버 상태 확인
# - Flask 로컬 UI 제공
#
# 실행:
#   python SafeNewCoin_Client_V19.py
#
# 설치:
#   pip install flask requests
#
# GPU 채굴 선택 설치:
#   pip install numpy cuda-python
#
# EXE 빌드 예:
#   pyinstaller --onefile --name SafeNewCoin_Client_V19 SafeNewCoin_Client_V19.py
# ============================================================

import os
import sys
import json
import time
import base64
import hashlib
import tempfile
import threading
import subprocess
import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests
from flask import Flask, jsonify, request, render_template_string


# ============================================================
# CUDA 선택 지원
# ============================================================

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


# ============================================================
# 기본 설정
# ============================================================

APP_NAME = "SafeNewCoin Client"
APP_VERSION = "V19 CLIENT ONLINE"
COIN_SYMBOL = "SNC"

DEFAULT_SERVER_URL = "https://tladu7.onrender.com"
LOCAL_HOST = "127.0.0.1"
LOCAL_PORT = 8787

THREADS_PER_BLOCK = 256
DEFAULT_GPU_BLOCKS = 16_384
DEFAULT_LOOP_COUNT = 192
CPU_BATCH = 100_000


def get_app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


APP_DIR = get_app_dir()
os.chdir(APP_DIR)

DATA_DIR = APP_DIR / "safe_newcoin_client_data"
CONFIG_FILE = DATA_DIR / "config_v19.json"
SESSION_FILE = DATA_DIR / "session_v19.json"
LOG_FILE = DATA_DIR / "client_v19.log"

DATA_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_CONFIG = {
    "version": APP_VERSION,
    "server_url": DEFAULT_SERVER_URL,
    "auto_open_browser": True,
    "gpu_mode_enabled": True,
    "gpu_blocks": DEFAULT_GPU_BLOCKS,
    "loop_count": DEFAULT_LOOP_COUNT,
    "mine_after_login": False,
}


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


def run_cmd(args):
    try:
        return subprocess.check_output(args, stderr=subprocess.DEVNULL).decode(errors="ignore").strip()
    except Exception:
        return ""


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


# ============================================================
# API Client
# ============================================================

class ServerAPI:
    def __init__(self):
        self.lock = threading.RLock()
        self.session_data = read_json(SESSION_FILE, {})
        self.last_error = ""
        self.last_status = "INIT"

    def server_url(self) -> str:
        return str(CONFIG.get("server_url", DEFAULT_SERVER_URL)).rstrip("/")

    def token(self) -> str:
        return str(self.session_data.get("token", ""))

    def headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.token():
            h["Authorization"] = "Bearer " + self.token()
        return h

    def save_session(self) -> None:
        atomic_json(SESSION_FILE, self.session_data)

    def request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None, timeout: int = 15) -> Dict[str, Any]:
        url = self.server_url() + path
        try:
            if method.upper() == "GET":
                r = requests.get(url, headers=self.headers(), timeout=timeout)
            else:
                r = requests.request(method.upper(), url, headers=self.headers(), json=payload or {}, timeout=timeout)
            try:
                data = r.json()
            except Exception:
                data = {"ok": False, "reason": r.text[:500]}
            if r.status_code >= 400:
                data.setdefault("ok", False)
                data.setdefault("http_status", r.status_code)
            self.last_status = "OK" if data.get("ok", True) else "ERROR"
            self.last_error = "" if data.get("ok", True) else str(data.get("reason", "ERROR"))
            return data
        except Exception as e:
            self.last_status = "CONNECTION_ERROR"
            self.last_error = str(e)
            return {"ok": False, "reason": str(e), "url": url}

    def status(self) -> Dict[str, Any]:
        return self.request("GET", "/api/status")

    def register(self, username: str, password: str, agreed: bool) -> Dict[str, Any]:
        data = self.request("POST", "/api/auth/register", {
            "username": username,
            "password": password,
            "inactive_delete_agreed": agreed,
        })
        if data.get("ok") and data.get("token"):
            self.session_data = {
                "token": data["token"],
                "username": data.get("username", username),
                "user_id": data.get("user_id", ""),
                "address": data.get("address", ""),
                "login_at": now(),
            }
            self.save_session()
        return data

    def login(self, username: str, password: str) -> Dict[str, Any]:
        data = self.request("POST", "/api/auth/login", {"username": username, "password": password})
        if data.get("ok") and data.get("token"):
            self.session_data = {
                "token": data["token"],
                "username": data.get("username", username),
                "user_id": data.get("user_id", ""),
                "address": data.get("address", ""),
                "login_at": now(),
            }
            self.save_session()
        return data

    def logout(self) -> Dict[str, Any]:
        self.session_data = {}
        self.save_session()
        return {"ok": True, "status": "LOGGED_OUT"}

    def me(self) -> Dict[str, Any]:
        return self.request("GET", "/api/me")

    def balance(self) -> Dict[str, Any]:
        return self.request("GET", "/api/wallet/balance")

    def mining_job(self, loop_count: int) -> Dict[str, Any]:
        return self.request("GET", f"/api/mining/job?loop_count={int(loop_count)}")

    def submit_mining(self, nonce: int, proof: int, loop_count: int) -> Dict[str, Any]:
        return self.request("POST", "/api/mining/submit", {
            "nonce": int(nonce),
            "proof": int(proof),
            "loop_count": int(loop_count),
        }, timeout=30)

    def send_tx(self, receiver: str, amount: float) -> Dict[str, Any]:
        return self.request("POST", "/api/tx/send", {"receiver": receiver, "amount": amount})

    def tx_history(self) -> Dict[str, Any]:
        return self.request("GET", "/api/tx/history")


API = ServerAPI()


# ============================================================
# CPU / GPU 채굴 엔진
# ============================================================

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
        for _ in range(int(loop_count)):
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
        self.cpu = CPUMixMiner()
        self.gpu = None
        self.mode = "CPU"
        self.gpu_error = ""
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

    def proof_value_cpu(self, seed: int, nonce: int, loop_count: int) -> int:
        return self.cpu.mix64_loop(seed ^ nonce, loop_count)

    def mine_nonce(self, seed: int, target: int, loop_count: int, blocks: int, stop_check) -> Tuple[Optional[int], Optional[int], float]:
        nonce = 0
        batch = THREADS_PER_BLOCK * int(blocks) if self.mode == "GPU" and self.gpu is not None else CPU_BATCH
        start = time.time()

        while not stop_check():
            with self.lock:
                engine = self.gpu if self.mode == "GPU" and self.gpu is not None else self.cpu

            found = engine.mine_batch(seed, nonce, target, int(blocks), int(loop_count))
            self.nonce_hashes += batch
            self.work_hashes += batch * int(loop_count)
            self.last_batch = batch

            if found is not None:
                elapsed = max(0.0001, time.time() - start)
                proof = self.proof_value_cpu(seed, int(found), loop_count)
                return int(found), int(proof), elapsed

            nonce += batch

        return None, None, max(0.0001, time.time() - start)

    def status(self) -> Dict[str, Any]:
        elapsed = max(time.time() - self.started, 1)
        return {
            "mode": self.mode,
            "gpu_error": self.gpu_error,
            "nonce_hashes": self.nonce_hashes,
            "work_hashes": self.work_hashes,
            "nonce_speed": self.nonce_hashes / elapsed,
            "work_speed": self.work_hashes / elapsed,
            "last_batch": self.last_batch,
            "gpu_info": self.gpu.gpu_info if self.gpu is not None else {},
        }


PROOF = ProofEngine()


# ============================================================
# 하드웨어 모니터
# ============================================================

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


# ============================================================
# 채굴 컨트롤러
# ============================================================

class MinerController:
    def __init__(self):
        self.lock = threading.RLock()
        self.running = False
        self.thread = None
        self.last_result = "IDLE"
        self.last_job = None
        self.last_submit = None
        self.blocks_found = 0
        self.started_at = 0.0
        self.block_speed = 0.0

    def start(self) -> Dict[str, Any]:
        with self.lock:
            if self.running:
                return {"ok": True, "status": "ALREADY_RUNNING"}
            if not API.token():
                return {"ok": False, "reason": "먼저 로그인해야 합니다."}
            self.running = True
            self.started_at = time.time()
            self.thread = threading.Thread(target=self.loop, daemon=True)
            self.thread.start()
            log_line("채굴 시작")
            return {"ok": True, "status": "MINING_ON"}

    def stop(self) -> Dict[str, Any]:
        with self.lock:
            self.running = False
            log_line("채굴 정지")
            return {"ok": True, "status": "MINING_OFF"}

    def is_stopped(self) -> bool:
        with self.lock:
            return not self.running

    def mine_once(self) -> Dict[str, Any]:
        if not API.token():
            return {"ok": False, "reason": "먼저 로그인해야 합니다."}
        return self.do_one_job()

    def loop(self):
        while True:
            with self.lock:
                if not self.running:
                    break
            result = self.do_one_job()
            with self.lock:
                self.last_result = str(result.get("reason") or result.get("status") or result.get("ok"))
            if not result.get("ok"):
                time.sleep(1.0)

    def do_one_job(self) -> Dict[str, Any]:
        loop_count = int(CONFIG.get("loop_count", DEFAULT_LOOP_COUNT))
        blocks = int(CONFIG.get("gpu_blocks", DEFAULT_GPU_BLOCKS))

        job_resp = API.mining_job(loop_count)
        with self.lock:
            self.last_job = job_resp

        if not job_resp.get("ok"):
            log_line(f"채굴 작업 요청 실패: {job_resp.get('reason')}")
            return job_resp

        job = job_resp.get("job", {})
        seed = int(job.get("seed", 0))
        target = int(job.get("target", 0))
        difficulty = int(job.get("difficulty", 1))

        log_line(f"채굴 작업 수신: height={job.get('index')} diff={difficulty} mode={PROOF.mode}")

        nonce, proof, elapsed = PROOF.mine_nonce(seed, target, loop_count, blocks, self.is_stopped)
        if nonce is None or proof is None:
            return {"ok": False, "reason": "MINING_STOPPED"}

        submit = API.submit_mining(nonce, proof, loop_count)
        with self.lock:
            self.last_submit = submit
            self.block_speed = round(1.0 / max(elapsed, 0.001), 4)
            if submit.get("ok"):
                self.blocks_found += 1
                self.last_result = f"BLOCK_ACCEPTED / {elapsed:.4f}s"
            else:
                self.last_result = str(submit.get("reason", "REJECTED"))

        if submit.get("ok"):
            log_line(f"채굴 성공 제출 승인: nonce={nonce} proof={proof} elapsed={elapsed:.4f}s")
        else:
            log_line(f"채굴 제출 거부: {submit.get('reason')}")

        result = dict(submit)
        result["local_elapsed"] = elapsed
        result["nonce"] = nonce
        result["proof"] = proof
        return result

    def status(self) -> Dict[str, Any]:
        proof = PROOF.status()
        hw = HW.status()
        with self.lock:
            return {
                "running": self.running,
                "last_result": self.last_result,
                "blocks_found": self.blocks_found,
                "block_speed": self.block_speed,
                "uptime": round(time.time() - self.started_at, 1) if self.started_at else 0,
                "last_job": self.last_job,
                "last_submit": self.last_submit,
                "gpu_blocks": CONFIG.get("gpu_blocks", DEFAULT_GPU_BLOCKS),
                "loop_count": CONFIG.get("loop_count", DEFAULT_LOOP_COUNT),
                **proof,
                **hw,
            }


MINER = MinerController()


# ============================================================
# 로컬 HTML UI
# ============================================================

HTML = r'''
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SafeNewCoin Client V19</title>
<style>
:root{--bg:#07111f;--line:rgba(255,255,255,.12);--text:#edf6ff;--muted:#9bb0c8;--blue:#4f7cff;--green:#19bf72;--red:#ff4d4d;--orange:#ff9f1c}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0%,#1e3458,#07111f 44%,#02060b);color:var(--text);font-family:Arial,Malgun Gothic,sans-serif}.wrap{max-width:1450px;margin:0 auto;padding:22px}.hero{display:flex;justify-content:space-between;gap:14px;align-items:center;border:1px solid var(--line);border-radius:26px;padding:24px;background:linear-gradient(135deg,rgba(79,124,255,.22),rgba(25,191,114,.12));box-shadow:0 20px 50px rgba(0,0,0,.25)}h1{margin:0;font-size:34px}p{color:var(--muted)}.grid{display:grid;gap:14px}.g4{grid-template-columns:repeat(4,1fr)}.g3{grid-template-columns:repeat(3,1fr)}.g2{grid-template-columns:repeat(2,1fr)}.card{border:1px solid var(--line);border-radius:22px;padding:17px;background:rgba(255,255,255,.07)}.card b{display:block;color:var(--muted);font-size:12px;margin-bottom:8px}.card strong{font-size:25px}.section{margin-top:18px}.badge{padding:10px 14px;border-radius:999px;background:rgba(255,255,255,.12);font-weight:800}.on{background:rgba(25,191,114,.22);color:#91ffc7}.off{background:rgba(255,159,28,.2);color:#ffd38a}.btn{border:0;border-radius:14px;padding:12px 16px;background:var(--blue);color:white;font-weight:800;cursor:pointer}.green{background:var(--green)}.red{background:var(--red)}.orange{background:var(--orange);color:#241500}.input{width:100%;padding:13px;border-radius:14px;border:1px solid var(--line);background:rgba(255,255,255,.07);color:white}.console{height:240px;overflow:auto;white-space:pre-wrap;background:#02060b;border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:14px;color:#b8ffd3;font-family:Consolas,monospace;font-size:12px}.row{display:flex;gap:10px;flex-wrap:wrap}@media(max-width:1000px){.g4,.g3,.g2{grid-template-columns:1fr}.hero{flex-direction:column;align-items:flex-start}}
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <div><h1>SafeNewCoin Client V19</h1><p>PC GPU/CPU 채굴 → 서버 검증/저장 → 온라인 지갑 유지</p></div>
    <div class="row"><span id="loginBadge" class="badge off">LOGOUT</span><span id="mineBadge" class="badge off">MINER OFF</span><span id="engineBadge" class="badge off">CPU</span></div>
  </div>

  <div class="section grid g4">
    <div class="card"><b>서버</b><strong id="serverUrl">-</strong></div>
    <div class="card"><b>내 잔액</b><strong id="balance">0 SNC</strong></div>
    <div class="card"><b>서버 블록</b><strong id="height">0</strong></div>
    <div class="card"><b>난이도</b><strong id="difficulty">0</strong></div>
  </div>

  <div class="section grid g4">
    <div class="card"><b>Nonce 속도</b><strong id="nonceSpeed">0 H/s</strong></div>
    <div class="card"><b>Work 속도</b><strong id="workSpeed">0 H/s</strong></div>
    <div class="card"><b>GPU 사용률</b><strong id="gpuUtil">0%</strong></div>
    <div class="card"><b>GPU 온도</b><strong id="gpuTemp">0℃</strong></div>
  </div>

  <div class="section grid g2">
    <div class="card">
      <h2>서버 설정 / 계정</h2>
      <input id="serverInput" class="input" placeholder="서버 주소"><br><br>
      <button class="btn" onclick="saveServer()">서버 저장</button>
      <button class="btn orange" onclick="serverStatus()">서버 확인</button>
      <br><br>
      <div class="grid g2">
        <input id="username" class="input" placeholder="아이디">
        <input id="password" class="input" placeholder="비밀번호" type="password">
      </div>
      <br>
      <label><input id="agree" type="checkbox"> 2년 미접속 + 30일 유예 후 자동 삭제 동의</label>
      <br><br>
      <button class="btn green" onclick="register()">회원가입</button>
      <button class="btn green" onclick="login()">로그인</button>
      <button class="btn red" onclick="logout()">로그아웃</button>
      <button class="btn" onclick="me()">내 정보</button>
      <div id="accountBox" class="console">대기</div>
    </div>

    <div class="card">
      <h2>채굴 제어</h2>
      <div class="row">
        <button class="btn green" onclick="minerStart()">채굴 시작</button>
        <button class="btn red" onclick="minerStop()">채굴 정지</button>
        <button class="btn orange" onclick="mineOnce()">1블록 테스트</button>
      </div>
      <br>
      <div class="grid g2">
        <input id="gpuBlocks" class="input" placeholder="GPU Blocks">
        <input id="loopCount" class="input" placeholder="Loop Count">
      </div>
      <br>
      <button class="btn" onclick="saveMinerConfig()">채굴 설정 저장</button>
      <div id="minerBox" class="console">채굴 대기</div>
    </div>
  </div>

  <div class="section grid g2">
    <div class="card">
      <h2>지갑 / 송금</h2>
      <input id="myAddress" class="input" readonly placeholder="내 주소"><br><br>
      <div class="grid g2">
        <input id="receiver" class="input" placeholder="받는 주소 SNC_...">
        <input id="amount" class="input" placeholder="금액" type="number">
      </div>
      <br>
      <button class="btn green" onclick="sendTx()">송금</button>
      <button class="btn" onclick="txHistory()">거래내역</button>
      <div id="walletBox" class="console">지갑 대기</div>
    </div>

    <div class="card">
      <h2>하드웨어</h2>
      <div class="grid g2">
        <div class="card"><b>GPU</b><strong id="gpuName">-</strong></div>
        <div class="card"><b>VRAM</b><strong id="gpuVram">-</strong></div>
        <div class="card"><b>블록 속도</b><strong id="blockSpeed">0</strong></div>
        <div class="card"><b>찾은 블록</b><strong id="foundBlocks">0</strong></div>
      </div>
      <div id="hwBox" class="console">하드웨어 대기</div>
    </div>
  </div>

  <div class="section card">
    <h2>로그</h2>
    <div id="logBox" class="console">로그 대기</div>
  </div>
</div>
<script>
async function api(url,opt={}){const r=await fetch(url,opt);return await r.json()}
function j(x){return JSON.stringify(x,null,2)}
function fmt(n){return Number(n||0).toLocaleString()}
function fmtHash(h){h=Number(h||0);if(h>1000000)return (h/1000000).toFixed(2)+' MH/s';if(h>1000)return (h/1000).toFixed(2)+' KH/s';return h.toFixed(0)+' H/s'}
async function refresh(){
  const s=await api('/local/status');
  serverUrl.textContent=s.config.server_url.replace('https://',''); serverInput.value=s.config.server_url;
  loginBadge.textContent=s.logged_in?'LOGIN':'LOGOUT'; loginBadge.className='badge '+(s.logged_in?'on':'off');
  mineBadge.textContent=s.miner.running?'MINER ON':'MINER OFF'; mineBadge.className='badge '+(s.miner.running?'on':'off');
  engineBadge.textContent=s.miner.mode; engineBadge.className='badge '+(s.miner.mode==='GPU'?'on':'off');
  balance.textContent=fmt(s.balance)+' SNC'; height.textContent=fmt(s.server.height); difficulty.textContent=s.server.difficulty||0;
  nonceSpeed.textContent=fmtHash(s.miner.nonce_speed); workSpeed.textContent=fmtHash(s.miner.work_speed); gpuUtil.textContent=(s.miner.gpu_util||0)+'%'; gpuTemp.textContent=(s.miner.gpu_temp||0)+'℃';
  gpuName.textContent=s.miner.gpu_name||'-'; gpuVram.textContent=s.miner.gpu_vram||'-'; blockSpeed.textContent=s.miner.block_speed; foundBlocks.textContent=s.miner.blocks_found;
  myAddress.value=s.address||''; gpuBlocks.value=s.config.gpu_blocks; loopCount.value=s.config.loop_count;
  minerBox.textContent=j(s.miner); hwBox.textContent=j({gpu_name:s.miner.gpu_name,gpu_info:s.miner.gpu_info,gpu_error:s.miner.gpu_error}); logBox.textContent=(s.logs||[]).join('\n');
}
async function saveServer(){const r=await api('/local/config/server',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({server_url:serverInput.value})});accountBox.textContent=j(r);refresh()}
async function serverStatus(){const r=await api('/local/server/status');accountBox.textContent=j(r);refresh()}
async function register(){const r=await api('/local/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:username.value,password:password.value,inactive_delete_agreed:agree.checked})});accountBox.textContent=j(r);refresh()}
async function login(){const r=await api('/local/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:username.value,password:password.value})});accountBox.textContent=j(r);refresh()}
async function logout(){const r=await api('/local/auth/logout',{method:'POST'});accountBox.textContent=j(r);refresh()}
async function me(){const r=await api('/local/me');accountBox.textContent=j(r);refresh()}
async function minerStart(){const r=await api('/local/miner/start',{method:'POST'});minerBox.textContent=j(r);refresh()}
async function minerStop(){const r=await api('/local/miner/stop',{method:'POST'});minerBox.textContent=j(r);refresh()}
async function mineOnce(){const r=await api('/local/miner/mine_once',{method:'POST'});minerBox.textContent=j(r);refresh()}
async function saveMinerConfig(){const r=await api('/local/config/miner',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({gpu_blocks:gpuBlocks.value,loop_count:loopCount.value})});minerBox.textContent=j(r);refresh()}
async function sendTx(){const r=await api('/local/tx/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({receiver:receiver.value,amount:amount.value})});walletBox.textContent=j(r);refresh()}
async function txHistory(){const r=await api('/local/tx/history');walletBox.textContent=j(r);refresh()}
setInterval(refresh,1500);refresh();
</script>
</body>
</html>
'''


# ============================================================
# 로컬 Flask API
# ============================================================

app = Flask(__name__)


def read_logs(limit: int = 120):
    try:
        if LOG_FILE.exists():
            lines = LOG_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()
            return lines[-limit:]
    except Exception:
        pass
    return []


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/local/status")
def local_status():
    server = API.status()
    balance_data = API.balance() if API.token() else {"balance": 0}
    miner = MINER.status()
    return jsonify({
        "ok": True,
        "app": APP_NAME,
        "version": APP_VERSION,
        "config": CONFIG,
        "session": {k: v for k, v in API.session_data.items() if k != "token"},
        "logged_in": bool(API.token()),
        "address": API.session_data.get("address", ""),
        "balance": balance_data.get("balance", 0),
        "server": server,
        "miner": miner,
        "api_last_status": API.last_status,
        "api_last_error": API.last_error,
        "logs": read_logs(),
    })


@app.route("/local/config/server", methods=["POST"])
def local_config_server():
    data = request.get_json(silent=True) or {}
    server_url = str(data.get("server_url", "")).strip().rstrip("/")
    if not server_url.startswith("http://") and not server_url.startswith("https://"):
        return jsonify({"ok": False, "reason": "서버 주소는 http:// 또는 https:// 로 시작해야 합니다."})
    CONFIG["server_url"] = server_url
    save_config(CONFIG)
    log_line(f"서버 주소 변경: {server_url}")
    return jsonify({"ok": True, "server_url": server_url})


@app.route("/local/config/miner", methods=["POST"])
def local_config_miner():
    data = request.get_json(silent=True) or {}
    try:
        gpu_blocks = int(data.get("gpu_blocks", DEFAULT_GPU_BLOCKS))
        loop_count = int(data.get("loop_count", DEFAULT_LOOP_COUNT))
    except Exception:
        return jsonify({"ok": False, "reason": "숫자 형식 오류"})
    CONFIG["gpu_blocks"] = max(1, min(131072, gpu_blocks))
    CONFIG["loop_count"] = max(1, min(4096, loop_count))
    save_config(CONFIG)
    return jsonify({"ok": True, "config": CONFIG})


@app.route("/local/server/status")
def local_server_status():
    return jsonify(API.status())


@app.route("/local/auth/register", methods=["POST"])
def local_register():
    data = request.get_json(silent=True) or {}
    result = API.register(str(data.get("username", "")), str(data.get("password", "")), bool(data.get("inactive_delete_agreed", False)))
    return jsonify(result)


@app.route("/local/auth/login", methods=["POST"])
def local_login():
    data = request.get_json(silent=True) or {}
    result = API.login(str(data.get("username", "")), str(data.get("password", "")))
    return jsonify(result)


@app.route("/local/auth/logout", methods=["POST"])
def local_logout():
    return jsonify(API.logout())


@app.route("/local/me")
def local_me():
    return jsonify(API.me())


@app.route("/local/miner/start", methods=["POST"])
def local_miner_start():
    return jsonify(MINER.start())


@app.route("/local/miner/stop", methods=["POST"])
def local_miner_stop():
    return jsonify(MINER.stop())


@app.route("/local/miner/mine_once", methods=["POST"])
def local_miner_once():
    return jsonify(MINER.mine_once())


@app.route("/local/tx/send", methods=["POST"])
def local_tx_send():
    data = request.get_json(silent=True) or {}
    try:
        amount = float(data.get("amount", 0))
    except Exception:
        return jsonify({"ok": False, "reason": "금액 오류"})
    return jsonify(API.send_tx(str(data.get("receiver", "")).strip(), amount))


@app.route("/local/tx/history")
def local_tx_history():
    return jsonify(API.tx_history())


# ============================================================
# 실행
# ============================================================

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
    log_line(f"SERVER: {CONFIG.get('server_url')}")
    log_line(f"PROOF MODE: {PROOF.mode}")
    if PROOF.gpu_error:
        log_line(f"GPU ERROR: {PROOF.gpu_error}")
    log_line(f"WEB UI: http://{LOCAL_HOST}:{LOCAL_PORT}")
    threading.Thread(target=open_browser_later, daemon=True).start()
    app.run(host=LOCAL_HOST, port=LOCAL_PORT, debug=False, threaded=True)


if __name__ == "__main__":
    main()
