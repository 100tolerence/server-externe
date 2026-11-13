# serverv1.0.0.py
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

def _env_hash(envelope: str) -> str:
    return hashlib.sha256(envelope.encode("utf-8")).hexdigest()

def _attempts_of(machine_id: str, env_h: str) -> int:
    """Max des compteurs machine et enveloppe : usurper un machine_id neuf ne
    réinitialise rien, changer d'enveloppe non plus."""
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
    """Parse l'enveloppe → (eph_pub, salt, nonce, ct). Aucun déchiffrement ici :
    le GCM n'est ouvert qu'après TOUTES les vérifications (MAC, réponse)."""
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
    """Déchiffrement authentifié (GCM) de la session_key — appelé en DERNIER,
    une fois MAC + anti-rejeu + réponse validés."""
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
               info=b"envelope").derive(shared)
    session_key = AESGCM(key).decrypt(nonce, ct, salt)
    if len(session_key) != 32:
        raise ValueError("session_key invalide")
    return session_key

def _encrypt_response(session_key: bytes, shared: bytes, salt: bytes):
    """Chiffre la session_key pour la réponse (clé HKDF distincte,
    info=b'response') : elle ne circule jamais en clair, même côté logs."""
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
               info=b"response").derive(shared)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, session_key, None)
    return ct.hex(), nonce.hex()

def _poll_mac(shared: bytes, salt: bytes, machine_id: str, nonce: str,
              ts: str, env_h: str) -> str:
    """MAC attendu sur /poll : clé HKDF info=b'poll' (domaine distinct du
    MAC /unlock), couvre machine_id, nonce, ts et le hash de l'enveloppe."""
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
               info=b"poll").derive(shared)
    msg = "\n".join([machine_id, nonce, ts, env_h]).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

def _seen_nonce(machine_id: str, nonce: str) -> bool:
    """Anti-rejeu /poll : True si le nonce a DÉJÀ été vu (cache purgé de la
    fenêtre TS_WINDOW). Le MAC étant vérifié AVANT, un faux MAC ne consomme
    jamais rien."""
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
    """Marque la machine « vue » (script ouvert) pour la commande !list."""
    with _state_lock:
        STATE.setdefault("h:" + machine_id, {})['last_seen'] = time.time()
        _save_state(STATE)

def _arm_recovery(machine_id: str) -> bool:
    """Arme le drapeau de récupération d'urgence (one-shot, TTL).
    Refusé si la machine est verrouillée (!lock). Retourne True si la machine
    était déjà connue du serveur."""
    with _state_lock:
        if STATE.get("m:" + machine_id, {}).get("locked"):
            return False
        known = any((p + machine_id) in STATE for p in ("h:", "m:", "r:"))
        STATE["r:" + machine_id] = {"pending": True, "issued_ts": time.time()}
        _save_state(STATE)
    return known

def _take_recovery(machine_id: str):
    """Consomme le drapeau de récupération (une seule fois) et le renvoie,
    ou None s'il est absent / déjà consommé / expiré (RECOVERY_TTL) ou si la
    machine est verrouillée."""
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

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "fcrypt-server"}), 200

@app.route("/", methods=["GET"])
def root():
    """Ping racine : navigateur, cron-job.org et health-check Render
    (HEAD / inclus, géré automatiquement). JSON minuscule, aucun secret."""
    return jsonify({"status": "ok", "service": "fcrypt-server", "version": "1.3"}), 200

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

    if _is_locked(machine_id, env_h) or _env_unlocked(env_h) or _attempts_of(machine_id, env_h) >= MAX_ATTEMPTS:
        app.logger.info("unlock locked_out ip=%s machine=%s env=%s",
                        ip, machine_id[:8], env_h[:8])
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
    """Heartbeat signé du PC (lien opérateur) + remise du grant de
    récupération d'urgence. Même discipline que /unlock : formats stricts,
    MAC obligatoire AVANT toute écriture d'état, anti-rejeu par nonce."""
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
        return jsonify({"status": "ok"}), 200

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

def _discord_bot_main(token: str):
    try:
        import discord
        from discord.ext import commands
    except Exception as e:
        print(f"[bot] discord.py indisponible ({e}) — pip install discord.py")
        return
    intents = discord.Intents.default()
    intents.message_content = True
    bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

    @bot.event
    async def on_ready():
        print(f"[bot] connecté : {bot.user} (id={bot.user.id})")

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
                ("!lock <id>", "Verrouille la machine : `/unlock` renvoie `locked_out` même avec une bonne réponse au QCM ; `!recovery` désactivé ; les `.fcrypt` restent chiffrés.", False),
                ("!unlock <id>", "Retire un verrou posé par `!lock` (si le compteur de tentatives n'est pas épuisé).", False),
                ("!recovery <id>", "Récupération d'urgence : le PC affiche la progression du déchiffrement en % (refusé si verrouillée).", False),
                ("!help", "Cette aide.", False),
            ],
            footer=f"fcrypt-server · demandé par {ctx.author}"))

    @bot.command(name="list")
    async def _list_cmd(ctx):
        if not _admin(ctx):
            await ctx.send(embed=_embed("Accès refusé", COL_ERR))
            return
        now = time.time()
        with _state_lock:
            mids = sorted({k[2:] for k in STATE if k[:2] in ("h:", "m:")})
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
            ago = "jamais vu" if not hs else f"vu il y a {int(now - hs)} s"
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
                "`!lock <machine_id>` — verrouille la machine. Même une bonne "
                "réponse au QCM ne rendra plus la clé de session ; les `.fcrypt` "
                "déjà chiffrés le restent."))
            return
        n = _lock_machine(mid)
        await ctx.send(embed=_embed(
            f"Machine verrouillée — `{mid}`", COL_LOCK,
            f"{n} enveloppe(s) associée(s) gelée(s).",
            fields=[
                ("/unlock", "Renvoie désormais `locked_out` même si la réponse au QCM est correcte.", False),
                ("!recovery", "Désactivé pour cette machine.", False),
                (".fcrypt existants", "Une enveloppe neuve dérive une `session_key` différente, incapable de déchiffrer les fichiers existants.", False),
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
        with _state_lock:
            m = STATE.get("m:" + mid)
            was = bool(m and m.get("locked"))
            if was:
                m["locked"] = False
                m.pop("locked_ts", None)
                for env_h in list(m.get("envs", {}).keys()):
                    e = STATE.get("e:" + env_h)
                    if e:
                        e["locked"] = False
                        e.pop("locked_ts", None)
                _save_state(STATE)
        if was:
            await ctx.send(embed=_embed(
                f"Verrou levé — `{mid}`", COL_OK,
                "La machine peut à nouveau tenter un `/unlock` (si le compteur "
                "de tentatives n'est pas épuisé).",
                footer=f"déverrouillé par {ctx.author}"))
        else:
            await ctx.send(embed=_embed(
                "Aucun verrou actif", COL_INFO,
                f"`{mid}` n'était pas verrouillée."))

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
                "Cette machine est verrouillée (`!lock`). Annulez d'abord le verrou pour armer une récupération."))
            return
        known = _arm_recovery(mid)
        if known:
            await ctx.send(embed=_embed(
                f"Récupération armée — `{mid}`", COL_OK,
                "Le déchiffrement démarrera au prochain poll du PC (≤ ~10 s) ; "
                "la progression s'affichera en % sur son écran (interface du mini-jeu).",
                footer=f"armé par {ctx.author}"))
        else:
            await ctx.send(embed=_embed(
                f"Récupération armée (machine inconnue) — `{mid}`", COL_WARN,
                "Machine inconnue du serveur — drapeau armé quand même, mais il "
                "ne sera consommé que si ce PC poll réellement."))

    bot.run(token)

if DISCORD_BOT_TOKEN:
    threading.Thread(target=_discord_bot_main, args=(DISCORD_BOT_TOKEN,), daemon=True).start()
    print("[bot] thread Discord démarré")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)

