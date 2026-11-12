#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
server.py — Serveur de validation pour Render (v1.2, durci).
Garde master.key, valide la réponse, renvoie la session_key CHIFFRÉE.

Sur Render : ce fichier s'appelle déjà « server.py » → Start Command inchangée :
    gunicorn server:app --bind 0.0.0.0:$PORT

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

Variables d'environnement (Render → Environment) :
  MASTER_KEY_B64   clé privée X25519 en base64 (générée à l'étape 1 du tuto)
  GOOD_ANSWER      réponse attendue (défaut "2")
  MAX_ATTEMPTS     nombre max d'essais par machine ET par enveloppe (défaut 1)
  STATE_FILE       chemin du fichier d'état (défaut /tmp/fcrypt_state.json)
  PORT             port d'écoute (Render injecte $PORT, défaut 10000)
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


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "fcrypt-server"}), 200


@app.route("/", methods=["GET"])
def root():
    """Ping racine : navigateur, cron-job.org et health-check Render
    (HEAD / inclus, géré automatiquement). JSON minuscule, aucun secret."""
    return jsonify({"status": "ok", "service": "fcrypt-server", "version": "1.2"}), 200


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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
