"""
ElectraCalc Backend - Servidor Flask Alternativo
Framework: Flask (Python 3.10+) con SQLite, Scrypt y Decorador @require_active_subscription
"""

import os
import time
import json
import hmac
import base64
import hashlib
import sqlite3
from functools import wraps
from typing import Optional
from datetime import datetime, timezone

from flask import Flask, request, jsonify, make_response, g

DB_FILE = os.getenv("ELECTRACALC_DB_PATH", os.path.join(os.path.dirname(__file__), "electracalc.db"))
SECRET_KEY = os.getenv("SECRET_KEY", "electracalc_super_secret_signing_key_change_in_production_99482")
COOKIE_NAME = "session_token"
IS_PRODUCTION = os.getenv("ENVIRONMENT", "development").lower() == "production"
TOKEN_MAX_AGE_SECONDS = 7 * 24 * 60 * 60

app = Flask(__name__)

# ---------------------------------------------------------
# Utilidades Criptográficas Scrypt y Token JWT
# ---------------------------------------------------------
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        maxmem=0,
        dklen=32,
    )
    return f"scrypt${salt.hex()}${key.hex()}"


def verify_password(password: str, hashed_password: str) -> bool:
    try:
        parts = hashed_password.split("$")
        if len(parts) != 3 or parts[0] != "scrypt":
            return False
        salt = bytes.fromhex(parts[1])
        expected_key = bytes.fromhex(parts[2])
        actual_key = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=16384,
            r=8,
            p=1,
            maxmem=0,
            dklen=32,
        )
        return hmac.compare_digest(actual_key, expected_key)
    except Exception:
        return False


def create_signed_token(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{signing_input}.{sig_b64}"


def decode_and_verify_token(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(
            SECRET_KEY.encode("utf-8"),
            signing_input.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        actual_sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)).decode())
        if payload.get("exp") and payload["exp"] < time.time():
            return None
        return payload
    except Exception:
        return None


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_FILE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            has_active_plan INTEGER NOT NULL DEFAULT 0,
            subscription_end_date TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cursor.execute("SELECT COUNT(*) as count FROM users")
    if cursor.fetchone()["count"] == 0:
        cursor.executemany(
            """
            INSERT INTO users (username, email, password_hash, is_active, has_active_plan, subscription_end_date)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                ("pro_engineer", "pro@electracalc.com.ar", hash_password("pro123"), 1, 1, "2030-12-31T23:59:59Z"),
                ("free_user", "free@electracalc.com.ar", hash_password("free123"), 1, 0, None),
                ("admin", "admin@electracalc.com.ar", hash_password("admin123"), 1, 1, "2035-01-01T00:00:00Z"),
            ],
        )
        conn.commit()
    conn.close()


# ---------------------------------------------------------
# Decoradores de Autenticación y Paywall
# ---------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get(COOKIE_NAME)
        if not token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ", 1)[1]

        if not token:
            return jsonify({"error": "unauthorized", "message": "No se encontró sesión activa"}), 401

        payload = decode_and_verify_token(token)
        if not payload:
            return jsonify({"error": "unauthorized", "message": "Sesión inválida o expirada"}), 401

        cursor = get_db().cursor()
        cursor.execute(
            "SELECT id, username, email, is_active, has_active_plan, subscription_end_date FROM users WHERE id = ?",
            (payload.get("sub"),),
        )
        user = cursor.fetchone()
        if not user or not user["is_active"]:
            return jsonify({"error": "unauthorized", "message": "Usuario inactivo o no encontrado"}), 401

        g.user = {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "has_active_plan": bool(user["has_active_plan"]),
            "subscription_end_date": user["subscription_end_date"],
        }
        return f(*args, **kwargs)
    return decorated_function


def require_active_subscription(f):
    """
    Middleware / Decorador @require_active_subscription para Flask.
    - 401 si no hay sesión.
    - 403 con {"error": "subscription_required"} si has_active_plan == False.
    """
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not g.user.get("has_active_plan"):
            return jsonify({
                "error": "subscription_required",
                "message": "Se requiere una suscripción activa para acceder a este módulo de cálculo.",
                "checkout_url": "/pricing",
            }), 403
        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------------------------
# Endpoints de Autenticación
# ---------------------------------------------------------
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    identifier = data.get("username", "").strip()
    raw_password = data.get("password", "")

    if not identifier or not raw_password:
        return jsonify({"error": "invalid_input", "message": "Debe ingresar usuario y contraseña"}), 400

    cursor = get_db().cursor()
    cursor.execute(
        "SELECT id, username, email, password_hash, is_active, has_active_plan, subscription_end_date FROM users WHERE username = ? OR email = ?",
        (identifier, identifier),
    )
    user = cursor.fetchone()

    if not user or not verify_password(raw_password, user["password_hash"]):
        return jsonify({"error": "invalid_credentials", "message": "Credenciales incorrectas"}), 401

    if not user["is_active"]:
        return jsonify({"error": "account_disabled", "message": "Cuenta inhabilitada"}), 403

    has_active_plan = bool(user["has_active_plan"])
    token = create_signed_token({
        "sub": user["id"],
        "username": user["username"],
        "email": user["email"],
        "has_active_plan": has_active_plan,
        "iat": int(time.time()),
        "exp": int(time.time() + TOKEN_MAX_AGE_SECONDS),
    })

    resp = make_response(jsonify({
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "has_active_plan": has_active_plan,
            "subscription_end_date": user["subscription_end_date"],
        }
    }))
    resp.set_cookie(
        COOKIE_NAME,
        token,
        max_age=TOKEN_MAX_AGE_SECONDS,
        httponly=True,
        secure=IS_PRODUCTION,
        samesite="Lax",
        path="/",
    )
    return resp


@app.route("/api/auth/me", methods=["GET"])
@login_required
def auth_me():
    return jsonify({"user": g.user})


@app.route("/api/logout", methods=["POST"])
def logout():
    resp = make_response(jsonify({"message": "Sesión cerrada correctamente", "success": True}))
    resp.set_cookie(COOKIE_NAME, "", max_age=0, expires=0, httponly=True, secure=IS_PRODUCTION, samesite="Lax", path="/")
    return resp


# ---------------------------------------------------------
# Rutas Protegidas por Paywall
# ---------------------------------------------------------
@app.route("/api/compute/circuit-sizing", methods=["GET"])
@require_active_subscription
def compute_circuit_sizing():
    return jsonify({
        "status": "success",
        "user": g.user["username"],
        "engine": "ElectraCalc AEA 90364-7-771",
    })


@app.route("/api/data/projects", methods=["GET"])
@require_active_subscription
def get_projects():
    return jsonify({"projects": []})


@app.route("/api/analyze-compliance", methods=["POST"])
@app.route("/api/compute/audit-compliance", methods=["POST"])
@require_active_subscription
def analyze_compliance():
    data = request.get_json(silent=True) or {}
    circuits = data.get("circuits", [])
    if not circuits:
        return jsonify({"error": "Debe proporcionar una lista de circuitos válida."}), 400

    # Retorno determinístico estructurado conforme a AEA 90364-7-771
    circuit_audits = []
    is_globally_compliant = True
    for c in circuits:
        calc = c.get("calculated", {})
        ip = float(calc.get("ip", 0) or 0)
        iz = float(calc.get("iz", 0) or 0)
        breaker = float(calc.get("breaker", 0) or 0)
        verdict = "compliant"
        issues = []
        if breaker < ip:
            verdict = "non_compliant"
            issues.append(f"In ({breaker} A) < Ip ({ip} A), provocará disparos intempestivos.")
        if breaker > iz:
            verdict = "non_compliant"
            issues.append(f"In ({breaker} A) > Iz ({iz} A), violando la regla de seguridad térmica AEA 771.19.")
        if verdict == "non_compliant":
            is_globally_compliant = False
        comments = " ".join(issues) if issues else f"Circuito conforme a los criterios de coordinación AEA 90364 (Ip={ip}A <= In={breaker}A <= Iz={iz}A)."
        circuit_audits.append({
            "circuitId": c.get("name") or c.get("id"),
            "verdict": verdict,
            "comments": comments,
        })

    return jsonify({
        "summary": "Auditoría técnica reglamentaria conforme a AEA 90364-7-770/771 y Ley Provincial 10.281 del ERSeP.",
        "isGloballyCompliant": is_globally_compliant,
        "circuitAudits": circuit_audits,
        "generalRecommendations": [
            "Verificar conductor de protección PE continuo (IRAM NM 247-3) según Tabla 771.19.I.",
            "Instalar interruptores diferenciales Idn = 30 mA para protección contra contactos directos e indirectos.",
            "Garantizar resistencia de puesta a tierra con jabalina IRAM 2309 Ra <= 40 Ohm.",
        ],
        "pdfDictamenText": "DICTAMEN TÉCNICO Y APTITUD REGLAMENTARIA (ERSeP / AEA): Instalación evaluada bajo la Ley 10.281.",
    })


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8000)), debug=not IS_PRODUCTION)
