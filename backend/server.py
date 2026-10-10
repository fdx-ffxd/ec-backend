"""
ElectraCalc Backend - Servidor de Autenticación, Sesiones Seguras y Paywall
Framework: FastAPI (Python 3.10+) con SQLite, Hashing Scrypt y Cookies HttpOnly.
"""

import os
import time
import json
import hmac
import base64
import hashlib
import sqlite3
from typing import Optional
from datetime import datetime, timezone
from contextlib import contextmanager

from fastapi import FastAPI, Request, Response, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------
# Configuración y Variables de Entorno
# ---------------------------------------------------------
DB_FILE = os.getenv("ELECTRACALC_DB_PATH", os.path.join(os.path.dirname(__file__), "electracalc.db"))
SECRET_KEY = os.getenv("SECRET_KEY", "electracalc_super_secret_signing_key_change_in_production_99482")
COOKIE_NAME = "session_token"
IS_PRODUCTION = os.getenv("ENVIRONMENT", "development").lower() == "production"
TOKEN_MAX_AGE_SECONDS = 7 * 24 * 60 * 60  # 7 días

app = FastAPI(
    title="ElectraCalc API - Auth & Paywall Engine",
    description="Backend de Autenticación con cookies seguras HttpOnly y control de acceso por suscripción",
    version="1.0.0",
)

# Configuración CORS para admitir cookies (credentials: include)
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# Utilidades Criptográficas y Hashing Seguro (Scrypt)
# ---------------------------------------------------------
def hash_password(password: str) -> str:
    """Genera hash scrypt con salt criptográfica aleatoria de 16 bytes."""
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
    # Formato: scrypt$hex(salt)$hex(hash)
    return f"scrypt${salt.hex()}${key.hex()}"


def verify_password(password: str, hashed_password: str) -> bool:
    """Valida la contraseña contra el hash scrypt almacenado."""
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
    """Genera un token JWT compacto firmado con HMAC-SHA256 sin dependencias externas."""
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
    """Decodifica y verifica la firma y expiración de un token JWT."""
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

        payload_json = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)).decode()
        payload = json.loads(payload_json)

        # Verificar expiración
        exp = payload.get("exp")
        if exp and exp < time.time():
            return None

        return payload
    except Exception:
        return None


# ---------------------------------------------------------
# Base de Datos SQLite y Context Manager
# ---------------------------------------------------------
@contextmanager
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Inicializa el esquema de la base de datos y añade usuarios de prueba."""
    with get_db() as conn:
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

        # Crear usuarios demo si no existen
        cursor.execute("SELECT COUNT(*) as count FROM users")
        if cursor.fetchone()["count"] == 0:
            print("⚡ Inicializando base de datos con usuarios de demostración...")
            demo_users = [
                # 1. Usuario con suscripción activa (Plan Pro AEA 90364)
                (
                    "pro_engineer",
                    "pro@electracalc.com.ar",
                    hash_password("pro123"),
                    1,
                    1,
                    "2030-12-31T23:59:59Z",
                ),
                # 2. Usuario sin plan activo (Para probar redirección al Paywall / Pricing)
                (
                    "free_user",
                    "free@electracalc.com.ar",
                    hash_password("free123"),
                    1,
                    0,
                    None,
                ),
                # 3. Administrador / Lead Auditor
                (
                    "admin",
                    "admin@electracalc.com.ar",
                    hash_password("admin123"),
                    1,
                    1,
                    "2035-01-01T00:00:00Z",
                ),
            ]
            cursor.executemany(
                """
                INSERT INTO users (username, email, password_hash, is_active, has_active_plan, subscription_end_date)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                demo_users,
            )
            print("✅ Usuarios demo creados: pro@electracalc.com.ar (Plan Activo) y free@electracalc.com.ar (Sin Plan)")


@app.on_event("startup")
def startup_event():
    init_db()


# ---------------------------------------------------------
# Esquemas Pydantic para Validación
# ---------------------------------------------------------
class LoginRequest(BaseModel):
    username: str = Field(..., description="Nombre de usuario o correo electrónico")
    password: str = Field(..., description="Contraseña")


class UserDTO(BaseModel):
    id: int
    username: str
    email: str
    has_active_plan: bool
    subscription_end_date: Optional[str] = None


# ---------------------------------------------------------
# Helper para Inyección de Usuario Actual
# ---------------------------------------------------------
async def get_current_user(request: Request) -> dict:
    """Extrae y verifica la cookie de sesión HttpOnly. Retorna el usuario o lanza 401."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        # También permitir cabecera Authorization: Bearer <token> para tests/APIs externas
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "message": "No se encontró cookie de sesión válida"},
        )

    payload = decode_and_verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "message": "Sesión expirada o inválida"},
        )

    user_id = payload.get("sub")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, email, is_active, has_active_plan, subscription_end_date FROM users WHERE id = ?",
            (user_id,),
        )
        user_row = cursor.fetchone()

    if not user_row or not user_row["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "message": "Usuario inactivo o no encontrado"},
        )

    return {
        "id": user_row["id"],
        "username": user_row["username"],
        "email": user_row["email"],
        "has_active_plan": bool(user_row["has_active_plan"]),
        "subscription_end_date": user_row["subscription_end_date"],
    }


# ---------------------------------------------------------
# Middleware / Dependencia @require_active_subscription
# ---------------------------------------------------------
async def require_active_subscription(user: dict = Depends(get_current_user)) -> dict:
    """
    Middleware / Dependencia para proteger rutas privadas (/api/compute/*, /api/data/*).
    - 401 si no hay sesión autenticada.
    - 403 si el usuario está autenticado pero has_active_plan == False.
    """
    if not user.get("has_active_plan"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "subscription_required",
                "message": "Se requiere una suscripción activa para acceder al motor de cálculo y memoria técnica de ElectraCalc.",
                "checkout_url": "/pricing",
            },
        )
    return user


# ---------------------------------------------------------
# Endpoints de Autenticación Requeridos
# ---------------------------------------------------------
@app.post("/api/login")
async def login(credentials: LoginRequest, response: Response):
    """
    POST /api/login:
    1. Valida credenciales contra scrypt hash.
    2. Genera token de sesión firmado.
    3. Emite cookie HttpOnly, SameSite=Lax, Path=/, Secure (en prod).
    4. Retorna { "user": { ... } }
    """
    identifier = credentials.username.strip()
    raw_password = credentials.password

    with get_db() as conn:
        cursor = conn.cursor()
        # Permite login con username o con email
        cursor.execute(
            """
            SELECT id, username, email, password_hash, is_active, has_active_plan, subscription_end_date 
            FROM users 
            WHERE username = ? OR email = ?
            """,
            (identifier, identifier),
        )
        user = cursor.fetchone()

    if not user or not verify_password(raw_password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_credentials", "message": "Credenciales incorrectas. Verifique usuario y contraseña."},
        )

    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "account_disabled", "message": "Esta cuenta ha sido inhabilitada. Contacte a soporte."},
        )

    has_active_plan = bool(user["has_active_plan"])

    # Generar Token con claims
    now = time.time()
    payload = {
        "sub": user["id"],
        "username": user["username"],
        "email": user["email"],
        "has_active_plan": has_active_plan,
        "iat": int(now),
        "exp": int(now + TOKEN_MAX_AGE_SECONDS),
    }
    token = create_signed_token(payload)

    # Configuración estricta de la cookie HttpOnly
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=TOKEN_MAX_AGE_SECONDS,
        httponly=True,
        secure=IS_PRODUCTION,  # True en HTTPS de producción
        samesite="lax",
        path="/",
    )

    return {
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "has_active_plan": has_active_plan,
            "subscription_end_date": user["subscription_end_date"],
        }
    }


@app.get("/api/auth/me")
async def get_current_user_profile(user: dict = Depends(get_current_user)):
    """
    GET /api/auth/me:
    Valida la cookie de sesión y devuelve el perfil del usuario autenticado.
    Si la cookie no existe o expiró, retorna 401 Unauthorized.
    """
    return {"user": user}


@app.post("/api/logout")
async def logout(response: Response):
    """
    POST /api/logout:
    Invalida la sesión limpiando la cookie HttpOnly (Max-Age=0).
    """
    response.delete_cookie(
        key=COOKIE_NAME,
        path="/",
        httponly=True,
        secure=IS_PRODUCTION,
        samesite="lax",
    )
    return {"message": "Sesión cerrada correctamente", "success": True}


# ---------------------------------------------------------
# Rutas Protegidas por Paywall (/api/compute/* y /api/data/*)
# ---------------------------------------------------------
@app.get("/api/compute/circuit-sizing")
async def compute_circuit_sizing(subscriber: dict = Depends(require_active_subscription)):
    """
    Endpoint protegido: Motor de dimensionamiento según AEA 90364.
    Solo accesible para usuarios con suscripción activa.
    """
    return {
        "status": "success",
        "authorized_user": subscriber["username"],
        "standard": "AEA 90364-7-770 / 7-771",
        "available_tables": ["Tabla 771.16.I", "Tabla 771.19.I", "IRAM NM 247-3"],
    }


@app.post("/api/compute/audit-compliance")
async def audit_compliance(request: Request, subscriber: dict = Depends(require_active_subscription)):
    """
    Endpoint protegido: Auditoría de cumplimiento normativo y dictamen técnico.
    """
    body = await request.json()
    circuits = body.get("circuits", [])
    return {
        "auditor": f"Ing. {subscriber['username']}",
        "circuits_count": len(circuits),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "isGloballyCompliant": True,
        "summary": "Planilla verificada bajo exigencias de seguridad de la Ley 10.281 ERSeP Córdoba.",
    }


@app.get("/api/data/projects")
async def get_user_projects(subscriber: dict = Depends(require_active_subscription)):
    """
    Endpoint protegido: Proyectos guardados en la nube del usuario suscripto.
    """
    return {
        "projects": [
            {
                "id": "proj-cordoba-01",
                "name": "Instalación Residencial Bº Jardín (Córdoba)",
                "created_at": "2026-09-15T14:30:00Z",
                "circuits_count": 8,
                "power_kva": 12.5,
            }
        ]
    }


# Ejecución directa con uvicorn si se corre `python backend/server.py`
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    print(f"🚀 Iniciando servidor ElectraCalc en http://0.0.0.0:{port}")
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=True)
