"""
Test suite de validación de Autenticación, Cookies Seguras y Paywall
"""

import sys
import os

# Asegurar path de importación
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from fastapi.testclient import TestClient
from server import app, init_db

init_db()
client = TestClient(app)

print("🧪 Iniciando pruebas de Autenticación, Cookies y Paywall...")

# 1. Login con credenciales incorrectas
res = client.post("/api/login", json={"username": "pro_engineer", "password": "wrong_password"})
assert res.status_code == 401, f"Esperaba 401, obtuve {res.status_code}"
print("✅ 1. Login con clave errónea bloqueado (401)")

# 2. Acceso sin cookie a endpoint protegido
res = client.get("/api/compute/circuit-sizing")
assert res.status_code == 401, f"Esperaba 401 sin sesión, obtuve {res.status_code}"
print("✅ 2. Acceso anónimo a /api/compute/* bloqueado (401)")

# 3. Login de Usuario PRO (Plan Activo)
res = client.post("/api/login", json={"username": "pro@electracalc.com.ar", "password": "pro123"})
assert res.status_code == 200, f"Error en login pro: {res.text}"
data = res.json()
assert data["user"]["has_active_plan"] is True, "El usuario pro debe tener has_active_plan == True"
cookies = res.cookies
assert "session_token" in cookies, "La cookie session_token no fue emitida"
set_cookie_header = res.headers.get("set-cookie", "")
assert "HttpOnly" in set_cookie_header, "La cookie debe tener flag HttpOnly"
assert "Path=/" in set_cookie_header, "La cookie debe tener flag Path=/"
print("✅ 3. Login Pro exitoso con Cookie HttpOnly y has_active_plan == True")

# 4. GET /api/auth/me con la cookie del usuario PRO
res_me = client.get("/api/auth/me", cookies=cookies)
assert res_me.status_code == 200, f"Error en auth/me: {res_me.text}"
assert res_me.json()["user"]["username"] == "pro_engineer"
print("✅ 4. /api/auth/me verificó la cookie y retornó el perfil de usuario")

# 5. Acceso a /api/compute/* con usuario PRO
res_compute = client.get("/api/compute/circuit-sizing", cookies=cookies)
assert res_compute.status_code == 200, f"Usuario pro debe acceder: {res_compute.text}"
print("✅ 5. Acceso autorizado al motor de cálculo (/api/compute/*)")

# 6. Login de Usuario FREE (Sin Plan Activo)
res_free = client.post("/api/login", json={"username": "free_user", "password": "free123"})
assert res_free.status_code == 200, f"Error en login free: {res_free.text}"
data_free = res_free.json()
assert data_free["user"]["has_active_plan"] is False, "El usuario free debe tener has_active_plan == False"
free_cookies = res_free.cookies
print("✅ 6. Login Free exitoso con has_active_plan == False")

# 7. Acceso a /api/compute/* con usuario FREE -> DEBE SER 403 FORBIDDEN (PAYWALL)
res_paywall = client.get("/api/compute/circuit-sizing", cookies=free_cookies)
assert res_paywall.status_code == 403, f"Esperaba 403 por paywall, obtuve {res_paywall.status_code}"
detail = res_paywall.json().get("detail", {})
assert detail.get("error") == "subscription_required", f"Esperaba subscription_required: {detail}"
print("✅ 7. Paywall Backend bloqueó al usuario sin suscripción con 403 Forbidden ({'error': 'subscription_required'})")

# 8. Logout
res_logout = client.post("/api/logout", cookies=cookies)
assert res_logout.status_code == 200
logout_cookie = res_logout.headers.get("set-cookie", "")
assert "max-age=0" in logout_cookie.lower() or "expires=" in logout_cookie.lower()
print("✅ 8. Logout limpió la cookie de sesión en el cliente y servidor")

print("\n🎉 ¡TODOS LOS TESTS DE AUTENTICACIÓN Y PAYWALL PASARON EXITOSAMENTE (8/8)!")
