#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"

need() { command -v "$1" >/dev/null || { echo "Falta $1"; exit 1; }; }
need curl; need jq; need base64

echo "== 1) Tokens"
TADM=$(curl -sS -X POST "$BASE_URL/api/token/" -H "Content-Type: application/json" -d '{"username":"admin1","password":"Admin_12345"}' | jq -r .access)
TTEC=$(curl -sS -X POST "$BASE_URL/api/token/" -H "Content-Type: application/json" -d '{"username":"tecnico1","password":"TecniC0_123"}' | jq -r .access)
TUSR=$(curl -sS -X POST "$BASE_URL/api/token/" -H "Content-Type: application/json" -d '{"username":"usuario1","password":"Usuari0_123"}' | jq -r .access)

echo "== 2) Roles en JWT"
echo "Técnico:"; echo "$TTEC" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{username,roles,is_staff}' || true
echo "Usuario:"; echo "$TUSR" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{username,roles,is_staff}' || true
echo "Admin:";   echo "$TADM" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{username,roles,is_staff}' || true

echo "== 3) Crear categoría si no existe"
CID=$(curl -sS -H "Authorization: Bearer $TADM" "$BASE_URL/api/categories/" | jq -r '(.results?[0].id // .[0].id // empty)')
if [[ -z "${CID:-}" || "$CID" == "null" ]]; then
  curl -sS -X POST "$BASE_URL/api/categories/" \
    -H "Authorization: Bearer $TADM" -H "Content-Type: application/json" \
    -d '{"name":"General"}' >/dev/null
  CID=$(curl -sS -H "Authorization: Bearer $TADM" "$BASE_URL/api/categories/" | jq -r '(.results?[0].id // .[0].id)')
fi
echo "CID=$CID"

echo "== 4) Crear tickets de prueba"
echo "Ticket usuario:"
curl -sS -X POST "$BASE_URL/api/tickets/" \
  -H "Authorization: Bearer $TUSR" -H "Content-Type: application/json" \
  -d "{\"title\":\"Ticket de usuario\",\"description\":\"prueba\",\"category\":{\"name\":\"General\"}}" \
| jq '{id,title,state,requester: .requester.username,category: .category.name}'

echo "Ticket tecnico:"
curl -sS -X POST "$BASE_URL/api/tickets/" \
  -H "Authorization: Bearer $TTEC" -H "Content-Type: application/json" \
  -d "{\"title\":\"Ticket de tecnico\",\"description\":\"prueba\",\"category\":{\"name\":\"General\"}}" \
| jq '{id,title,state,requester: .requester.username,category: .category.name}'

echo "== 5) Listados por rol"
echo -n "usuario1 ve: "
curl -sS -H "Authorization: Bearer $TUSR" "$BASE_URL/api/tickets/" | jq 'length'
echo -n "tecnico1 ve: "
curl -sS -H "Authorization: Bearer $TTEC" "$BASE_URL/api/tickets/" | jq 'length'
echo -n "admin1 ve: "
curl -sS -H "Authorization: Bearer $TADM" "$BASE_URL/api/tickets/" | jq 'length'

echo "== Listo"
