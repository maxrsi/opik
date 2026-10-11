#!/bin/bash
# Assumes a FRESH stack started with OPIK_AUTH_BOOTSTRAP_ADMIN_PASSWORD=Bootstrap-Admin-Pass-1 (it changes passwords
# and creates users ed/vi). Needs curl, python3 and docker (for the ClickHouse check).
# End-to-end check against the docker-compose + docker-compose.auth.yaml stack (http://localhost:5173).
B=${B:-http://localhost:5173}
J='Content-Type: application/json'
W='Comet-Workspace: default'
C=/tmp/e2e-cookies; rm -rf $C; mkdir -p $C
req() { # name method path [data] -> prints "status body"
  local who=$1 m=$2 p=$3 d=$4
  curl -s -o /tmp/e2e-body -w '%{http_code}' -b $C/$who -c $C/$who -X $m -H "$J" -H "$W" ${d:+-d "$d"} "$B$p"; echo " $(head -c 300 /tmp/e2e-body)"
}
key() { # apikey method path [data]
  curl -s -o /tmp/e2e-body -w '%{http_code}' -X $2 -H "$J" -H "$W" -H "Authorization: $1" ${4:+-d "$4"} "$B$3"; echo " $(head -c 200 /tmp/e2e-body)"
}
echo "== 1 bootstrap admin login";   req admin POST /auth/api/login '{"username":"admin","password":"Bootstrap-Admin-Pass-1"}'
echo "== 1a wrong password";          req bad POST /auth/api/login '{"username":"admin","password":"wrong-password-123"}'
echo "== 1b API blocked before password change"; req admin GET /api/v1/private/projects
echo "== 1c change password";        req admin POST /auth/api/me/password '{"currentPassword":"Bootstrap-Admin-Pass-1","newPassword":"Admin-Pass-E2E-2026"}'
echo "== 1d me";                     req admin GET /auth/api/me
echo "== 2 create editor/viewer"
req admin POST /auth/api/users '{"username":"ed","role":"editor","userType":"human","password":"Editor-Initial-Pass-1"}'
req admin POST /auth/api/users '{"username":"vi","role":"viewer","userType":"human","password":"Viewer-Initial-Pass-1"}'
for u in ed:Editor vi:Viewer; do n=${u%%:*}; r=${u##*:}
  req $n POST /auth/api/login "{\"username\":\"$n\",\"password\":\"$r-Initial-Pass-1\"}"
  req $n POST /auth/api/me/password "{\"currentPassword\":\"$r-Initial-Pass-1\",\"newPassword\":\"$r-Final-Pass-2026\"}"
done
echo "== 3 viewer: read ok, writes denied"
req vi GET /api/v1/private/projects
req vi POST /api/v1/private/projects '{"name":"viewer-project"}'
req vi POST /api/v1/private/datasets '{"name":"viewer-ds"}'
req vi POST /api/v1/private/feedback-definitions '{"name":"fd","type":"numerical","details":{"min":0,"max":1}}'
echo "== 4 editor: writes ok"
req ed POST /api/v1/private/projects '{"name":"editor-project"}'
req ed POST /api/v1/private/datasets '{"name":"editor-ds"}'
req ed POST /api/v1/private/feedback-definitions '{"name":"fd-ed","type":"numerical","details":{"min":0,"max":1}}'
echo "== 5 API keys"
EK=$(curl -s -b $C/ed -X POST -H "$J" -d '{"name":"sdk"}' $B/auth/api/me/api-keys | python3 -c 'import sys,json;print(json.load(sys.stdin)["key"])')
VK=$(curl -s -b $C/vi -X POST -H "$J" -d '{"name":"sdk"}' $B/auth/api/me/api-keys | python3 -c 'import sys,json;print(json.load(sys.stdin)["key"])')
TID=$(python3 -c 'import uuid,time;t=int(time.time()*1000);u=uuid.uuid4().int;print(str(uuid.UUID(int=(t<<80)|(0x7<<76)|(u&((1<<76)-1))&~(0x3<<62)|(0x2<<62))))')
NOW=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "editor key -> create trace";  key $EK POST /api/v1/private/traces "{\"id\":\"$TID\",\"project_name\":\"sdk-project\",\"name\":\"t\",\"start_time\":\"$NOW\"}"
echo "editor key -> get trace";     sleep 2; key $EK GET /api/v1/private/traces/$TID
echo "viewer key -> create trace";  key $VK POST /api/v1/private/traces "{\"project_name\":\"sdk-project\",\"name\":\"t2\",\"start_time\":\"$NOW\"}"
echo "viewer key -> list projects"; key $VK GET /api/v1/private/projects
echo "bad key";                     key not-a-key GET /api/v1/private/projects
echo "no credentials";              curl -s -o /dev/null -w '%{http_code}\n' -H "$W" $B/api/v1/private/projects
echo "SDK auth check endpoint";     key $EK POST /api/v1/private/auth ''
echo "== 6 internal endpoints hidden"; curl -s -o /dev/null -w '%{http_code}\n' $B/api/v1/internal/usage/bi-traces
echo "== 7 opik-auth protocol not exposed"; curl -s -o /dev/null -w '%{http_code}\n' -X POST $B/auth/opik/auth
echo "== 8 revoke key + logout"
KID=$(curl -s -b $C/ed $B/auth/api/me/api-keys | python3 -c 'import sys,json;print([k["id"] for k in json.load(sys.stdin) if k["name"]=="sdk"][0])')
req ed DELETE /auth/api/me/api-keys/$KID
sleep 7  # AUTH_API_KEY_RESOLUTION_CACHE_TTL_IN_SEC=5
echo "revoked editor key -> list projects"; key $EK GET /api/v1/private/projects
req ed POST /auth/api/logout
req ed GET /api/v1/private/projects
sleep 3
echo "== 9 audit via API (admin)"; curl -s -b $C/admin "$B/auth/api/audit-logs?size=100" | python3 -c '
import sys,json; d=json.load(sys.stdin); print("total",d["total"])
for i in d["content"]: print(i["eventTime"],i["source"],i["actor"],i["action"],i["outcome"],i["status"],i["route"] or i["path"])'
echo "viewer audit access"; req vi GET /auth/api/audit-logs
echo "== 10 ClickHouse audit_logs (direct)"
docker exec opik-clickhouse-1 clickhouse-client -u opik --password opik -q "SELECT source, action, outcome, count() FROM opik.audit_logs GROUP BY source, action, outcome ORDER BY source, action FORMAT PrettyCompactMonoBlock"
docker exec opik-clickhouse-1 clickhouse-client -u opik --password opik -q "SELECT engine_full LIKE '%TTL toDateTime(event_time) + toIntervalDay(180)%' AS ttl_180d FROM system.tables WHERE database='opik' AND name='audit_logs'"
