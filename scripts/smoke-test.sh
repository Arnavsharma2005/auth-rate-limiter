#!/usr/bin/env bash
# Smoke test against a running app: ./scripts/smoke-test.sh [base-url]
# Needs: curl, and `docker compose` in this folder (to promote a user to ADMIN).
# Note: it uses up this machine's login rate limit for about a minute.
BASE=${1:-http://localhost:8080}
JSON='Content-Type: application/json'
pass=0; fail=0

check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "PASS  $1 ($3)"; pass=$((pass+1)); else echo "FAIL  $1 (expected $2, got $3)"; fail=$((fail+1)); fi
}
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
field() { sed -E "s/.*\"$1\":\"?([^\",}]*).*/\1/"; }

EMAIL="smoke-$(date +%s)-$RANDOM@example.com"
ADMIN="smoke-admin-$(date +%s)-$RANDOM@example.com"
PW=correct-horse-battery

check "health"                       200 "$(status $BASE/actuator/health)"
check "register"                     201 "$(status -X POST $BASE/auth/register -H "$JSON" -d "{\"email\":\"$EMAIL\",\"password\":\"$PW\"}")"
check "register duplicate"           409 "$(status -X POST $BASE/auth/register -H "$JSON" -d "{\"email\":\"$EMAIL\",\"password\":\"$PW\"}")"
check "register bad input"           400 "$(status -X POST $BASE/auth/register -H "$JSON" -d '{"email":"bad","password":"x"}')"

LOGIN=$(curl -s -X POST $BASE/auth/login -H "$JSON" -d "{\"email\":\"$EMAIL\",\"password\":\"$PW\"}")
ACCESS=$(echo "$LOGIN" | field accessToken); REFRESH=$(echo "$LOGIN" | field refreshToken)
check "login returns tokens"         yes "$([ ${#ACCESS} -gt 50 ] && [ ${#REFRESH} -eq 43 ] && echo yes || echo no)"
check "me with token"                200 "$(status $BASE/api/me -H "Authorization: Bearer $ACCESS")"
check "me without token"             401 "$(status $BASE/api/me)"
check "me with garbage token"        401 "$(status $BASE/api/me -H 'Authorization: Bearer garbage')"
check "admin endpoint as USER"       403 "$(status $BASE/api/admin/users -H "Authorization: Bearer $ACCESS")"

NEW=$(curl -s -X POST $BASE/auth/refresh -H "$JSON" -d "{\"refreshToken\":\"$REFRESH\"}")
NEW_REFRESH=$(echo "$NEW" | field refreshToken); NEW_ACCESS=$(echo "$NEW" | field accessToken)
check "refresh issues new pair"      yes "$([ ${#NEW_REFRESH} -eq 43 ] && [ "$NEW_REFRESH" != "$REFRESH" ] && echo yes || echo no)"
check "new access token works"       200 "$(status $BASE/api/me -H "Authorization: Bearer $NEW_ACCESS")"
check "old refresh token replay"     401 "$(status -X POST $BASE/auth/refresh -H "$JSON" -d "{\"refreshToken\":\"$REFRESH\"}")"
check "logout"                       204 "$(status -X POST $BASE/auth/logout -H "$JSON" -d "{\"refreshToken\":\"$NEW_REFRESH\"}")"
check "refresh after logout"         401 "$(status -X POST $BASE/auth/refresh -H "$JSON" -d "{\"refreshToken\":\"$NEW_REFRESH\"}")"

curl -s -o /dev/null -X POST $BASE/auth/register -H "$JSON" -d "{\"email\":\"$ADMIN\",\"password\":\"$PW\"}"
docker compose exec -T postgres psql -q -U auth -d auth -c "UPDATE users SET role='ADMIN' WHERE email='$ADMIN'" >/dev/null
ADMIN_ACCESS=$(curl -s -X POST $BASE/auth/login -H "$JSON" -d "{\"email\":\"$ADMIN\",\"password\":\"$PW\"}" | field accessToken)
check "admin endpoint as ADMIN"      200 "$(status $BASE/api/admin/users -H "Authorization: Bearer $ADMIN_ACCESS")"

check "github login when not configured" 401 "$(status $BASE/oauth2/authorization/github)"

# The bucket holds 5 tokens and some were used above, so a 429 must arrive within 6 more attempts
code=""; attempts=0
while [ "$code" != "429" ] && [ $attempts -lt 6 ]; do
  HDRS=$(curl -s -D - -o /dev/null -X POST $BASE/auth/login -H "$JSON" -d "{\"email\":\"$EMAIL\",\"password\":\"wrong-pass\"}")
  code=$(echo "$HDRS" | head -1 | grep -oE '[0-9]{3}'); attempts=$((attempts+1))
done
check "login rate limit within 6 attempts" 429 "$code"
check "Retry-After header present"   yes "$(echo "$HDRS" | grep -qi '^Retry-After: [0-9]' && echo yes || echo no)"
# %6c decodes to "l", so this is the same login endpoint and must share the same limit
check "encoded login path also limited" 429 "$(status -X POST "$BASE/auth/%6cogin" -H "$JSON" -d "{\"email\":\"$EMAIL\",\"password\":\"$PW\"}")"

echo "----"; echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
