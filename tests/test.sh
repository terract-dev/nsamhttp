#!/bin/bash
# nasmhttp test suite
# Author: jackson-peg

BASE="https://localhost:8443"
CURL="curl -sk -o /dev/null -w %{http_code}"
PASS=0
FAIL=0

check() {
    local desc="$1"
    local expected="$2"
    local actual="$3"

    if [ "$actual" = "$expected" ]; then
        echo "  PASS  $desc"
        PASS=$((PASS+1))
    else
        echo "  FAIL  $desc (expected $expected, got $actual)"
        FAIL=$((FAIL+1))
    fi
}

echo ""
echo "nasmhttp v0.1.0 - Test Suite"
echo "=============================="
echo ""

echo "[ Method Tests ]"
check "GET  /" "200" "$($CURL -X GET $BASE/)"
check "POST /data" "201" "$($CURL -X POST $BASE/data -H 'Content-Type: application/json' -d '{}')"
check "PUT  /data" "200" "$($CURL -X PUT $BASE/data -H 'Content-Type: application/json' -d '{}')"
check "DELETE /data" "204" "$($CURL -X DELETE $BASE/data)"
check "PATCH /data" "200" "$($CURL -X PATCH $BASE/data -H 'Content-Type: application/json' -d '{}')"

echo ""
echo "[ Error Handling ]"
check "GET  /unknown → 404" "404" "$($CURL -X GET $BASE/unknown)"
check "POST /       → 405" "405" "$($CURL -X POST $BASE/)"
check "DELETE /     → 405" "405" "$($CURL -X DELETE $BASE/)"

echo ""
echo "[ Static Files ]"
check "GET /static/index.html" "200" "$($CURL -X GET $BASE/static/index.html)"
check "GET /static/test.json" "200" "$($CURL -X GET $BASE/static/test.json)"
check "GET /static/missing.txt → 404" "404" "$($CURL -X GET $BASE/static/missing.txt)"

echo ""
echo "[ Response Body ]"
BODY=$(curl -sk -X GET $BASE/)
echo "$BODY" | grep -q '"status":"ok"' && check "GET / body has status ok" "ok" "ok" || check "GET / body has status ok" "ok" "fail"
echo "$BODY" | grep -q '"server":"nasmhttp"' && check "GET / body has server name" "ok" "ok" || check "GET / body has server name" "ok" "fail"

echo ""
echo "=============================="
echo "Results: $PASS passed, $FAIL failed"
echo ""

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
