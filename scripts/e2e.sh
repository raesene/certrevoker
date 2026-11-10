#!/usr/bin/env bash
# End-to-end demo / test for the certrevoker PoC. Run from a host with kubectl
# access to the cluster and network access to the control-plane and worker nodes.
#
#   CTX=vmm-certrevoke CP_IP=172.16.0.5 WORKER_IP=172.16.0.6 TLS_DIR=./tls \
#   SUPER_ADMIN_KUBECONFIG=./super-admin.conf ./e2e.sh
#
# Scenarios:
#   1. Issue client certs via the CSR API: alice and bob (group "devs"), carol
#      (group "kubeadm:cluster-admins", which kubeadm binds to cluster-admin).
#      A CSR for O=system:masters is rejected by the CertificateSubjectRestriction
#      admission plugin.
#   2. They appear in the inventory (Source=CSR) and the portal.
#   3. Revoke alice through the portal's HTTP flow (TokenReview login + CSRF).
#      alice is denied at kube-apiserver; bob is unaffected. Measure latency.
#   4. alice is also denied when going directly to a kubelet (the kubelet
#      authorizes via SubjectAccessReview, which reaches the webhook). Measure
#      latency: the kubelet caches its own authorization decisions.
#   5. carol (cluster-admin via an RBAC-bound group) can be revoked.
#      kubeadm's super-admin.conf (O=system:masters) cannot: the portal's
#      Inspect page flags it, and revoking it has no effect.
#   6. Webhook outage: failurePolicy NoOpinion means revoked certs work again
#      until it's back (the fail-open trade-off).
#   7. Denied-request counter; unrevoke alice; access returns.
set -uo pipefail
CTX=${CTX:-vmm-certrevoke}
CP_IP=${CP_IP:-172.16.0.5}
WORKER_IP=${WORKER_IP:-172.16.0.6}
TLS_DIR=${TLS_DIR:-./tls}
SUPER_ADMIN_KUBECONFIG=${SUPER_ADMIN_KUBECONFIG:-}
PORTAL=https://$CP_IP:8443
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
K="kubectl --context $CTX"
PASS=0; FAIL=0
ok()   { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
step() { echo; echo "== $*"; }

CA_DATA=$($K config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
SERVER=$($K config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')

csr_manifest() { # name csr-file
  cat <<EOF
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata: {name: e2e-$1}
spec:
  request: $(base64 -w0 < "$2")
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 86400
  usages: [client auth]
EOF
}

issue_cert() { # name org
  local name=$1 org=$2
  openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/$name.key" 2>/dev/null
  openssl req -new -key "$WORK/$name.key" -subj "/CN=$name/O=$org" -out "$WORK/$name.csr" 2>/dev/null
  $K delete csr "e2e-$name" --ignore-not-found >/dev/null
  csr_manifest "$name" "$WORK/$name.csr" | $K apply -f - >/dev/null || return 1
  $K certificate approve "e2e-$name" >/dev/null
  for _ in $(seq 1 30); do
    $K get csr "e2e-$name" -o jsonpath='{.status.certificate}' | base64 -d > "$WORK/$name.crt" 2>/dev/null
    [ -s "$WORK/$name.crt" ] && break; sleep 1
  done
  cat > "$WORK/$name.kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: $SERVER, certificate-authority-data: $CA_DATA}}]
users: [{name: $name, user: {client-certificate-data: $(base64 -w0 < "$WORK/$name.crt"), client-key-data: $(base64 -w0 < "$WORK/$name.key")}}]
contexts: [{name: c, context: {cluster: c, user: $name}}]
current-context: c
EOF
}

cred_id() { echo "X509SHA256=$(openssl x509 -in "$WORK/$1.crt" -outform DER | sha256sum | cut -d' ' -f1)"; }
as() { local who=$1; shift; kubectl --kubeconfig "$WORK/$who.kubeconfig" "$@" 2>&1; }
kubelet_pods() { # prints HTTP status for GET /pods on the worker's kubelet as $1
  curl -s -o /dev/null -w '%{http_code}' -k \
    --cert "$WORK/$1.crt" --key "$WORK/$1.key" "https://$WORKER_IP:10250/pods"
}

# Portal session using the demo admin token.
portal_login() {
  local token; token=$($K -n certrevoker create token revocation-admin --duration=1h)
  rm -f "$WORK/jar"
  curl -s --cacert "$TLS_DIR/ca.crt" -c "$WORK/jar" -b "$WORK/jar" -o /dev/null \
    --data-urlencode "token=$token" "$PORTAL/login"
  CSRF=$(curl -s --cacert "$TLS_DIR/ca.crt" -b "$WORK/jar" "$PORTAL/" | grep -o 'name="csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"$//')
}
portal_post() { # path id [reason]
  curl -s --cacert "$TLS_DIR/ca.crt" -b "$WORK/jar" -o /dev/null -w '%{http_code}' \
    --data-urlencode "csrf=$CSRF" --data-urlencode "id=$2" --data-urlencode "reason=${3:-}" "$PORTAL$1"
}
portal_page() { curl -s --cacert "$TLS_DIR/ca.crt" -b "$WORK/jar" "$PORTAL$1"; }

# wait_until <timeout-seconds> <command...>; prints elapsed seconds, returns 1 on timeout
wait_until() {
  local timeout=$1; shift; local start=$SECONDS
  until "$@"; do
    (( SECONDS - start >= timeout )) && { echo "timeout"; return 1; }
    sleep 1
  done
  echo $((SECONDS - start))
}

##############################################################################
step "1. Issue client certificates via the CSR API"
issue_cert alice devs
issue_cert bob devs
issue_cert carol kubeadm:cluster-admins
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/m.key" 2>/dev/null
openssl req -new -key "$WORK/m.key" -subj "/CN=mallory/O=system:masters" -out "$WORK/m.csr" 2>/dev/null
out=$(csr_manifest mallory "$WORK/m.csr" | $K apply -f - 2>&1)
grep -q "system:masters group is not allowed" <<<"$out" \
  && ok "CSR for O=system:masters rejected by CertificateSubjectRestriction admission" \
  || bad "system:masters CSR not rejected: $out"
$K create clusterrolebinding e2e-devs-view --clusterrole=view --group=devs --dry-run=client -o yaml | $K apply -f - >/dev/null
# Let devs read pods through the kubelet API too (nodes/proxy, nodes/pods).
cat <<'EOF' | $K apply -f - >/dev/null
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: e2e-kubelet-read}
rules:
- {apiGroups: [""], resources: [nodes/proxy, nodes/pods], verbs: [get]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: e2e-devs-kubelet-read}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: e2e-kubelet-read}
subjects: [{kind: Group, name: devs, apiGroup: rbac.authorization.k8s.io}]
EOF
ALICE=$(cred_id alice); BOB=$(cred_id bob); CAROL=$(cred_id carol)
echo "  alice $ALICE"; echo "  bob   $BOB"; echo "  carol $CAROL (O=kubeadm:cluster-admins)"
as alice get pods -n kube-system >/dev/null && ok "alice can list pods" || bad "alice cannot list pods"
as bob get pods -n kube-system >/dev/null && ok "bob can list pods" || bad "bob cannot list pods"
as carol get secrets -A >/dev/null && ok "carol (CSR-issued kubeadm:cluster-admins) can list all secrets" || bad "carol cannot list secrets"
[ "$(kubelet_pods alice)" = 200 ] && ok "alice can read pods directly from the worker kubelet" || bad "alice cannot reach kubelet /pods"
WHOAMI=$(as alice auth whoami -o jsonpath='{.status.userInfo.extra.authentication\.kubernetes\.io/credential-id[0]}')
[ "$WHOAMI" = "$ALICE" ] && ok "kubectl auth whoami credential-id matches our computed ID" || bad "whoami ID $WHOAMI != $ALICE"

step "2. Certificates appear in the inventory and portal"
in_inventory() { $K get issuedcertificate "sha256-${1#X509SHA256=}" >/dev/null 2>&1; }
for who in alice bob carol; do
  t=$(wait_until 30 in_inventory "$(cred_id $who)") && ok "$who recorded in inventory (${t}s)" || bad "$who not in inventory"
done
portal_login
[ -n "$CSRF" ] && ok "logged in to portal with revocation-admin token" || bad "portal login failed"
page=$(portal_page /)
grep -q '>alice<' <<<"$page" && grep -q '>kubernetes-admin<' <<<"$page" \
  && ok "portal lists alice (CSR) and kubeadm's kubernetes-admin (Observed)" || bad "portal inventory page unexpected"

step "3. Revoke alice via the portal; kube-apiserver denies her"
code=$(portal_post /revoke "$ALICE" "e2e: laptop stolen")
[ "$code" = 303 ] && ok "portal accepted revocation" || bad "portal revoke returned $code"
$K get certificaterevocations
alice_denied() { [[ $(as alice get pods -n kube-system) == *"has been revoked"* ]]; }  # no pipe: pipefail would see kubectl exit 1
t=$(wait_until 60 alice_denied) && ok "alice denied at kube-apiserver after ${t}s (webhook unauthorizedTTL is 10s)" || bad "alice still allowed after 60s"
echo "  alice now sees: $(as alice get pods -n kube-system | head -1)"
as bob get pods -n kube-system >/dev/null && ok "bob unaffected" || bad "bob was affected"
as alice auth whoami >/dev/null 2>&1 && bad "alice can still call SelfSubjectReview" || ok "explicit deny also blocks alice's SelfSubjectReview (system:authenticated grants don't apply)"

step "4. alice is also denied directly at the kubelet (SubjectAccessReview path)"
kubelet_denied() { [ "$(kubelet_pods alice)" = 403 ]; }
echo "  (the kubelet caches 'allowed' decisions for authorization.webhook.cacheAuthorizedTTL, default 5m)"
t=$(wait_until 330 kubelet_denied) && ok "kubelet denied alice after ${t}s" || bad "kubelet still allows alice after 330s"
[ "$(kubelet_pods bob)" = 200 ] && ok "bob still allowed at kubelet" || bad "bob denied at kubelet"

step "5. cluster-admin via an RBAC group can be revoked; system:masters cannot"
portal_post /revoke "$CAROL" "e2e: departed admin" >/dev/null
carol_denied() { [[ $(as carol get secrets -A) == *"has been revoked"* ]]; }
t=$(wait_until 60 carol_denied) && ok "carol (cluster-admin via kubeadm:cluster-admins) denied after ${t}s" || bad "carol still allowed"
if [ -n "$SUPER_ADMIN_KUBECONFIG" ] && [ -r "$SUPER_ADMIN_KUBECONFIG" ]; then
  SA_ID=$(kubectl config view --raw --kubeconfig "$SUPER_ADMIN_KUBECONFIG" -o jsonpath='{.users[0].user.client-certificate-data}' \
    | base64 -d | openssl x509 -outform DER | sha256sum | cut -d' ' -f1)
  SA_ID="X509SHA256=$SA_ID"
  sa() { kubectl --kubeconfig "$SUPER_ADMIN_KUBECONFIG" --server "$SERVER" "$@" 2>&1; }
  # Send only the certificate (never the private key) to the portal.
  kubectl config view --raw --kubeconfig "$SUPER_ADMIN_KUBECONFIG" -o jsonpath='{.users[0].user.client-certificate-data}' \
    | base64 -d > "$WORK/super-admin.crt"
  insp=$(curl -s --cacert "$TLS_DIR/ca.crt" -b "$WORK/jar" --data-urlencode "csrf=$CSRF" \
    --data-urlencode "input@$WORK/super-admin.crt" "$PORTAL/inspect")
  grep -q "will not be enforced" <<<"$insp" && grep -q "${SA_ID#X509SHA256=}" <<<"$insp" \
    && ok "portal Inspect computes super-admin.conf's ID and flags system:masters as not enforceable" || bad "inspect output unexpected"
  portal_post /revoke "$SA_ID" "e2e: should have no effect" >/dev/null
  sleep 15
  sa get secrets -A >/dev/null && ok "super-admin.conf (system:masters) still works after revocation: expected limitation" || bad "super-admin was blocked?"
  in_inventory "$SA_ID" && bad "super-admin unexpectedly observed by webhook" || ok "super-admin.conf never reaches the webhook (not in the 'seen' inventory)"
  portal_post /unrevoke "$SA_ID" >/dev/null
else
  echo "  (skipping super-admin.conf checks: set SUPER_ADMIN_KUBECONFIG)"
fi

step "6. Webhook outage: failurePolicy NoOpinion fails open"
$K -n certrevoker scale deploy/certrevoker --replicas=0 >/dev/null
$K -n certrevoker wait --for=delete pod -l app=certrevoker --timeout=60s >/dev/null 2>&1
alice_allowed() { as alice get pods -n kube-system >/dev/null; }
t=$(wait_until 60 alice_allowed) && ok "with the webhook down, revoked alice gets in again after ${t}s (fail-open trade-off)" || bad "alice still denied with webhook down"
$K -n certrevoker scale deploy/certrevoker --replicas=1 >/dev/null
$K -n certrevoker rollout status deploy/certrevoker --timeout=120s >/dev/null
t=$(wait_until 60 alice_denied) && ok "webhook back: alice denied again after ${t}s" || bad "alice not denied after webhook restart"

step "7. Denied-request counter and unrevoke"
portal_login   # sessions are in memory; the pod restarted
as alice get pods -n kube-system >/dev/null
sleep 16       # one observer flush interval
denied=$($K get certificaterevocation "sha256-${ALICE#X509SHA256=}" -o jsonpath='{.status.deniedRequests}')
[ "${denied:-0}" -gt 0 ] && ok "revocation records $denied denied request(s)" || bad "no denied requests recorded"
for id in "$ALICE" "$CAROL"; do
  code=$(portal_post /unrevoke "$id")
  [ "$code" = 303 ] || bad "portal unrevoke returned $code"
done
ok "portal removed revocations"
t=$(wait_until 60 alice_allowed) && ok "alice allowed again after ${t}s" || bad "alice still denied after unrevoke"

step "Cleanup"
$K delete csr e2e-alice e2e-bob e2e-carol --ignore-not-found >/dev/null
$K delete clusterrolebinding e2e-devs-view e2e-devs-kubelet-read --ignore-not-found >/dev/null
$K delete clusterrole e2e-kubelet-read --ignore-not-found >/dev/null
echo; echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
