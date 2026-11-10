#!/usr/bin/env bash
# Generates TLS material for the certrevoker PoC:
#   ca.crt/ca.key            private CA for the webhook and portal
#   webhook.crt/key          webhook serving cert (SAN 127.0.0.1)
#   apiserver-client.crt/key client cert kube-apiserver presents to the webhook
#   portal.crt/key           portal serving cert (SANs: node IP, 127.0.0.1, localhost)
#   authz-webhook.kubeconfig kubeconfig kube-apiserver uses to call the webhook
#   secret.yaml              Secret certrevoker-tls for the Deployment
#
# Usage: gen-certs.sh <out-dir> <control-plane-node-ip>
set -euo pipefail
OUT=${1:?out dir}; NODE_IP=${2:?control plane node IP}
mkdir -p "$OUT"; cd "$OUT"
umask 077

key() { openssl ecparam -name prime256v1 -genkey -noout -out "$1"; }

key ca.key
openssl req -x509 -new -key ca.key -sha256 -days 365 -subj "/CN=certrevoker-ca" -out ca.crt \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

issue() { # name cn eku san
  local name=$1 cn=$2 eku=$3 san=${4:-}
  key "$name.key"
  openssl req -new -key "$name.key" -subj "/CN=$cn" -out "$name.csr"
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature"
    echo "extendedKeyUsage=$eku"
    [ -n "$san" ] && echo "subjectAltName=$san"
  } > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -sha256 \
    -extfile "$name.ext" -out "$name.crt" 2>/dev/null
  rm -f "$name.csr" "$name.ext"
}

issue webhook certrevoker-webhook serverAuth "IP:127.0.0.1"
issue apiserver-client kube-apiserver-certrevoker-client clientAuth
issue portal certrevoker-portal serverAuth "IP:$NODE_IP,IP:127.0.0.1,DNS:localhost"

b64() { base64 -w0 < "$1"; }
cat > authz-webhook.kubeconfig <<KC
apiVersion: v1
kind: Config
clusters:
- name: certrevoker
  cluster:
    server: https://127.0.0.1:9443/authorize
    certificate-authority-data: $(b64 ca.crt)
users:
- name: kube-apiserver
  user:
    client-certificate-data: $(b64 apiserver-client.crt)
    client-key-data: $(b64 apiserver-client.key)
contexts:
- name: certrevoker
  context: {cluster: certrevoker, user: kube-apiserver}
current-context: certrevoker
KC

cat > secret.yaml <<SEC
apiVersion: v1
kind: Secret
metadata:
  name: certrevoker-tls
  namespace: certrevoker
type: Opaque
data:
  ca.crt: $(b64 ca.crt)
  webhook.crt: $(b64 webhook.crt)
  webhook.key: $(b64 webhook.key)
  portal.crt: $(b64 portal.crt)
  portal.key: $(b64 portal.key)
SEC
echo "Wrote TLS material to $OUT"
