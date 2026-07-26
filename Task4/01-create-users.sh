#!/usr/bin/env bash
# Создание пользователей кластера.
# Пользователь в Kubernetes — это сертификат: CN = имя пользователя, O = группа.
# Скрипт создаёт ключ, запрос на сертификат, подписывает его в кластере
# и складывает готовый файл доступа в каталог kubeconfig/.
set -euo pipefail

WORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${WORK_DIR}/certs"
KUBECONFIG_DIR="${WORK_DIR}/kubeconfig"
CLUSTER_NAME="$(kubectl config current-context)"
API_SERVER="$(kubectl config view -o jsonpath="{.clusters[?(@.name==\"${CLUSTER_NAME}\")].cluster.server}")"

# имя:группа:группа...
USERS=(
  "anna-devops:platform:operators"
  "ivan-security:security:auditors"
  "petr-sales-dev:sales:developers"
  "olga-sales-view:sales:viewers"
  "sergey-tenant-dev:tenant:developers"
)

mkdir -p "${CERT_DIR}" "${KUBECONFIG_DIR}"

# корневой сертификат кластера нужен, чтобы клиент доверял серверу
kubectl config view --raw --minify --flatten \
  -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "${CERT_DIR}/ca.crt"

for entry in "${USERS[@]}"; do
  user="${entry%%:*}"
  group="${entry#*:}"

  echo "==> Пользователь ${user}, группа ${group}"

  # 1. ключ и запрос на сертификат
  openssl genrsa -out "${CERT_DIR}/${user}.key" 2048 2>/dev/null
  openssl req -new -key "${CERT_DIR}/${user}.key" \
    -out "${CERT_DIR}/${user}.csr" \
    -subj "/CN=${user}/O=${group}"

  # 2. отправляем запрос в кластер
  kubectl delete csr "${user}" --ignore-not-found >/dev/null
  cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: ${user}
spec:
  request: $(base64 < "${CERT_DIR}/${user}.csr" | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 7776000
  usages:
    - client auth
EOF

  # 3. подтверждаем запрос и забираем подписанный сертификат
  kubectl certificate approve "${user}"
  for _ in $(seq 1 20); do
    cert="$(kubectl get csr "${user}" -o jsonpath='{.status.certificate}')"
    [ -n "${cert}" ] && break
    sleep 1
  done
  echo "${cert}" | base64 -d > "${CERT_DIR}/${user}.crt"

  # 4. собираем отдельный файл доступа для пользователя
  export KUBECONFIG="${KUBECONFIG_DIR}/${user}.kubeconfig"
  rm -f "${KUBECONFIG}"
  kubectl config set-cluster "${CLUSTER_NAME}" \
    --server="${API_SERVER}" \
    --certificate-authority="${CERT_DIR}/ca.crt" \
    --embed-certs=true >/dev/null
  kubectl config set-credentials "${user}" \
    --client-certificate="${CERT_DIR}/${user}.crt" \
    --client-key="${CERT_DIR}/${user}.key" \
    --embed-certs=true >/dev/null
  kubectl config set-context "${user}" \
    --cluster="${CLUSTER_NAME}" \
    --user="${user}" >/dev/null
  kubectl config use-context "${user}" >/dev/null
  unset KUBECONFIG

  echo "    файл доступа: ${KUBECONFIG_DIR}/${user}.kubeconfig"
done

echo
echo "Готово. Проверить можно так:"
echo "  KUBECONFIG=${KUBECONFIG_DIR}/petr-sales-dev.kubeconfig kubectl get pods -n sales"
