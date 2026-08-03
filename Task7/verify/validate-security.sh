set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "нужна команда: $1" >&2
    exit 1
  }
}

need_cmd kubectl

echo "==> Namespace"
kubectl apply -f "${ROOT}/01-create-namespace.yaml"

if ! kubectl get crd constrainttemplates.templates.gatekeeper.sh >/dev/null 2>&1; then
  echo "==> Устанавливаем OPA Gatekeeper"
  kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.17.1/deploy/gatekeeper.yaml
  echo "==> Ждём webhook"
  kubectl -n gatekeeper-system wait --for=condition=Available deploy/gatekeeper-controller-manager --timeout=180s
  kubectl -n gatekeeper-system wait --for=condition=Available deploy/gatekeeper-audit --timeout=180s
else
  echo "==> Gatekeeper уже установлен"
fi

echo "==> ConstraintTemplates"
kubectl apply -f "${ROOT}/gatekeeper/constraint-templates/"
echo "==> Ждём CRD от шаблонов"
for crd in \
  k8spspprivilegedcontainer.constraints.gatekeeper.sh \
  k8spsphostfilesystem.constraints.gatekeeper.sh \
  k8spsprunasnonroot.constraints.gatekeeper.sh
do
  for i in $(seq 1 60); do
    if kubectl get crd "$crd" >/dev/null 2>&1; then
      echo "OK: ${crd}"
      break
    fi
    sleep 2
    if [[ "$i" -eq 60 ]]; then
      echo "CRD ${crd} не появился" >&2
      exit 1
    fi
  done
done

# Даём контроллеру зафиксировать статус шаблонов
sleep 5

echo "==> Constraints"
kubectl apply -f "${ROOT}/gatekeeper/constraints/"

echo
echo "==> Проверка: constraints на месте"
kubectl get k8spspprivilegedcontainer deny-privileged-containers >/dev/null
kubectl get k8spsphostfilesystem deny-hostpath-volumes >/dev/null
kubectl get k8spsprunasnonroot require-nonroot-and-readonly-rootfs >/dev/null
echo "OK: все три constraint-объекта доступны API"

echo
echo "==> Небезопасные манифесты должны отклоняться (PSA и/или Gatekeeper)"
for f in "${ROOT}"/insecure-manifests/*.yaml; do
  name="$(basename "$f")"
  if kubectl apply -f "$f" 2>/tmp/task7-gk.err; then
    echo "FAIL: ${name} принят"
    kubectl delete -f "$f" --ignore-not-found >/dev/null 2>&1 || true
    fail=1
  else
    echo "OK: ${name} отклонён"
    sed -n '1,4p' /tmp/task7-gk.err | sed 's/^/    /'
  fi
done

echo
echo "==> Безопасные манифесты должны проходить"
for f in "${ROOT}"/secure-manifests/*.yaml; do
  name="$(basename "$f")"
  if kubectl apply -f "$f"; then
    echo "OK: ${name} принят"
  else
    echo "FAIL: ${name} отклонён"
    fail=1
  fi
done

kubectl delete -f "${ROOT}/secure-manifests" --ignore-not-found >/dev/null 2>&1 || true

echo
echo "==> PSA labels на namespace"
kubectl get ns audit-zone --show-labels | grep -q 'pod-security.kubernetes.io/enforce=restricted' \
  && echo "OK: enforce=restricted" || { echo "FAIL: нет PSA restricted"; fail=1; }

if [[ "$fail" -eq 0 ]]; then
  echo
  echo "validate-security: успех (Gatekeeper активен, PSA включён)"
  exit 0
fi

echo
echo "validate-security: есть ошибки" >&2
exit 1
