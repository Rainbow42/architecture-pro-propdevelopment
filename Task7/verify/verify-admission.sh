set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS=audit-zone
fail=0

echo "==> Namespace с PSA restricted"
kubectl apply -f "${ROOT}/01-create-namespace.yaml"

echo
echo "==> Небезопасные манифесты должны быть отклонены"
for f in "${ROOT}"/insecure-manifests/*.yaml; do
  name="$(basename "$f")"
  if kubectl apply -f "$f" 2>/tmp/task7-insecure.err; then
    echo "FAIL: ${name} принят, ожидался отказ"
    kubectl delete -f "$f" --ignore-not-found >/dev/null 2>&1 || true
    fail=1
  else
    echo "OK: ${name} отклонён"
    sed -n '1,3p' /tmp/task7-insecure.err | sed 's/^/    /'
  fi
done

echo
echo "==> Безопасные манифесты должны пройти"
for f in "${ROOT}"/secure-manifests/*.yaml; do
  name="$(basename "$f")"
  if kubectl apply -f "$f"; then
    echo "OK: ${name} принят"
  else
    echo "FAIL: ${name} отклонён"
    fail=1
  fi
done

echo
echo "==> Очистка безопасных подов"
kubectl delete -f "${ROOT}/secure-manifests" --ignore-not-found >/dev/null 2>&1 || true

if [[ "$fail" -eq 0 ]]; then
  echo
  echo "verify-admission: успех"
  exit 0
fi

echo
echo "verify-admission: есть ошибки" >&2
exit 1
