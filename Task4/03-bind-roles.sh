#!/usr/bin/env bash
# Связывание групп пользователей с ролями.
# Права выдаются группам, а не людям: при переходе сотрудника меняется только
# его группа в сертификате, роли трогать не нужно.
set -euo pipefail

NAMESPACES=(sales tenant finance data platform)

echo "==> Привязки уровня кластера"
cat <<'EOF' | kubectl apply -f -
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: platform-admins
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: platform-admin
subjects:
  - kind: Group
    name: platform:admins
    apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: security-auditors
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: security-auditor
subjects:
  - kind: Group
    name: security:auditors
    apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: platform-operators
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-operator
subjects:
  - kind: Group
    name: platform:operators
    apiGroup: rbac.authorization.k8s.io
EOF

echo "==> Привязки внутри пространств имён"
# группа <домен>:developers и <домен>:viewers получает права только в своём домене
for ns in "${NAMESPACES[@]}"; do
  cat <<EOF | kubectl apply -f -
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${ns}-developers
  namespace: ${ns}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: namespace-developer
subjects:
  - kind: Group
    name: ${ns}:developers
    apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${ns}-viewers
  namespace: ${ns}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: namespace-viewer
subjects:
  - kind: Group
    name: ${ns}:viewers
    apiGroup: rbac.authorization.k8s.io
EOF
done

echo
echo "Готово. Привязки:"
kubectl get clusterrolebindings platform-admins security-auditors platform-operators
kubectl get rolebindings -A | grep -E 'developers|viewers'
