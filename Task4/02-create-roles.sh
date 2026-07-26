#!/usr/bin/env bash
# Создание пространств имён и ролей по таблице из roles-table.md.
set -euo pipefail

NAMESPACES=(sales tenant finance data platform)

echo "==> Пространства имён по доменам компании"
for ns in "${NAMESPACES[@]}"; do
  kubectl create namespace "${ns}" --dry-run=client -o yaml | kubectl apply -f -
done

echo "==> Роли уровня кластера"
cat <<'EOF' | kubectl apply -f -
---
# Платформенная команда: полный доступ к кластеру
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: platform-admin
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
  - nonResourceURLs: ["*"]
    verbs: ["*"]
---
# Специалист по информационной безопасности: только чтение, но включая секреты
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: security-auditor
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log", "services", "configmaps", "secrets",
                "serviceaccounts", "namespaces", "nodes", "events",
                "persistentvolumes", "persistentvolumeclaims"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies", "ingresses"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["policy"]
    resources: ["poddisruptionbudgets"]
    verbs: ["get", "list", "watch"]
---
# DevOps-инженеры: настройка кластера, но без доступа к секретам
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-operator
rules:
  - apiGroups: [""]
    resources: ["namespaces", "resourcequotas", "limitranges", "services",
                "configmaps", "persistentvolumes", "persistentvolumeclaims"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: [""]
    resources: ["pods", "pods/log", "nodes", "events", "serviceaccounts"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["patch", "update"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies", "ingresses", "ingressclasses"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["apiextensions.k8s.io"]
    resources: ["customresourcedefinitions"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
EOF

echo "==> Роли внутри каждого пространства имён"
for ns in "${NAMESPACES[@]}"; do
  cat <<EOF | kubectl apply -f -
---
# Только просмотр. Секреты не входят в список ресурсов
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: namespace-viewer
  namespace: ${ns}
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log", "services", "configmaps", "events",
                "persistentvolumeclaims"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies", "ingresses"]
    verbs: ["get", "list", "watch"]
---
# Разработчик продуктовой команды: выкладывает приложения в своём домене.
# Секреты, роли и вход в контейнер недоступны
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: namespace-developer
  namespace: ${ns}
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log", "services", "configmaps", "events",
                "persistentvolumeclaims"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "replicasets"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["batch"]
    resources: ["jobs", "cronjobs"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses"]
    verbs: ["get", "list", "watch"]
EOF
done

echo
echo "Готово. Список ролей:"
kubectl get clusterroles platform-admin security-auditor cluster-operator
kubectl get roles -A | grep -E 'namespace-viewer|namespace-developer'
