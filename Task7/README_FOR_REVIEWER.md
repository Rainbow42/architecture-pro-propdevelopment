# Task7 — Pod Security Admission и OPA Gatekeeper

## Что сделано

1. Namespace `audit-zone` с **Pod Security Admission** в режиме `enforce=restricted`.
2. Три небезопасных манифеста в `insecure-manifests/` — должны отклоняться:
   - privileged-контейнер;
   - том `hostPath`;
   - запуск от UID 0.
3. Исправленные манифесты в `secure-manifests/` — проходят PSA и Gatekeeper.
4. OPA Gatekeeper: запрет `privileged`, запрет `hostPath`, обязательные
   `runAsNonRoot=true` и `readOnlyRootFilesystem=true`.
5. `audit-policy.yaml` — аудит операций с подами в `audit-zone` (для включения
   аудита на apiserver, по аналогии с Task6).

## Структура

```
Task7/
├── 01-create-namespace.yaml
├── insecure-manifests/
├── secure-manifests/
├── gatekeeper/
│   ├── constraint-templates/
│   └── constraints/
├── verify/
├── audit-policy.yaml
└── README_FOR_REVIEWER.md
```

## Как проверить

Нужен рабочий кластер (например minikube).

```bash
# 1) Только Pod Security Admission
bash verify/verify-admission.sh

# 2) Gatekeeper + PSA + повторная проверка манифестов
bash verify/validate-security.sh
```

Ожидание:

- insecure-манифесты → отказ admission (PSA и/или Gatekeeper);
- secure-манифесты → успешно создаются;
- в `audit-zone` метка `pod-security.kubernetes.io/enforce=restricted`;
- constraints Gatekeeper присутствуют в API.

## Ручная проверка

```bash
kubectl apply -f 01-create-namespace.yaml
kubectl apply -f insecure-manifests/01-privileged-pod.yaml   # отказ
kubectl apply -f secure-manifests/01-secure.yaml             # ок
kubectl get k8spspprivilegedcontainer,k8spsphostfilesystem,k8spsprunasnonroot
```
