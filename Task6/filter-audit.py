#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Фильтрация журнала аудита Kubernetes.

Читает audit.log (одна запись JSON в строке), отбирает подозрительные события
и складывает их в audit-extract.json.

Запуск:
    python3 filter-audit.py audit.log
    python3 filter-audit.py audit.log --out audit-extract.json
"""
import argparse
import json
import sys
from collections import OrderedDict

# служебные учётные записи самого кластера — их обращения не считаем подозрительными,
# иначе журнал утонет в служебном шуме
SYSTEM_USERS_PREFIX = (
    "system:apiserver",
    "system:kube-controller-manager",
    "system:kube-scheduler",
    "system:node:",
    "system:serviceaccount:kube-system:",
)

CATEGORIES = OrderedDict([
    ("secrets_access", {
        "title": "Доступ к секретам",
        "severity": "критический",
        "why": "В секретах лежат пароли к базам и токены. Читать их вправе только "
               "платформенная команда и специалист по безопасности",
    }),
    ("privileged_pod", {
        "title": "Создание привилегированного пода",
        "severity": "критический",
        "why": "Привилегированный контейнер выходит за границы пода и получает доступ к узлу",
    }),
    ("pod_exec", {
        "title": "Вход в чужой под",
        "severity": "критический",
        "why": "Внутри контейнера видны данные приложения и переменные окружения "
               "в обход журналирования самого приложения",
    }),
    ("rbac_escalation", {
        "title": "Расширение прав через RBAC",
        "severity": "критический",
        "why": "Выдача роли уровня администратора кластера снимает все остальные ограничения",
    }),
    ("audit_policy_change", {
        "title": "Попытка изменить или удалить политику аудита",
        "severity": "критический",
        "why": "Отключение аудита скрывает следы и делает расследование невозможным",
    }),
    ("impersonation", {
        "title": "Действие от чужого имени",
        "severity": "значительный",
        "why": "Работа под чужой учётной записью маскирует настоящего исполнителя",
    }),
    ("access_denied", {
        "title": "Отказ в доступе",
        "severity": "значительный",
        "why": "Серия отказов обычно означает разведку: человек проверяет, куда его пустят",
    }),
])


def load(path):
    events, broken = [], 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                broken += 1
                continue
            if item.get("kind") == "Event":
                events.append(item)
    return events, broken


def user_of(ev):
    return ev.get("user", {}).get("username", "неизвестно")


def impersonated_of(ev):
    imp = ev.get("impersonatedUser", {}).get("username")
    if imp:
        return imp
    ann = ev.get("annotations", {}) or {}
    return ann.get("authentication.k8s.io/impersonated-user")


def is_system(ev):
    return user_of(ev).startswith(SYSTEM_USERS_PREFIX) and not impersonated_of(ev)


def decision_of(ev):
    return (ev.get("annotations", {}) or {}).get("authorization.k8s.io/decision", "")


def has_privileged_container(ev):
    spec = (ev.get("requestObject") or {}).get("spec") or {}
    for field in ("containers", "initContainers"):
        for container in spec.get(field) or []:
            sc = container.get("securityContext") or {}
            if sc.get("privileged") or sc.get("allowPrivilegeEscalation"):
                return True
    if spec.get("hostPID") or spec.get("hostNetwork") or spec.get("hostIPC"):
        return True
    return False


def is_admin_roleref(ev):
    role = ((ev.get("requestObject") or {}).get("roleRef") or {}).get("name", "")
    return role in ("cluster-admin", "admin") or "admin" in role


def classify(ev):
    """Возвращает список категорий, под которые попадает событие."""
    hits = []
    ref = ev.get("objectRef", {}) or {}
    resource = ref.get("resource", "")
    subresource = ref.get("subresource", "")
    verb = ev.get("verb", "")
    uri = ev.get("requestURI", "") or ""
    name = ref.get("name", "") or ""

    if resource == "secrets" and verb in ("get", "list", "watch"):
        hits.append("secrets_access")

    if resource == "pods" and verb == "create" and has_privileged_container(ev):
        hits.append("privileged_pod")

    if subresource == "exec" and verb in ("create", "get"):
        hits.append("pod_exec")

    if resource in ("rolebindings", "clusterrolebindings") and \
            verb in ("create", "update", "patch") and is_admin_roleref(ev):
        hits.append("rbac_escalation")

    if "audit-policy" in name.lower() or "audit-policy" in uri.lower():
        hits.append("audit_policy_change")

    if impersonated_of(ev):
        hits.append("impersonation")

    if decision_of(ev) == "forbid":
        hits.append("access_denied")

    return hits


def short(ev):
    ref = ev.get("objectRef", {}) or {}
    return OrderedDict([
        ("time", ev.get("requestReceivedTimestamp")),
        ("auditID", ev.get("auditID")),
        ("user", user_of(ev)),
        ("impersonatedUser", impersonated_of(ev)),
        ("sourceIPs", ev.get("sourceIPs")),
        ("userAgent", ev.get("userAgent")),
        ("verb", ev.get("verb")),
        ("resource", ref.get("resource")),
        ("subresource", ref.get("subresource")),
        ("namespace", ref.get("namespace")),
        ("name", ref.get("name")),
        ("requestURI", ev.get("requestURI")),
        ("decision", decision_of(ev)),
        ("responseCode", (ev.get("responseStatus") or {}).get("code")),
    ])


def main():
    parser = argparse.ArgumentParser(description="Фильтрация журнала аудита Kubernetes")
    parser.add_argument("logfile", help="путь к audit.log")
    parser.add_argument("--out", default="audit-extract.json", help="куда записать выжимку")
    parser.add_argument("--with-system", action="store_true",
                        help="не отбрасывать обращения служебных компонентов кластера")
    args = parser.parse_args()

    try:
        events, broken = load(args.logfile)
    except FileNotFoundError:
        print(f"Файл не найден: {args.logfile}", file=sys.stderr)
        return 1

    buckets = {key: [] for key in CATEGORIES}
    suspicious_ids = set()

    for ev in events:
        if not args.with_system and is_system(ev):
            continue
        for category in classify(ev):
            buckets[category].append(short(ev))
            suspicious_ids.add(ev.get("auditID"))

    findings = []
    for key, meta in CATEGORIES.items():
        if not buckets[key]:
            continue
        findings.append(OrderedDict([
            ("category", key),
            ("title", meta["title"]),
            ("severity", meta["severity"]),
            ("why", meta["why"]),
            ("count", len(buckets[key])),
            ("events", buckets[key]),
        ]))

    result = OrderedDict([
        ("source", args.logfile),
        ("totalEvents", len(events)),
        ("brokenLines", broken),
        ("suspiciousEvents", len(suspicious_ids)),
        ("findings", findings),
    ])

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"Всего записей в журнале: {len(events)}")
    print(f"Подозрительных событий:  {len(suspicious_ids)}")
    print()
    for finding in findings:
        print(f"  [{finding['severity']:>13}] {finding['title']}: {finding['count']}")
        for ev in finding["events"][:3]:
            who = ev["impersonatedUser"] or ev["user"]
            target = "/".join(x for x in [ev["namespace"], ev["resource"], ev["name"]] if x)
            print(f"        {ev['time']}  {who}  {ev['verb']} {target}")
        if finding["count"] > 3:
            print(f"        ... ещё {finding['count'] - 3}")
    print()
    print(f"Выжимка записана в {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
