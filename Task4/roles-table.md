| Роль | Права роли | Группы пользователей |
| --- | --- | --- |
| `platform-admin` (ClusterRole) | Полный доступ ко всему кластеру, в том числе к секретам, ролям и привязкам. Может выдавать права. Только у этой роли есть `pods/exec` и `pods/portforward`. | `platform:admins` — платформенная команда |
| `security-auditor` (ClusterRole) | Только чтение любых ресурсов, включая секреты и логи. Менять ничего нельзя. | `security:auditors` — ИБ |
| `cluster-operator` (ClusterRole) | Namespace, узлы, NetworkPolicy, квоты, Ingress, StorageClass. Секреты не читает и не меняет. | `platform:operators` — DevOps |
| `namespace-viewer` (Role в `sales`, `tenant`, `finance`, `data`) | Смотрит поды, сервисы, деплои, конфиги и логи в своём namespace. Секреты не видит. | `sales:viewers`, `tenant:viewers`, `finance:viewers`, `data:viewers` — аналитики, менеджеры |
| `namespace-developer` (Role в своём namespace) | Деплои, поды, конфиги, сервисы; читает логи. Секреты, роли и привязки не трогает. | `sales:developers`, `tenant:developers`, `finance:developers`, `data:developers` — разработчики и эксплуатация |

Namespaces: `sales`, `tenant`, `finance`, `data`, `platform`.
