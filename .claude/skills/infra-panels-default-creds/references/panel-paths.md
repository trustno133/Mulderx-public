# Paths típicos por panel — carga condicional

Usar solo si el panel no se identificó por path obvio en recon.
Agregar entradas nuevas cuando aparezca un panel no listado acá.

| Producto | Paths típicos | Puerto default |
|---|---|---|
| Grafana | `/`, `/login`, `/api/health` | 3000 |
| Kibana | `/`, `/app/home`, `/api/status` | 5601 |
| Elasticsearch | `/`, `/_cat/indices`, `/_cluster/health` | 9200 |
| Jenkins | `/`, `/login`, `/api/json` | 8080 |
| Prometheus | `/`, `/metrics`, `/targets`, `/graph` | 9090 |
| Alertmanager | `/`, `/#/alerts`, `/api/v1/alerts` | 9093 |
| Portainer | `/`, `/#/auth` | 9000 |
| Jupyter | `/`, `/tree`, `/api/kernels` | 8888 |
| Tomcat Manager | `/manager/html`, `/manager/text/list` | 8080 |
| phpMyAdmin | `/`, `/index.php`, `/phpmyadmin/` | 80/443 |
| Consul | `/ui/`, `/v1/agent/members` | 8500 |
| Vault (HashiCorp) | `/ui/`, `/v1/sys/health` | 8200 |
| RabbitMQ | `/`, `/#/`, `/api/overview` | 15672 |
| Redis Commander | `/`, `/info` | 8081 |
| Flower (Celery) | `/`, `/tasks` | 5555 |
| Spring Actuator | `/actuator`, `/actuator/env`, `/actuator/heapdump` | — |
| WireMock | `/__admin/`, `/__admin/mappings` | 8080 |
| Traefik | `/dashboard/`, `/api/rawdata` | 8080 |
| Kubernetes Dashboard | `/`, `/#/login` | 443/8001 |
| Argo CD | `/`, `/auth/login` | 443/8080 |
| MinIO | `/minio/`, `/login` | 9000/9001 |
| Netdata | `/`, `/#menu_system` | 19999 |

## Nota sobre puertos no estándar

Recon pasivo (katana, domain-recon) puede no cubrir puertos no
estándar (3000, 5601, 9090, etc.). Si el target tiene subdominios
de infraestructura (`monitoring.`, `metrics.`, `ops.`, `admin.`,
`internal.`), vale la pena probar estos puertos directamente con
`curl` antes de asumir que no hay nada.
