# Mapeo stack → archivo SecLists

El fingerprint del stack lo hace Recon, no este skill — este archivo
solo mapea lo que ya viene en `recon.md` a un archivo puntual dentro
de `$SECLISTS_PATH/Discovery/Web-Content/`. Ampliar esta tabla cuando
aparezca un stack nuevo en algún target — no reescribir wordlists a
mano, buscar si SecLists ya tiene el archivo correspondiente primero.

| Stack detectado en recon.md | Archivo en SecLists (Discovery/Web-Content/) |
|---|---|
| WordPress | `CMS/wordpress.fuzz.txt` |
| Drupal | `CMS/drupal.fuzz.txt` |
| Joomla | `CMS/joomla.fuzz.txt` |
| Apache (server genérico) | `Apache.fuzz.txt` |
| IIS / .NET | `IIS.fuzz.txt` |
| Nginx | `nginx.txt` |
| Sin stack identificado / genérico | `raft-medium-directories.txt` |
| Genérico, corrida rápida | `raft-small-directories.txt` |
| Archivos con extensión (backups, configs) | `raft-medium-files.txt` |

Si el archivo listado acá no existe en el checkout local
(`$SECLISTS_PATH`), bajarlo puntual:

```bash
curl -sO "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/<archivo>"
```

No hacer `git sparse-checkout add` por cada archivo nuevo salvo que se
vaya a reusar seguido — para un uso puntual, `curl` directo alcanza y
no infla el checkout local.

## Notas por stack no listado arriba

Wien, MercadoLibre/MercadoPago y United todavía no tienen stack
confirmado documentado acá — completar esta tabla con lo que tire
`recon.md` real en cada uno a medida que se corra, en vez de
precargar stacks que quizás no aparezcan nunca en estos 3 programas.
