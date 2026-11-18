# Mulderx Fusion

Integración del workspace local y `Poggiecar/Mulderx`, conservando ambos como
fuentes intactas. Esta distribución toma el commit upstream `de904d05` como
base ejecutable y añade el contenido reutilizable del workspace local.

## Qué se combinó

- El upstream aporta control de scope, bloqueo de redirecciones fuera del
  scope, validación de rutas, almacén de evidencia con transiciones y hashes,
  memoria por programa, diagnóstico y pruebas.
- El workspace local aporta el modo estricto de operador al mando, skills
  Codex completas y el índice/biblioteca local de conocimiento H1.
- Se conservaron las skills completas de Claude y se prepararon playbooks
  completos para Codex en `.agents/skills/`. El chequeo
  `scripts/sync_codex_skills.py --check` detecta contenido ausente, demasiado
  corto o convertido en redirección; no reescribe skills.
- Se amplió el mapa de especialistas Codex del upstream y se conservaron las
  definiciones locales cuando aportaban instrucciones más extensas.
- El orquestador legacy ya no pide a Claude que omita las confirmaciones, no
  concede tools automáticamente con `--allowedTools`, pide aprobación Codex
  `on-request` y no usa la opción automática de OpenCode. El modo manual sigue
  siendo el predeterminado.

## Credenciales y dos cuentas de prueba

Dos cuentas autorizadas y de igual rol permiten comprobar diferencias de
autorización entre actores. Por ejemplo, se puede observar un recurso propio
con la cuenta A y repetir la petición permitida con la sesión de B para
comprobar si el servidor aplica ownership y tenant checks. Las skills IDOR /
BOLA y lógica de negocio dan el método, los gates de evidencia y los casos de
estado que conviene comparar.

Mulderx **no** convierte automáticamente dos pares usuario/contraseña en dos
sesiones funcionales. El login, MFA, cookies, tokens, CSRF, flujos OAuth y la
renovación de sesión dependen de cada aplicación. El pipeline de dominio hace
reconocimiento y análisis de superficie; la validación autenticada requiere
que el operador prepare las sesiones de prueba o una integración específica,
indique las rutas y autorice esa fase. Un dominio y dos credenciales por sí
solos no bastan para ejecutar un test completo ni autorizan acciones activas.

El orquestador legacy puede leer variables desde
`.credentials/<programa>.env` y ponerlas en el entorno de los CLI locales; el
archivo no se copia en esta fusión. Si se usa esa integración, conservar los
valores fuera del repositorio, no pegarlos en prompts ni logs y no imprimirlos.
Las sesiones A/B deben quedar identificadas y separadas para que una prueba no
confunda propiedad propia con acceso cruzado.

## Límites conocidos

- `orchestrator.py` sigue siendo legacy. Aunque se quitaron los bypasses de
  aprobación automática, el modo recomendado es operar por fases y no usarlo
  sin pedido explícito y revisión de sus permisos efectivos.
- Codex, Claude y Hermes no comparten todavía un protocolo común de sesión,
  cancelación y resultado.
- El pipeline de recon no implementa login universal, rotación de dos cuentas,
  crawling autenticado completo ni validación automática de IDOR.
- No se probaron dominios externos ni credenciales. Las verificaciones de
  esta integración fueron locales.
