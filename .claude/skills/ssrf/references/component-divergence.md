# Divergencia entre componentes — heurístico, no catálogo de payloads

**Cuándo cargar esto**: cuando ya se probó una ronda razonable del
catálogo de bypass (`bypass-catalog.md`) contra un filtro específico y
todo sigue bloqueado. Antes de seguir iterando más encodings/variantes
del mismo tipo, pará y hacete esta pregunta:

> **¿Hay más de un componente leyendo esta misma URL/input, y pueden
> interpretarla distinto entre sí — ya sea porque la miran de forma
> diferente, o porque la miran en momentos diferentes?**

Si la respuesta es sí, el bypass no está en encontrar un encoding más
raro para el MISMO componente que ya te está rechazando todo — está en
explotar la diferencia entre lo que ve el que valida y lo que hace lo
que realmente conecta. Esto no es una técnica puntual, es una forma de
mirar el problema cuando el catálogo se agota.

## Por qué existe este archivo

En el lab de whitelist (PortSwigger, EXPERT), Mulderx agotó un barrido
extenso de bypasses clásicos contra un parser (`java.net.URI`) robusto
de verdad, sin resultado — y solo llegó a la técnica correcta
consultando la solución pública, no derivándola solo. El barrido fallido
en sí fue correcto (confirmó que ese parser no cae con lo básico), pero
el agente no se preguntó en ningún momento si había un SEGUNDO
componente en juego con lectura distinta. Este archivo existe para que
la próxima vez esa pregunta se haga ANTES de agotar 60k tokens de
variantes del mismo ataque.

## Las dos formas en que diverge la lectura

### 1. Divergencia espacial/sintáctica — dos componentes, mismo momento, distinta interpretación de la FORMA

El validador y el componente que conecta leen el input al mismo tiempo,
pero uno decodifica/parsea distinto que el otro (uno decodifica una vez,
el otro dos; uno respeta RFC estricto, el otro es permisivo).

**Ejemplos confirmados:**

- **Open redirect propio de la app** (`bypass-catalog.md`,
  `confirmado`, derivado por el agente): el filtro SSRF valida el
  parámetro `stockApi`, pero el endpoint de redirect de la misma app
  interpreta su propio parámetro sin re-validar — dos componentes
  DISTINTOS de la misma app, ninguno decodifica raro, simplemente el
  filtro nunca ve la URL final porque no es el mismo punto de entrada.
- **Open redirect vía acortador de terceros** (Rocket.Chat/HackerOne,
  reporte público, `confirmado` por el reporter): mismo mecanismo, pero
  ni siquiera hace falta que la app tenga su propio redirect — un
  acortador externo (tinyurl) alcanza si el fetcher sigue redirects sin
  re-validar el destino.
- **Doble-encoding del `#` en userinfo** (PortSwigger whitelist lab,
  `confirmado en vivo, técnica externa` — Mulderx la reprodujo pero no
  la derivó solo): el parser que valida decodifica el string una vez
  (ve el host completo, pasa), el mecanismo que conecta decodifica una
  vez más (interpreta el `%23` extra como `#`, corta antes del host
  real) — mismo momento, distinta profundidad de decodificación.

### 2. Divergencia temporal (TOCTOU) — mismo componente o distinto, pero LEE EN MOMENTOS DISTINTOS y el input puede cambiar en el medio

El validador resuelve/chequea algo en el momento T1. El componente que
efectivamente conecta lo vuelve a resolver en T2. Si el atacante
controla que la respuesta sea distinta entre T1 y T2, el chequeo en T1
no garantiza nada sobre lo que pasa en T2.

**Ejemplo confirmado:**

- **DNS rebinding clásico** (reporte HackerOne, arkadiyt-projects,
  `confirmado` por el reporter, mecanismo bien explicado): el código
  valida la IP resuelta de un hostname, pero después llama
  `Net::HTTP.start(uri.hostname, ...)` — que hace SU PROPIA resolución
  DNS nueva, en un momento distinto. Un DNS bajo control del atacante
  devuelve una IP pública/segura en la primera consulta (la de
  validación) y `127.0.0.1` (o una IP interna) en la segunda (la de
  conexión real). Confirmado también en Rocket.Chat/Voxtelesys con TTL=0
  para forzar la segunda resolución inmediatamente — y ese caso puntual
  bypaseaba un fix previo que solo agregaba la validación sin resolver
  DNS una única vez.
- **Remediación real que corta esto de raíz** (mencionada en el mismo
  reporte, no verificada en vivo por Mulderx): conectar directo a la IP
  ya validada en vez de al hostname (`Net::HTTP.start(validated_ip,
  ...)` con el header `Host` seteado a mano) — elimina la ventana de
  divergencia porque DNS se resuelve una sola vez, no dos.

## Cómo aplicarlo en la práctica

1. Cuando el catálogo se agote contra un filtro, no sigas iterando
   variantes del mismo tipo de encoding/payload. Preguntate: ¿quién
   valida esto, y quién conecta de verdad? ¿Son el mismo código/proceso,
   o hay una posta entre dos partes?
2. Si son dos partes distintas (misma app con dos endpoints, o
   validación vs. cliente HTTP de bajo nivel): buscá divergencia
   espacial — algo que uno decodifique/acepte y el otro no, o un punto
   de entrada que el validador nunca ve.
3. Si el chequeo depende de resolver algo (DNS, un lookup, un estado
   externo) y ese algo se puede volver a resolver más tarde: buscá
   divergencia temporal — controlar que la segunda resolución difiera
   de la primera.
4. Confirmar SIEMPRE con el gate de evidencia del SKILL.md (callback o
   data interna filtrada) antes de marcar algo como bypass real — un
   mecanismo que "debería" funcionar por este razonamiento no es
   evidencia hasta que se prueba.
