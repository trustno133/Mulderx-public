# XSS en formatos, impresores y ramas de fallback

Usar esta referencia cuando un endpoint ofrece distintos formatos o genera
HTML desde resultados, reportes, gráficos, tablas, exportaciones o plantillas.
La idea central es seguir cómo la opción de salida cambia el contrato de
escape y qué ocurre en ramas poco transitadas; un parámetro reflejado por sí
solo no prueba XSS.

## Superficies que conviene inventariar

- Selectores de formato, vista, exportación o modo de respuesta (`html`, `raw`,
  tabla, gráfico, árbol, lista, impresión o descarga).
- Opciones de cada impresor: `default` o fallback, separador, etiqueta/título,
  prefijo/sufijo, nombre de columna/eje, agrupación y plantilla.
- Ramas con cero resultados, propiedades vacías o ausentes, valor nulo,
  paginación truncada y errores de validación.
- En el navegador: etiquetas, títulos y series que pasan a renderizadores de
  gráficos/markdown o a sinks HTML como `.html()`, `innerHTML` y
  `insertAdjacentHTML`.

Esta lista orienta búsquedas, no es una wordlist para enviar completa. Usa el
formato y los campos que realmente expone la aplicación o su código. Prioriza
un canary distinto por campo y una comparación baseline/canary.

## Trazado requerido

1. Confirma que el endpoint, formato, impresor y rama probada son alcanzables
   para el actor y el método de entrega que se evalúan.
2. Sigue el dato desde el parser de request y la opción seleccionada hasta el
   formatter/renderer, sus transformaciones y el wrapper final de respuesta.
   En revisión de código, comprueba callers, versión desplegada, configuración,
   feature flags y que el sink observado pertenece a esa ruta.
3. Determina qué significa realmente cada modo: dónde escapa, si invoca un
   parser/template, quién agrega markup, qué `Content-Type` devuelve y cómo
   responde el navegador. La etiqueta `raw` no implica por sí sola que la
   respuesta sea HTML ejecutable.
4. Repite el canary en una rama normal y en la rama relevante de vacío/fallback
   o error. Registra si el valor aparece como texto, en atributo, script,
   respuesta JSON/XML o markup. JSON/XML reflejado sin un consumidor HTML
   vulnerable no es XSS reflected; si el cliente lo inserta en un sink, enruta
   ese flujo como DOM XSS.
5. Para un sink de biblioteca como `.html()`, demuestra que el dato controlado
   llega a esa llamada en el renderer y configuración activos. La presencia de
   la API o de una versión vulnerable en un bundle no demuestra reachability.
6. Si el canary alcanza un contexto HTML inseguro, valida con una prueba mínima
   y no destructiva en un navegador del origen objetivo. Registra el efecto
   local observable. No recolectes ni envíes cookies, tokens, datos de cuenta o
   contenido a servidores externos.

## Gates para descartar falsos positivos

- Sink encontrado por grep, pero caller/renderer no ejecutable o parámetro no
  conectado: candidato estático, no hallazgo.
- Campo de etiqueta reflejado, pero formato, datos o condición necesaria no
  alcanzables: no aplicable a esa ruta; registrar la condición que faltó.
- Valor reflejado únicamente como texto codificado, JSON/XML sin consumidor
  ejecutable, `text/plain`, descarga o contexto de texto: no es XSS por sí solo.
- CSP, sanitizer o escape efectivo: registrar exactamente qué bloqueó la
  ejecución; no intentar evadir un challenge o una señal de parada.
- Falla de browser, extensión, terceros o restricción del entorno: dejar como
  candidato y nombrar la verificación pendiente; no inferir ejecución.

El resultado debe separar observación, inferencia y prueba, e incluir endpoint,
método, formato/opción, rama de datos, contexto de salida, transformación,
renderer/sink, headers relevantes, resultado del navegador y limitaciones.
