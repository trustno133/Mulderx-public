# Contrato de handoffs de fases

Cada handoff debe dejar, como mínimo:

```markdown
## Sesión
- Programa:
- Target/scope:
- Fecha:
- Fase origen:
- Fase destino:

## Evidencia disponible
- Artefactos leídos:
- Artefactos escritos:
- Cuenta/identity lane usada: <referencia segura, nunca secreto>

## Cobertura y estado
| Lane / endpoint / clase | Estado | Evidencia | Blocker | Siguiente paso |
|---|---|---|---|---|

## Decisiones
- Confirmados:
- Candidatos:
- Descartados y killer:
- Bloqueados externamente:

## Límites
- Requests nuevos permitidos en la próxima fase:
- Rate limit/concurrencia:
- Acciones manuales requeridas:
```

Estados válidos: `CUBIERTO`, `PARCIAL`, `BLOQUEADO`, `NO APLICA`,
`PENDIENTE-OPERADOR`. Un estado `CUBIERTO` necesita evidencia o un descarte
con motivo; una fila sin evidencia no cuenta como cobertura.

## Artefactos por fase

| Fase | Artefacto | Autor | Consume |
|---|---|---|---|
| 00 | `recon.md` / `recon_summary.md` | recon/summarizer | triage |
| 02 | `triage.md`, `leads.md`, `discarded.md` | triage/hunters | closeout |
| 03 | `coverage.md` | closeout | posthunt/judge |
| 06 | `posthunt-triage.md` | posthunt-triage | judge |
| 09 | revisión humana | operador | disclosure manual |

No se guardan secretos, cookies, tokens ni contenido masivo de cuentas en
estos artefactos.

