# Archivos target de alto valor — hunt-path-traversal

Carga condicional: leer cuando hay file read confirmado y querés
maximizar el impacto antes de documentar.

## Unix/Linux — PoC básico
```
/etc/passwd          # PoC de read — confirma traversal, sin impacto crítico solo
/etc/hosts           # IPs internas, nombres de servicios internos
/etc/hostname        # nombre del host
```

## Unix/Linux — Credenciales y secretos
```
/etc/shadow          # hashes de passwords (requiere root en el proceso)
/etc/mysql/my.cnf    # config MySQL con credenciales
/etc/nginx/nginx.conf
/etc/apache2/apache2.conf
```

## /proc — runtime del proceso (gold mine en Linux)
```
/proc/self/environ   # variables de entorno: AWS_ACCESS_KEY, tokens, flags debug
/proc/self/cmdline   # flags de línea de comandos del proceso
/proc/self/maps      # memory maps — revela paths de librerías y archivos abiertos
/proc/self/fd/       # file descriptors abiertos (puede incluir sockets, pipes)
/proc/net/tcp        # conexiones TCP activas — puertos internos, IPs de servicios
```

## Configs de app — secretos directos
```
.env
.env.local
.env.production
.env.development
config.json
config.yml
config.yaml
settings.py
local_settings.py
application.properties
application.yml
appsettings.json
appsettings.Development.json
secrets.json
database.yml
```

## Cloud — entornos serverless y containerizados
```
/var/task/index.js         # AWS Lambda — source code del servicio
/var/task/.env             # AWS Lambda — variables
/home/site/wwwroot/        # Azure App Service — webroot
/var/secrets/              # secrets montados en pods
/run/secrets/              # Docker secrets
/var/run/secrets/kubernetes.io/serviceaccount/token  # K8s service account token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

## AWS específico
```
/home/ec2-user/.aws/credentials
/root/.aws/credentials
~/.aws/credentials
~/.aws/config
# En Lambda: las keys salen de /proc/self/environ (AWS_ACCESS_KEY_ID, etc.)
```

## Source control y CI/CD
```
.git/config
.git/HEAD
.gitignore
.travis.yml
.gitlab-ci.yml
Jenkinsfile
.github/workflows/
```

## Logs — tokens, JWTs, headers de requests
```
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/apache2/access.log
/var/log/apache2/error.log
logs/app.log
storage/logs/laravel.log
# Los logs pueden contener: Authorization headers, session tokens, JWTs en query strings
```

## Package managers y dependencias
```
composer.lock
package-lock.json
yarn.lock
Gemfile.lock
requirements.txt
# Útiles para identificar versiones con CVEs conocidos
```

## Windows — PoC y secretos
```
C:\Windows\win.ini              # PoC de read en Windows
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config   # IIS — credenciales de app, connection strings
C:\Users\Administrator\NTUser.dat
%APPDATA%\Microsoft\Credentials\
```

## Kubernetes
```
/var/run/secrets/kubernetes.io/serviceaccount/token
~/.kube/config
/etc/kubernetes/admin.conf
```

## Nota de escalada

Si encontrás `/proc/self/environ` con AWS keys → chain inmediato con
`exposed-secrets` para validar las keys antes de reportar.

Si encontrás source code del servicio → buscar hardcoded secrets,
endpoints internos, lógica de auth que no está expuesta en la API
pública → leads para `idor-bola` o `ssrf`.

Si encontrás logs con tokens/JWTs → validar que no estén expirados
antes de reportar como hallazgo de impacto real.
