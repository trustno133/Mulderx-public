# Archivos sensibles genéricos — siempre incluir

Independiente del stack detectado, esta lista se suma siempre a la
wordlist final (paso 3 del skill principal).

## Control de versiones
```
.git/config
.git/HEAD
.gitignore
.svn/entries
.hg/
```

## Configuración / secretos
```
.env
.env.local
.env.production
.env.example
config.php.bak
config.yml
config.json.bak
secrets.yml
credentials.json
```

## Backups
```
backup/
backup.zip
backup.sql
backup.tar.gz
site.bak
index.php.bak
index.html.old
www.zip
```

## Bases de datos / dumps
```
dump.sql
database.sql
db_backup.sql
```

## Metadata de sistema/editor
```
.DS_Store
Thumbs.db
.vscode/settings.json
.idea/workspace.xml
```

## Logs
```
error.log
debug.log
access.log
logs/
npm-debug.log
yarn-error.log
```

## CI/CD y despliegue
```
.travis.yml
.gitlab-ci.yml
Jenkinsfile
docker-compose.yml
docker-compose.override.yml
Dockerfile
.dockerignore
deploy.sh
```

## Cloud / infra
```
.aws/credentials
.aws/config
serverless.yml
terraform.tfstate
terraform.tfvars
.terraform/
```

## Certificados y claves
```
id_rsa
id_rsa.pub
private.key
server.key
server.pem
*.pfx
```

## Configuración de apps específicas
```
web.config
appsettings.json
appsettings.Development.json
application.properties
application.yml
settings.py
local_settings.py
```

## Archivos de dependencias (pueden filtrar versiones/paths internos)
```
composer.json
composer.lock
package-lock.json
yarn.lock
Gemfile.lock
requirements.txt
Pipfile.lock
```

## Documentación interna filtrada por error
```
README.md
CHANGELOG.md
TODO.md
NOTES.txt
swagger.json
openapi.json
api-docs/
```

Nota: cada hit acá es un LEAD para `exposed-secrets`, no un finding
por sí solo — confirmar que el archivo realmente contiene algo
sensible (no un `.env.example` vacío de valores reales, no un
`package-lock.json` público sin nada interno) antes de escalar.
