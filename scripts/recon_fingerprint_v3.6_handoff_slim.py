#!/usr/bin/env python3
"""
recon_fingerprint.py v3.5
=========================

Recolector de contexto para una URL objetivo. NO crawlea. Target-agnostic.

v3.0 novedades (vs v2.1):
    - Reglas reorganizadas en 5 categorías (frameworks, CMS, hosted
      platforms, dev tools, IdPs) con tiers strict/loose para bajar
      falsos positivos agresivamente.
    - ~300+ reglas nuevas: frameworks modernos (SvelteKit, Qwik, HTMX,
      Alpine.js, Stimulus, Lit), legacy enterprise (WebLogic, WebSphere,
      JBoss, Struts, Oracle EBS, SAP NetWeaver), CMS (Craft, TYPO3, DNN,
      Kentico, Sitefinity), headless CMS (Payload, Storyblok, Prismic),
      dev tools público-facing (Jenkins, GitLab, Grafana, Kibana, Argo,
      Nexus, Artifactory, SonarQube), network/VPN admin (Citrix NetScaler,
      Pulse Secure, Ivanti, FortiGate, GlobalProtect, BIG-IP iControl,
      Synology, QNAP, Proxmox, iDRAC, iLO, IPMI, Ubiquiti, pfSense),
      mainframe (PeopleSoft, Siebel, JD Edwards, WebSphere Portal,
      Domino), monitoring (Nagios, Zabbix, Splunk, Graylog), CI/CD
      self-hosted, ~40 SSO providers (consumer/enterprise/gov).
    - SSOSignal como dataclass con categoría.
    - Custom stack hints (headers/cookies/paths corporativos).
    - Reglas precompiladas al inicio.
    - Priority scoring: dev tools público-facing +4, admin panels
      network +5, IdPs enterprise +2. Cap 0-20.

Qué hace:
    - Fetch de la página principal + OPTIONS + CORS reflect test
    - Parse HTML, inventario de assets JS/CSS (concurrente)
    - Detección multi-categoría con tiers de confianza
    - Detección de WAF/CDN separados
    - Path probes en paralelo (64+ paths con --extra-probes)
    - TLS/cert fetch → SANs como scope hints pasivas
    - CSP parser real, cookie security, SRI/mixed content
    - Secret scanner pasivo (~35 patterns + entropy + anti-placeholder)
    - JWT extractor + decode (sin validar firma)
    - Open-redirect/SSRF param hints
    - ArcGIS/Elasticsearch/Firebase/S3/Actuator/Hasura/k8s/cloud fn
    - Priority scoring + top targets + analyzer_handoff
    - Reporte Markdown opcional
    - Proxy support (Burp), retry con backoff, concurrency configurable

Uso:
    python3 recon_fingerprint.py https://target.tld -o fp.json --scope target.tld
    python3 recon_fingerprint.py https://target.tld --md-report fp.md --concurrency 8
    python3 recon_fingerprint.py https://target.tld --proxy http://127.0.0.1:8080
    python3 recon_fingerprint.py https://target.tld --extra-probes
    python3 recon_fingerprint.py https://api.target.tld --local-js ./bundles/*.js

Hecho para workflows tipo Bugcrowd / HackerOne / privados donde el tiempo
importa y el output alimenta otros tools (analyzer de JS, linters, etc.).

Filosofía: ruidoso lo mínimo posible, útil lo máximo posible. Target-agnostic.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import math
import os
import re
import shutil
import socket
import ssl
import sys
import threading
import time
from contextlib import contextmanager
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from html import unescape as html_unescape
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlparse, parse_qsl
from scope_policy import HostScope, ScopeError

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter

try:  # urllib3 retry (standard requests dep)
    from urllib3.util.retry import Retry  # type: ignore
except Exception:  # pragma: no cover
    Retry = None  # type: ignore


# =============================================================================
# Constantes, UAs y defaults
# =============================================================================

__version__ = "3.6-handoff-slim"

DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
DEFAULT_TIMEOUT = 12
DEFAULT_MAX_ASSETS = 15
DEFAULT_CONCURRENCY = 6
DEFAULT_SAMPLE_BYTES = 260_000
MAX_TECH_PROBES_PER_RUN = 80

PARAM_CATEGORIES: List[Tuple[str, int, List[str]]] = [
    ("idor_id", 5, [
        r"^(?:user|account|owner|member|customer|client|patient|student|employee|org|organization|team|group|company|tenant|workspace|project|order|invoice|document|doc|file|record|entity|item|object|resource|asset)_?id$",
        r"^(?:id|uid|uuid|guid)$",
        r".*_uuid$",
    ]),
    ("ssrf_url", 6, [
        r"^(?:url|uri|link|endpoint|target|dest|destination|src|source|fetch_url|callback|webhook|proxy|via)$",
        r".*_url$", r".*_uri$", r".*_endpoint$", r".*_webhook$",
    ]),
    ("ssrf_file_fetch", 5, [
        r"^(?:image|img|avatar|photo|picture|thumbnail|thumb|icon|logo|file|attachment|media|video|audio|document|pdf|asset|resource)$",
    ]),
    ("open_redirect", 5, [
        r"^(?:redirect|redir|redirect_to|return_to|returnto|return_url|returnurl|next|continue|destination|goto|go|to|forward|success_url|failure_url|cancel_url|back|ref|referer|referrer|origin|rurl)$",
    ]),
    ("path_traversal", 5, [
        r"^(?:path|file|filename|filepath|dir|directory|folder|template|include|load|read|page|module|doc|docfile)$",
    ]),
    ("cmd_injection", 5, [
        r"^(?:cmd|command|exec|execute|run|shell|ssh|eval|query|expr|expression|code|script|formula)$",
    ]),
    ("mass_assignment", 6, [
        r"^(?:role|roles|admin|is_admin|isadmin|is_superuser|is_staff|permissions|perms|scope|scopes|privileges|access_level|grants|capabilities|flags|enabled|verified|is_verified|approved|active|status|state|owner|owner_id|created_by|updated_by)$",
    ]),
    ("auth_token", 4, [
        r"^(?:token|access_token|refresh_token|id_token|jwt|bearer|api_key|apikey|secret|session|sess|sid|auth|authorization|key|client_secret)$",
    ]),
    ("xss_content", 3, [
        r"^(?:html|content|body|text|message|description|comment|note|bio|about|title|name|label|subject|template|markup|snippet|embed)$",
    ]),
    ("sqli_hint", 3, [
        r"^(?:order_by|orderby|sort|sort_by|sortby|group_by|groupby|filter|where|q|query|search|term|keyword|select|fields|columns|having|offset|limit)$",
    ]),
    ("debug_flag", 4, [
        r"^(?:debug|dev|devmode|test|testing|trace|verbose|diagnostic|profile|profiling|mock|stub|fake|bypass|skip_auth|no_auth|admin_mode)$",
    ]),
    ("deserialization", 4, [
        r"^(?:xml|payload|data|state|__viewstate|viewstate|serialized|pickle|yaml|json_data|config)$",
    ]),
]

PARAM_FROM_URL_RE = re.compile(r"[?&]([a-zA-Z_][a-zA-Z0-9_\-]{0,60})=")
PARAM_FROM_JS_OBJECT_RE = re.compile(r"['\"]?([a-zA-Z_][a-zA-Z0-9_]{1,50})['\"]?\s*:\s*")
FETCH_CALL_RE = re.compile(r"(?:fetch|axios(?:\.(?:get|post|put|patch|delete))?|\$\.(?:get|post|ajax)|(?:XMLHttpRequest|xhr)\.open\s*\(\s*['\"][A-Z]+['\"]\s*,\s*)\s*\(?\s*['`\"]([^'`\"]{3,200})['`\"]", re.I)
PARAM_HEADER_RE = re.compile(r"(?:setRequestHeader|headers?\[?['\"]?)\s*[\(:\[,]?\s*['\"]((?:X-|x-)[A-Za-z0-9\-_]{2,40})['\"]", re.I)
PARAM_STOPLIST = {
    "function","return","const","let","var","new","this","class","extends","import","export","default","async","await","yield","typeof","instanceof","void","null","undefined","true","false",
    "render","props","state","children","key","ref","classname","style","onclick","onchange","onsubmit","usestate","useeffect","usememo","usecallback","useref","component","template","setup","computed","watch","methods","data","mounted","created","beforedestroy",
    "color","background","margin","padding","border","display","flex","grid","width","height","font","length","size","index","count","value","label","disabled","loading","error","success","open","close","visible","hidden","show","hide","toggle",
    "map","filter","reduce","foreach","find","some","every","push","pop","shift","unshift","slice","splice","concat","join","split","trim","replace","match","test","exec","tostring","valueof","constructor","prototype",
    "href","src","alt","title","target","rel","type","id","name","class","for","px","em","rem","vh","vw","deg","rad"
}
MIN_PARAM_LEN = 2
MAX_PARAM_LEN = 60

TECH_SPECIFIC_PROBES: Dict[str, Dict[str, Any]] = {

    # =========================================================================
    # JAVA / JVM STACK
    # =========================================================================

    "Spring Boot": {
        "paths": [
            ("/actuator/heapdump", "GET", [
                ("heap_dump_exposed", None, "status:200"),
                ("heap_dump_binary", r"HPROF|JAVA PROFILE", "body"),
            ]),
            ("/actuator/jolokia", "GET", [
                ("jolokia_exposed", r"\"agent\"\s*:", "body"),
            ]),
            ("/actuator/jolokia/list", "GET", [
                ("jolokia_mbeans_listable", r"java\.lang:type=Runtime", "body"),
            ]),
            ("/actuator/jolokia/read/java.lang:type=Memory", "GET", [
                ("jolokia_read_works", r"HeapMemoryUsage", "body"),
            ]),
            ("/actuator/gateway/routes", "GET", [
                ("gateway_routes_exposed", r"predicate|filters", "body"),
            ]),
            ("/actuator/env", "GET", [
                ("env_exposed", r"\"propertySources\"", "body"),
                ("env_secrets_visible", r"password|secret|token|apikey|api_key", "body"),
            ]),
            ("/actuator/configprops", "GET", [
                ("configprops_exposed", r"\"beans\"|\"contexts\"", "body"),
            ]),
            ("/actuator/beans", "GET", [
                ("beans_exposed", r"\"beans\"", "body"),
            ]),
            ("/actuator/threaddump", "GET", [
                ("threaddump_exposed", r"threadName", "body"),
            ]),
            ("/actuator/loggers", "GET", [
                ("loggers_exposed", r"\"loggers\"", "body"),
            ]),
            ("/actuator/logfile", "GET", [
                ("logfile_exposed", None, "status:200"),
            ]),
            ("/actuator/mappings", "GET", [
                ("mappings_exposed", r"handlerMethod|dispatcherHandler", "body"),
            ]),
            ("/actuator/httptrace", "GET", [
                ("httptrace_exposed", r"\"traces\"", "body"),
            ]),
            ("/actuator/scheduledtasks", "GET", [
                ("scheduledtasks_exposed", r"\"cron\"|\"fixedRate\"", "body"),
            ]),
            ("/actuator/auditevents", "GET", [
                ("auditevents_exposed", r"\"events\"", "body"),
            ]),
            ("/actuator/caches", "GET", [
                ("caches_exposed", r"\"caches\"", "body"),
            ]),
            ("/actuator/sessions", "GET", [
                ("sessions_exposed", r"\"sessions\"", "body"),
            ]),
        ],
        "notes": "Spring Actuator: heapdump + env → credentials. Jolokia → JNDI. Gateway routes → SSRF vectors.",
    },

    "Spring Cloud Config Server": {
        "paths": [
            ("/env", "GET", [("spring_cloud_env", r"propertySources", "body")]),
            ("/application/default", "GET", [("spring_cloud_config", r"propertySources", "body")]),
        ],
        "notes": "Config server expone secretos de apps clientes.",
    },

    "Apache Tomcat": {
        "paths": [
            ("/manager/html", "GET", [
                ("tomcat_manager", r"Tomcat Web Application Manager", "body"),
                ("tomcat_manager_auth", None, "status:401"),
            ]),
            ("/host-manager/html", "GET", [
                ("tomcat_host_manager", r"Tomcat Virtual Host Manager", "body"),
            ]),
            ("/manager/status", "GET", [
                ("tomcat_status_exposed", r"Tomcat Version", "body"),
            ]),
            ("/examples/servlets/servlet/SessionExample", "GET", [
                ("tomcat_examples_exposed", r"Sessions Example", "body"),
            ]),
            ("/docs/", "GET", [
                ("tomcat_docs_exposed", r"Apache Tomcat", "body"),
            ]),
        ],
        "notes": "Tomcat manager con default creds (tomcat:tomcat, admin:admin) → WAR deploy RCE.",
    },

    "JBoss / WildFly": {
        "paths": [
            ("/jmx-console", "GET", [("jboss_jmx_console", r"JMX Console|MBean", "body")]),
            ("/web-console/ServerInfo.jsp", "GET", [("jboss_web_console", r"JBoss", "body")]),
            ("/invoker/JMXInvokerServlet", "GET", [("jboss_jmx_invoker", None, "status:200")]),
            ("/management", "GET", [("wildfly_mgmt", r"management-major-version", "body")]),
            ("/console/", "GET", [("jboss_console", r"WildFly|JBoss", "body")]),
        ],
        "notes": "JBoss JMX → RCE vía MainDeployer. Ver CVE-2017-12149, CVE-2017-7504.",
    },

    "Oracle WebLogic": {
        "paths": [
            ("/console/login/LoginForm.jsp", "GET", [
                ("weblogic_console", r"WebLogic|Oracle", "body"),
            ]),
            ("/wls-wsat/CoordinatorPortType", "GET", [
                ("weblogic_wsat_exposed", r"wsat|CoordinatorPortType", "body"),
            ]),
            ("/_async/AsyncResponseService", "GET", [
                ("weblogic_async_exposed", r"AsyncResponseService", "body"),
            ]),
            ("/bea_wls_internal/", "GET", [
                ("weblogic_internal", None, "status:200"),
            ]),
            ("/uddiexplorer/SearchPublicRegistries.jsp", "GET", [
                ("weblogic_uddi_ssrf", r"uddi", "body"),
            ]),
        ],
        "notes": "WebLogic: CVE-2017-10271, CVE-2019-2725, CVE-2020-2883 (wsat y async RCE). UDDI explorer → SSRF.",
    },

    "IBM WebSphere": {
        "paths": [
            ("/ibm/console/logon.jsp", "GET", [("websphere_console", r"WebSphere", "body")]),
            ("/admin", "GET", [("websphere_admin", r"WebSphere", "body")]),
        ],
        "notes": "WebSphere admin console default en /ibm/console. CVE-2020-4450 (IIOP deserialization).",
    },

    "Apache Struts": {
        "paths": [
            ("/struts/webconsole.html", "GET", [("struts_console", r"Struts|OGNL", "body")]),
        ],
        "notes": "Struts: CVE-2017-5638 (Content-Type header OGNL). Siempre probar versión.",
    },

    # =========================================================================
    # RUBY STACK
    # =========================================================================

    "Ruby on Rails": {
        "paths": [
            ("/rails/info/routes", "GET", [
                ("rails_routes_exposed", r"HTTP Verb|Path Helper", "body"),
            ]),
            ("/rails/info/properties", "GET", [
                ("rails_properties", r"Ruby version|Rails version", "body"),
            ]),
            ("/rails/conductor/action_mailbox", "GET", [
                ("rails_conductor", None, "status:200"),
            ]),
            ("/rails/mailers", "GET", [
                ("rails_mailers_preview", r"Action Mailer", "body"),
            ]),
            ("/sidekiq", "GET", [
                ("sidekiq_exposed", r"Sidekiq", "body"),
            ]),
            ("/sidekiq/queues", "GET", [
                ("sidekiq_queues", r"queue", "body"),
            ]),
            ("/cable", "GET", [
                ("rails_actioncable", None, "status:404"),
            ]),
        ],
        "notes": "Rails DEV: /rails/info expone TODO el routing. Sidekiq sin auth → queue manipulation.",
    },

    "Redmine": {
        "paths": [
            ("/users", "GET", [("redmine_users_enum", r"users", "body")]),
            ("/projects.json", "GET", [("redmine_projects_api", r"projects", "body")]),
        ],
        "notes": "Redmine: project listing público si no se restringe.",
    },

    "Discourse": {
        "paths": [
            ("/about.json", "GET", [("discourse_about", r"top_users|admins", "body")]),
            ("/site.json", "GET", [("discourse_site", r"discourse", "body")]),
            ("/latest.json", "GET", [("discourse_latest", r"topic_list", "body")]),
            ("/admin/backups", "GET", [("discourse_admin_backups", None, "status:200")]),
        ],
        "notes": "Discourse: /about.json expone admins. Admin API sin 2FA en instancias viejas.",
    },

    # =========================================================================
    # PYTHON STACK
    # =========================================================================

    "Django": {
        "paths": [
            ("/admin/", "GET", [
                ("django_admin_page", r"Django administration|Log in \| Django", "body"),
            ]),
            ("/admin/login/", "GET", [
                ("django_admin_login", r"Django administration", "body"),
            ]),
            ("/api/schema/", "GET", [
                ("drf_schema", r"openapi", "body"),
            ]),
            ("/api/schema/swagger-ui/", "GET", [
                ("drf_swagger", r"swagger", "body"),
            ]),
            ("/api/schema/redoc/", "GET", [
                ("drf_redoc", r"redoc", "body"),
            ]),
            ("/__debug__/", "GET", [
                ("django_debug_toolbar", r"debug toolbar|djdt", "body"),
            ]),
            ("/silk/", "GET", [
                ("django_silk", r"silk", "body"),
            ]),
        ],
        "notes": "Django: /admin/ default. DEBUG=True → tracebacks con paths/SECRET_KEY parcial.",
    },

    "Flask": {
        "paths": [
            ("/console", "GET", [("werkzeug_debugger", r"werkzeug|debugger|PIN", "body")]),
            ("/debug", "GET", [("flask_debug", r"werkzeug|debugger", "body")]),
        ],
        "notes": "Werkzeug debugger con PIN weak → RCE. Ver HackerOne reports de 2019-2023.",
    },

    "FastAPI": {
        "paths": [
            ("/docs", "GET", [("fastapi_docs", r"FastAPI|Swagger UI", "body")]),
            ("/redoc", "GET", [("fastapi_redoc", r"FastAPI|ReDoc", "body")]),
            ("/openapi.json", "GET", [("fastapi_openapi", r"openapi|paths", "body")]),
        ],
        "notes": "FastAPI: /docs y /openapi.json expuestos por default → API map completo.",
    },

    "Tornado": {
        "paths": [
            ("/", "GET", [("tornado_server", r"TornadoServer", "header:Server")]),
        ],
        "notes": "Tornado: verificar debug mode si aparece.",
    },

    # =========================================================================
    # PHP STACK
    # =========================================================================

    "Laravel": {
        "paths": [
            ("/_ignition/health-check", "GET", [
                ("ignition_exposed", r"ignition|flare", "body"),
            ]),
            ("/_ignition/execute-solution", "POST", [
                ("ignition_rce_endpoint", None, "status:200"),
                ("ignition_rce_endpoint_method", None, "status:405"),
            ]),
            ("/telescope", "GET", [
                ("laravel_telescope", r"telescope|Laravel Telescope", "body"),
            ]),
            ("/telescope/requests", "GET", [
                ("laravel_telescope_requests", r"telescope", "body"),
            ]),
            ("/horizon", "GET", [
                ("laravel_horizon", r"horizon", "body"),
            ]),
            ("/horizon/api/stats", "GET", [
                ("laravel_horizon_api", r"failedJobs|queues", "body"),
            ]),
            ("/_debugbar/open", "GET", [
                ("laravel_debugbar", r"debugbar", "body"),
            ]),
            ("/api/documentation", "GET", [
                ("laravel_scribe", r"scribe|API Documentation", "body"),
            ]),
            ("/.env", "GET", [
                ("laravel_env_exposed", r"APP_KEY|DB_PASSWORD", "body"),
            ]),
        ],
        "notes": "Laravel Ignition CVE-2021-3129 → RCE pre-parche. Telescope filtra TODO (requests, queries, jobs).",
    },

    "Symfony": {
        "paths": [
            ("/_profiler", "GET", [("symfony_profiler", r"Symfony Profiler|sf-toolbar", "body")]),
            ("/_profiler/phpinfo", "GET", [("symfony_phpinfo", r"phpinfo\(\)", "body")]),
            ("/_wdt", "GET", [("symfony_wdt", r"sf-toolbar", "body")]),
            ("/app_dev.php", "GET", [("symfony_dev_front", r"Symfony", "body")]),
            ("/config.php", "GET", [("symfony_config", r"Symfony|Environment check", "body")]),
        ],
        "notes": "Symfony dev mode: profiler y phpinfo expuestos. CVE-2019-10910 conocido.",
    },

    "CodeIgniter": {
        "paths": [
            ("/index.php/welcome", "GET", [("codeigniter_welcome", r"CodeIgniter", "body")]),
        ],
        "notes": "CodeIgniter: verificar si DEBUG está on.",
    },

    "CakePHP": {
        "paths": [
            ("/debug-kit/requests/view", "GET", [("cakephp_debugkit", r"DebugKit", "body")]),
        ],
        "notes": "CakePHP DebugKit: expone requests, SQL, env.",
    },

    # =========================================================================
    # JAVASCRIPT / NODE STACK
    # =========================================================================

    "Next.js": {
        "paths": [
            ("/_next/data", "GET", [("next_data_listing", None, "status:200")]),
            ("/_next/static/chunks/", "GET", [("next_chunks_dir", None, "status:200")]),
            ("/api/", "GET", [("next_api_root", None, "status:200")]),
            ("/_next/image", "GET", [("next_image_optim", None, "status:400")]),
            ("/api/auth/providers", "GET", [
                ("next_auth_providers", r"google|github|credentials", "body"),
            ]),
            ("/api/auth/session", "GET", [
                ("next_auth_session", r"user|expires", "body"),
            ]),
            ("/api/auth/csrf", "GET", [
                ("next_auth_csrf", r"csrfToken", "body"),
            ]),
        ],
        "params_to_test": [
            ("/_next/image", "url", "http://169.254.169.254/latest/meta-data/",
             "next_image_ssrf_hint"),
        ],
        "notes": "Next.js /_next/image SSRF si no restringe domains. NextAuth endpoints map completo.",
    },

    "Nuxt.js": {
        "paths": [
            ("/_nuxt/", "GET", [("nuxt_assets_dir", None, "status:200")]),
            ("/api/_content/", "GET", [("nuxt_content_api", None, "status:200")]),
            ("/__nuxt_error", "GET", [("nuxt_error_page", r"nuxt", "body")]),
            ("/_ipx/", "GET", [("nuxt_ipx", None, "status:400")]),
        ],
        "notes": "Nuxt @nuxt/image IPX tiene SSRF history. Buscar payload.js con rutas.",
    },

    "SvelteKit": {
        "paths": [
            ("/_app/", "GET", [("sveltekit_app_dir", None, "status:200")]),
            ("/_app/immutable/", "GET", [("sveltekit_immutable", None, "status:200")]),
        ],
        "notes": "SvelteKit: /_app/immutable contiene chunks con rutas server.",
    },

    "Express.js / Node": {
        "paths": [
            ("/debug/vars", "GET", [("node_debug_vars", r"cmdline", "body")]),
            ("/status", "GET", [("express_status", None, "status:200")]),
            ("/explorer/", "GET", [("loopback_explorer", r"LoopBack", "body")]),
        ],
        "notes": "Express + status-monitor a veces expuesto. LoopBack explorer filtra API.",
    },

    "Meteor": {
        "paths": [
            ("/sockjs/info", "GET", [("meteor_sockjs", r"websocket|origins", "body")]),
        ],
        "notes": "Meteor apps: /sockjs/info confirma stack. DDP interno a veces expuesto.",
    },

    "AdonisJS": {
        "paths": [
            ("/__exception", "GET", [("adonis_exception", r"AdonisJS|Adonis", "body")]),
        ],
        "notes": "AdonisJS: errores en dev leak stack trace.",
    },

    # =========================================================================
    # .NET STACK
    # =========================================================================

    "ASP.NET": {
        "paths": [
            ("/Trace.axd", "GET", [("aspnet_trace", r"Application Trace", "body")]),
            ("/elmah.axd", "GET", [("elmah_exposed", r"Error Log for|ELMAH", "body")]),
            ("/WebResource.axd", "GET", [("aspnet_webresource", None, "status:200")]),
            ("/ScriptResource.axd", "GET", [("aspnet_scriptresource", None, "status:200")]),
            ("/_vti_bin/", "GET", [("frontpage_vti", None, "status:200")]),
        ],
        "notes": "ASP.NET: elmah.axd filtra TODOS los errores con stack traces. Trace.axd idem.",
    },

    "ASP.NET Core": {
        "paths": [
            ("/swagger", "GET", [("aspnet_core_swagger", r"swagger", "body")]),
            ("/swagger/index.html", "GET", [("aspnet_core_swagger_ui", r"Swagger UI", "body")]),
            ("/swagger/v1/swagger.json", "GET", [("aspnet_core_openapi", r"openapi|swagger", "body")]),
            ("/healthchecks-ui", "GET", [("healthchecks_ui", r"Health Checks UI", "body")]),
            ("/hc", "GET", [("healthcheck_exposed", r"Healthy|Degraded|Unhealthy", "body")]),
        ],
        "notes": "ASP.NET Core: Swagger en dev por default. Healthchecks-ui a veces expuesto.",
    },

    "Umbraco": {
        "paths": [
            ("/umbraco/", "GET", [("umbraco_login", r"Umbraco", "body")]),
            ("/umbraco/api/", "GET", [("umbraco_api", None, "status:200")]),
            ("/App_Plugins/", "GET", [("umbraco_plugins", None, "status:200")]),
        ],
        "notes": "Umbraco: panel en /umbraco/. CVE history alto.",
    },

    "Kentico": {
        "paths": [
            ("/CMSPages/logon.aspx", "GET", [("kentico_login", r"Kentico|CMS", "body")]),
            ("/Admin/cmsadministration.aspx", "GET", [("kentico_admin", r"Kentico", "body")]),
        ],
        "notes": "Kentico: paths estándar, varios XSS y SQLi históricos.",
    },

    "DotNetNuke": {
        "paths": [
            ("/Install/InstallWizard.aspx", "GET", [("dnn_install_wizard", r"InstallWizard|DotNetNuke", "body")]),
            ("/DesktopModules/", "GET", [("dnn_desktopmodules", None, "status:200")]),
            ("/Portals/_default/", "GET", [("dnn_portals_default", None, "status:200")]),
        ],
        "notes": "DNN: InstallWizard expuesto = CVE-2018-15811 RCE.",
    },

    "Sitefinity": {
        "paths": [
            ("/Sitefinity/Login", "GET", [("sitefinity_login", r"Sitefinity", "body")]),
            ("/Sitefinity/Services/", "GET", [("sitefinity_services", None, "status:401")]),
        ],
        "notes": "Sitefinity: CVE-2019-17392 y otros en version history.",
    },

    "Sitecore": {
        "paths": [
            ("/sitecore/login", "GET", [("sitecore_login", r"Sitecore", "body")]),
            ("/sitecore/admin/", "GET", [("sitecore_admin", r"Sitecore", "body")]),
            ("/sitecore/service/xdb/info.aspx", "GET", [("sitecore_xdb_info", r"Sitecore", "body")]),
        ],
        "notes": "Sitecore: CVE-2021-42237 deserialization RCE. admin default credentials historia.",
    },

    # =========================================================================
    # CMS: WORDPRESS, DRUPAL, JOOMLA, FAMILIA
    # =========================================================================

    "WordPress": {
        "paths": [
            ("/wp-json/wp/v2/users", "GET", [
                ("wp_users_enum", r"\"id\"\s*:\s*\d", "body"),
            ]),
            ("/wp-json/", "GET", [
                ("wp_api_root", r"namespaces", "body"),
            ]),
            ("/wp-json/wp/v2/posts", "GET", [
                ("wp_posts_api", r"\"id\"", "body"),
            ]),
            ("/xmlrpc.php", "POST", [
                ("wp_xmlrpc", r"XML-RPC server accepts POST", "body"),
            ]),
            ("/wp-content/debug.log", "GET", [
                ("wp_debug_log", None, "status:200"),
            ]),
            ("/wp-admin/admin-ajax.php", "POST", [
                ("wp_ajax", None, "status:200"),
            ]),
            ("/wp-login.php", "GET", [
                ("wp_login", r"WordPress", "body"),
            ]),
            ("/wp-admin/install.php", "GET", [
                ("wp_install_page", r"WordPress &rsaquo; Installation", "body"),
            ]),
            ("/wp-content/uploads/", "GET", [
                ("wp_uploads_listing", r"Index of", "body"),
            ]),
            ("/wp-config.php.bak", "GET", [
                ("wp_config_backup", r"DB_PASSWORD|wp-config", "body"),
            ]),
            ("/wp-config.php~", "GET", [
                ("wp_config_tilde", r"DB_PASSWORD|wp-config", "body"),
            ]),
            ("/wp-content/plugins/", "GET", [
                ("wp_plugins_listing", r"Index of", "body"),
            ]),
            ("/wp-json/oembed/1.0/embed", "GET", [
                ("wp_oembed", None, "status:400"),
            ]),
            ("/readme.html", "GET", [
                ("wp_readme", r"WordPress.*Version", "body"),
            ]),
        ],
        "notes": "WP: /wp-json/wp/v2/users → usernames. xmlrpc → pingback SSRF + brute force amplification. Backup files comunes.",
    },

    "Drupal": {
        "paths": [
            ("/user/login", "GET", [("drupal_login", r"user-login-form", "body")]),
            ("/?q=user/login", "GET", [("drupal_clean_url_off", r"user-login-form", "body")]),
            ("/CHANGELOG.txt", "GET", [("drupal_changelog", r"Drupal", "body")]),
            ("/core/CHANGELOG.txt", "GET", [("drupal_core_changelog", r"Drupal", "body")]),
            ("/README.txt", "GET", [("drupal_readme", r"Drupal", "body")]),
            ("/jsonapi/", "GET", [("drupal_jsonapi", r"jsonapi", "body")]),
            ("/jsonapi/user/user", "GET", [("drupal_jsonapi_users", r"data", "body")]),
            ("/rest/session/token", "GET", [("drupal_rest_token", None, "status:200")]),
            ("/update.php", "GET", [("drupal_update_page", r"Drupal database update", "body")]),
            ("/INSTALL.txt", "GET", [("drupal_install_txt", r"Drupal", "body")]),
            ("/core/install.php", "GET", [("drupal_core_install", r"Drupal", "body")]),
            ("/sites/default/files/", "GET", [("drupal_files_listing", r"Index of", "body")]),
        ],
        "notes": "Drupal: CHANGELOG → versión exacta → CVE match. Drupalgeddon family. JSON:API a veces filtra users.",
    },

    "Joomla": {
        "paths": [
            ("/administrator/", "GET", [("joomla_admin", r"Joomla", "body")]),
            ("/administrator/index.php", "GET", [("joomla_admin_login", r"Joomla", "body")]),
            ("/api/index.php/v1/users", "GET", [("joomla_api_users", None, "status:401")]),
            ("/README.txt", "GET", [("joomla_readme", r"Joomla", "body")]),
            ("/htaccess.txt", "GET", [("joomla_htaccess_txt", r"Joomla", "body")]),
            ("/configuration.php-dist", "GET", [("joomla_config_dist", r"JConfig", "body")]),
            ("/language/en-GB/en-GB.xml", "GET", [("joomla_language_xml", r"<version>", "body")]),
        ],
        "notes": "Joomla: /language/en-GB/en-GB.xml leak versión. API nueva (4.x) tiene bypass conocidos.",
    },

    "Magento": {
        "paths": [
            ("/admin/", "GET", [("magento_admin_redirect", None, "status:302")]),
            ("/rest/V1/products", "GET", [("magento_rest_products", None, "status:401")]),
            ("/downloader/", "GET", [("magento_downloader", r"Magento", "body")]),
            ("/magento_version", "GET", [("magento_version_leak", r"Magento/\d", "body")]),
            ("/errors/local.xml", "GET", [("magento_errors_xml", r"skin", "body")]),
            ("/app/etc/local.xml", "GET", [("magento_local_xml", r"<config>", "body")]),
        ],
        "notes": "Magento /magento_version leak directo. CVE-2022-24086 (Magecart). Admin brute force clásico.",
    },

    "Shopware": {
        "paths": [
            ("/admin", "GET", [("shopware_admin", r"Shopware|Administration", "body")]),
            ("/api/_info/openapi3.json", "GET", [("shopware_openapi", r"openapi|paths", "body")]),
            ("/recovery/install", "GET", [("shopware_recovery", r"Shopware", "body")]),
        ],
        "notes": "Shopware: OpenAPI completo en paths conocidos.",
    },

    "PrestaShop": {
        "paths": [
            ("/adminXXXXXXX/", "GET", [("prestashop_admin_dir", None, "status:404")]),
            ("/install/", "GET", [("prestashop_install", r"PrestaShop", "body")]),
            ("/api/", "GET", [("prestashop_api", None, "status:401")]),
        ],
        "notes": "PrestaShop: CVE chain history, varios SQLi.",
    },

    "TYPO3": {
        "paths": [
            ("/typo3/", "GET", [("typo3_backend", r"TYPO3", "body")]),
            ("/typo3_src/", "GET", [("typo3_src", None, "status:200")]),
            ("/typo3conf/LocalConfiguration.php", "GET", [("typo3_localconf", r"LocalConfiguration", "body")]),
            ("/INSTALL.md", "GET", [("typo3_install_md", r"TYPO3", "body")]),
        ],
        "notes": "TYPO3: varios RCE históricos. Backend en /typo3/ fijo.",
    },

    "Ghost CMS": {
        "paths": [
            ("/ghost/", "GET", [("ghost_admin", r"Ghost|Sign in", "body")]),
            ("/ghost/api/admin/", "GET", [("ghost_admin_api", None, "status:401")]),
            ("/ghost/api/content/", "GET", [("ghost_content_api", None, "status:400")]),
            ("/ghost/api/content/posts/", "GET", [("ghost_content_posts", None, "status:400")]),
        ],
        "notes": "Ghost: admin API en /ghost/. CVE-2023-40028 (path traversal via symlink).",
    },

    "Craft CMS": {
        "paths": [
            ("/admin", "GET", [("craft_admin", r"Craft CMS|craftcms", "body")]),
            ("/index.php?p=admin", "GET", [("craft_admin_alt", r"Craft", "body")]),
            ("/actions/entries/saveEntry", "POST", [("craft_actions", None, "status:400")]),
        ],
        "notes": "Craft: CVE-2023-41892 unauthenticated RCE.",
    },

    "Contentful / Storyblok / Headless": {
        "paths": [
            ("/spaces/", "GET", [("headless_spaces", None, "status:401")]),
            ("/api/v2/cdn/spaces/me", "GET", [("storyblok_cdn", None, "status:401")]),
        ],
        "notes": "Headless CMS: API tokens muchas veces en frontend.",
    },

    "Strapi": {
        "paths": [
            ("/admin", "GET", [("strapi_admin", r"strapi", "body")]),
            ("/admin/init", "GET", [("strapi_admin_init", r"hasAdmin|uuid", "body")]),
            ("/api/users/me", "GET", [("strapi_users_me", None, "status:401")]),
            ("/graphql", "POST", [("strapi_graphql", r"__schema|errors", "body")]),
            ("/_health", "GET", [("strapi_health", None, "status:204")]),
            ("/admin/users-permissions/roles", "GET", [("strapi_roles", None, "status:401")]),
        ],
        "notes": "Strapi: /admin/init con hasAdmin=false → takeover. CVE-2023-22894 reset password chain.",
    },

    "Directus": {
        "paths": [
            ("/admin/", "GET", [("directus_admin", r"Directus", "body")]),
            ("/server/info", "GET", [("directus_server_info", r"directus|project", "body")]),
            ("/graphql", "POST", [("directus_graphql", r"__schema", "body")]),
            ("/items/", "GET", [("directus_items", None, "status:403")]),
        ],
        "notes": "Directus: /server/info leak versión + config. Item-level permissions a veces mal configuradas.",
    },

    "Payload CMS": {
        "paths": [
            ("/admin", "GET", [("payload_admin", r"Payload", "body")]),
            ("/api/users/me", "GET", [("payload_users_me", None, "status:401")]),
            ("/api/access", "GET", [("payload_access", None, "status:200")]),
        ],
        "notes": "Payload: /api/access revela permisos por colección.",
    },

    "Keystone.js": {
        "paths": [
            ("/admin", "GET", [("keystone_admin", r"KeystoneJS|Keystone", "body")]),
            ("/api/graphql", "POST", [("keystone_graphql", r"__schema", "body")]),
        ],
        "notes": "Keystone: GraphQL endpoint fijo.",
    },

    # =========================================================================
    # GRAPHQL IMPLEMENTATIONS
    # =========================================================================

    "Hasura": {
        "paths": [
            ("/v1/graphql", "POST", [
                ("hasura_introspection_ok", r"__schema", "body"),
            ]),
            ("/v1/metadata", "POST", [
                ("hasura_metadata_ok", r"is_admin|sources|tables", "body"),
            ]),
            ("/v1/query", "POST", [
                ("hasura_admin_api", None, "status:200"),
            ]),
            ("/v2/query", "POST", [
                ("hasura_v2_query", None, "status:200"),
            ]),
            ("/healthz", "GET", [
                ("hasura_healthz", r"OK|healthy", "body"),
            ]),
            ("/v1alpha1/config", "GET", [
                ("hasura_config", r"is_admin_secret_set", "body"),
            ]),
        ],
        "notes": "Hasura: X-Hasura-Role bypass (anonymous→admin). /v1/metadata con admin secret = full DB.",
    },

    "Apollo Server": {
        "paths": [
            ("/graphql", "GET", [("apollo_playground", r"Apollo|playground|sandbox", "body")]),
            ("/.well-known/apollo/server-health", "GET", [("apollo_health", None, "status:200")]),
        ],
        "notes": "Apollo: playground habilitado en prod a veces. Introspection default.",
    },

    "PostGraphile": {
        "paths": [
            ("/graphql", "POST", [("postgraphile_schema", r"__schema", "body")]),
            ("/graphiql", "GET", [("postgraphile_graphiql", r"GraphiQL", "body")]),
        ],
        "notes": "PostGraphile genera schema desde Postgres — introspection = estructura de DB real.",
    },

    # =========================================================================
    # DEV TOOLS / CI / REGISTRIES PUBLIC-FACING
    # =========================================================================

    "Jenkins": {
        "paths": [
            ("/manage", "GET", [("jenkins_manage", r"Manage Jenkins", "body")]),
            ("/script", "GET", [("jenkins_script_console", r"Script Console|Groovy", "body")]),
            ("/asynchPeople/api/json", "GET", [("jenkins_users_enum", r"\"users\"", "body")]),
            ("/api/json", "GET", [("jenkins_api_json", r"jobs|nodeName", "body")]),
            ("/computer/api/json", "GET", [("jenkins_computers", r"computer|displayName", "body")]),
            ("/credentials/", "GET", [("jenkins_credentials", r"Credentials", "body")]),
            ("/view/All/builds", "GET", [("jenkins_builds", r"build", "body")]),
            ("/signup", "GET", [("jenkins_signup_enabled", r"Create an account", "body")]),
            ("/whoAmI/", "GET", [("jenkins_whoami", r"authorities|Anonymous", "body")]),
        ],
        "notes": "Jenkins: /script = RCE. /asynchPeople = user enum. /signup abierto = takeover. CVE-2024-23897 file read.",
    },

    "GitLab": {
        "paths": [
            ("/api/v4/users", "GET", [("gitlab_users_api", r"\"username\"", "body")]),
            ("/api/v4/projects", "GET", [("gitlab_projects_api", r"\"path_with_namespace\"", "body")]),
            ("/api/v4/snippets", "GET", [("gitlab_snippets_api", r"title|file_name", "body")]),
            ("/explore", "GET", [("gitlab_explore", r"explore", "body")]),
            ("/users/sign_up", "GET", [("gitlab_signup", r"Register", "body")]),
            ("/api/v4/version", "GET", [("gitlab_version", r"\"version\"", "body")]),
            ("/-/metrics", "GET", [("gitlab_metrics", r"HELP|TYPE", "body")]),
            ("/-/readiness", "GET", [("gitlab_readiness", None, "status:200")]),
        ],
        "notes": "GitLab: users API público histórico. Signup abierto = takeover path. Muchos CVEs críticos 2023-2025.",
    },

    "Gitea": {
        "paths": [
            ("/api/v1/users/search", "GET", [("gitea_users_search", r"\"data\"", "body")]),
            ("/api/v1/version", "GET", [("gitea_version", r"\"version\"", "body")]),
            ("/explore/users", "GET", [("gitea_explore_users", r"explore", "body")]),
            ("/user/sign_up", "GET", [("gitea_signup", r"Register|Sign Up", "body")]),
        ],
        "notes": "Gitea: similar a GitLab. API user enum. Signup abierto.",
    },

    "Bitbucket Server": {
        "paths": [
            ("/rest/api/1.0/users", "GET", [("bitbucket_users_api", None, "status:401")]),
            ("/rest/api/1.0/projects", "GET", [("bitbucket_projects_api", None, "status:401")]),
            ("/admin", "GET", [("bitbucket_admin", r"Bitbucket", "body")]),
        ],
        "notes": "Bitbucket Server: CVE-2022-36804 command injection, CVE-2023-22518 RCE.",
    },

    "Grafana": {
        "paths": [
            ("/api/org", "GET", [("grafana_org_api", r"\"name\"", "body")]),
            ("/api/datasources", "GET", [("grafana_datasources_exposed", r"\"type\"", "body")]),
            ("/api/datasources/proxy/1/api/v1/query", "GET", [("grafana_proxy_ssrf_hint", None, "status:200")]),
            ("/public/plugins/", "GET", [("grafana_plugins_dir", None, "status:200")]),
            ("/api/snapshots", "GET", [("grafana_snapshots_api", None, "status:200")]),
            ("/login", "GET", [("grafana_login", r"Grafana", "body")]),
            ("/api/health", "GET", [("grafana_health", r"commit|version", "body")]),
            ("/public/plugins/alertlist/../../../../../../../../etc/passwd", "GET", [
                ("grafana_path_traversal_cve", r"root:x:", "body"),
            ]),
        ],
        "notes": "Grafana CVE-2021-43798 path traversal. Default creds admin:admin histórico. Datasource proxy → SSRF.",
    },

    "Kibana": {
        "paths": [
            ("/app/kibana", "GET", [("kibana_app", r"kibana", "body")]),
            ("/api/status", "GET", [("kibana_status_api", r"\"version\"", "body")]),
            ("/api/saved_objects/_find", "GET", [("kibana_saved_objects", None, "status:200")]),
            ("/api/console/api_server", "GET", [("kibana_console", r"endpoints", "body")]),
        ],
        "notes": "Kibana: CVE-2019-7609 LFI→RCE. Console expone Elasticsearch backend.",
    },

    "Prometheus": {
        "paths": [
            ("/metrics", "GET", [("prometheus_metrics", r"HELP|TYPE", "body")]),
            ("/graph", "GET", [("prometheus_graph", r"Prometheus", "body")]),
            ("/api/v1/status/config", "GET", [("prometheus_config", r"scrape_configs", "body")]),
            ("/api/v1/targets", "GET", [("prometheus_targets", r"activeTargets", "body")]),
            ("/api/v1/query", "GET", [("prometheus_query_api", None, "status:400")]),
        ],
        "notes": "Prometheus: /api/v1/status/config filtra scrape targets internos (subdominios).",
    },

    "Alertmanager": {
        "paths": [
            ("/#/alerts", "GET", [("alertmanager_ui", r"Alertmanager", "body")]),
            ("/api/v2/status", "GET", [("alertmanager_status", r"versionInfo", "body")]),
        ],
        "notes": "Alertmanager: UI + API sin auth típico.",
    },

    "Argo CD": {
        "paths": [
            ("/api/version", "GET", [("argocd_version", r"\"Version\"", "body")]),
            ("/api/v1/applications", "GET", [("argocd_apps_api", None, "status:401")]),
            ("/auth/login", "GET", [("argocd_login", r"Argo CD", "body")]),
        ],
        "notes": "Argo CD: varios bypass auth CVEs 2022-2024. API versión sin auth.",
    },

    "Argo Workflows": {
        "paths": [
            ("/api/v1/info", "GET", [("argo_workflows_info", r"managedNamespace|links", "body")]),
            ("/api/v1/workflows/", "GET", [("argo_workflows_list", None, "status:200")]),
        ],
        "notes": "Argo Workflows: CVE-2023-28551 RBAC bypass.",
    },

    "Harbor": {
        "paths": [
            ("/api/v2.0/systeminfo", "GET", [("harbor_systeminfo", r"harbor_version", "body")]),
            ("/api/v2.0/projects", "GET", [("harbor_projects", None, "status:401")]),
            ("/c/login", "GET", [("harbor_login", r"Harbor", "body")]),
        ],
        "notes": "Harbor: CVE-2022-31671 y otros. Default admin/Harbor12345.",
    },

    "Nexus Repository": {
        "paths": [
            ("/nexus/", "GET", [("nexus_root", r"Nexus Repository Manager", "body")]),
            ("/service/rest/v1/status", "GET", [("nexus_status", None, "status:200")]),
            ("/service/rest/v1/repositories", "GET", [("nexus_repos", r"name|format", "body")]),
        ],
        "notes": "Nexus: CVE-2024-4956 path traversal. CVE-2020-10204 EL injection.",
    },

    "Artifactory": {
        "paths": [
            ("/artifactory/api/system/ping", "GET", [("artifactory_ping", r"OK", "body")]),
            ("/artifactory/api/system/version", "GET", [("artifactory_version", r"version", "body")]),
            ("/artifactory/api/repositories", "GET", [("artifactory_repos", None, "status:200")]),
            ("/artifactory/webapp/", "GET", [("artifactory_ui", r"Artifactory", "body")]),
        ],
        "notes": "Artifactory: CVE-2022-0399 (ABC exploit). API sin auth en repos públicos filtra estructura.",
    },

    "SonarQube": {
        "paths": [
            ("/api/server/version", "GET", [("sonarqube_version", r"\d+\.\d+", "body")]),
            ("/api/users/search", "GET", [("sonarqube_users", None, "status:401")]),
            ("/api/authentication/validate", "GET", [("sonarqube_auth_validate", r"valid", "body")]),
            ("/api/settings/values", "GET", [("sonarqube_settings", None, "status:200")]),
        ],
        "notes": "SonarQube: default admin/admin. Public by default → código fuente leak.",
    },

    "Jira": {
        "paths": [
            ("/secure/Dashboard.jspa", "GET", [("jira_dashboard", r"Atlassian JIRA|Jira", "body")]),
            ("/rest/api/2/user/picker", "GET", [("jira_user_picker", None, "status:401")]),
            ("/rest/api/2/dashboard", "GET", [("jira_dashboard_api", None, "status:200")]),
            ("/rest/api/latest/serverInfo", "GET", [("jira_serverinfo", r"version|buildNumber", "body")]),
            ("/login.jsp", "GET", [("jira_login", r"Atlassian", "body")]),
            ("/rest/api/2/projectCategory", "GET", [("jira_project_categories", None, "status:200")]),
        ],
        "notes": "Jira: CVE-2019-8449 user enum, CVE-2021-26086 LFI, CVE-2022-0540 auth bypass.",
    },

    "Confluence": {
        "paths": [
            ("/confluence/", "GET", [("confluence_root", r"Confluence|Atlassian", "body")]),
            ("/rest/api/content", "GET", [("confluence_content_api", None, "status:200")]),
            ("/spaces/", "GET", [("confluence_spaces", r"Confluence", "body")]),
            ("/login.action", "GET", [("confluence_login", r"Confluence", "body")]),
            ("/setup/setupadministrator.action", "GET", [("confluence_setup", r"Confluence Setup", "body")]),
        ],
        "notes": "Confluence: CVE-2022-26134 OGNL RCE crítico. CVE-2023-22515 broken access control.",
    },

    "Bamboo": {
        "paths": [
            ("/bamboo/", "GET", [("bamboo_root", r"Bamboo|Atlassian", "body")]),
            ("/userlogin!default.action", "GET", [("bamboo_login", r"Bamboo", "body")]),
        ],
        "notes": "Bamboo: CVE-2022-26138 hardcoded password.",
    },

    "Crowd": {
        "paths": [
            ("/crowd/console/", "GET", [("crowd_console", r"Crowd|Atlassian", "body")]),
        ],
        "notes": "Crowd: CVE-2019-11580 pdkinstall plugin RCE.",
    },

    "TeamCity": {
        "paths": [
            ("/login.html", "GET", [("teamcity_login", r"TeamCity", "body")]),
            ("/app/rest/server", "GET", [("teamcity_server_api", None, "status:401")]),
            ("/admin/diagnostic.html", "GET", [("teamcity_diagnostic", r"TeamCity", "body")]),
        ],
        "notes": "TeamCity: CVE-2023-42793 auth bypass RCE crítico. CVE-2024-27198 también.",
    },

    "GoCD": {
        "paths": [
            ("/go/", "GET", [("gocd_root", r"GoCD|Go Server", "body")]),
            ("/go/api/config/pipeline_groups", "GET", [("gocd_pipeline_groups", None, "status:200")]),
        ],
        "notes": "GoCD: CVE-2021-43287 auth bypass.",
    },

    "Drone CI": {
        "paths": [
            ("/version", "GET", [("drone_version", r"\"version\"", "body")]),
            ("/api/user", "GET", [("drone_user_api", None, "status:401")]),
        ],
        "notes": "Drone CI: API sin auth a veces en repos públicos.",
    },

    "Concourse CI": {
        "paths": [
            ("/api/v1/info", "GET", [("concourse_info", r"\"version\"", "body")]),
            ("/api/v1/teams", "GET", [("concourse_teams", None, "status:200")]),
        ],
        "notes": "Concourse: /api/v1/info sin auth = versión exacta.",
    },

    "Rundeck": {
        "paths": [
            ("/user/login", "GET", [("rundeck_login", r"Rundeck", "body")]),
            ("/api/40/system/info", "GET", [("rundeck_sysinfo", None, "status:200")]),
        ],
        "notes": "Rundeck: CVE-2023-41265 HTTP request smuggling → auth bypass.",
    },

    # =========================================================================
    # MONITORING & LOGGING
    # =========================================================================

    "Nagios": {
        "paths": [
            ("/nagios/", "GET", [("nagios_root", r"Nagios", "body")]),
            ("/cgi-bin/nagios/status.cgi", "GET", [("nagios_status", None, "status:401")]),
            ("/nagiosxi/", "GET", [("nagiosxi_root", r"Nagios XI", "body")]),
        ],
        "notes": "Nagios XI: CVE-2023-40931 SQLi. Multiple RCEs históricos.",
    },

    "Zabbix": {
        "paths": [
            ("/zabbix/", "GET", [("zabbix_root", r"Zabbix", "body")]),
            ("/zabbix/setup.php", "GET", [("zabbix_setup", r"Welcome to Zabbix", "body")]),
            ("/zabbix/api_jsonrpc.php", "POST", [("zabbix_api", None, "status:200")]),
        ],
        "notes": "Zabbix: CVE-2022-24917 SSRF. Default Admin/zabbix.",
    },

    "Splunk": {
        "paths": [
            ("/en-US/account/login", "GET", [("splunk_login", r"Splunk", "body")]),
            ("/services/server/info", "GET", [("splunk_server_info", None, "status:401")]),
            ("/en-US/splunkd/__raw/services/server/info", "GET", [("splunk_raw_info", None, "status:401")]),
        ],
        "notes": "Splunk: CVE-2023-46214 RCE, CVE-2024-36991 path traversal. Default admin/changeme.",
    },

    "Graylog": {
        "paths": [
            ("/api/system", "GET", [("graylog_system", None, "status:401")]),
            ("/api/cluster", "GET", [("graylog_cluster", None, "status:401")]),
        ],
        "notes": "Graylog: CVE-2023-52035 search filter injection.",
    },

    "Elasticsearch": {
        "paths": [
            ("/", "GET", [("elasticsearch_root", r"You Know, for Search|cluster_name", "body")]),
            ("/_cluster/health", "GET", [("es_cluster_health", r"cluster_name|status", "body")]),
            ("/_cat/indices", "GET", [("es_indices_listable", None, "status:200")]),
            ("/_nodes", "GET", [("es_nodes", r"nodes|version", "body")]),
            ("/_search", "GET", [("es_search_open", r"hits", "body")]),
            ("/_snapshot", "GET", [("es_snapshots", None, "status:200")]),
        ],
        "notes": "Elasticsearch: sin auth = full data read. Shodan lo encuentra pero siempre vale re-check en bug bounty.",
    },

    "Kubernetes Dashboard": {
        "paths": [
            ("/#!/login", "GET", [("k8s_dashboard_login", r"Kubernetes Dashboard", "body")]),
            ("/api/v1/login/status", "GET", [("k8s_dashboard_status", r"tokenPresent|headerPresent", "body")]),
        ],
        "notes": "K8s Dashboard: skip login histórico. Token-less access = full cluster.",
    },

    "Kubernetes API Server": {
        "paths": [
            ("/version", "GET", [("k8s_api_version", r"gitVersion", "body")]),
            ("/api/v1/namespaces", "GET", [("k8s_namespaces", None, "status:401")]),
            ("/apis", "GET", [("k8s_apis", r"groups|preferredVersion", "body")]),
            ("/healthz", "GET", [("k8s_healthz", r"ok", "body")]),
            ("/livez", "GET", [("k8s_livez", None, "status:200")]),
            ("/readyz", "GET", [("k8s_readyz", None, "status:200")]),
        ],
        "notes": "K8s API: anon access sometimes. /version leaks cluster version.",
    },

    "Consul": {
        "paths": [
            ("/v1/status/leader", "GET", [("consul_leader", r"\d+\.\d+\.\d+\.\d+", "body")]),
            ("/v1/catalog/services", "GET", [("consul_services", None, "status:200")]),
            ("/v1/kv/?recurse", "GET", [("consul_kv", None, "status:200")]),
            ("/ui/", "GET", [("consul_ui", r"Consul", "body")]),
        ],
        "notes": "Consul: KV sin ACL = secrets. Service catalog = topología interna.",
    },

    "Vault": {
        "paths": [
            ("/v1/sys/health", "GET", [("vault_health", r"initialized|sealed", "body")]),
            ("/v1/sys/init", "GET", [("vault_init", r"initialized", "body")]),
            ("/v1/sys/seal-status", "GET", [("vault_seal_status", r"sealed|version", "body")]),
            ("/ui/", "GET", [("vault_ui", r"Vault", "body")]),
        ],
        "notes": "Vault: sealed=false + unauth config = 🚨. CVE-2020-16250 JWT auth bypass.",
    },

    "etcd": {
        "paths": [
            ("/version", "GET", [("etcd_version", r"etcdserver|etcdcluster", "body")]),
            ("/v2/keys/?recursive=true", "GET", [("etcd_keys_v2", None, "status:200")]),
            ("/v3/keys", "GET", [("etcd_keys_v3", None, "status:200")]),
        ],
        "notes": "etcd: full K8s secrets si sin auth.",
    },

    # =========================================================================
    # NETWORK APPLIANCES / VPN / ADMIN
    # =========================================================================

    "Fortinet FortiGate": {
        "paths": [
            ("/login", "GET", [("fortigate_login", r"FortiGate|Fortinet", "body")]),
            ("/remote/login", "GET", [("fortinet_sslvpn", r"SSL-VPN|Fortinet", "body")]),
            ("/remote/fgt_lang", "GET", [("fortinet_fgt_lang", None, "status:200")]),
        ],
        "notes": "FortiGate: CVE-2022-40684 auth bypass, CVE-2023-27997 SSL-VPN heap overflow. Siempre chequear versión.",
    },

    "Pulse Secure / Ivanti Connect Secure": {
        "paths": [
            ("/dana-na/auth/url_default/welcome.cgi", "GET", [
                ("pulse_secure_login", r"Pulse Secure|Ivanti", "body"),
            ]),
            ("/dana-cached/sc/SecureConnect.exe", "GET", [("pulse_secure_connect", None, "status:200")]),
        ],
        "notes": "Ivanti/Pulse: CVE-2023-46805 + CVE-2024-21887 zero-click RCE 2024.",
    },

    "Citrix NetScaler / ADC": {
        "paths": [
            ("/vpn/index.html", "GET", [("netscaler_vpn", r"NetScaler|Citrix", "body")]),
            ("/logon/LogonPoint/tmindex.html", "GET", [("netscaler_logon", r"Citrix", "body")]),
            ("/nsconfig/", "GET", [("netscaler_nsconfig", None, "status:403")]),
        ],
        "notes": "NetScaler: CVE-2023-4966 Citrix Bleed, CVE-2019-19781 RCE clásico.",
    },

    "Palo Alto GlobalProtect": {
        "paths": [
            ("/global-protect/login.esp", "GET", [("globalprotect_login", r"GlobalProtect|Palo Alto", "body")]),
            ("/ssl-vpn/login.esp", "GET", [("paloalto_sslvpn", r"login", "body")]),
        ],
        "notes": "GlobalProtect: CVE-2024-3400 command injection zero-day.",
    },

    "F5 BIG-IP": {
        "paths": [
            ("/tmui/login.jsp", "GET", [("f5_tmui_login", r"BIG-IP", "body")]),
            ("/mgmt/tm/util/bash", "POST", [("f5_icontrol_bash", None, "status:401")]),
            ("/mgmt/shared/authn/login", "POST", [("f5_icontrol_login", None, "status:401")]),
        ],
        "notes": "F5: CVE-2022-1388 auth bypass iControl → RCE. CVE-2023-46747.",
    },

    "Cisco ASA / AnyConnect": {
        "paths": [
            ("/+CSCOE+/logon.html", "GET", [("cisco_asa_logon", r"WebVPN|AnyConnect", "body")]),
            ("/CSCOSSLC/config-auth", "GET", [("cisco_config_auth", None, "status:200")]),
        ],
        "notes": "Cisco ASA: CVE-2020-3452 path traversal, CVE-2018-0101 heap overflow.",
    },

    "SonicWall": {
        "paths": [
            ("/sonicui/7/m/login/", "GET", [("sonicwall_login", r"SonicWall", "body")]),
            ("/cgi-bin/welcome", "GET", [("sonicwall_welcome", r"SonicWall", "body")]),
        ],
        "notes": "SonicWall: CVE-2021-20016 SQLi, varios RCE 2022-2024.",
    },

    "Pfsense": {
        "paths": [
            ("/index.php", "GET", [("pfsense_index", r"pfSense", "body")]),
            ("/diag_backup.php", "GET", [("pfsense_backup", r"pfSense", "body")]),
        ],
        "notes": "pfSense: CVE-2023-27253 RCE auth. Default admin/pfsense.",
    },

    "OpenVPN AS": {
        "paths": [
            ("/admin/", "GET", [("openvpn_as_admin", r"OpenVPN", "body")]),
        ],
        "notes": "OpenVPN Access Server: default openvpn/openvpn.",
    },

    "Ubiquiti UniFi": {
        "paths": [
            ("/manage/", "GET", [("unifi_manage", r"UniFi", "body")]),
            ("/api/system", "GET", [("unifi_system_api", None, "status:401")]),
        ],
        "notes": "UniFi: CVE-2024-42025 heap overflow, CVE-2021-22906 defaults.",
    },

    "Synology DSM": {
        "paths": [
            ("/webman/index.cgi", "GET", [("synology_webman", r"Synology", "body")]),
            ("/webapi/entry.cgi", "GET", [("synology_webapi", None, "status:200")]),
        ],
        "notes": "Synology: CVE-2023-2729 photo station RCE.",
    },

    "QNAP QTS": {
        "paths": [
            ("/cgi-bin/authLogin.cgi", "GET", [("qnap_authlogin", r"QDocRoot|QNAP", "body")]),
        ],
        "notes": "QNAP: DeadBolt ransomware history. CVE-2022-27596 SQLi.",
    },

    "Proxmox VE": {
        "paths": [
            ("/", "GET", [("proxmox_root", r"Proxmox", "body")]),
            ("/api2/json/version", "GET", [("proxmox_version_api", None, "status:401")]),
        ],
        "notes": "Proxmox: CVE-2022-35508 stored XSS. Default root/PAM.",
    },

    "VMware vCenter": {
        "paths": [
            ("/ui/", "GET", [("vcenter_ui", r"vSphere|vCenter", "body")]),
            ("/ui/login", "GET", [("vcenter_login", r"vSphere", "body")]),
            ("/vsphere-client/", "GET", [("vsphere_client", r"vSphere", "body")]),
            ("/websso/SAML2/SSO/vsphere.local", "GET", [("vcenter_sso", r"SAML", "body")]),
        ],
        "notes": "vCenter: CVE-2021-21972 log4shell variants, CVE-2021-22005 file upload RCE.",
    },

    "iDRAC (Dell)": {
        "paths": [
            ("/login.html", "GET", [("idrac_login", r"iDRAC|Integrated Dell", "body")]),
            ("/sysmgmt/2015/bmc/info", "GET", [("idrac_bmc_info", None, "status:401")]),
        ],
        "notes": "iDRAC: CVE-2018-1207 path traversal. Default root/calvin.",
    },

    "HP iLO": {
        "paths": [
            ("/login.html", "GET", [("ilo_login", r"iLO|Integrated Lights-Out", "body")]),
            ("/redfish/v1/", "GET", [("ilo_redfish", r"Redfish", "body")]),
        ],
        "notes": "HP iLO: CVE-2017-12542 auth bypass (28 chars A's).",
    },

    # =========================================================================
    # FORUMS / COMMUNITIES
    # =========================================================================

    "phpBB": {
        "paths": [
            ("/ucp.php?mode=register", "GET", [("phpbb_register", r"phpBB|Registration", "body")]),
            ("/memberlist.php", "GET", [("phpbb_memberlist", r"phpBB", "body")]),
            ("/install/", "GET", [("phpbb_install", r"phpBB|Installation", "body")]),
        ],
        "notes": "phpBB: memberlist enum público default.",
    },

    "vBulletin": {
        "paths": [
            ("/install/install.php", "GET", [("vbulletin_install", r"vBulletin", "body")]),
            ("/admincp/", "GET", [("vbulletin_admincp", r"vBulletin", "body")]),
            ("/memberlist.php", "GET", [("vbulletin_memberlist", r"vBulletin", "body")]),
        ],
        "notes": "vBulletin: CVE-2019-16759 RCE famoso. Múltiples SQLi.",
    },

    "XenForo": {
        "paths": [
            ("/install/", "GET", [("xenforo_install", r"XenForo", "body")]),
            ("/index.php?members/", "GET", [("xenforo_members", r"XenForo", "body")]),
        ],
        "notes": "XenForo: CVE-2020-8637 auth bypass.",
    },

    "MyBB": {
        "paths": [
            ("/install/", "GET", [("mybb_install", r"MyBB", "body")]),
            ("/admin/", "GET", [("mybb_admin", r"MyBB", "body")]),
        ],
        "notes": "MyBB: varios RCE históricos vía template injection.",
    },

    "Discourse": {
        "paths": [
            ("/about.json", "GET", [("discourse_about", r"top_users|admins|moderators", "body")]),
            ("/site.json", "GET", [("discourse_site", r"discourse", "body")]),
            ("/u.json", "GET", [("discourse_users_json", None, "status:200")]),
            ("/directory_items.json", "GET", [("discourse_directory", r"directory_items", "body")]),
        ],
        "notes": "Discourse: about.json siempre filtra admins/mods por diseño. /u/<user>.json user detail.",
    },

    "NodeBB": {
        "paths": [
            ("/api/config", "GET", [("nodebb_config", r"\"version\"", "body")]),
            ("/users", "GET", [("nodebb_users", r"NodeBB", "body")]),
            ("/admin", "GET", [("nodebb_admin", r"NodeBB", "body")]),
        ],
        "notes": "NodeBB: /api/config leak version y settings.",
    },

    "Flarum": {
        "paths": [
            ("/api", "GET", [("flarum_api", r"flarum|jsonapi", "body")]),
            ("/admin", "GET", [("flarum_admin", r"Flarum", "body")]),
        ],
        "notes": "Flarum: API JSON:API estándar.",
    },

    # =========================================================================
    # DATABASES WEB UI / ADMIN TOOLS
    # =========================================================================

    "phpMyAdmin": {
        "paths": [
            ("/phpmyadmin/", "GET", [("phpmyadmin_root", r"phpMyAdmin", "body")]),
            ("/pma/", "GET", [("phpmyadmin_pma", r"phpMyAdmin", "body")]),
            ("/PMA/", "GET", [("phpmyadmin_pma_upper", r"phpMyAdmin", "body")]),
            ("/phpmyadmin/setup/", "GET", [("phpmyadmin_setup", r"Setup|phpMyAdmin", "body")]),
            ("/phpmyadmin/doc/html/index.html", "GET", [("phpmyadmin_docs", r"phpMyAdmin", "body")]),
        ],
        "notes": "phpMyAdmin: default root/empty. CVE-2022-0813 XSS. Setup script → config overwrite.",
    },

    "Adminer": {
        "paths": [
            ("/adminer.php", "GET", [("adminer_root", r"Adminer", "body")]),
            ("/adminer/", "GET", [("adminer_dir", r"Adminer", "body")]),
            ("/db/adminer.php", "GET", [("adminer_db_dir", r"Adminer", "body")]),
        ],
        "notes": "Adminer: SSRF via connect to arbitrary DB. Login clásico.",
    },

    "CouchDB": {
        "paths": [
            ("/_utils/", "GET", [("couchdb_utils", r"CouchDB|Fauxton", "body")]),
            ("/_all_dbs", "GET", [("couchdb_all_dbs", r"\[", "body")]),
            ("/_membership", "GET", [("couchdb_membership", None, "status:200")]),
        ],
        "notes": "CouchDB: CVE-2017-12635 admin escalation. Default admin party mode.",
    },

    "MongoDB HTTP": {
        "paths": [
            ("/_health", "GET", [("mongo_health", r"ok", "body")]),
            ("/listDatabases", "GET", [("mongo_listdbs", None, "status:200")]),
        ],
        "notes": "MongoDB: REST interface deprecated pero existe en viejas.",
    },

    "Redis Commander": {
        "paths": [
            ("/sign-in", "GET", [("redis_commander", r"Redis Commander", "body")]),
        ],
        "notes": "Redis Commander: UI exposed → Redis completo.",
    },

    "RethinkDB": {
        "paths": [
            ("/#tables", "GET", [("rethinkdb_tables", r"RethinkDB", "body")]),
        ],
        "notes": "RethinkDB: UI default sin auth.",
    },

    "Kafka UI": {
        "paths": [
            ("/ui/clusters", "GET", [("kafka_ui_clusters", r"Kafka", "body")]),
        ],
        "notes": "Kafka UI: suele exponer topics y consumer groups.",
    },

    "RabbitMQ Management": {
        "paths": [
            ("/api/overview", "GET", [("rabbitmq_overview", None, "status:401")]),
            ("/api/whoami", "GET", [("rabbitmq_whoami", None, "status:401")]),
        ],
        "notes": "RabbitMQ: default guest/guest sobre localhost. CVE-2023-46118 heap overflow.",
    },

    # =========================================================================
    # SSO / IDENTITY PROVIDERS
    # =========================================================================

    "Keycloak": {
        "paths": [
            ("/auth/", "GET", [("keycloak_auth_root", r"Keycloak", "body")]),
            ("/auth/admin/", "GET", [("keycloak_admin_console", r"Keycloak", "body")]),
            ("/realms/master/.well-known/openid-configuration", "GET", [
                ("keycloak_master_realm", r"issuer|jwks_uri", "body"),
            ]),
            ("/realms/master/protocol/openid-connect/registrations", "GET", [
                ("keycloak_open_registration", None, "status:200"),
            ]),
        ],
        "notes": "Keycloak: CVE-2023-6134 SAML replay. Master realm expuesto = full IdP.",
    },

    "Okta": {
        "paths": [
            ("/.well-known/okta-organization", "GET", [("okta_org_info", r"okta", "body")]),
            ("/app/UserHome", "GET", [("okta_user_home", r"Okta", "body")]),
        ],
        "notes": "Okta tenant hosted; raro encontrar config misconfig pero vale verificar subdominios.",
    },

    "Auth0": {
        "paths": [
            ("/.well-known/jwks.json", "GET", [("auth0_jwks", r"keys", "body")]),
            ("/u/login", "GET", [("auth0_login", r"auth0|Log in", "body")]),
        ],
        "notes": "Auth0: tenant hosted. Buscar redirect_uri misconfig.",
    },

    "ADFS": {
        "paths": [
            ("/adfs/ls/", "GET", [("adfs_ls", r"ADFS|Active Directory", "body")]),
            ("/FederationMetadata/2007-06/FederationMetadata.xml", "GET", [
                ("adfs_federation_metadata", r"EntityDescriptor", "body"),
            ]),
        ],
        "notes": "ADFS: FederationMetadata.xml expone todo el IdP SAML config.",
    },

    "Shibboleth": {
        "paths": [
            ("/Shibboleth.sso/Metadata", "GET", [("shibboleth_metadata", r"EntityDescriptor|md:", "body")]),
            ("/idp/shibboleth", "GET", [("shibboleth_idp", r"Shibboleth", "body")]),
        ],
        "notes": "Shibboleth: metadata expone cert + bindings.",
    },

    "CAS": {
        "paths": [
            ("/cas/login", "GET", [("cas_login", r"CAS|Central Authentication Service", "body")]),
            ("/cas/actuator/env", "GET", [("cas_actuator_env", r"propertySources", "body")]),
        ],
        "notes": "CAS: basado en Spring → misma surface de actuators a veces.",
    },

    "OpenAM / ForgeRock": {
        "paths": [
            ("/openam/", "GET", [("openam_root", r"OpenAM|ForgeRock", "body")]),
            ("/openam/UI/Login", "GET", [("openam_login", r"OpenAM", "body")]),
        ],
        "notes": "OpenAM: CVE-2021-35464 ViewBean RCE crítico.",
    },

    "Gluu Server": {
        "paths": [
            ("/identity/", "GET", [("gluu_identity", r"Gluu", "body")]),
        ],
        "notes": "Gluu: OIDC provider open source. Verificar admin.",
    },

    # =========================================================================
    # OBSERVABILITY / MONITORING DASHBOARDS
    # =========================================================================

    "Sentry": {
        "paths": [
            ("/auth/login/", "GET", [("sentry_login", r"Sentry", "body")]),
            ("/api/0/", "GET", [("sentry_api_root", None, "status:401")]),
        ],
        "notes": "Sentry: DSN leak en JS = error ingestion abuse. Org enum via /<slug>/.",
    },

    "New Relic": {
        "paths": [
            ("/api/v2/", "GET", [("newrelic_api", None, "status:401")]),
        ],
        "notes": "New Relic: hosted — mirá si hay license key en JS.",
    },

    "Datadog": {
        "paths": [
            ("/api/v1/validate", "GET", [("datadog_validate", None, "status:403")]),
        ],
        "notes": "Datadog: hosted — los API keys en JS son findings comunes.",
    },

    "Zipkin": {
        "paths": [
            ("/zipkin/", "GET", [("zipkin_ui", r"Zipkin", "body")]),
            ("/api/v2/services", "GET", [("zipkin_services", None, "status:200")]),
        ],
        "notes": "Zipkin: service topology interna sin auth.",
    },

    "Jaeger": {
        "paths": [
            ("/search", "GET", [("jaeger_search", r"Jaeger", "body")]),
            ("/api/services", "GET", [("jaeger_services", r"data", "body")]),
        ],
        "notes": "Jaeger: traces completos sin auth por default.",
    },

    # =========================================================================
    # SAAS / EMBEDDED PLATFORMS
    # =========================================================================

    "Ghost CMS": {
        "paths": [
            ("/ghost/", "GET", [("ghost_admin", r"Ghost|Sign in", "body")]),
            ("/ghost/api/admin/", "GET", [("ghost_admin_api", None, "status:401")]),
            ("/ghost/api/content/", "GET", [("ghost_content_api", None, "status:400")]),
        ],
        "notes": "Ghost CMS: CVE-2023-40028 symlink path traversal.",
    },

    "Webmin": {
        "paths": [
            ("/session_login.cgi", "GET", [("webmin_login", r"Webmin", "body")]),
            ("/unauthenticated/", "GET", [("webmin_unauth", None, "status:200")]),
        ],
        "notes": "Webmin: CVE-2019-15107 RCE via password change. Default root login.",
    },

    "cPanel / WHM": {
        "paths": [
            ("/cpanel", "GET", [("cpanel_login", r"cPanel", "body")]),
            ("/whm", "GET", [("whm_login", r"WHM|WebHost Manager", "body")]),
            ("/:2083/", "GET", [("cpanel_port", None, "status:0")]),  # suele estar en port raro
        ],
        "notes": "cPanel: muchos XSS/CSRF históricos. Ver hosted subdomains.",
    },

    "Plesk": {
        "paths": [
            ("/login_up.php3", "GET", [("plesk_login", r"Plesk", "body")]),
            ("/smb/login", "GET", [("plesk_smb_login", r"Plesk", "body")]),
        ],
        "notes": "Plesk: CVE-2018-19571 SSRF. Default admin/setup.",
    },

    "Mattermost": {
        "paths": [
            ("/api/v4/system/ping", "GET", [("mattermost_ping", None, "status:200")]),
            ("/api/v4/config/client", "GET", [("mattermost_client_config", r"SiteURL|Version", "body")]),
            ("/api/v4/users", "GET", [("mattermost_users", None, "status:401")]),
        ],
        "notes": "Mattermost: /config/client leak SiteURL + features. CVE-2023-2028 path traversal.",
    },

    "Rocket.Chat": {
        "paths": [
            ("/api/info", "GET", [("rocketchat_info", r"version", "body")]),
            ("/api/v1/users.list", "GET", [("rocketchat_users", None, "status:401")]),
        ],
        "notes": "Rocket.Chat: CVE-2023-28359 IDOR. /api/info leak version.",
    },

    "Zimbra": {
        "paths": [
            ("/zimbra/", "GET", [("zimbra_root", r"Zimbra", "body")]),
            ("/service/soap", "POST", [("zimbra_soap", None, "status:500")]),
            ("/zimbra/public/launchNewWindow.jsp", "GET", [("zimbra_launch", r"Zimbra", "body")]),
        ],
        "notes": "Zimbra: CVE-2022-41352 tar RCE, CVE-2023-37580 XSS to takeover.",
    },

    "Roundcube": {
        "paths": [
            ("/?_task=login", "GET", [("roundcube_login", r"Roundcube|webmail", "body")]),
            ("/CHANGELOG", "GET", [("roundcube_changelog", r"Roundcube", "body")]),
        ],
        "notes": "Roundcube: CVE-2023-43770 XSS stored. CVE-2024-37383 habitual.",
    },

    "Nextcloud / ownCloud": {
        "paths": [
            ("/status.php", "GET", [("nextcloud_status", r"installed|version|productname", "body")]),
            ("/ocs/v1.php/cloud/users", "GET", [("nextcloud_users_ocs", None, "status:401")]),
            ("/index.php/login", "GET", [("nextcloud_login", r"Nextcloud|ownCloud", "body")]),
        ],
        "notes": "Nextcloud status.php = version exacto. CVE-2023-49791 bypass 2FA.",
    },

    "Bitwarden / Vaultwarden": {
        "paths": [
            ("/alive", "GET", [("bitwarden_alive", None, "status:200")]),
            ("/api/config", "GET", [("bitwarden_config", r"version|gitHash", "body")]),
        ],
        "notes": "Vaultwarden: CVE-2023-46918 admin panel unauthenticated.",
    },

    "Gitbook": {
        "paths": [
            ("/.gitbook/", "GET", [("gitbook_dir", None, "status:200")]),
        ],
        "notes": "GitBook: revisar si el space es privado o público.",
    },

    "MkDocs": {
        "paths": [
            ("/sitemap.xml", "GET", [("mkdocs_sitemap", r"mkdocs", "body")]),
            ("/search/search_index.json", "GET", [("mkdocs_search_index", None, "status:200")]),
        ],
        "notes": "MkDocs: search_index.json tiene TODO el contenido.",
    },

    "Docusaurus": {
        "paths": [
            ("/docs", "GET", [("docusaurus_docs", r"docusaurus", "body")]),
            ("/__docusaurus/debug", "GET", [("docusaurus_debug", r"Debug", "body")]),
        ],
        "notes": "Docusaurus: debug page si dev mode expuesto.",
    },

    "Zendesk Help Center": {
        "paths": [
            ("/hc/api/v2/help_center/articles", "GET", [("zendesk_articles_api", None, "status:200")]),
        ],
        "notes": "Zendesk: HC API pública — útil para enum de staff (authors).",
    },

    "ServiceNow": {
        "paths": [
            ("/nav_to.do?uri=%2Fx_ui%2Flogin.do", "GET", [("servicenow_login", r"ServiceNow", "body")]),
            ("/stats.do", "GET", [("servicenow_stats", r"Servlet|Stats", "body")]),
            ("/xmlhttp.do", "POST", [("servicenow_xmlhttp", None, "status:200")]),
        ],
        "notes": "ServiceNow: CVE-2024-4879 Jelly template injection RCE. /stats.do leak version.",
    },

    "Salesforce Communities": {
        "paths": [
            ("/services/data/", "GET", [("salesforce_services_data", None, "status:401")]),
            ("/aura", "GET", [("salesforce_aura", None, "status:404")]),
            ("/s/sfsites/aura", "POST", [("salesforce_aura_endpoint", None, "status:200")]),
        ],
        "notes": "Salesforce Communities: Aura misconfig → ghost user IDOR (clásico 2022-2024).",
    },

    "SAP NetWeaver": {
        "paths": [
            ("/sap/bc/ping", "GET", [("sap_bc_ping", r"Server reached|SAP", "body")]),
            ("/sap/public/info", "GET", [("sap_public_info", r"SAP|SAPSystem", "body")]),
            ("/irj/portal", "GET", [("sap_irj_portal", r"SAP|Portal", "body")]),
        ],
        "notes": "SAP NetWeaver: CVE-2020-6287 RECON (auth bypass crítico). /public/info = version.",
    },

    "PeopleSoft": {
        "paths": [
            ("/psp/ps/", "GET", [("peoplesoft_psp", r"PeopleSoft", "body")]),
            ("/psc/ps/", "GET", [("peoplesoft_psc", r"PeopleSoft", "body")]),
        ],
        "notes": "PeopleSoft: multiple CVEs. XXE histórico.",
    },

    "Oracle EBS": {
        "paths": [
            ("/OA_HTML/AppsLogin", "GET", [("oracle_ebs_login", r"Oracle E-Business|E-Business Suite", "body")]),
            ("/OA_HTML/AppsLocalLogin.jsp", "GET", [("oracle_ebs_local_login", r"Oracle", "body")]),
        ],
        "notes": "Oracle EBS: CVE-2022-21587 unauth RCE (chain).",
    },

    "IBM Domino / Lotus": {
        "paths": [
            ("/names.nsf", "GET", [("domino_names_nsf", r"Domino|Lotus", "body")]),
            ("/?OpenServer", "GET", [("domino_openserver", r"Domino", "body")]),
        ],
        "notes": "Domino: CVE-2019-4716 path traversal. Database dump via names.nsf.",
    },

    # =========================================================================
    # MISC HIGH-VALUE
    # =========================================================================

    "Apache Airflow": {
        "paths": [
            ("/home", "GET", [("airflow_home", r"Airflow", "body")]),
            ("/api/v1/config", "GET", [("airflow_config_api", None, "status:401")]),
            ("/api/v1/dags", "GET", [("airflow_dags_api", None, "status:401")]),
            ("/api/experimental/dags", "GET", [("airflow_experimental", None, "status:200")]),
        ],
        "notes": "Airflow: CVE-2020-17526 auth bypass. Experimental API = RCE via DAG trigger.",
    },

    "Apache Superset": {
        "paths": [
            ("/login/", "GET", [("superset_login", r"Superset", "body")]),
            ("/api/v1/database/", "GET", [("superset_databases_api", None, "status:401")]),
        ],
        "notes": "Superset: CVE-2023-27524 default SECRET_KEY → auth bypass.",
    },

    "Jupyter Notebook / Lab": {
        "paths": [
            ("/tree", "GET", [("jupyter_tree", r"Jupyter", "body")]),
            ("/lab", "GET", [("jupyter_lab", r"JupyterLab", "body")]),
            ("/api", "GET", [("jupyter_api", r"\"version\"", "body")]),
            ("/terminals", "GET", [("jupyter_terminals", None, "status:200")]),
        ],
        "notes": "Jupyter sin token → shell completa. /terminals = RCE directo.",
    },

    "MinIO": {
        "paths": [
            ("/minio/health/live", "GET", [("minio_health_live", None, "status:200")]),
            ("/minio/health/ready", "GET", [("minio_health_ready", None, "status:200")]),
            ("/minio/login", "GET", [("minio_login", r"MinIO", "body")]),
            ("/minio/admin/v3/info", "GET", [("minio_admin_info", None, "status:403")]),
        ],
        "notes": "MinIO: CVE-2023-28432 info disclosure. Default minioadmin/minioadmin.",
    },

    "Weaviate": {
        "paths": [
            ("/v1/meta", "GET", [("weaviate_meta", r"version", "body")]),
            ("/v1/schema", "GET", [("weaviate_schema", r"classes", "body")]),
        ],
        "notes": "Weaviate vector DB: sin auth default. Schema leak.",
    },

    "Qdrant": {
        "paths": [
            ("/collections", "GET", [("qdrant_collections", r"result", "body")]),
            ("/cluster", "GET", [("qdrant_cluster", r"peer_id|status", "body")]),
        ],
        "notes": "Qdrant: API sin auth default.",
    },

    "Ollama": {
        "paths": [
            ("/api/tags", "GET", [("ollama_tags", r"models", "body")]),
            ("/api/version", "GET", [("ollama_version", r"version", "body")]),
        ],
        "notes": "Ollama: expuesto sin auth = model abuse + sistema internals leak.",
    },

    "Home Assistant": {
        "paths": [
            ("/manifest.json", "GET", [("home_assistant_manifest", r"Home Assistant", "body")]),
            ("/api/", "GET", [("home_assistant_api", None, "status:401")]),
        ],
        "notes": "Home Assistant: expuesto por mistake en cloud = device control.",
    },

    "Octoprint": {
        "paths": [
            ("/api/version", "GET", [("octoprint_version", r"OctoPrint|server", "body")]),
        ],
        "notes": "OctoPrint: expuesto en internet = impresora 3D control.",
    },
}


HIGH_VALUE_SIGNALS = {
    "heap_dump_exposed", "env_secrets_visible", "jolokia_exposed",
    "ignition_rce_endpoint", "laravel_env_exposed",
    "jenkins_script_console", "grafana_datasources_exposed",
    "hasura_admin_api", "wp_xmlrpc", "rails_routes_exposed",
    "graphql_introspection_enabled", "drupal_jsonapi", "strapi_graphql",
    "logfile_exposed", "strapi_admin_init",
}

# Paths probados (HEAD u GET según path). Ordenados por "familia" para leer
# cómodo. Probes paralelos via ThreadPoolExecutor.
PROBE_PATHS_CORE = [
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/graphql",
    "/api",
    "/api/",
    "/api/v1",
    "/api/v2",
    "/api/docs",
    "/api-docs",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui/index.html",
    "/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
]

# Paths "extra" (más ruido, solo si --extra-probes). Cosas que suelen dar
# info pero pegar al target más fuerte.
PROBE_PATHS_EXTRA = [
    "/.env",
    "/.env.local",
    "/.git/HEAD",
    "/.git/config",
    "/.DS_Store",
    "/.svn/entries",
    "/server-status",
    "/server-info",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/info",
    "/actuator/mappings",
    "/actuator/prometheus",
    "/actuator/heapdump",
    "/metrics",
    "/health",
    "/healthz",
    "/readyz",
    "/livez",
    "/status",
    "/debug",
    "/debug/pprof/",
    "/phpinfo.php",
    "/info.php",
    "/config.json",
    "/config.yml",
    "/wp-json/wp/v2/users",
    "/wp-login.php",
    "/administrator/",
    "/user/login",
    "/login",
    "/signin",
    "/api/login",
    "/auth",
    "/__webpack_hmr",
    "/_next/static",
    "/_nuxt/",
    "/static/js/",
    "/.well-known/mta-sts.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
]

# Dominios de assets que no aportan señal para fingerprinting.
SKIP_ASSET_DOMAINS = {
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "www.googletagmanager.com",
    "www.google-analytics.com",
    "ssl.google-analytics.com",
    "stats.g.doubleclick.net",
}

# =============================================================================
# Reglas de detección: WAFs, CDNs, frameworks, libraries, sanitizers, etc.
# =============================================================================

# Separamos WAF de CDN: muchas veces sirven propósitos distintos y a un
# hunter le importa la diferencia (CDN implica cache poisoning potential,
# WAF implica bypass técnicas específicas).
WAF_PATTERNS: Dict[str, List[str]] = {
    "cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare",
                   "__cfduid", "cf_clearance", "cf-mitigated"],
    "akamai": ["akamai-grn", "x-akamai-transformed", "akamaighost",
               "akamai-origin-hop", "ak_bmsc", "akamaighost"],
    "sucuri": ["x-sucuri-id", "x-sucuri-cache", "sucuri/cloudproxy"],
    "imperva": ["x-iinfo", "incap_ses", "visid_incap_", "x-cdn: incapsula"],
    "f5_bigip": ["bigipserver", "f5-", "ts01", "lastmrh_session",
                 "the requested url was rejected"],
    "aws_waf": ["x-amzn-requestid", "x-amz-cf-id", "awselb",
                "x-amz-cf-pop", "x-amzn-trace-id"],
    "azure_front_door": ["x-azure-ref", "azurefd", "x-fd-"],
    "modsecurity": ["mod_security", "modsecurity", "not acceptable"],
    "barracuda": ["barra_counter_session", "barracuda_"],
    "fortiweb": ["fortiwaf", "fortiweb"],
    "citrix_netscaler": ["ns_af=", "citrix_ns_id", "netscaler"],
    "wallarm": ["nginx-wallarm"],
    "stackpath": ["x-sp-", "server: stackpath"],
    "reblaze": ["x-rbzid", "rbzid"],
    "perimeterx_human": ["_px2=", "_px3=", "pxhd="],
    "datadome": ["datadome", "x-dd-b"],
    "radware": ["x-sl-compstate"],
}

CDN_PATTERNS: Dict[str, List[str]] = {
    "cloudflare": ["cf-ray", "server: cloudflare"],
    "akamai": ["akamaighost", "akamai-grn"],
    "fastly": ["x-served-by", "fastly", "x-cache: hit from",
               "x-fastly-request-id"],
    "aws_cloudfront": ["x-amz-cf-id", "x-amz-cf-pop", "server: cloudfront"],
    "azure_cdn": ["x-azure-ref", "x-cache: tcp_hit"],
    "google_cloud_cdn": ["via: 1.1 google", "x-goog-"],
    "bunny": ["server: bunnycdn"],
    "keycdn": ["server: keycdn", "x-edge-location"],
    "varnish": ["via: 1.1 varnish", "x-varnish"],
    "stackpath": ["server: stackpath"],
    "section_io": ["x-section-"],
    "netlify": ["x-nf-request-id", "server: netlify"],
    "vercel": ["x-vercel-id", "x-vercel-cache", "server: vercel"],
}

# =============================================================================
# SISTEMA DE REGLAS TIER-BASED (v3.0)
# =============================================================================
#
# Cada regla es (pattern, tier) donde tier ∈ {"strict", "loose"}.
#
# - "strict": patrón muy específico del producto (header único, cookie única,
#   path único, clase JS única, DSN único). Un match strict sube confidence.
# - "loose": mención genérica que podría ser falso positivo (el nombre del
#   producto suelto en un comentario, una substring común). Un match loose
#   sólo confirma algo si hay al menos otro match (strict o loose) distinto.
#
# Umbrales de confianza:
#   - 2+ strict         → high
#   - 1 strict + 1 loose → medium
#   - 1 strict          → low
#   - 2+ loose          → low (informational)
#   - 1 loose           → no se reporta (se ignora para evitar ruido)
#
# Esto reemplaza el sistema viejo donde 1 match en cualquier fuente era
# suficiente para reportar. Con 300+ reglas eso daba muchísimo ruido.
# =============================================================================

# Tipo helper: cada regla es (pattern_regex, tier)
_Rule = Tuple[str, str]


# -----------------------------------------------------------------------------
# FRAMEWORKS: JS frameworks, backend frameworks, meta-frameworks
# -----------------------------------------------------------------------------
FRAMEWORK_RULES: Dict[str, List[_Rule]] = {
    # --- JS frameworks modernos ---
    "React": [
        (r"__REACT_DEVTOOLS_GLOBAL_HOOK__", "strict"),
        (r"data-reactroot", "strict"),
        (r"data-react-helmet", "strict"),
        (r"react\.production\.min\.js", "strict"),
        (r"reactdom", "loose"),
        (r"\breact\b", "loose"),
    ],
    "Preact": [
        (r"\bpreact/hooks\b", "strict"),
        (r"\bpreact/compat\b", "strict"),
        (r"\bpreact\b", "loose"),
    ],
    "Vue": [
        (r"__VUE_DEVTOOLS_GLOBAL_HOOK__", "strict"),
        (r"__vue_app__", "strict"),
        (r"\bv-if=", "strict"),
        (r"\bv-for=", "strict"),
        (r"data-v-[0-9a-f]{6,}", "strict"),
        (r"vue\.runtime", "strict"),
        (r"\bvue\.js\b", "loose"),
    ],
    "Angular": [
        (r"ng-version=", "strict"),
        (r"\bɵɵdefinecomponent\b", "strict"),
        (r"@angular/core", "strict"),
        (r"ng-app=", "strict"),
    ],
    "AngularJS": [
        (r"ng-controller=", "strict"),
        (r"ng-repeat=", "strict"),
        (r"ng-model=", "strict"),
        (r"angular\.module\(", "strict"),
    ],
    "Svelte": [
        (r"svelte-[a-z0-9]{6,}", "strict"),
        (r"__svelte_meta", "strict"),
        (r"\bsvelte\b", "loose"),
    ],
    "SvelteKit": [
        (r"__sveltekit", "strict"),
        (r"/_app/immutable/", "strict"),
        (r"kit\.start\(", "strict"),
    ],
    "SolidJS": [
        (r"solid-js", "strict"),
        (r"createsignal\(", "strict"),
    ],
    "SolidStart": [
        (r"@solidjs/start", "strict"),
    ],
    "Qwik": [
        (r"q:container", "strict"),
        (r"q:base", "strict"),
        (r"q:manifest", "strict"),
        (r"@builder\.io/qwik", "strict"),
    ],
    "Next.js": [
        (r"__NEXT_DATA__", "strict"),
        (r"/_next/static/", "strict"),
        (r"next/router", "strict"),
    ],
    "Nuxt": [
        (r"__NUXT__", "strict"),
        (r"/_nuxt/", "strict"),
        (r"nuxt-link", "strict"),
    ],
    "Remix": [
        (r"__remixContext", "strict"),
        (r"remix-run/react", "strict"),
    ],
    "Gatsby": [
        (r"___gatsby", "strict"),
        (r"gatsby-chunk-mapping", "strict"),
    ],
    "Astro": [
        (r"astro-island", "strict"),
        (r"astro:scripts", "strict"),
    ],
    "Fresh (Deno)": [
        (r"/_frsh/", "strict"),
        (r"data-fresh-key", "strict"),
    ],
    "Redwood": [
        (r"@redwoodjs/", "strict"),
    ],
    "Blitz.js": [
        (r"@blitzjs/", "strict"),
    ],
    "TanStack Start": [
        (r"@tanstack/start", "strict"),
        (r"@tanstack/router", "strict"),
    ],
    "Analog (Angular)": [
        (r"@analogjs/", "strict"),
    ],

    # --- Build tools / bundlers (sirven como hint) ---
    "Vite": [
        (r"/@vite/client", "strict"),
        (r"import\.meta\.hot", "strict"),
        (r"/@fs/", "strict"),
    ],
    "Webpack": [
        (r"webpackChunk[_a-zA-Z0-9]*", "strict"),
        (r"__webpack_require__", "strict"),
        (r"webpackJsonp", "strict"),
    ],
    "Turbopack": [
        (r"__turbopack_", "strict"),
    ],
    "esbuild": [
        (r"esbuild", "loose"),
    ],
    "Parcel": [
        (r"parcelRequire", "strict"),
    ],
    "Rollup": [
        (r"rollup", "loose"),
    ],

    # --- JS frameworks "sprinkles" / hypermedia ---
    "Alpine.js": [
        (r"\bx-data=", "strict"),
        (r"\bx-show=", "strict"),
        (r"alpinejs", "strict"),
    ],
    "Lit": [
        (r"lit-element", "strict"),
        (r"@lit/reactive-element", "strict"),
        (r"lit-html", "strict"),
    ],
    "Stimulus": [
        (r"data-controller=", "strict"),
        (r"@hotwired/stimulus", "strict"),
    ],
    "Turbo (Hotwire)": [
        (r"@hotwired/turbo", "strict"),
        (r"turbo-frame", "strict"),
        (r"turbo-stream", "strict"),
    ],
    "HTMX": [
        (r"\bhx-get=", "strict"),
        (r"\bhx-post=", "strict"),
        (r"\bhx-swap=", "strict"),
        (r"htmx\.org", "strict"),
    ],
    "Unpoly": [
        (r"\bup-target=", "strict"),
        (r"unpoly\.com", "strict"),
    ],
    "Petite-Vue": [
        (r"petite-vue", "strict"),
    ],

    # --- Backend Python ---
    "Django": [
        (r"csrfmiddlewaretoken", "strict"),
        (r"__admin_media_prefix__", "strict"),
        (r"django\.contrib", "strict"),
    ],
    "Flask": [
        (r"flask\.", "strict"),
        (r"werkzeug", "strict"),
    ],
    "FastAPI": [
        (r"/openapi\.json", "strict"),
        (r"/docs#/default", "strict"),
        (r"fastapi", "loose"),
    ],
    "Starlette": [
        (r"\bstarlette\b", "strict"),
    ],
    "Tornado": [
        (r"tornado\.web", "strict"),
    ],
    "Sanic": [
        (r"\bsanic\b", "strict"),
    ],
    "Pyramid": [
        (r"pyramid\.config", "strict"),
    ],
    "aiohttp": [
        (r"aiohttp", "strict"),
    ],
    "Falcon": [
        (r"falcon\.api", "strict"),
    ],

    # --- Backend Ruby ---
    "Rails": [
        (r"csrf-param.+authenticity_token", "strict"),
        (r"_rails_session", "strict"),
        (r"data-turbolinks", "strict"),
        (r"authenticity_token", "loose"),
    ],
    "Sinatra": [
        (r"sinatra", "strict"),
    ],
    "Hanami": [
        (r"\bhanami\b", "strict"),
    ],

    # --- Backend PHP ---
    "Laravel": [
        (r"laravel_session", "strict"),
        (r"XSRF-TOKEN", "strict"),
        (r"/vendor/laravel/", "strict"),
    ],
    "Symfony": [
        (r"sf_redirect", "strict"),
        (r"symfony/", "strict"),
        (r"/_profiler/", "strict"),
        (r"/_wdt/", "strict"),
    ],
    "CodeIgniter": [
        (r"ci_session", "strict"),
        (r"codeigniter", "strict"),
    ],
    "CakePHP": [
        (r"CAKEPHP=", "strict"),
        (r"cakephp", "strict"),
    ],
    "Yii": [
        (r"yiiframework", "strict"),
        (r"\b_csrf-\d+", "strict"),
    ],
    "Zend / Laminas": [
        (r"zendframework", "strict"),
        (r"laminas/", "strict"),
    ],
    "Slim (PHP)": [
        (r"slimframework", "strict"),
    ],
    "Phalcon": [
        (r"phalcon", "strict"),
    ],

    # --- Backend Node ---
    "Express": [
        (r"x-powered-by:\s*express", "strict"),
        (r"\bexpress\b", "loose"),
    ],
    "Koa": [
        (r"koajs", "strict"),
    ],
    "NestJS": [
        (r"@nestjs/", "strict"),
    ],
    "Fastify": [
        (r"fastify", "strict"),
    ],
    "Hapi": [
        (r"@hapi/hapi", "strict"),
    ],
    "Meteor": [
        (r"__meteor_runtime_config__", "strict"),
    ],

    # --- Backend Go / Rust / Kotlin / Scala ---
    "Gin (Go)": [
        (r"gin-gonic", "strict"),
    ],
    "Echo (Go)": [
        (r"labstack/echo", "strict"),
    ],
    "Fiber (Go)": [
        (r"gofiber", "strict"),
    ],
    "Actix (Rust)": [
        (r"actix-web", "strict"),
    ],
    "Rocket (Rust)": [
        (r"rocket\.rs", "strict"),
    ],
    "Axum (Rust)": [
        (r"\btokio-rs/axum\b", "strict"),
    ],
    "Ktor (Kotlin)": [
        (r"ktor-server", "strict"),
    ],
    "Play Framework": [
        (r"play\.api", "strict"),
        (r"play-framework", "strict"),
    ],
    "Phoenix (Elixir)": [
        (r"phoenix\.js", "strict"),
        (r"phx-socket", "strict"),
    ],

    # --- Backend Java enterprise ---
    "Spring": [
        (r"org\.springframework", "strict"),
        (r"spring-security", "strict"),
        (r"whitelabel error page", "strict"),
    ],
    "Spring Boot Actuator": [
        (r"/actuator/", "strict"),
    ],
    "Spring Cloud Gateway": [
        (r"spring-cloud-gateway", "strict"),
    ],
    "Apache Struts": [
        (r"struts2", "strict"),
        (r"\.action(?:\?|$)", "strict"),
        (r"struts", "loose"),
    ],
    "JSF / PrimeFaces": [
        (r"javax\.faces", "strict"),
        (r"jakarta\.faces", "strict"),
        (r"primefaces", "strict"),
    ],
    "RichFaces": [
        (r"richfaces", "strict"),
    ],
    "ICEfaces": [
        (r"icefaces", "strict"),
    ],
    "Vaadin": [
        (r"\bvaadin\b", "strict"),
        (r"v-system-error", "strict"),
    ],
    "GWT": [
        (r"gwt\.rpc", "strict"),
        (r"com\.google\.gwt", "strict"),
    ],
    "Quarkus": [
        (r"quarkus", "strict"),
    ],
    "Micronaut": [
        (r"micronaut", "strict"),
    ],
    "Dropwizard": [
        (r"dropwizard", "strict"),
    ],
    "Tomcat": [
        (r"apache tomcat", "strict"),
        (r"jsessionid", "loose"),
    ],
    "Jetty": [
        (r"server:\s*jetty", "strict"),
    ],
    "JBoss / WildFly": [
        (r"server:\s*(?:jboss|wildfly)", "strict"),
        (r"jboss-seam", "strict"),
        (r"wildfly", "strict"),
    ],
    "WebLogic": [
        (r"weblogic", "strict"),
        (r"/console/login/LoginForm\.jsp", "strict"),
        (r"/wls-wsat/", "strict"),
    ],
    "WebSphere": [
        (r"websphere", "strict"),
        (r"/ibm/console/", "strict"),
    ],
    "GlassFish": [
        (r"glassfish", "strict"),
    ],

    # --- .NET ---
    "ASP.NET WebForms": [
        (r"__VIEWSTATE", "strict"),
        (r"__EVENTVALIDATION", "strict"),
        (r"__EVENTTARGET", "strict"),
    ],
    "ASP.NET MVC": [
        (r"__RequestVerificationToken", "strict"),
        (r"x-aspnetmvc-version", "strict"),
    ],
    "ASP.NET Core": [
        (r"\.aspxauth", "strict"),
        (r"\.aspnetcore\.", "strict"),
    ],
    "Nancy": [
        (r"nancyfx", "strict"),
    ],
    "ServiceStack": [
        (r"servicestack", "strict"),
    ],

    # --- Serverless / hosted function platforms ---
    "AWS API Gateway": [
        (r"execute-api\.[a-z0-9-]+\.amazonaws\.com", "strict"),
    ],
    "AWS Lambda URL": [
        (r"lambda-url\.[a-z0-9-]+\.on\.aws", "strict"),
    ],
    "Google Cloud Run": [
        (r"\.run\.app", "strict"),
    ],
    "Google Cloud Functions": [
        (r"cloudfunctions\.net", "strict"),
    ],
    "Azure Functions": [
        (r"\.azurewebsites\.net", "strict"),
    ],
    "Netlify Functions": [
        (r"/\.netlify/functions/", "strict"),
    ],
    "Vercel Functions": [
        (r"x-vercel-id", "strict"),
        (r"x-vercel-cache", "strict"),
    ],
    "Cloudflare Workers": [
        (r"cf-worker", "strict"),
        (r"\.workers\.dev", "strict"),
    ],

    # --- GraphQL implementations ---
    "Hasura": [
        (r"x-hasura-", "strict"),
        (r"/v1/graphql", "strict"),
        (r"hasura", "loose"),
    ],
    "Apollo Server": [
        (r"apollo-tracing", "strict"),
        (r"apollo-server", "strict"),
    ],
    "PostGraphile": [
        (r"postgraphile", "strict"),
    ],
}


# -----------------------------------------------------------------------------
# CMS: tradicional + headless + e-commerce platforms
# -----------------------------------------------------------------------------
CMS_RULES: Dict[str, List[_Rule]] = {
    # --- PHP CMS tradicional ---
    "WordPress": [
        (r"/wp-content/", "strict"),
        (r"/wp-includes/", "strict"),
        (r"/wp-json/", "strict"),
        (r"wordpress", "loose"),
    ],
    "WooCommerce": [
        (r"woocommerce", "strict"),
        (r"wc-ajax=", "strict"),
    ],
    "Drupal": [
        (r"drupalSettings", "strict"),
        (r"/sites/default/files/", "strict"),
        (r"generator.+drupal", "strict"),
        (r"X-Generator.*Drupal", "strict"),
    ],
    "Joomla": [
        (r"/media/jui/", "strict"),
        (r"/components/com_", "strict"),
        (r"joomla!", "strict"),
    ],
    "PrestaShop": [
        (r"prestashop", "strict"),
        (r"/modules/ps_", "strict"),
    ],
    "OpenCart": [
        (r"opencart", "strict"),
        (r"route=common/home", "strict"),
    ],
    "Magento": [
        (r"/skin/frontend/", "strict"),
        (r"Mage\.Cookies", "strict"),
        (r"/static/version\d+/frontend/", "strict"),
    ],
    "osCommerce": [
        (r"oscommerce", "strict"),
    ],
    "Zen Cart": [
        (r"zen-cart", "strict"),
        (r"zencart", "strict"),
    ],
    "TYPO3": [
        (r"typo3conf/", "strict"),
        (r"typo3temp/", "strict"),
        (r"typo3", "loose"),
    ],
    "Craft CMS": [
        (r"craftcms", "strict"),
        (r"CRAFT_CSRF_TOKEN", "strict"),
    ],
    "Kirby": [
        (r"getkirby\.com", "strict"),
        (r"/kirby/", "strict"),
    ],
    "ExpressionEngine": [
        (r"expressionengine", "strict"),
        (r"/system/expressionengine/", "strict"),
    ],
    "Concrete CMS": [
        (r"concrete5", "strict"),
        (r"concretecms", "strict"),
    ],
    "Grav": [
        (r"getgrav", "strict"),
    ],
    "October CMS": [
        (r"octobercms", "strict"),
    ],
    "Statamic": [
        (r"statamic", "strict"),
    ],
    "Plone": [
        (r"\bplone\b", "strict"),
        (r"@@plone\.", "strict"),
    ],
    "SilverStripe": [
        (r"silverstripe", "strict"),
    ],
    "ProcessWire": [
        (r"processwire", "strict"),
    ],
    "Bolt": [
        (r"bolt\.cm", "strict"),
    ],
    "Pimcore": [
        (r"pimcore", "strict"),
    ],
    "dotCMS": [
        (r"dotcms", "strict"),
    ],
    "Ghost": [
        (r"ghost-sdk", "strict"),
        (r"/ghost/api/", "strict"),
    ],

    # --- .NET CMS ---
    "Sitecore": [
        (r"/sitecore/", "strict"),
        (r"sc_site=", "strict"),
        (r"sitecore", "loose"),
    ],
    "Kentico": [
        (r"kentico", "strict"),
        (r"CMSPreferredCulture", "strict"),
    ],
    "Sitefinity": [
        (r"sitefinity", "strict"),
        (r"Telerik\.Sitefinity", "strict"),
    ],
    "Episerver / Optimizely CMS": [
        (r"episerver", "strict"),
        (r"/EPiServer/", "strict"),
    ],
    "Orchard CMS": [
        (r"orchardcms", "strict"),
    ],
    "Umbraco": [
        (r"/umbraco/", "strict"),
        (r"umbraco\.", "strict"),
    ],
    "DNN (DotNetNuke)": [
        (r"dnn_ctr", "strict"),
        (r"dotnetnuke", "strict"),
        (r"/DesktopModules/", "strict"),
    ],
    "SharePoint": [
        (r"_layouts/15/", "strict"),
        (r"MicrosoftSharePointTeamServices", "strict"),
        (r"SharePoint", "loose"),
    ],

    # --- Java CMS ---
    "Adobe AEM": [
        (r"/content/dam/", "strict"),
        (r"/etc/designs/", "strict"),
        (r"/etc\.clientlibs/", "strict"),
        (r"cq-analytics", "strict"),
    ],
    "Liferay": [
        (r"Liferay\.", "strict"),
        (r"/o/frontend-js-", "strict"),
    ],

    # --- Wiki / docs ---
    "MediaWiki": [
        (r"mw\.config", "strict"),
        (r"wgAction", "strict"),
        (r"mw\.loader", "strict"),
    ],
    "DokuWiki": [
        (r"dokuwiki", "strict"),
    ],
    "Confluence": [
        (r"confluence", "strict"),
        (r"ajs-page-id", "strict"),
        (r"atlassian-token", "strict"),
    ],
    "GitBook": [
        (r"gitbook\.io", "strict"),
        (r"gitbook-content", "strict"),
    ],
    "Docusaurus": [
        (r"docusaurus", "strict"),
    ],
    "MkDocs": [
        (r"mkdocs", "strict"),
    ],
    "VuePress / VitePress": [
        (r"vuepress", "strict"),
        (r"vitepress", "strict"),
    ],
    "Sphinx": [
        (r"sphinx-doc", "strict"),
        (r"_static/doctools\.js", "strict"),
    ],
    "Zendesk Help Center": [
        (r"zendesk\.com/hc/", "strict"),
        (r"/hc/theming_assets/", "strict"),
    ],
    "ReadMe.io": [
        (r"readme\.io", "strict"),
    ],

    # --- Forums / community ---
    "Discourse": [
        (r"discourse", "strict"),
        (r"Discourse\.start_time", "strict"),
    ],
    "phpBB": [
        (r"phpbb_", "strict"),
        (r"phpbb", "loose"),
    ],
    "vBulletin": [
        (r"vbulletin", "strict"),
    ],
    "XenForo": [
        (r"xenforo", "strict"),
    ],
    "NodeBB": [
        (r"nodebb", "strict"),
    ],
    "Flarum": [
        (r"flarum", "strict"),
    ],
    "MyBB": [
        (r"mybb", "strict"),
    ],
    "Invision Community": [
        (r"invisionpower", "strict"),
        (r"invisioncommunity", "strict"),
    ],

    # --- LMS ---
    "Moodle": [
        (r"/mod/quiz/", "strict"),
        (r"moodle", "loose"),
        (r"MoodleSession", "strict"),
    ],
    "Canvas LMS": [
        (r"instructure\.com", "strict"),
        (r"canvas-lms", "strict"),
    ],
    "Blackboard": [
        (r"blackboard", "strict"),
        (r"/webapps/login/", "strict"),
    ],

    # --- Headless CMS ---
    "Strapi": [
        (r"\bstrapi\b", "strict"),
        (r"/api/users/me", "strict"),
    ],
    "Directus": [
        (r"@directus/", "strict"),
        (r"directus", "loose"),
    ],
    "Contentful": [
        (r"cdn\.contentful\.com", "strict"),
        (r"images\.ctfassets\.net", "strict"),
    ],
    "Sanity": [
        (r"cdn\.sanity\.io", "strict"),
        (r"apicdn\.sanity\.io", "strict"),
    ],
    "Payload CMS": [
        (r"payloadcms", "strict"),
    ],
    "Keystone": [
        (r"@keystone-next/", "strict"),
        (r"keystonejs", "strict"),
    ],
    "Builder.io": [
        (r"builder\.io", "strict"),
    ],
    "Storyblok": [
        (r"storyblok", "strict"),
        (r"a\.storyblok\.com", "strict"),
    ],
    "Prismic": [
        (r"prismic\.io", "strict"),
        (r"cdn\.prismic\.io", "strict"),
    ],
    "DatoCMS": [
        (r"datocms-assets", "strict"),
        (r"datocms\.com", "strict"),
    ],
    "Hygraph / GraphCMS": [
        (r"hygraph\.com", "strict"),
        (r"graphcms\.com", "strict"),
    ],
    "ButterCMS": [
        (r"buttercms", "strict"),
    ],
    "TinaCMS": [
        (r"tinacms", "strict"),
    ],
    "Decap CMS": [
        (r"decap-cms", "strict"),
        (r"netlify-cms", "strict"),
    ],

    # --- Hosted e-commerce ---
    "Shopify": [
        (r"cdn\.shopify\.com", "strict"),
        (r"Shopify\.theme", "strict"),
        (r"shopify-section-", "strict"),
    ],
    "BigCommerce": [
        (r"bigcommerce", "strict"),
        (r"cdn11\.bigcommerce\.com", "strict"),
    ],
    "Salesforce Commerce Cloud": [
        (r"demandware\.net", "strict"),
        (r"demandware\.store", "strict"),
    ],
    "SAP Commerce Cloud / Hybris": [
        (r"hybris", "strict"),
    ],
    "Medusa": [
        (r"medusajs", "strict"),
    ],
    "Saleor": [
        (r"saleor", "strict"),
    ],
    "Spree": [
        (r"spreecommerce", "strict"),
    ],
    "Solidus": [
        (r"solidus\.io", "strict"),
    ],
    "Vendure": [
        (r"vendure", "strict"),
    ],
    "commercetools": [
        (r"commercetools", "strict"),
    ],
    "Snipcart": [
        (r"snipcart", "strict"),
    ],

    # --- Enterprise ERP / CRM (públicos o semi-públicos) ---
    "Salesforce": [
        (r"force\.com", "strict"),
        (r"salesforce\.com/services/", "strict"),
        (r"sfdc-", "strict"),
    ],
    "ServiceNow": [
        (r"service-now\.com", "strict"),
        (r"servicenow\.com", "strict"),
        (r"/navpage\.do", "strict"),
    ],
    "Workday": [
        (r"workday\.com/", "strict"),
        (r"myworkday", "strict"),
    ],
    "SAP SuccessFactors": [
        (r"successfactors", "strict"),
    ],
    "Microsoft Dynamics 365": [
        (r"dynamics\.com", "strict"),
        (r"/XRMServices/", "strict"),
    ],
    "Oracle PeopleSoft": [
        (r"/psp/", "strict"),
        (r"peoplesoft", "strict"),
    ],
    "Oracle Siebel": [
        (r"siebel", "strict"),
        (r"/siebel/app/", "strict"),
    ],
    "Oracle EBS (E-Business Suite)": [
        (r"OA_HTML", "strict"),
        (r"/oa_servlets/", "strict"),
    ],
    "Oracle JD Edwards": [
        (r"jdedwards", "strict"),
        (r"e1menuappcache", "strict"),
    ],
    "SAP NetWeaver": [
        (r"sap-system", "strict"),
        (r"/sap/bc/", "strict"),
        (r"sap-ur-bodycolors", "strict"),
    ],
    "SAP Fiori": [
        (r"/sap/bc/ui5_ui5/", "strict"),
        (r"sap\.ui\.core", "strict"),
    ],
    "SAP BusinessObjects": [
        (r"/BOE/BI", "strict"),
        (r"businessobjects", "strict"),
    ],
    "IBM WebSphere Portal": [
        (r"/wps/portal/", "strict"),
        (r"websphere portal", "strict"),
    ],
    "IBM Domino / Lotus": [
        (r"domino", "strict"),
        (r"/names\.nsf", "strict"),
        (r"\.nsf/", "strict"),
    ],
}


# -----------------------------------------------------------------------------
# HOSTED PLATFORMS: donde "vive" el sitio (CDN/edge/PaaS/BaaS)
# -----------------------------------------------------------------------------
HOSTED_PLATFORM_RULES: Dict[str, List[_Rule]] = {
    "Vercel": [
        (r"x-vercel-id", "strict"),
        (r"x-vercel-cache", "strict"),
        (r"server:\s*vercel", "strict"),
    ],
    "Netlify": [
        (r"x-nf-request-id", "strict"),
        (r"server:\s*netlify", "strict"),
    ],
    "Cloudflare Pages": [
        (r"cf-pages", "strict"),
        (r"\.pages\.dev", "strict"),
    ],
    "GitHub Pages": [
        (r"server:\s*github\.com", "strict"),
        (r"\.github\.io", "strict"),
    ],
    "GitLab Pages": [
        (r"\.gitlab\.io", "strict"),
    ],
    "Heroku": [
        (r"herokuapp\.com", "strict"),
        (r"x-heroku-", "strict"),
    ],
    "Render": [
        (r"\.onrender\.com", "strict"),
    ],
    "Fly.io": [
        (r"\.fly\.dev", "strict"),
        (r"fly-request-id", "strict"),
    ],
    "Railway": [
        (r"\.railway\.app", "strict"),
        (r"\.up\.railway\.app", "strict"),
    ],
    "Deno Deploy": [
        (r"\.deno\.dev", "strict"),
    ],
    "AWS Amplify": [
        (r"\.amplifyapp\.com", "strict"),
    ],
    "AWS Elastic Beanstalk": [
        (r"\.elasticbeanstalk\.com", "strict"),
    ],
    "AWS S3 Website": [
        (r"\.s3-website[.\-][a-z0-9-]+\.amazonaws\.com", "strict"),
    ],
    "Google Firebase Hosting": [
        (r"\.firebaseapp\.com", "strict"),
        (r"\.web\.app", "strict"),
    ],
    "Google App Engine": [
        (r"\.appspot\.com", "strict"),
    ],
    "Azure Static Web Apps": [
        (r"\.azurestaticapps\.net", "strict"),
    ],
    "Azure App Service": [
        (r"\.azurewebsites\.net", "strict"),
    ],
    "DigitalOcean App Platform": [
        (r"\.ondigitalocean\.app", "strict"),
    ],
    "Supabase": [
        (r"\.supabase\.co", "strict"),
        (r"\.supabase\.in", "strict"),
    ],
    "Appwrite": [
        (r"appwrite\.io", "strict"),
        (r"\.appwrite\.global", "strict"),
    ],
    "PocketBase": [
        (r"pocketbase", "strict"),
    ],
    "Parse Server": [
        (r"parse-server", "strict"),
        (r"X-Parse-Application-Id", "strict"),
    ],
    "Nhost": [
        (r"\.nhost\.run", "strict"),
    ],
    "Firebase Realtime DB": [
        (r"\.firebaseio\.com", "strict"),
    ],
    "Firestore": [
        (r"firestore\.googleapis\.com", "strict"),
    ],
}


# -----------------------------------------------------------------------------
# DEV TOOLS público-facing (cuando aparecen estos sin auth, es un hallazgo)
# -----------------------------------------------------------------------------
DEV_TOOLS_RULES: Dict[str, List[_Rule]] = {
    # --- CI/CD ---
    "Jenkins": [
        (r"x-jenkins", "strict"),
        (r"x-jenkins-session", "strict"),
        (r"hudson\.", "strict"),
        (r">jenkins<", "strict"),
        (r"jenkins", "loose"),
    ],
    "GitLab (self-hosted)": [
        (r"gitlab-ci", "strict"),
        (r"X-Gitlab-", "strict"),
        (r"gitlab-workhorse", "strict"),
    ],
    "Gitea": [
        (r">gitea<", "strict"),
        (r"gitea", "loose"),
    ],
    "Gogs": [
        (r">gogs<", "strict"),
    ],
    "Forgejo": [
        (r"forgejo", "strict"),
    ],
    "Bitbucket Server": [
        (r"bitbucket-server", "strict"),
        (r"X-AREQUESTID", "strict"),
        (r"atlassian-token.+bitbucket", "strict"),
    ],
    "TeamCity": [
        (r"teamcity", "strict"),
        (r"TCSESSIONID", "strict"),
    ],
    "Bamboo": [
        (r"bamboo\.", "strict"),
        (r"atlassian-bamboo", "strict"),
    ],
    "Drone CI": [
        (r"drone\.io", "strict"),
        (r"\bdrone-ci\b", "strict"),
    ],
    "Woodpecker CI": [
        (r"woodpecker-ci", "strict"),
    ],
    "Concourse": [
        (r"concourse\.ci", "strict"),
        (r"concourse-ci", "strict"),
    ],
    "Spinnaker": [
        (r"spinnaker", "strict"),
    ],
    "ArgoCD": [
        (r"argo-cd", "strict"),
        (r"argocd", "strict"),
    ],
    "Argo Workflows": [
        (r"argo-workflows", "strict"),
    ],
    "Tekton Dashboard": [
        (r"tekton-dashboard", "strict"),
    ],
    "GoCD": [
        (r"gocd", "strict"),
    ],
    "Buildkite": [
        (r"buildkite", "strict"),
    ],
    "Azure DevOps Server": [
        (r"tfs/", "strict"),
        (r"azure-devops", "strict"),
        (r"azuredevops", "strict"),
    ],

    # --- Code quality / registry ---
    "SonarQube": [
        (r"sonarqube", "strict"),
        (r"sonar_", "strict"),
    ],
    "Nexus Repository": [
        (r"nexus-repository", "strict"),
        (r"/nexus/#", "strict"),
        (r"sonatype nexus", "strict"),
    ],
    "JFrog Artifactory": [
        (r"artifactory", "strict"),
        (r"X-JFrog-Art-Api", "strict"),
    ],
    "Harbor": [
        (r"\bharbor\b.+registry", "strict"),
        (r"goharbor", "strict"),
    ],

    # --- Monitoring / observability ---
    "Grafana": [
        (r"grafana", "strict"),
        (r"grafana_session", "strict"),
        (r">Grafana<", "strict"),
    ],
    "Kibana": [
        (r"kbn-name", "strict"),
        (r"kbn-version", "strict"),
        (r"kibana", "loose"),
    ],
    "Prometheus": [
        (r"prometheus", "strict"),
        (r"/api/v1/query", "strict"),
    ],
    "Splunk": [
        (r"splunk", "strict"),
        (r"splunkd", "strict"),
    ],
    "Graylog": [
        (r"graylog", "strict"),
    ],
    "Wazuh": [
        (r"wazuh", "strict"),
    ],
    "Nagios": [
        (r"nagios", "strict"),
    ],
    "Cacti": [
        (r"cacti", "strict"),
    ],
    "Zabbix": [
        (r"zabbix", "strict"),
    ],
    "Icinga": [
        (r"icinga", "strict"),
    ],
    "LibreNMS": [
        (r"librenms", "strict"),
    ],
    "Observium": [
        (r"observium", "strict"),
    ],
    "PRTG": [
        (r"paessler\.com", "strict"),
        (r"prtg/", "strict"),
    ],
    "Netdata": [
        (r"netdata", "strict"),
    ],

    # --- Issue trackers / dev collab ---
    "Jira": [
        (r"jira\.", "strict"),
        (r"atlassian-token.+jira", "strict"),
        (r"/rest/api/2/issue/", "strict"),
    ],
    "Atlassian Crowd": [
        (r"crowd/", "strict"),
        (r"atlassian-crowd", "strict"),
    ],

    # --- Container / orchestration UI ---
    "Portainer": [
        (r"portainer", "strict"),
    ],
    "Rancher": [
        (r"rancher", "strict"),
    ],
    "Kubernetes Dashboard": [
        (r"kubernetes-dashboard", "strict"),
    ],
    "phpMyAdmin": [
        (r"phpmyadmin", "strict"),
        (r"pmaCookieVer", "strict"),
    ],
    "Adminer": [
        (r"adminer\.php", "strict"),
    ],
    "Webmin": [
        (r"webmin", "strict"),
    ],
    "cPanel": [
        (r"cpanel", "strict"),
        (r"/cpsess\d+/", "strict"),
    ],
    "Plesk": [
        (r"plesk", "strict"),
        (r"/smb/", "strict"),
    ],
    "DirectAdmin": [
        (r"directadmin", "strict"),
    ],

    # --- Security tools ---
    "OpenVAS / Greenbone": [
        (r"greenbone", "strict"),
        (r"openvas", "strict"),
    ],
    "MISP": [
        (r"misp-project", "strict"),
        (r"misp_session", "strict"),
    ],
    "TheHive": [
        (r"thehive-project", "strict"),
    ],
}


# -----------------------------------------------------------------------------
# IDP / Identity Providers (auth-as-a-service + enterprise)
# -----------------------------------------------------------------------------
IDP_RULES: Dict[str, List[_Rule]] = {
    "Keycloak": [
        (r"/auth/realms/", "strict"),
        (r"keycloak", "strict"),
        (r"kc_idp_hint", "strict"),
    ],
    "Auth0": [
        (r"\.auth0\.com", "strict"),
        (r"auth0-spa-js", "strict"),
    ],
    "Okta": [
        (r"\.okta\.com", "strict"),
        (r"okta-signin-widget", "strict"),
        (r"oktaauthn", "strict"),
    ],
    "Microsoft Entra ID / Azure AD": [
        (r"login\.microsoftonline\.com", "strict"),
        (r"login\.windows\.net", "strict"),
    ],
    "AD FS": [
        (r"/adfs/ls/", "strict"),
        (r"MSISAuth", "strict"),
    ],
    "AWS Cognito": [
        (r"cognito-idp\.", "strict"),
        (r"cognitoidentityprovider", "strict"),
    ],
    "GCP Identity Platform": [
        (r"identitytoolkit\.googleapis\.com", "strict"),
    ],
    "Firebase Auth": [
        (r"firebase.+auth", "strict"),
        (r"securetoken\.googleapis\.com", "strict"),
    ],
    "Ping Identity": [
        (r"pingidentity", "strict"),
        (r"pingfederate", "strict"),
        (r"pingone\.com", "strict"),
    ],
    "ForgeRock": [
        (r"forgerock", "strict"),
        (r"openam/", "strict"),
    ],
    "OneLogin": [
        (r"onelogin\.com", "strict"),
    ],
    "JumpCloud": [
        (r"jumpcloud\.com", "strict"),
    ],
    "WSO2 Identity Server": [
        (r"wso2is", "strict"),
        (r"/carbon/admin/", "strict"),
    ],
    "Gluu": [
        (r"gluu\.org", "strict"),
        (r"/oxauth/", "strict"),
    ],
    "Authelia": [
        (r"authelia", "strict"),
    ],
    "Authentik": [
        (r"goauthentik", "strict"),
        (r"authentik", "strict"),
    ],
    "Ory Hydra / Kratos": [
        (r"ory\.sh", "strict"),
        (r"ory-hydra", "strict"),
        (r"ory-kratos", "strict"),
    ],
    "SuperTokens": [
        (r"supertokens", "strict"),
    ],
    "Clerk": [
        (r"clerk\.accounts", "strict"),
        (r"clerk-js", "strict"),
    ],
    "WorkOS": [
        (r"workos\.com", "strict"),
    ],
    "Stytch": [
        (r"stytch\.com", "strict"),
    ],
    "FusionAuth": [
        (r"fusionauth", "strict"),
    ],
    "Frontegg": [
        (r"frontegg", "strict"),
    ],
    "Descope": [
        (r"descope\.com", "strict"),
    ],
    "Kinde": [
        (r"kinde\.com", "strict"),
    ],
    "LoginRadius": [
        (r"loginradius", "strict"),
    ],
    "MiniOrange": [
        (r"miniorange", "strict"),
    ],
    "Shibboleth IdP": [
        (r"/idp/profile/SAML2/", "strict"),
        (r"shibboleth", "strict"),
    ],
    "SimpleSAMLphp": [
        (r"simplesamlphp", "strict"),
        (r"/simplesaml/", "strict"),
    ],
    "CA SiteMinder": [
        (r"siteminder", "strict"),
        (r"SMSESSION", "strict"),
    ],
    "Oracle Access Manager": [
        (r"OAM_REQ", "strict"),
        (r"oracle access manager", "strict"),
    ],
    "IBM Security Verify": [
        (r"ibm security verify", "strict"),
        (r"ibmsecurityverify", "strict"),
    ],
    "RSA SecurID": [
        (r"rsa secure.*id", "strict"),
    ],
}


# -----------------------------------------------------------------------------
# NETWORK APPLIANCES / VPN SSL / admin panels (los CVEs más jugosos)
# -----------------------------------------------------------------------------
# Detectar estos casi siempre vale como hallazgo de prioridad alta.
NETWORK_APPLIANCE_RULES: Dict[str, List[_Rule]] = {
    "Citrix NetScaler / ADC": [
        (r"/vpn/index\.html", "strict"),
        (r"citrix gateway", "strict"),
        (r"nsc_", "strict"),
        (r"citrix\.com", "loose"),
    ],
    "Citrix StoreFront": [
        (r"/Citrix/StoreWeb/", "strict"),
        (r"storefront", "loose"),
    ],
    "Citrix Web Interface": [
        (r"/Citrix/XenApp/", "strict"),
    ],
    "VMware vCenter": [
        (r"/vsphere-client/", "strict"),
        (r"vmware vcenter", "strict"),
    ],
    "VMware Horizon": [
        (r"/portal/webclient/", "strict"),
        (r"vmware horizon", "strict"),
    ],
    "VMware ESXi": [
        (r"vmware esxi", "strict"),
        (r"/ui/#/host", "strict"),
    ],
    "VMware Workspace ONE": [
        (r"workspaceone", "strict"),
        (r"airwatch", "strict"),
    ],
    "Pulse Secure / Ivanti Connect Secure": [
        (r"/dana-na/auth/", "strict"),
        (r"pulse secure", "strict"),
        (r"ivanti connect secure", "strict"),
    ],
    "F5 BIG-IP iControl": [
        (r"/mgmt/tm/", "strict"),
        (r"f5-bigip", "strict"),
        (r"big-ip", "loose"),
    ],
    "Palo Alto GlobalProtect": [
        (r"/global-protect/", "strict"),
        (r"globalprotect", "strict"),
    ],
    "Fortinet FortiGate": [
        (r"fortigate", "strict"),
        (r"/remote/login\?", "strict"),
        (r"fgt_lang", "strict"),
    ],
    "Fortinet FortiWeb": [
        (r"fortiweb", "strict"),
    ],
    "SonicWall SSL-VPN": [
        (r"sonicwall", "strict"),
        (r"/cgi-bin/welcome", "strict"),
    ],
    "Cisco AnyConnect": [
        (r"anyconnect", "strict"),
        (r"/\+CSCOE\+/", "strict"),
    ],
    "Cisco ASA": [
        (r"cisco asa", "strict"),
        (r"/\+webvpn\+/", "strict"),
    ],
    "Check Point": [
        (r"checkpoint", "strict"),
        (r"/sslvpn/Login/", "strict"),
    ],
    "WatchGuard": [
        (r"watchguard", "strict"),
    ],
    "Sophos UTM / XG": [
        (r"sophos", "strict"),
        (r"/userportal/", "strict"),
    ],
    "Ubiquiti UniFi Controller": [
        (r"unifi_controller", "strict"),
        (r"/manage/site/", "strict"),
    ],
    "Mikrotik RouterOS": [
        (r"routeros", "strict"),
        (r"mikrotik", "strict"),
    ],
    "pfSense": [
        (r"pfsense", "strict"),
        (r"/index\.php\?logout", "strict"),
    ],
    "OPNsense": [
        (r"opnsense", "strict"),
    ],
    "OpenWrt LuCI": [
        (r"luci", "strict"),
        (r"openwrt", "strict"),
    ],
    "iDRAC (Dell)": [
        (r"idrac", "strict"),
        (r"dell remote access", "strict"),
    ],
    "iLO (HPE)": [
        (r"integrated lights-out", "strict"),
        (r"\bilo\b", "strict"),
    ],
    "Supermicro IPMI": [
        (r"supermicro", "strict"),
        (r"atenjavaclient", "strict"),
    ],
    "Synology DSM": [
        (r"synology", "strict"),
        (r"/webman/index\.cgi", "strict"),
    ],
    "QNAP QTS": [
        (r"qnap", "strict"),
        (r"/cgi-bin/authLogin", "strict"),
    ],
    "TrueNAS / FreeNAS": [
        (r"truenas", "strict"),
        (r"freenas", "strict"),
    ],
    "Proxmox VE": [
        (r"proxmox", "strict"),
        (r"PVEAuthCookie", "strict"),
    ],
    "XCP-ng / Xen Orchestra": [
        (r"xen-orchestra", "strict"),
    ],
    "Microsoft Exchange OWA": [
        (r"/owa/", "strict"),
        (r"outlook web access", "strict"),
        (r"OwaCanary", "strict"),
    ],
    "Exchange Autodiscover": [
        (r"autodiscover/autodiscover\.xml", "strict"),
    ],
    "Skype for Business": [
        (r"skype for business", "strict"),
        (r"/LWA/", "strict"),
    ],
}


LIBRARY_RULES: Dict[str, List[_Rule]] = {
    "jQuery": [
        (r"jquery\.min\.js", "strict"),
        (r"jQuery\.fn\.jquery", "strict"),
        (r"\bjquery\b", "loose"),
    ],
    "Bootstrap": [
        (r"bootstrap\.min\.js", "strict"),
        (r"bootstrap\.bundle", "strict"),
        (r"/bootstrap@\d", "strict"),
    ],
    "Tailwind": [
        (r"tailwindcss", "strict"),
        (r"tw-merge", "strict"),
    ],
    "DOMPurify": [
        (r"dompurify", "strict"),
        (r"DOMPurify\.sanitize", "strict"),
    ],
    "sanitize-html": [
        (r"sanitize-html", "strict"),
    ],
    "Axios": [
        (r"axios/\d", "strict"),
        (r"\baxios\b", "loose"),
    ],
    "Lodash": [
        (r"lodash\.min", "strict"),
        (r"lodash@\d", "strict"),
        (r"\blodash\b", "loose"),
    ],
    "Moment": [
        (r"moment\.min\.js", "strict"),
        (r"moment\.locale", "strict"),
    ],
    "Day.js": [
        (r"dayjs\.min", "strict"),
        (r"dayjs@\d", "strict"),
    ],
    "date-fns": [
        (r"date-fns", "strict"),
    ],
    "RxJS": [
        (r"\brxjs/", "strict"),
        (r"rxjs\.min", "strict"),
    ],
    "Redux": [
        (r"@reduxjs/toolkit", "strict"),
        (r"redux-thunk", "strict"),
        (r"createSlice\(", "strict"),
    ],
    "MobX": [
        (r"\bmobx\b", "strict"),
        (r"mobx-react", "strict"),
    ],
    "React Hook Form": [
        (r"react-hook-form", "strict"),
    ],
    "Formik": [
        (r"\bformik\b", "strict"),
    ],
    "Yup": [
        (r"yup\.object\(", "strict"),
    ],
    "Zod": [
        (r"z\.object\(", "strict"),
        (r"\"zod\"", "strict"),
    ],
    "Sentry": [
        (r"@sentry/", "strict"),
        (r"Sentry\.init\(", "strict"),
    ],
    "PostHog": [
        (r"posthog\.init", "strict"),
        (r"phc_[a-z0-9]{20,}", "strict"),
    ],
    "Segment": [
        (r"analytics\.segment\.io", "strict"),
        (r"segment\.io/v1", "strict"),
    ],
    "Mixpanel": [
        (r"mixpanel\.init", "strict"),
        (r"cdn\.mxpnl\.com", "strict"),
    ],
    "Amplitude": [
        (r"amplitude\.init", "strict"),
        (r"api\.amplitude\.com", "strict"),
    ],
    "Hotjar": [
        (r"static\.hotjar\.com", "strict"),
        (r"hjSiteSettings", "strict"),
    ],
    "FullStory": [
        (r"fullstory\.com/s/fs\.js", "strict"),
    ],
    "LogRocket": [
        (r"logrocket", "strict"),
    ],
    "Microsoft Clarity": [
        (r"clarity\.ms", "strict"),
    ],
    "Pendo": [
        (r"pendo\.io", "strict"),
    ],
    "Heap": [
        (r"heap-analytics", "strict"),
        (r"heapanalytics\.com", "strict"),
    ],
    "Plausible": [
        (r"plausible\.io/js", "strict"),
    ],
    "Umami": [
        (r"umami\.js", "strict"),
        (r"data-website-id", "loose"),
    ],
    "Fathom": [
        (r"cdn\.usefathom\.com", "strict"),
    ],
    "Intercom": [
        (r"widget\.intercom\.io", "strict"),
        (r"intercomSettings", "strict"),
    ],
    "Drift": [
        (r"js\.driftt\.com", "strict"),
        (r"drift\.load", "strict"),
    ],
    "Zendesk Widget": [
        (r"static\.zdassets\.com", "strict"),
    ],
    "Crisp": [
        (r"client\.crisp\.chat", "strict"),
    ],
    "Tippy.js": [
        (r"tippy\.js", "strict"),
    ],
    "Popper.js": [
        (r"popper\.js", "strict"),
        (r"createPopper\(", "strict"),
    ],
    "MathJax": [
        (r"mathjax", "strict"),
    ],
    "D3": [
        (r"d3\.min\.js", "strict"),
        (r"d3\.select\(", "strict"),
    ],
    "Three.js": [
        (r"three\.min\.js", "strict"),
        (r"THREE\.Scene", "strict"),
    ],
    "Chart.js": [
        (r"chart\.js", "strict"),
        (r"new Chart\(", "strict"),
    ],
    "Mapbox GL": [
        (r"mapbox-gl\.js", "strict"),
        (r"api\.mapbox\.com", "strict"),
    ],
    "Leaflet": [
        (r"leaflet\.js", "strict"),
        (r"\bL\.map\(", "strict"),
    ],
    "ArcGIS API": [
        (r"arcgis/core", "strict"),
        (r"esri/Map", "strict"),
    ],
    "OpenLayers": [
        (r"openlayers", "strict"),
        (r"\bol/Map\b", "strict"),
    ],
    "Google Maps": [
        (r"maps\.googleapis\.com/maps/api", "strict"),
    ],
    "HERE Maps": [
        (r"js\.api\.here\.com", "strict"),
    ],
    "Cesium": [
        (r"cesium\.js", "strict"),
        (r"Cesium\.Viewer", "strict"),
    ],
    "deck.gl": [
        (r"deck\.gl", "strict"),
    ],
    "Stripe.js": [
        (r"js\.stripe\.com", "strict"),
    ],
    "Braintree": [
        (r"js\.braintreegateway\.com", "strict"),
    ],
    "Adyen": [
        (r"checkoutshopper-live\.adyen\.com", "strict"),
    ],
    "PayPal SDK": [
        (r"paypal\.com/sdk/js", "strict"),
    ],
    "Square": [
        (r"web\.squarecdn\.com/v1/square\.js", "strict"),
    ],
    "reCAPTCHA": [
        (r"www\.google\.com/recaptcha", "strict"),
        (r"grecaptcha", "strict"),
    ],
    "hCaptcha": [
        (r"hcaptcha\.com/1/api", "strict"),
    ],
    "Turnstile": [
        (r"challenges\.cloudflare\.com/turnstile", "strict"),
    ],
    "Firebase": [
        (r"firebase-app\.js", "strict"),
        (r"firebaseapp\.com", "strict"),
    ],
    "Algolia": [
        (r"algolianet\.com", "strict"),
        (r"algoliasearch", "strict"),
    ],
    "Prism.js": [
        (r"prism\.js", "strict"),
        (r"prismjs", "strict"),
    ],
    "CodeMirror": [
        (r"codemirror", "strict"),
    ],
    "Monaco Editor": [
        (r"monaco-editor", "strict"),
    ],
    "PDF.js": [
        (r"pdfjs-dist", "strict"),
        (r"pdf\.worker", "strict"),
    ],
    "FormatJS / react-intl": [
        (r"@formatjs/", "strict"),
        (r"IntlMessageFormat", "strict"),
    ],
    "LaunchDarkly": [
        (r"launchdarkly", "strict"),
        (r"ldclient", "strict"),
    ],
    "Unleash": [
        (r"unleash-client", "strict"),
    ],
    "Statsig": [
        (r"statsig-js", "strict"),
    ],
    "Split.io": [
        (r"split\.io", "strict"),
    ],
    "Optimizely": [
        (r"cdn\.optimizely\.com", "strict"),
    ],
    "GrowthBook": [
        (r"growthbook", "strict"),
    ],
    "Typeform": [
        (r"embed\.typeform\.com", "strict"),
    ],
    "Satismeter": [
        (r"satismeter", "strict"),
    ],
    "Weglot": [
        (r"weglot", "strict"),
    ],
    "GTM": [
        (r"www\.googletagmanager\.com/gtm\.js", "strict"),
        (r"GTM-[A-Z0-9]{5,}", "strict"),
    ],
    "Matomo / Piwik": [
        (r"matomo\.js", "strict"),
        (r"matomo\.php", "strict"),
        (r"piwik\.js", "strict"),
    ],
    "Adobe Analytics": [
        (r"adobedtm\.com", "strict"),
        (r"s_code\.js", "strict"),
    ],
    "Snowplow": [
        (r"snowplow", "strict"),
        (r"sp\.js", "loose"),
    ],
    "Rudderstack": [
        (r"rudderlabs\.com", "strict"),
    ],
}

SANITIZER_RULES: Dict[str, List[str]] = {
    "dompurify": [r"dompurify", r"dompurify\.sanitize"],
    "sanitize_html": [r"sanitize-html"],
    "xss_lib": [r"\bxss\("],
    "he": [r"html-entities"],
    "sanitize_url": [r"sanitize-url"],
    "markdown-it": [r"markdown-it"],
    "DOMPurify_wrapper": [r"sanitizer\s*:\s*dompurify"],
}


# -----------------------------------------------------------------------------
# PRECOMPILACIÓN de reglas tier-based (se hace una vez al importar el módulo)
# -----------------------------------------------------------------------------
def _compile_tier_rules(
    rules: Dict[str, List[_Rule]]
) -> Dict[str, List[Tuple[Any, str]]]:
    """Precompila todos los regex una sola vez al arrancar."""
    out: Dict[str, List[Tuple[Any, str]]] = {}
    for name, patterns in rules.items():
        compiled: List[Tuple[Any, str]] = []
        for pat, tier in patterns:
            try:
                compiled.append((re.compile(pat, re.IGNORECASE), tier))
            except re.error:
                # patrón inválido — lo saltamos silenciosamente
                continue
        if compiled:
            out[name] = compiled
    return out


_COMPILED_FRAMEWORK_RULES = _compile_tier_rules(FRAMEWORK_RULES)
_COMPILED_CMS_RULES = _compile_tier_rules(CMS_RULES)
_COMPILED_HOSTED_PLATFORM_RULES = _compile_tier_rules(HOSTED_PLATFORM_RULES)
_COMPILED_DEV_TOOLS_RULES = _compile_tier_rules(DEV_TOOLS_RULES)
_COMPILED_NETWORK_APPLIANCE_RULES = _compile_tier_rules(NETWORK_APPLIANCE_RULES)
_COMPILED_IDP_RULES = _compile_tier_rules(IDP_RULES)
_COMPILED_LIBRARY_RULES = _compile_tier_rules(LIBRARY_RULES)

# Dict categoría → (reglas compiladas, display name)
_ALL_TIER_CATEGORIES = {
    "frameworks": (_COMPILED_FRAMEWORK_RULES, "framework"),
    "cms": (_COMPILED_CMS_RULES, "cms"),
    "hosted_platforms": (_COMPILED_HOSTED_PLATFORM_RULES, "hosted_platform"),
    "dev_tools": (_COMPILED_DEV_TOOLS_RULES, "dev_tool"),
    "network_appliances": (_COMPILED_NETWORK_APPLIANCE_RULES, "network_appliance"),
    "idps": (_COMPILED_IDP_RULES, "idp"),
    "libraries": (_COMPILED_LIBRARY_RULES, "library"),
}


THIRD_PARTY_RULES: Dict[str, Dict[str, List[str]]] = {
    "analytics": {
        "posthog": [r"posthog", r"phc_[a-z0-9]"],
        "google_tag_manager": [r"googletagmanager", r"gtm-[a-z0-9]+"],
        "matomo": [r"matomo", r"piwik"],
        "segment": [r"segment\.com", r"analytics\.js"],
        "mixpanel": [r"mixpanel"],
        "amplitude": [r"amplitude\.com"],
        "plausible": [r"plausible\.io"],
        "hotjar": [r"hotjar", r"hj\("],
    },
    "error_tracking": {
        "sentry": [r"sentry", r"captureexception"],
        "rollbar": [r"rollbar"],
        "bugsnag": [r"bugsnag"],
        "datadog_rum": [r"datadoghq", r"dd-rum"],
        "new_relic": [r"newrelic", r"nr-data"],
    },
    "chat": {
        "intercom": [r"intercom"],
        "drift": [r"drift"],
        "zendesk": [r"zendesk", r"zdassets"],
        "crisp": [r"crisp\.chat"],
    },
    "surveys": {
        "satismeter": [r"satismeter"],
        "typeform": [r"typeform"],
        "hotjar": [r"hotjar"],
    },
    "translation": {
        "weglot": [r"weglot"],
        "transifex": [r"transifex"],
        "lokalise": [r"lokalise"],
    },
    "feature_flags": {
        "launchdarkly": [r"launchdarkly", r"ldclient"],
        "unleash": [r"unleash"],
        "statsig": [r"statsig"],
        "split_io": [r"split\.io"],
    },
    "cdn_storage": {
        "aws_s3": [r"\.s3\.amazonaws\.com", r"s3\.[a-z0-9-]+\.amazonaws\.com"],
        "gcs": [r"storage\.googleapis\.com"],
        "azure_blob": [r"\.blob\.core\.windows\.net"],
        "cloudfront": [r"\.cloudfront\.net"],
    },
    "auth_as_service": {
        "auth0": [r"auth0\.com", r"auth0-spa"],
        "okta": [r"okta\.com"],
        "firebase_auth": [r"firebaseauth"],
        "keycloak": [r"keycloak"],
        "cognito": [r"cognito-idp"],
    },
    "payments": {
        "stripe": [r"js\.stripe\.com"],
        "paypal": [r"paypal\.com/sdk"],
    },
}

# Patrones de secretos. El enfoque: pattern + label + entropy opcional.
# El scanner aplica contexto y ventana alrededor del match para reducir FPs.
SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    # (name, regex, severity)
    ("aws_access_key_id", r"\bAKIA[0-9A-Z]{16}\b", "high"),
    ("aws_secret_access_key",
     r"(?i)aws(.{0,20})?(secret|access)(.{0,20})?['\"]([A-Za-z0-9/+=]{40})['\"]",
     "high"),
    ("aws_session_token", r"\bFQoGZXIvYXdzE[0-9A-Za-z/+=]{100,}\b", "high"),
    ("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "high"),
    ("google_oauth", r"\bya29\.[0-9A-Za-z_\-]{20,}\b", "high"),
    ("gcp_service_account",
     r'"type"\s*:\s*"service_account"', "high"),
    ("firebase_url", r"\bhttps?://[a-z0-9-]+\.firebaseio\.com\b", "medium"),
    ("firebase_config",
     r'apiKey["\']\s*:\s*["\']AIza[0-9A-Za-z_\-]{35}["\']', "medium"),
    ("github_pat",
     r"\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b", "high"),
    ("github_oauth", r"\bgho_[A-Za-z0-9]{36}\b", "high"),
    ("github_app", r"\b(ghu|ghs)_[A-Za-z0-9]{36}\b", "high"),
    ("slack_token",
     r"\bxox[pborsa]-\d+-\d+-\d+-[0-9a-f]{32}\b", "high"),
    ("slack_webhook",
     r"\bhttps://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24}\b",
     "high"),
    ("discord_bot_token",
     r"\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b", "high"),
    ("stripe_live_key", r"\bsk_live_[0-9a-zA-Z]{24,}\b", "high"),
    ("stripe_test_key", r"\bsk_test_[0-9a-zA-Z]{24,}\b", "low"),
    ("stripe_publishable",
     r"\bpk_(live|test)_[0-9a-zA-Z]{24,}\b", "low"),
    ("mailgun", r"\bkey-[0-9a-zA-Z]{32}\b", "medium"),
    ("sendgrid", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", "high"),
    ("twilio_sid", r"\bAC[a-f0-9]{32}\b", "medium"),
    ("twilio_auth", r'(?i)twilio.{0,20}[0-9a-f]{32}', "medium"),
    ("npm_token", r"\bnpm_[A-Za-z0-9]{36}\b", "high"),
    ("heroku_api_key",
     r"\b[hH]eroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
     "medium"),
    ("mapbox_token", r"\bpk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]+\b",
     "medium"),
    ("algolia_admin",
     r'(?i)algolia.{0,20}[0-9a-f]{32}', "medium"),
    ("algolia_app_id",
     r'(?i)algolia.{0,20}["\'][A-Z0-9]{10}["\']', "low"),
    ("sentry_dsn",
     r"\bhttps?://[a-f0-9]{20,}@[a-z0-9.-]+/\d+\b", "medium"),
    ("gtm_id", r"\bGTM-[A-Z0-9]{5,}\b", "info"),
    ("ga_tracking", r"\bUA-\d{4,}-\d{1,4}\b", "info"),
    ("ga4_id", r"\bG-[A-Z0-9]{8,12}\b", "info"),
    ("posthog_key", r"\bphc_[A-Za-z0-9]{30,}\b", "medium"),
    ("generic_bearer_hardcoded",
     r'(?i)(?:bearer|authorization)["\']?\s*[:=]\s*["\'](eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*)["\']',
     "high"),
    ("jwt_standalone",
     r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
     "medium"),
    ("rsa_private_key",
     r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----",
     "high"),
    ("putty_key", r"PuTTY-User-Key-File-\d", "high"),
    ("generic_api_key_assign",
     r"(?i)(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)"
     r"""["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{24,})["']""",
     "low"),
    ("basic_auth_url",
     r"\b[a-z]+://[A-Za-z0-9_\-.%]+:[^@\s/]{4,}@[A-Za-z0-9.\-]+", "medium"),
    ("postgres_dsn",
     r"\bpostgres(?:ql)?://[^\s'\"<>]+", "medium"),
    ("mongo_dsn",
     r"\bmongodb(?:\+srv)?://[^\s'\"<>]+", "medium"),
    ("redis_dsn", r"\bredis://[^\s'\"<>]+", "medium"),
    ("s3_uri", r"\bs3://[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9](?:/[^\s'\"]*)?\b",
     "low"),
]

# Parámetros típicos de open redirect / SSRF. Si aparecen en endpoints/links,
# se flaggean como "interesting" para auditar manualmente.
OPEN_REDIRECT_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "redir", "return",
    "return_to", "returnto", "return_url", "returnurl", "next",
    "continue", "url", "goto", "destination", "dest", "target",
    "forward", "callback", "back", "r", "u", "rurl", "view",
    "link", "out", "go", "referer", "ref", "image_url", "site",
    "window", "ourl", "to", "from", "path",
}

# Headers que conviene resaltar en la salida.
SECURITY_HEADER_KEYS = [
    "content-security-policy",
    "content-security-policy-report-only",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "expect-ct",
]


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class Observation:
    name: str
    source: str
    confidence: str
    version: Optional[str] = None
    details: Optional[str] = None


@dataclass
class SecretFinding:
    name: str
    severity: str
    source: str           # ej: "asset_sample:main.js" / "inline_script" / "headers"
    match_preview: str    # primeros/últimos chars enmascarados
    entropy: Optional[float] = None
    context: Optional[str] = None


@dataclass
class CSPPolicy:
    raw: Optional[str] = None
    report_only: bool = False
    directives: Dict[str, List[str]] = field(default_factory=dict)
    report_uri: List[str] = field(default_factory=list)
    report_to: Optional[str] = None
    nonce_used: bool = False
    strict_dynamic: bool = False
    unsafe_inline: bool = False
    unsafe_eval: bool = False
    has_wildcard_sources: bool = False
    wildcard_directives: List[str] = field(default_factory=list)
    allowed_origins: List[str] = field(default_factory=list)


@dataclass
class SSOSignal:
    provider: str
    category: str       # "consumer" | "enterprise" | "gov" | "protocol"
    confidence: str     # "high" | "medium" | "low"
    source: str


# =============================================================================
# SSO providers (provider, category, [patterns])
# =============================================================================

SSO_PROVIDERS: List[Tuple[str, str, List[str]]] = [
    # consumer
    ("google",      "consumer", ["accounts.google.com", "google-signin", "apis.google.com/js/platform"]),
    ("facebook",    "consumer", ["connect.facebook.net", "facebook.com/v2.0/dialog/oauth", "facebook.com/dialog/oauth"]),
    ("apple",       "consumer", ["appleid.apple.com", "sign in with apple", "appleid-signin"]),
    ("github",      "consumer", ["github.com/login/oauth"]),
    ("gitlab",      "consumer", ["gitlab.com/oauth"]),
    ("bitbucket",   "consumer", ["bitbucket.org/site/oauth2"]),
    ("twitter_x",   "consumer", ["twitter.com/i/oauth", "api.twitter.com/oauth", "x.com/i/oauth"]),
    ("linkedin",    "consumer", ["linkedin.com/oauth"]),
    ("discord",     "consumer", ["discord.com/api/oauth2"]),
    ("twitch",      "consumer", ["id.twitch.tv/oauth2"]),
    ("spotify",     "consumer", ["accounts.spotify.com"]),
    ("slack",       "consumer", ["slack.com/oauth"]),
    ("dropbox",     "consumer", ["dropbox.com/oauth2"]),
    ("amazon",      "consumer", ["amazon.com/ap/oa", "login with amazon"]),
    ("steam",       "consumer", ["steamcommunity.com/openid"]),
    ("yahoo",       "consumer", ["api.login.yahoo.com/oauth2"]),
    ("wechat",      "consumer", ["open.weixin.qq.com"]),
    ("line",        "consumer", ["access.line.me/oauth2"]),
    ("kakao",       "consumer", ["kauth.kakao.com"]),
    ("naver",       "consumer", ["nid.naver.com/oauth2"]),
    ("vk",          "consumer", ["oauth.vk.com"]),
    ("yandex",      "consumer", ["oauth.yandex"]),
    ("weibo",       "consumer", ["api.weibo.com/oauth2"]),

    # enterprise
    ("azure_ad_entra",  "enterprise", ["login.microsoftonline.com", "login.windows.net", "login.microsoft.com"]),
    ("adfs",            "enterprise", ["/adfs/ls/", "msisauth"]),
    ("okta",            "enterprise", [".okta.com", "okta-signin-widget"]),
    ("auth0",           "enterprise", [".auth0.com", "auth0-spa-js"]),
    ("keycloak",        "enterprise", ["/auth/realms/", "kc_idp_hint"]),
    ("ping_identity",   "enterprise", ["pingidentity", "pingfederate", "pingone.com"]),
    ("forgerock",       "enterprise", ["forgerock", "openam/"]),
    ("onelogin",        "enterprise", ["onelogin.com"]),
    ("jumpcloud",       "enterprise", ["jumpcloud.com"]),
    ("cognito",         "enterprise", ["cognito-idp."]),
    ("gcp_identity",    "enterprise", ["identitytoolkit.googleapis.com"]),
    ("firebase_auth",   "enterprise", ["securetoken.googleapis.com"]),
    ("wso2",            "enterprise", ["wso2is", "/carbon/admin/"]),
    ("gluu",            "enterprise", ["gluu.org", "/oxauth/"]),
    ("authelia",        "enterprise", ["authelia"]),
    ("authentik",       "enterprise", ["goauthentik"]),
    ("ory",             "enterprise", ["ory.sh", "ory-hydra", "ory-kratos"]),
    ("supertokens",     "enterprise", ["supertokens"]),
    ("clerk",           "enterprise", ["clerk.accounts", "clerk-js"]),
    ("workos",          "enterprise", ["workos.com"]),
    ("stytch",          "enterprise", ["stytch.com"]),
    ("fusionauth",      "enterprise", ["fusionauth"]),
    ("frontegg",        "enterprise", ["frontegg"]),
    ("descope",         "enterprise", ["descope.com"]),
    ("kinde",           "enterprise", ["kinde.com"]),
    ("loginradius",     "enterprise", ["loginradius"]),
    ("miniorange",      "enterprise", ["miniorange"]),
    ("shibboleth",      "enterprise", ["/idp/profile/saml2/", "shibboleth"]),
    ("simplesamlphp",   "enterprise", ["simplesamlphp", "/simplesaml/"]),
    ("siteminder",      "enterprise", ["smsession", "siteminder"]),
    ("oracle_oam",      "enterprise", ["oam_req", "oracle access manager"]),
    ("ibm_security_verify", "enterprise", ["ibmsecurityverify"]),

    # gov
    ("id_me",           "gov", ["id.me/oauth"]),
    ("login_gov",       "gov", ["secure.login.gov"]),
    ("franceconnect",   "gov", ["franceconnect.gouv.fr"]),
    ("bankid_se",       "gov", ["bankid.com"]),
    ("mitid",           "gov", ["mitid.dk"]),
    ("itsme",           "gov", ["itsme.be"]),
    ("spid",            "gov", ["spid.gov.it"]),
    ("digid",           "gov", ["digid.nl"]),
    ("clave",           "gov", ["clave.gob.es"]),
    ("singpass",        "gov", ["singpass.gov.sg"]),
    ("aadhaar",         "gov", ["uidai.gov.in"]),
    ("gov_uk_verify",   "gov", ["verify.service.gov.uk"]),
    ("mygovid",         "gov", ["mygovid"]),

    # protocol (no es un proveedor, pero indica qué se está usando)
    ("oidc_generic",    "protocol", [".well-known/openid-configuration", "id_token"]),
    ("oauth2_generic",  "protocol", ["response_type=code", "redirect_uri=", "client_id="]),
    ("oauth1",          "protocol", ["oauth_consumer_key", "oauth_token"]),
    ("saml2_generic",   "protocol", ["samlrequest", "samlresponse", "relaystate"]),
    ("ws_federation",   "protocol", ["wsfederation", "wa=wsignin"]),
    ("cas",             "protocol", ["/cas/login", "casticket"]),
    ("webauthn_fido2",  "protocol", ["navigator.credentials.create", "publickeycredential"]),
]


# =============================================================================
# Clase principal
# =============================================================================

class Fingerprinter:
    def __init__(
        self,
        target_url: str,
        timeout: int = DEFAULT_TIMEOUT,
        user_agent: str = DEFAULT_UA,
        render: bool = False,
        local_js: Optional[List[str]] = None,
        max_assets: int = DEFAULT_MAX_ASSETS,
        scope: Optional[str] = None,
        no_path_probes: bool = False,
        no_source_map_check: bool = False,
        download_interesting: bool = False,
        download_dir: str = "downloads",
        extra_probes: bool = False,
        concurrency: int = DEFAULT_CONCURRENCY,
        proxy: Optional[str] = None,
        insecure: bool = False,
        no_tls_info: bool = False,
        verbose: bool = False,
        no_param_mining: bool = False,
        no_tech_probes: bool = False,
        wayback: bool = False,
        wayback_limit: int = 500,
        wayback_since: Optional[str] = None,
        ct_logs: bool = False,
        ct_limit: int = 300,
        tech_probe_only: Optional[List[str]] = None,
    ) -> None:
        self.input_url = target_url
        parsed_target = urlparse(target_url)
        if parsed_target.scheme.lower() not in {"http", "https"} or not parsed_target.hostname:
            raise ScopeError("El target debe ser una URL HTTP(S) con hostname válido.")
        if parsed_target.username is not None or parsed_target.password is not None:
            raise ScopeError("No se admiten credenciales embebidas en el URL objetivo.")
        self.scope = scope or parsed_target.hostname
        self.scope_policy = HostScope.parse(self.scope)
        if not self.scope_policy.matches_url(target_url):
            raise ScopeError("El URL objetivo no pertenece al scope declarado.")
        self.timeout = timeout
        self.render = render
        self.local_js = local_js or []
        self.max_assets = max_assets
        self.no_path_probes = no_path_probes
        self.no_source_map_check = no_source_map_check
        self.download_interesting = download_interesting
        self.download_dir = download_dir
        self.extra_probes = extra_probes
        self.concurrency = max(1, min(32, concurrency))
        self.proxy = proxy
        self.insecure = insecure
        self.no_tls_info = no_tls_info
        self.verbose = verbose
        self.no_param_mining = no_param_mining
        self.no_tech_probes = no_tech_probes
        self.wayback = wayback
        self.wayback_limit = max(1, wayback_limit)
        self.wayback_since = wayback_since
        self.ct_logs = ct_logs
        self.ct_limit = max(1, ct_limit)
        self.tech_probe_only = set(tech_probe_only or [])
        self.feature_stats: Dict[str, Dict[str, Any]] = {}
        self.downloaded_assets: List[Dict[str, Any]] = []

        self.session = self._build_session(user_agent)

        self.final_url = target_url
        self.main_response: Optional[requests.Response] = None
        self.main_html = ""
        self.soup: Optional[BeautifulSoup] = None
        self.asset_samples: Dict[str, str] = {}
        self.asset_bodies: Dict[str, str] = {}
        self.observed_texts: List[Tuple[str, str]] = []
        self.inline_script_texts: List[str] = []
        self.page_endpoint_cache: List[Dict[str, Any]] = []
        self.page_action_cache: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    @contextmanager
    def _time_feature(self, name: str):
        start = time.monotonic()
        stats = {"enabled": True, "elapsed_ms": 0, "items_found": 0, "errors": 0}
        self.feature_stats[name] = stats
        try:
            yield stats
        finally:
            stats["elapsed_ms"] = int((time.monotonic() - start) * 1000)

    def is_in_scope_hostname(self, hostname: str) -> bool:
        return self.scope_policy.matches_host(hostname)

    # --------------------------------------------------------------
    # Session building con retry, proxy, TLS opcional
    # --------------------------------------------------------------
    def _build_session(self, user_agent: str) -> requests.Session:
        scope_policy = self.scope_policy

        class ScopeEnforcingSession(requests.Session):
            def get_redirect_target(self, response):
                location = super().get_redirect_target(response)
                if location:
                    resolved = urljoin(response.url, location)
                    if not scope_policy.matches_url(resolved):
                        raise requests.RequestException(
                            "Redirect blocked because its destination leaves the authorized scope."
                        )
                return location

        session = ScopeEnforcingSession()
        session.headers.update({
            "User-Agent": user_agent,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.8,es;q=0.6",
        })
        if self.proxy:
            session.proxies.update({"http": self.proxy, "https": self.proxy})
        if self.insecure:
            session.verify = False
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
        if Retry is not None:
            retry = Retry(
                total=2,
                backoff_factor=0.4,
                status_forcelist=(500, 502, 503, 504),
                allowed_methods=frozenset(["HEAD", "GET", "OPTIONS"]),
                raise_on_status=False,
            )
            adapter = HTTPAdapter(max_retries=retry, pool_connections=16,
                                  pool_maxsize=32)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
        return session

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"[recon] {msg}", file=sys.stderr, flush=True)

    # --------------------------------------------------------------
    # Orquestador principal
    # --------------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        self.feature_stats = {}
        self._log(f"fetching main: {self.input_url}")
        http_info = self.fetch_main()

        tls_info: Dict[str, Any] = {}
        if not self.no_tls_info and self.final_url.startswith("https://"):
            self._log("fetching TLS cert info")
            tls_info = self.fetch_tls_info()

        html_info = self.parse_html()
        assets_info = self.inventory_assets(html_info)

        parameter_intelligence: Dict[str, Any] = {"summary": {"total_unique_params": 0, "by_category": {}, "high_value_count": 0}, "top_params": [], "custom_headers": [], "storage_keys": []}
        if not self.no_param_mining:
            self._log("mining parameters from JS/HTML")
            parameter_intelligence = self.mine_parameters(html_info, assets_info)
        else:
            self.feature_stats["parameter_mining"] = {"enabled": False, "elapsed_ms": 0, "items_found": 0, "errors": 0}

        download_info: Dict[str, Any] = {}
        if self.download_interesting:
            download_info = self.download_interesting_assets(assets_info)

        path_info: Dict[str, Any] = {}
        if not self.no_path_probes:
            self._log("running path probes")
            path_info = self.path_probes()

        tech_stack = self.detect_tech_stack(http_info, html_info, assets_info)
        tech_specific_probes: Dict[str, Any] = {"triggered_techs": [], "findings": []}
        if not self.no_tech_probes:
            tech_specific_probes = self.run_tech_specific_probes(tech_stack, path_info)
        else:
            self.feature_stats["tech_specific_probes"] = {"enabled": False, "elapsed_ms": 0, "items_found": 0, "errors": 0}

        csp_info = self.parse_csp(http_info)
        cookies_sec = self.analyze_cookies(http_info)
        secrets_info = self.scan_secrets()
        jwt_info = self.extract_jwts()
        auth_surface = self.detect_auth_surface(http_info, html_info, path_info)
        special = self.detect_special_services(html_info, assets_info, path_info)
        custom_stack = self.detect_custom_stack_hints(http_info, html_info)
        redirect_params = self.detect_open_redirect_params(html_info)
        integrity = self.analyze_sri_and_mixed_content(html_info)
        wayback_info = self.fetch_wayback_urls() if self.wayback else {"enabled": False}
        if not self.wayback:
            self.feature_stats["wayback"] = {"enabled": False, "elapsed_ms": 0, "items_found": 0, "errors": 0}
        ct_info = self.fetch_ct_logs() if self.ct_logs else {"enabled": False}
        if not self.ct_logs:
            self.feature_stats["ct_logs"] = {"enabled": False, "elapsed_ms": 0, "items_found": 0, "errors": 0}
        scope_hints = self.build_scope_hints(html_info, assets_info, path_info, tls_info, wayback_info=wayback_info, ct_info=ct_info)
        priorities = self.build_priority_scores(
            http_info, html_info, tech_stack, assets_info, auth_surface,
            path_info, scope_hints, download_info, secrets_info, special,
            csp_info, cookies_sec, redirect_params, custom_stack,
            param_intel=parameter_intelligence, tech_probes_info=tech_specific_probes,
            wayback_info=wayback_info, ct_info=ct_info,
        )
        analyzer_handoff = self.build_analyzer_handoff(
            http_info, html_info, tech_stack, assets_info, auth_surface,
            path_info, scope_hints, priorities, secrets_info, csp_info,
            cookies_sec, special, redirect_params, custom_stack,
            param_intel=parameter_intelligence, tech_probes_info=tech_specific_probes,
        )

        return {
            "meta": {
                "tool": "recon_fingerprint",
                "version": __version__,
                "timestamp": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                "feature_stats": self.feature_stats,
            },
            "target": {"input_url": self.input_url, "final_url": self.final_url},
            "http": http_info,
            "tls": tls_info,
            "html": html_info,
            "tech_stack": tech_stack,
            "csp": asdict(csp_info) if isinstance(csp_info, CSPPolicy) else csp_info,
            "cookies_security": cookies_sec,
            "assets": assets_info,
            "downloads": download_info,
            "auth_surface": auth_surface,
            "path_probes": path_info,
            "parameter_intelligence": parameter_intelligence,
            "tech_specific_probes": tech_specific_probes,
            "wayback": wayback_info,
            "ct_logs": ct_info,
            "secrets": secrets_info,
            "jwts": jwt_info,
            "special_services": special,
            "open_redirect_hints": redirect_params,
            "integrity_checks": integrity,
            "scope_hints": scope_hints,
            "priorities": priorities,
            "analyzer_handoff": analyzer_handoff,
            "custom_stack": custom_stack,
            "notes": self.build_notes(http_info, html_info, tech_stack, assets_info, auth_surface, path_info, secrets_info, csp_info, cookies_sec, special),
        }

    # --------------------------------------------------------------
    # Core fetch: página principal + OPTIONS + CORS reflect test
    # --------------------------------------------------------------
    def fetch_main(self) -> Dict[str, Any]:
        try:
            response = self.session.get(
                self.input_url, timeout=self.timeout, allow_redirects=True,
            )
            self.main_response = response
            self.final_url = response.url
            self.main_html = response.text or ""
        except Exception as exc:
            raise SystemExit(f"[!] Error fetching main URL: {exc}")

        if self.render:
            rendered = self.try_render(self.final_url)
            if rendered:
                self.main_html = rendered

        self.soup = BeautifulSoup(self.main_html, "html.parser")

        redirect_chain = []
        for hop in response.history:
            redirect_chain.append({
                "url": hop.url,
                "status_code": hop.status_code,
                "location": hop.headers.get("Location"),
                "headers": self.lower_headers(hop.headers),
            })

        headers = self.lower_headers(response.headers)
        waf_signals = self.detect_waf(headers, self.main_html)
        cdn_signals = self.detect_cdn(headers)
        security_headers = self.extract_security_headers(headers)
        cookies = self.serialize_cookies(response.cookies, headers)
        server_hints = self.detect_server_hints(headers)

        options_info = self._probe_options(self.final_url)
        cors_reflect = self._probe_cors_reflect(self.final_url)

        http_version = self._http_version_hint(response)

        # observar textos para secret scan y fingerprint
        self.observed_texts.append(("main_html", self.main_html))
        self.observed_texts.append(("headers", json.dumps(headers,
                                                          ensure_ascii=False)))

        return {
            "status_code": response.status_code,
            "http_version": http_version,
            "redirect_chain": redirect_chain,
            "headers": headers,
            "cookies": cookies,
            "server_hints": server_hints,
            "security_headers": security_headers,
            "waf_signals": waf_signals,
            "cdn_signals": cdn_signals,
            "options_probe": options_info,
            "cors_reflect_test": cors_reflect,
            "body_bytes": len(self.main_html or ""),
        }

    def _http_version_hint(self, response: requests.Response) -> Optional[str]:
        raw = getattr(response, "raw", None)
        if raw is None:
            return None
        v = getattr(raw, "version", None)
        # urllib3 expone 10 para HTTP/1.0, 11 para HTTP/1.1. Para HTTP/2 es 20.
        if v == 20:
            return "HTTP/2"
        if v == 11:
            return "HTTP/1.1"
        if v == 10:
            return "HTTP/1.0"
        return None

    def _probe_options(self, url: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"attempted": True}
        try:
            resp = self.session.options(url, timeout=self.timeout,
                                        allow_redirects=True)
            out["status_code"] = resp.status_code
            allow = resp.headers.get("Allow") or resp.headers.get("allow")
            out["allow"] = [m.strip() for m in allow.split(",")] if allow else []
            acam = resp.headers.get("Access-Control-Allow-Methods")
            out["cors_allow_methods"] = (
                [m.strip() for m in acam.split(",")] if acam else []
            )
            out["cors_allow_origin"] = resp.headers.get("Access-Control-Allow-Origin")
            out["cors_allow_credentials"] = resp.headers.get(
                "Access-Control-Allow-Credentials")
            out["cors_allow_headers"] = resp.headers.get("Access-Control-Allow-Headers")
        except Exception as exc:
            out["error"] = str(exc)
        return out

    def _probe_cors_reflect(self, url: str) -> Dict[str, Any]:
        """
        Test rápido de reflected Origin: 1 GET con Origin: https://evil.tld.
        Pasivo-ish: no escala, solo detecta la típica misconfig de reflejar
        Origin y ACAC=true en cualquier request.
        """
        evil = "https://attacker.example"
        out: Dict[str, Any] = {"origin_sent": evil}
        try:
            resp = self.session.get(
                url, timeout=self.timeout, allow_redirects=True,
                headers={"Origin": evil},
            )
            acao = resp.headers.get("Access-Control-Allow-Origin")
            acac = resp.headers.get("Access-Control-Allow-Credentials")
            out["access_control_allow_origin"] = acao
            out["access_control_allow_credentials"] = acac
            out["reflects_origin"] = bool(acao and evil in acao)
            out["wildcard_with_creds"] = (
                acao == "*" and (acac or "").lower() == "true"
            )
            out["null_origin_allowed"] = acao == "null"
            out["exploitable_hint"] = bool(
                out["reflects_origin"] and (acac or "").lower() == "true"
            )
        except Exception as exc:
            out["error"] = str(exc)
        return out

    def try_render(self, url: str) -> Optional[str]:
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
        except Exception:
            return None
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, wait_until="networkidle",
                          timeout=self.timeout * 1000)
                content = page.content()
                browser.close()
                return content
        except Exception:
            return None

    # --------------------------------------------------------------
    # TLS info: SAN extraction → subdominios pasivos + cert hash
    # --------------------------------------------------------------
    def fetch_tls_info(self) -> Dict[str, Any]:
        p = urlparse(self.final_url)
        host = p.hostname
        port = p.port or 443
        if not host:
            return {}
        out: Dict[str, Any] = {"host": host, "port": port}
        try:
            ctx = ssl.create_default_context()
            if self.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = ssock.getpeercert()
                    out["protocol"] = ssock.version()
                    out["cipher"] = ssock.cipher()
            if cert:
                out["subject"] = dict(x[0] for x in cert.get("subject", []))
                out["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                out["not_before"] = cert.get("notBefore")
                out["not_after"] = cert.get("notAfter")
                sans = []
                for typ, val in cert.get("subjectAltName", []):
                    sans.append(f"{typ}:{val}")
                out["subject_alt_names"] = sans
                # SAN DNS hostnames crudos para scope_hints
                san_dns = [v for typ, v in cert.get("subjectAltName", [])
                           if typ.lower() == "dns"]
                out["san_dns"] = san_dns
            if cert_bin:
                import hashlib
                out["cert_sha256"] = hashlib.sha256(cert_bin).hexdigest()
        except Exception as exc:
            out["error"] = str(exc)
        return out

    # --------------------------------------------------------------
    # HTML parsing (robusto, sin crawler)
    # --------------------------------------------------------------
    def parse_html(self) -> Dict[str, Any]:
        assert self.soup is not None
        soup = self.soup

        title = (soup.title.string.strip()
                 if soup.title and soup.title.string else None)
        meta_tags: Dict[str, Any] = {}
        generator = None
        csrf_meta = None
        viewport = None
        inline_globals: List[str] = []
        script_srcs: List[str] = []
        script_entries: List[Dict[str, Any]] = []  # con integrity/crossorigin
        css_links: List[Dict[str, Any]] = []
        forms: List[Dict[str, Any]] = []
        links: List[Dict[str, Any]] = []
        iframes: List[Dict[str, Any]] = []
        data_endpoints: List[Dict[str, Any]] = []
        inline_endpoints: List[Dict[str, Any]] = []
        inline_realtime: List[Dict[str, Any]] = []
        page_actions: List[Dict[str, Any]] = []
        jsonld_blocks: List[Any] = []
        comments: List[str] = []
        images: List[Dict[str, Any]] = []

        for meta in soup.find_all("meta"):
            name = (meta.get("name") or meta.get("property") or
                    meta.get("http-equiv") or "").strip()
            content = (meta.get("content") or "").strip()
            if not name:
                continue
            meta_tags[name] = content
            low_name = name.lower()
            if low_name == "generator":
                generator = content or None
            if low_name in {"csrf-token", "csrf_token", "x-csrf-token"}:
                csrf_meta = name
            if low_name == "viewport":
                viewport = content or None

        for tag in soup.find_all("script"):
            src = tag.get("src")
            script_type = (tag.get("type") or "").lower()
            if src:
                full = self.normalize_url(src)
                if full:
                    script_srcs.append(full)
                    script_entries.append({
                        "url": full,
                        "integrity": tag.get("integrity"),
                        "crossorigin": tag.get("crossorigin"),
                        "type": script_type or None,
                        "nonce": tag.get("nonce"),
                    })
            else:
                text = tag.get_text("\n", strip=False) or ""
                if script_type == "application/ld+json" and text:
                    try:
                        jsonld_blocks.append(json.loads(text))
                    except Exception:
                        pass
                if text:
                    inline_globals.extend(self.extract_inline_globals(text))
                    self.inline_script_texts.append(text)
                    self.observed_texts.append(("inline_script", text))
                    inline_endpoints.extend(
                        self.extract_interesting_strings_from_text(
                            text, source="inline_script")
                    )
                    inline_realtime.extend(
                        self.extract_realtime_strings_from_text(
                            text, source="inline_script")
                    )

        for link in soup.find_all("link"):
            href = link.get("href")
            if not href:
                continue
            rel_tokens = [str(x).lower() for x in (link.get("rel") or [])]
            rel = " ".join(rel_tokens)
            full = self.normalize_url(href)
            if not full:
                continue
            # v3.3: solo stylesheets van a css_links — icons/favicons quedan fuera
            is_stylesheet = "stylesheet" in rel_tokens or full.lower().endswith(".css")
            if is_stylesheet:
                css_links.append({
                    "rel": rel,
                    "url": full,
                    "integrity": link.get("integrity"),
                    "crossorigin": link.get("crossorigin"),
                })
            if self.looks_interesting_endpoint(full):
                links.append({"url": full, "source": "link_href",
                              "label": rel or "link"})

        for a in soup.find_all("a"):
            href = a.get("href") or ""
            full = self.normalize_url(href) or href
            text = a.get_text(" ", strip=True) or ""
            if full:
                entry = {"url": full, "source": "a_href",
                         "label": text[:120]}
                links.append(entry)
                if self.looks_interesting_endpoint(full):
                    page_actions.append({
                        "kind": "link",
                        "action": text[:120] or "link",
                        "url": full,
                        "method": "GET",
                    })

        for iframe in soup.find_all(["iframe", "frame"]):
            raw = iframe.get("src") or ""
            full = self.normalize_url(raw) or raw
            if full:
                iframes.append({"url": full, "source": "iframe_src"})

        for form in soup.find_all("form"):
            inputs = form.find_all(["input", "textarea", "select"])
            has_password = any(
                (i.get("type") or "").lower() == "password" for i in inputs
            )
            hidden_names = [
                i.get("name") for i in inputs
                if (i.get("type") or "").lower() == "hidden" and i.get("name")
            ]
            all_names = [i.get("name") for i in inputs if i.get("name")]
            action = (self.normalize_url(form.get("action") or "") or
                      form.get("action") or "")
            method = (form.get("method") or "GET").upper()
            enctype = (form.get("enctype") or "").lower() or None
            autocomplete = (form.get("autocomplete") or "").lower() or None
            has_captcha_hint = bool(
                form.find(attrs={"class": re.compile(r"captcha|recaptcha|hcaptcha|turnstile", re.I)})
                or form.find(attrs={"id": re.compile(r"captcha|recaptcha|hcaptcha|turnstile", re.I)})
            )
            form_info = {
                "action": action,
                "method": method,
                "enctype": enctype,
                "autocomplete": autocomplete,
                "has_password_field": has_password,
                "has_captcha_hint": has_captcha_hint,
                "hidden_inputs": hidden_names[:15],
                "input_names": all_names[:25],
            }
            forms.append(form_info)
            if action:
                page_actions.append({
                    "kind": "form",
                    "action": action,
                    "method": method,
                    "has_password_field": has_password,
                    "has_captcha_hint": has_captcha_hint,
                    "hidden_inputs": hidden_names[:15],
                })

        for img in soup.find_all("img"):
            src = img.get("src") or img.get("data-src") or ""
            full = self.normalize_url(src) or src
            if full and full.lower().startswith("http"):
                images.append({"url": full})

        # data-* attributes con endpoints
        candidate_data_attrs = {
            "data-url", "data-src", "data-endpoint", "data-api",
            "data-api-url", "data-action", "data-href", "data-link",
            "data-download", "data-upload-url", "data-graphql",
            "data-ws", "data-websocket", "data-callback", "data-return-url",
        }
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                attr_name = str(attr).lower()
                if attr_name.startswith("data-") and isinstance(value, str):
                    if (attr_name in candidate_data_attrs
                            or self.looks_interesting_endpoint(value)):
                        normalized = self.normalize_url(value) or value
                        if normalized:
                            data_endpoints.append({
                                "url": normalized,
                                "source": attr_name,
                                "tag": tag.name,
                            })

        # comentarios HTML (a veces hay endpoints/TODOs/debug info)
        try:
            from bs4 import Comment
            for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
                text = str(c).strip()
                if text and len(text) < 400:
                    comments.append(text)
        except Exception:
            pass

        # Dedupe
        script_srcs = self.dedupe(script_srcs)
        inline_globals = self.dedupe(inline_globals)
        links = self.dedupe(links)
        iframes = self.dedupe(iframes)
        data_endpoints = self.dedupe(data_endpoints)
        inline_endpoints = self.dedupe(inline_endpoints)
        inline_realtime = self.dedupe(inline_realtime)
        # v3.2: separar page_actions en internas y externas
        page_actions_internal, page_actions_external = self.split_actions_by_scope(
            self.dedupe(page_actions)
        )
        images = self.dedupe(images)

        page_endpoints = self.collect_page_endpoints(
            forms=forms, links=links, iframes=iframes,
            data_endpoints=data_endpoints,
            inline_endpoints=inline_endpoints,
            inline_realtime=inline_realtime,
        )
        # v3.2: agrupar endpoints por familia canónica
        page_endpoint_families = self.build_endpoint_families(page_endpoints)
        self.page_endpoint_cache = page_endpoints
        self.page_action_cache = page_actions_internal

        return {
            "title": title,
            "meta_tags": meta_tags,
            "generator": generator,
            "csrf_meta": csrf_meta,
            "viewport": viewport,
            "script_srcs": script_srcs,
            "script_entries": script_entries[:60],
            "css_links": css_links,
            "inline_globals": inline_globals,
            "forms": forms,
            "links": links[:120],
            "iframes": iframes[:40],
            "data_endpoints": data_endpoints[:80],
            "inline_endpoints": inline_endpoints[:120],
            "inline_realtime": inline_realtime[:40],
            "page_actions": page_actions_internal[:120],
            "page_actions_external": page_actions_external[:60],
            "page_endpoints": page_endpoints[:150],
            "page_endpoint_families": page_endpoint_families[:80],
            "jsonld_blocks": jsonld_blocks[:10],
            "html_comments": comments[:30],
            "image_count": len(images),
        }

    def extract_inline_globals(self, text: str) -> List[str]:
        matches = []
        patterns = [
            r"window\.__[A-Z0-9_]+__",
            r"window\.__[A-Za-z0-9_]+",
            r"window\.[A-Za-z_$][A-Za-z0-9_$]{2,}",
            r"drupalSettings",
            r"mw\.config",
        ]
        for pat in patterns:
            matches.extend(re.findall(pat, text))
        return matches[:30]

    # --------------------------------------------------------------
    # Assets: inventario concurrente
    # --------------------------------------------------------------
    def inventory_assets(self, html_info: Dict[str, Any]) -> Dict[str, Any]:
        js_assets: List[Dict[str, Any]] = []
        css_assets: List[Dict[str, Any]] = []

        script_urls = [u for u in html_info.get("script_srcs", [])
                       if self.keep_asset_url(u)][: self.max_assets]
        css_urls = [x["url"] for x in html_info.get("css_links", [])
                    if self.keep_asset_url(x.get("url", ""))][: self.max_assets]

        # JS en paralelo
        if script_urls:
            with ThreadPoolExecutor(max_workers=self.concurrency) as ex:
                futures = {
                    ex.submit(self.inspect_asset, url, "js"): url
                    for url in script_urls
                }
                for fut in as_completed(futures):
                    try:
                        js_assets.append(fut.result())
                    except Exception as exc:
                        js_assets.append({"url": futures[fut],
                                          "error": str(exc)})

        # CSS en paralelo (HEAD solo, menos info)
        if css_urls:
            with ThreadPoolExecutor(max_workers=self.concurrency) as ex:
                futures = {
                    ex.submit(self.inspect_asset, url, "css"): url
                    for url in css_urls
                }
                for fut in as_completed(futures):
                    try:
                        css_assets.append(fut.result())
                    except Exception as exc:
                        css_assets.append({"url": futures[fut],
                                           "error": str(exc)})

        # Local JS bundles (--local-js)
        for local in self.local_js:
            p = Path(local)
            if not p.exists():
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            self.asset_bodies[str(p)] = text
            self.asset_samples[str(p)] = text[:200_000]
            self.observed_texts.append((f"local_js:{p.name}", text[:200_000]))
            sm_url = self.extract_source_map_from_text(text)
            sm_status = self.build_local_sourcemap_status(sm_url)
            js_assets.append({
                "url": str(p),
                "filename": p.name,
                "size_kb": round(p.stat().st_size / 1024, 2),
                "content_type": "application/javascript",
                "asset_role": self.classify_asset_role(p.name),
                "source_map_declared": bool(re.search(
                    r"sourceMappingURL=", text[-1000:], re.I)),
                "source_map_url": sm_url,
                "source_map_accessible": sm_status.get("parses_as_sourcemap"),
                "source_map_status": sm_status,
                "source": "local_file",
            })

        return {"js": js_assets, "css": css_assets}

    def inspect_asset(self, url: str, kind: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "url": url,
            "filename": Path(urlparse(url).path).name,
            "size_kb": None,
            "content_type": None,
            "asset_role": self.classify_asset_role(url),
            "source_map_declared": False,
            "source_map_url": None,
            "source_map_accessible": None,
            "source_map_status": None,
            "source": "remote_asset",
        }
        try:
            head = self.session.head(url, timeout=self.timeout,
                                     allow_redirects=True)
            info["content_type"] = head.headers.get("Content-Type")
            info["http_status"] = head.status_code
            cl = head.headers.get("Content-Length")
            if cl and cl.isdigit():
                info["size_kb"] = round(int(cl) / 1024, 2)
            info["cache_control"] = head.headers.get("Cache-Control")
            info["etag"] = head.headers.get("ETag")
        except Exception:
            pass

        if kind == "js":
            text_sample = self.fetch_text_sample(url)
            if text_sample:
                with self._lock:
                    self.asset_samples[url] = text_sample
                    self.observed_texts.append(
                        (f"asset:{info['filename']}", text_sample)
                    )
                info["source_map_url"] = self.extract_source_map_from_text(
                    text_sample)
                info["source_map_declared"] = bool(info["source_map_url"])
                if info["source_map_declared"] and not self.no_source_map_check:
                    sm_url = self.normalize_url(info["source_map_url"], base=url)
                    info["source_map_url"] = sm_url
                    sm_status = self.inspect_sourcemap(sm_url)
                    info["source_map_status"] = sm_status
                    info["source_map_accessible"] = sm_status.get(
                        "parses_as_sourcemap")
                elif info["source_map_declared"]:
                    info["source_map_status"] = (
                        self.build_declared_only_sourcemap_status(
                            info["source_map_url"], base=url)
                    )
                    info["source_map_accessible"] = None

        return info

    def fetch_text_sample(self, url: str,
                          max_bytes: int = DEFAULT_SAMPLE_BYTES) -> str:
        try:
            resp = self.session.get(url, timeout=self.timeout, stream=True)
            chunks: List[str] = []
            total = 0
            for chunk in resp.iter_content(chunk_size=8192, decode_unicode=True):
                if not chunk:
                    continue
                if isinstance(chunk, bytes):
                    piece = chunk.decode("utf-8", errors="ignore")
                else:
                    piece = chunk
                chunks.append(piece)
                total += len(piece)
                if total >= max_bytes:
                    break
            return "".join(chunks)
        except Exception:
            return ""

    def download_interesting_assets(
            self, assets_info: Dict[str, Any]) -> Dict[str, Any]:
        host = urlparse(self.final_url).netloc or "target"
        host_dir = Path(self.download_dir) / self.safe_fs_name(host)
        host_dir.mkdir(parents=True, exist_ok=True)

        manifest: List[Dict[str, Any]] = []
        for asset in assets_info.get("js", []):
            if not self.is_interesting_asset(asset):
                continue
            downloaded = self.download_one_asset(asset.get("url"), host_dir)
            if downloaded:
                manifest.append({
                    "url": asset.get("url"),
                    "saved_to": downloaded,
                    "asset_role": asset.get("asset_role"),
                    "source_map_declared": asset.get("source_map_declared"),
                })

            sm_url = asset.get("source_map_url")
            sm_status = asset.get("source_map_status") or {}
            if (asset.get("source_map_declared")
                    and sm_status.get("parses_as_sourcemap") and sm_url):
                sm_downloaded = self.download_one_asset(sm_url, host_dir)
                if sm_downloaded:
                    manifest.append({
                        "url": sm_url,
                        "saved_to": sm_downloaded,
                        "asset_role": "source_map",
                        "source_map_declared": True,
                    })

        manifest_path = host_dir / "download_manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self.downloaded_assets = manifest
        return {
            "enabled": True,
            "download_dir": str(host_dir),
            "downloaded_count": len(manifest),
            "manifest_path": str(manifest_path),
            "items": manifest,
        }

    def is_interesting_asset(self, asset: Dict[str, Any]) -> bool:
        url = (asset.get("url") or "").lower()
        role = (asset.get("asset_role") or "").lower()
        filename = (asset.get("filename") or "").lower()
        size_kb = asset.get("size_kb") or 0
        content_type = (asset.get("content_type") or "").lower()

        if role == "vendor":
            return False

        if any(x in filename for x in ["main", "app", "index", "bundle", "entry"]):
            return True

        if any(x in url for x in ["main", "app", "index", "bundle", "entry"]):
            return True

        if asset.get("source_map_declared"):
            return True

        # assets dinámicos o no-vendor con tamaño decente
        if size_kb and size_kb >= 20:
            return True

        # endpoints de script raros pero útiles
        if any(x in filename for x in [".ctrl", ".axd", ".ashx", ".asmx"]):
            return True

        # si parece JS aunque el nombre sea raro
        if "javascript" in content_type and role != "vendor":
            return True

        return False

    def download_one_asset(self, url: Optional[str], host_dir: Path) -> Optional[str]:
        if not url:
            return None
        try:
            resp = self.session.get(url, timeout=self.timeout, stream=True)
            if resp.status_code != 200:
                return None

            parsed = urlparse(url)
            filename = Path(parsed.path).name or "downloaded_asset"

            # conservar query string para distinguir assets dinámicos
            if parsed.query:
                filename = f"{filename}__{parsed.query}"

            local_name = self.safe_fs_name(filename)
            destination = host_dir / local_name
            counter = 1
            while destination.exists():
                stem = destination.stem
                suffix = destination.suffix
                destination = host_dir / f"{stem}_{counter}{suffix}"
                counter += 1

            with destination.open("wb") as f:
                shutil.copyfileobj(resp.raw, f)

            return str(destination)
        except Exception:
            return None

    def safe_fs_name(self, value: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
        return cleaned or "file"

    # --------------------------------------------------------------
    # Tech stack detection
    # --------------------------------------------------------------
    def detect_tech_stack(self, http_info: Dict[str, Any],
                          html_info: Dict[str, Any],
                          assets_info: Dict[str, Any]) -> Dict[str, Any]:
        pool = self.make_text_pool(http_info, html_info, assets_info)
        frameworks = self.detect_named_entities(
            _COMPILED_FRAMEWORK_RULES, pool, "framework")
        cms = self.detect_named_entities(
            _COMPILED_CMS_RULES, pool, "cms")
        hosted = self.detect_named_entities(
            _COMPILED_HOSTED_PLATFORM_RULES, pool, "hosted_platform")
        dev_tools = self.detect_named_entities(
            _COMPILED_DEV_TOOLS_RULES, pool, "dev_tool")
        network_appliances = self.detect_named_entities(
            _COMPILED_NETWORK_APPLIANCE_RULES, pool, "network_appliance")
        idps = self.detect_named_entities(
            _COMPILED_IDP_RULES, pool, "idp")
        libraries = self.detect_named_entities(
            _COMPILED_LIBRARY_RULES, pool, "library")
        sanitizers = self.detect_sanitizers(pool, http_info)
        third_party = self.detect_third_party(pool)
        server_tech = self.infer_server_tech(http_info, html_info)
        return {
            "frameworks": [asdict(x) for x in frameworks],
            "cms": [asdict(x) for x in cms],
            "hosted_platforms": [asdict(x) for x in hosted],
            "dev_tools": [asdict(x) for x in dev_tools],
            "network_appliances": [asdict(x) for x in network_appliances],
            "idps": [asdict(x) for x in idps],
            "libraries": [asdict(x) for x in libraries],
            "sanitizers": sanitizers,
            "server_tech": server_tech,
            "third_party_services": third_party,
        }

    def make_text_pool(self, http_info: Dict[str, Any],
                       html_info: Dict[str, Any],
                       assets_info: Dict[str, Any]) -> List[Tuple[str, str]]:
        pool: List[Tuple[str, str]] = []
        pool.extend(self.observed_texts)
        pool.append(("meta_tags", json.dumps(
            html_info.get("meta_tags", {}), ensure_ascii=False)))
        pool.append(("script_srcs",
                     "\n".join(html_info.get("script_srcs", []))))
        pool.append(("css_links", json.dumps(
            html_info.get("css_links", []), ensure_ascii=False)))
        pool.append(("server_hints", json.dumps(
            http_info.get("server_hints", []), ensure_ascii=False)))
        pool.append(("title",
                     str(html_info.get("title") or "")))
        for js in assets_info.get("js", []):
            url = js.get("url") or ""
            if url in self.asset_samples:
                pool.append((
                    f"asset_sample:{Path(urlparse(url).path).name}",
                    self.asset_samples[url],
                ))
        return pool

    def detect_named_entities(
        self,
        compiled_rules: Dict[str, List[Tuple[Any, str]]],
        text_pool: List[Tuple[str, str]],
        kind: str,
    ) -> List[Observation]:
        """
        Nuevo sistema tier-based (v3.0).

        Para cada entity, cuenta hits strict y hits loose (de sources distintos).
        Umbrales:
            - strict ≥ 2                        → high
            - strict = 1 y loose ≥ 1            → medium
            - strict = 1                        → low
            - strict = 0 y loose ≥ 2            → low (informational)
            - strict = 0 y loose ≤ 1            → no se reporta

        compiled_rules: {name: [(compiled_regex, tier), ...]}
        """
        results: List[Observation] = []

        for name, rules in compiled_rules.items():
            strict_sources: set = set()
            loose_sources: set = set()
            version: Optional[str] = None
            details_bits: List[str] = []

            for source_name, text in text_pool:
                if not text:
                    continue
                for compiled_re, tier in rules:
                    m = compiled_re.search(text)
                    if not m:
                        continue
                    if tier == "strict":
                        strict_sources.add(source_name)
                    else:
                        loose_sources.add(source_name)
                    if version is None:
                        version = self._extract_version_near_match(text, m)
                    # una sola regla por source-text es suficiente para no
                    # contar 5 veces el mismo source si matchea varias reglas.
                    break

            strict_n = len(strict_sources)
            loose_n = len(loose_sources)

            # Threshold tier-based
            if strict_n >= 2:
                confidence = "high"
            elif strict_n == 1 and loose_n >= 1:
                confidence = "medium"
            elif strict_n == 1:
                confidence = "low"
            elif strict_n == 0 and loose_n >= 2:
                confidence = "low"
                details_bits.append("loose-only")
            else:
                # strict=0 loose<=1 → ignorar (anti-FP)
                continue

            all_sources = sorted(strict_sources | loose_sources)[:4]
            details = (", ".join(details_bits)) or None
            results.append(Observation(
                name=name,
                source=", ".join(all_sources),
                confidence=confidence,
                version=version,
                details=details,
            ))

        results.sort(key=lambda x: (self.conf_rank(x.confidence),
                                    x.name.lower()))
        return results

    def _extract_version_near_match(self, text: str,
                                     match: Any) -> Optional[str]:
        try:
            start = max(0, match.start() - 80)
            end = min(len(text), match.end() + 120)
            window = text[start:end]
            v = re.search(r"\bv?(\d+\.\d+(?:\.\d+)?)\b", window)
            return v.group(1) if v else None
        except Exception:
            return None

    def detect_sanitizers(self, text_pool: List[Tuple[str, str]],
                          http_info: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        all_text = "\n".join(text for _, text in text_pool)
        low = all_text.lower()
        for name, patterns in SANITIZER_RULES.items():
            out[name] = any(re.search(p, low, re.I) for p in patterns)

        custom = sorted(set(re.findall(
            r"\b(?:sanitize|sanitise|escape|clean)[A-Za-z0-9_]*\s*\(",
            all_text, re.I,
        )))
        out["custom_sanitizer_signals"] = custom[:12]

        csp = http_info.get("security_headers", {}).get("csp") or ""
        csp_low = csp.lower()
        out["csp_blocks_inline"] = bool(csp and "'unsafe-inline'" not in csp_low)
        out["csp_blocks_eval"] = bool(csp and "'unsafe-eval'" not in csp_low)
        return out

    def detect_third_party(self, text_pool: List[Tuple[str, str]]) -> Dict[str, Any]:
        all_text = "\n".join(text for _, text in text_pool)
        low = all_text.lower()
        result: Dict[str, Any] = {}
        for category, providers in THIRD_PARTY_RULES.items():
            present = []
            for provider, patterns in providers.items():
                if any(re.search(p, low, re.I) for p in patterns):
                    present.append(provider)
            if present:
                result[category] = sorted(set(present))

        # IDs/keys puntuales
        m = re.search(r"https?://[a-f0-9]{20,}@[a-z0-9.-]+/\d+", all_text, re.I)
        if m:
            result["sentry_dsn"] = m.group(0)
        m = re.search(r"\bphc_[A-Za-z0-9]{20,}\b", all_text)
        if m:
            result["posthog_key"] = m.group(0)
        m = re.search(r"\bGTM-[A-Z0-9]{4,}\b", all_text)
        if m:
            result["gtm_id"] = m.group(0)
        m = re.search(r"\bG-[A-Z0-9]{8,12}\b", all_text)
        if m:
            result["ga4_id"] = m.group(0)
        return result

    def infer_server_tech(self, http_info: Dict[str, Any],
                          html_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        results: List[Observation] = []
        for hint in http_info.get("server_hints", []):
            name = hint.get("name")
            source = hint.get("source", "headers")
            if name:
                results.append(Observation(
                    name=name, source=source, confidence="high",
                    version=hint.get("version"),
                ))
        generator = html_info.get("generator")
        if generator:
            results.append(Observation(
                name=generator, source="meta_generator", confidence="high"))
        return [asdict(x) for x in results]

    # --------------------------------------------------------------
    # CSP parser real
    # --------------------------------------------------------------
    def parse_csp(self, http_info: Dict[str, Any]) -> CSPPolicy:
        headers = http_info.get("headers", {})
        raw = (headers.get("content-security-policy")
               or headers.get("content-security-policy-report-only") or "")
        report_only = bool(
            headers.get("content-security-policy-report-only") and not
            headers.get("content-security-policy")
        )
        policy = CSPPolicy(raw=raw or None, report_only=report_only)
        if not raw:
            return policy
        directives: Dict[str, List[str]] = {}
        for part in raw.split(";"):
            part = part.strip()
            if not part:
                continue
            pieces = part.split()
            name = pieces[0].lower()
            values = pieces[1:]
            directives[name] = values
        policy.directives = directives
        for name, values in directives.items():
            for v in values:
                low = v.lower()
                if low == "'unsafe-inline'":
                    policy.unsafe_inline = True
                if low == "'unsafe-eval'":
                    policy.unsafe_eval = True
                if low == "'strict-dynamic'":
                    policy.strict_dynamic = True
                if low.startswith("'nonce-"):
                    policy.nonce_used = True
                if v == "*":
                    policy.has_wildcard_sources = True
                    policy.wildcard_directives.append(name)
                if (v.startswith("http://") or v.startswith("https://")
                        or re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}$", low)):
                    policy.allowed_origins.append(v)
            if name == "report-uri":
                policy.report_uri.extend(values)
            if name == "report-to":
                policy.report_to = " ".join(values) or None
        policy.allowed_origins = sorted(set(policy.allowed_origins))
        policy.wildcard_directives = sorted(set(policy.wildcard_directives))
        return policy

    # --------------------------------------------------------------
    # Cookie security analysis
    # --------------------------------------------------------------
    def analyze_cookies(self, http_info: Dict[str, Any]) -> Dict[str, Any]:
        cookies = http_info.get("cookies", [])
        issues: List[Dict[str, Any]] = []
        summary: Dict[str, int] = Counter()
        for c in cookies:
            name = c.get("name") or ""
            secure = bool(c.get("secure"))
            http_only = bool(c.get("http_only"))
            same_site = (c.get("same_site") or "").lower() or None
            host_prefix = name.startswith("__Host-")
            secure_prefix = name.startswith("__Secure-")
            if not secure:
                issues.append({"cookie": name, "issue": "missing_Secure"})
                summary["missing_secure"] += 1
            if not http_only and any(x in name.lower() for x in
                                     ("session", "sess", "auth", "token",
                                      "sid", "jwt")):
                issues.append({"cookie": name,
                               "issue": "session_without_HttpOnly"})
                summary["session_without_httponly"] += 1
            if same_site is None:
                issues.append({"cookie": name, "issue": "missing_SameSite"})
                summary["missing_samesite"] += 1
            elif same_site == "none" and not secure:
                issues.append({"cookie": name,
                               "issue": "SameSite_None_without_Secure"})
                summary["samesite_none_insecure"] += 1
            if host_prefix and (not secure or (c.get("path") or "/") != "/"
                                or c.get("domain")):
                issues.append({"cookie": name,
                               "issue": "__Host-_prefix_misconfigured"})
                summary["host_prefix_bad"] += 1
            if secure_prefix and not secure:
                issues.append({"cookie": name,
                               "issue": "__Secure-_prefix_without_Secure"})
                summary["secure_prefix_bad"] += 1
        return {
            "count": len(cookies),
            "summary": dict(summary),
            "issues": issues,
        }

    # --------------------------------------------------------------
    # Secret scanning pasivo sobre todo el pool observado
    # --------------------------------------------------------------
    def scan_secrets(self) -> Dict[str, Any]:
        findings: List[SecretFinding] = []
        seen: set = set()
        for source_name, text in self.observed_texts:
            if not text:
                continue
            for name, pattern, severity in SECRET_PATTERNS:
                try:
                    for m in re.finditer(pattern, text):
                        raw = m.group(0)
                        key = (name, raw[:80])
                        if key in seen:
                            continue
                        seen.add(key)
                        entropy = self._shannon_entropy(raw)
                        # heurística anti-FP: rechazar placeholders obvios
                        if self._looks_like_placeholder(raw):
                            continue
                        masked = self._mask(raw)
                        start = max(0, m.start() - 40)
                        end = min(len(text), m.end() + 40)
                        ctx = text[start:end].replace("\n", " ")[:200]
                        findings.append(SecretFinding(
                            name=name, severity=severity,
                            source=source_name,
                            match_preview=masked,
                            entropy=round(entropy, 2) if entropy else None,
                            context=ctx,
                        ))
                except re.error:
                    continue
        # prioridad: high > medium > low > info
        sev_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
        findings.sort(key=lambda f: (sev_rank.get(f.severity, 9), f.name))
        return {
            "count": len(findings),
            "by_severity": dict(Counter(f.severity for f in findings)),
            "findings": [asdict(f) for f in findings[:60]],
        }

    def _shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        counts: Dict[str, int] = {}
        for ch in s:
            counts[ch] = counts.get(ch, 0) + 1
        length = len(s)
        ent = 0.0
        for c in counts.values():
            p = c / length
            ent -= p * math.log2(p)
        return ent

    def _looks_like_placeholder(self, s: str) -> bool:
        low = s.lower()
        bad = ("example", "xxxxxx", "your-", "placeholder", "dummy",
               "sample", "test_", "changeme", "replace-this",
               "...", "yyyy", "abcdef0123456789")
        return any(b in low for b in bad)

    def _mask(self, s: str) -> str:
        if len(s) <= 8:
            return s[0] + "***" + s[-1]
        return s[:4] + "…" + s[-4:] + f" ({len(s)}c)"

    # --------------------------------------------------------------
    # JWT extractor + decode de header/payload
    # --------------------------------------------------------------
    def extract_jwts(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        seen: set = set()
        jwt_re = re.compile(
            r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{0,}\b"
        )
        for source_name, text in self.observed_texts:
            if not text:
                continue
            for m in jwt_re.finditer(text):
                raw = m.group(0)
                if raw in seen or len(raw) < 40:
                    continue
                seen.add(raw)
                parts = raw.split(".")
                if len(parts) < 2:
                    continue
                try:
                    header = self._b64url_decode_json(parts[0])
                    payload = self._b64url_decode_json(parts[1])
                except Exception:
                    continue
                if not isinstance(header, dict):
                    continue
                out.append({
                    "source": source_name,
                    "preview": raw[:18] + "…" + raw[-6:],
                    "header": header,
                    "payload": payload if isinstance(payload, dict) else None,
                    "algorithm": (header or {}).get("alg"),
                    "issuer": (payload or {}).get("iss") if isinstance(payload, dict) else None,
                    "audience": (payload or {}).get("aud") if isinstance(payload, dict) else None,
                    "expires": (payload or {}).get("exp") if isinstance(payload, dict) else None,
                    "none_alg": (header or {}).get("alg", "").lower() == "none",
                })
                if len(out) >= 20:
                    return out
        return out

    def _b64url_decode_json(self, seg: str) -> Any:
        padded = seg + "=" * (-len(seg) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("utf-8"))
        return json.loads(raw.decode("utf-8", errors="ignore"))

    # --------------------------------------------------------------
    # Auth surface
    # --------------------------------------------------------------
    def detect_sso_signals(self) -> List[Dict[str, Any]]:
        """Escanea todo el text pool buscando SSO providers con contexto auth real."""
        signals: List[SSOSignal] = []
        seen: set = set()

        sources: List[Tuple[str, str]] = list(self.observed_texts)
        if self.soup is not None:
            hrefs = []
            for a in self.soup.find_all("a"):
                href = a.get("href") or ""
                text = a.get_text(" ", strip=True) or ""
                combo = f"{href} {text}".strip()
                if combo:
                    hrefs.append(combo)
            if hrefs:
                sources.append(("anchor_hrefs", "\n".join(hrefs)))

        # v3.3: requerimos contexto auth real para providers consumer
        auth_context_re = re.compile(
            r"oauth|openid|saml|login|sign[- ]?in|signin|signup|authorize|"
            r"continue with|response_type=|redirect_uri=|client_id=|id_token|"
            r"access_token|code_challenge|code_verifier|realm|kc_idp_hint|"
            r"/dialog/oauth|/login/oauth|/oauth2|/authorize",
            re.I,
        )
        # v3.3: señales que son puramente social/analytics, no SSO
        social_only_re = re.compile(
            r"facebook pixel|fbq\(|twitter pixel|gtag\(|analytics|share|"
            r"instagram\.com|facebook\.com/[A-Za-z0-9_.\-]+/?$|youtube\.com/channel/",
            re.I,
        )

        for provider, category, patterns in SSO_PROVIDERS:
            hits = 0
            hit_sources: List[str] = []

            for source_name, text in sources:
                if not text:
                    continue
                low = text.lower()
                provider_hit = any(pat.lower() in low for pat in patterns)
                if not provider_hit:
                    continue
                # Para providers consumer exigimos contexto auth — evita falsos
                # positivos por pixels, share buttons o links sociales genéricos
                if category == "consumer":
                    if social_only_re.search(text) and not auth_context_re.search(text):
                        continue
                    if not auth_context_re.search(text):
                        continue
                hits += 1
                hit_sources.append(source_name)
                if hits >= 2:
                    break

            if hits == 0:
                continue
            if (provider, category) in seen:
                continue
            seen.add((provider, category))
            confidence = "high" if hits >= 2 else "low"
            signals.append(SSOSignal(
                provider=provider,
                category=category,
                confidence=confidence,
                source=", ".join(sorted(set(hit_sources))[:3]),
            ))

        return [asdict(s) for s in signals]

    # --------------------------------------------------------------
    # Custom stack hints (señales de stack propio/interno)
    # --------------------------------------------------------------
    def detect_custom_stack_hints(
        self, http_info: Dict[str, Any], html_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        hints: Dict[str, Any] = {
            "custom_headers": [],
            "custom_cookies": [],
            "internal_paths": [],
            "custom_generators": [],
            "html_comment_hints": [],
        }

        # Headers con prefijos "corporativos" o genéricos de backend custom
        CORP_HEADER_PREFIXES = ("x-corp-", "x-company-", "x-org-", "x-internal-",
                                 "x-backend-", "x-app-", "x-service-", "x-tenant-",
                                 "x-customer-", "x-client-id", "x-request-id",
                                 "x-trace-id", "x-correlation-id")
        NOISY_TRACE_HEADERS = {"x-request-id", "x-trace-id", "x-correlation-id"}
        headers = http_info.get("headers", {})
        for k in headers.keys():
            low = k.lower()
            if any(low.startswith(p) for p in CORP_HEADER_PREFIXES):
                if low not in NOISY_TRACE_HEADERS:
                    hints["custom_headers"].append(k)
            if low in ("x-generator", "x-application", "x-backend-server",
                       "x-powered-by", "x-served-by", "x-served-from",
                       "x-host", "x-node", "x-origin-server"):
                val = headers.get(k)
                if val and not any(known in str(val).lower() for known in
                                   ("express", "php", "asp.net", "tomcat", "nginx",
                                    "apache", "cloudflare", "fastly", "varnish",
                                    "cache", "github.com")):
                    hints["custom_generators"].append(
                        {"header": k, "value": str(val)[:120]})

        # Cookies con nombres que parecen custom (no genéricos)
        GENERIC_COOKIE_NAMES = {
            "sessionid", "session", "sess", "connect.sid", "jsessionid",
            "phpsessid", "asp.net_sessionid", "csrftoken", "xsrf-token",
            "_ga", "_gid", "_gat", "_fbp", "_fbc", "cf_clearance",
            "laravel_session", "_rails_session", "moodlesession",
            "_octo", "logged_in", "user_session", "tz",
        }
        for c in http_info.get("cookies", []):
            name = (c.get("name") or "")
            low = name.lower()
            if not name or low in GENERIC_COOKIE_NAMES:
                continue
            if re.match(r"^[a-z]{3,15}_sess", low) or re.match(
                    r"^[a-z]{2,10}_(token|id|auth)$", low):
                hints["custom_cookies"].append(name)
            if "_" in name and name.isupper() and len(name) >= 5:
                hints["custom_cookies"].append(name)

        # Paths "internos" clásicos (en links del HTML)
        INTERNAL_PATH_HINTS = (
            "/intranet", "/mitarbeiter", "/staff", "/employees",
            "/internal", "/private", "/backoffice",
            "/back-office", "/corp", "/corporate",
            "/partner-portal", "/vendor-portal", "/reseller-portal",
        )
        for link in html_info.get("links", []):
            url = (link.get("url") or "").lower()
            for hint in INTERNAL_PATH_HINTS:
                if hint in url:
                    hints["internal_paths"].append(link.get("url"))
                    break

        # Comentarios HTML con nombres de devs / internos / TODOs / paths
        INTERESTING_COMMENT_RE = re.compile(
            r"(?i)(?:todo|fixme|hack|bug:|xxx|@author|@dev|"
            r"internal|staging|localhost|127\.0\.0\.1|\b10\.\d|192\.168\.)")
        for comment in html_info.get("html_comments", []):
            if INTERESTING_COMMENT_RE.search(comment):
                hints["html_comment_hints"].append(comment[:180])

        # dedupe
        for k in hints:
            if isinstance(hints[k], list):
                hints[k] = self.dedupe(hints[k])[:20]

        # Has anything?
        hints["has_custom_stack_signals"] = bool(
            hints["custom_headers"] or hints["custom_cookies"]
            or hints["custom_generators"] or hints["internal_paths"]
        )

        return hints

    def detect_auth_surface(self, http_info: Dict[str, Any],
                            html_info: Dict[str, Any],
                            path_info: Dict[str, Any]) -> Dict[str, Any]:
        internal_login_links: List[str] = []
        federated_login_links: List[str] = []
        oauth_signals = False
        saml_signals = False
        oidc_signals = False
        csrf_mechanisms: List[str] = []
        captcha_detected = False
        captcha_providers: List[str] = []
        forms_detected = html_info.get("forms", [])

        if self.soup is not None:
            for a in self.soup.find_all("a"):
                href = a.get("href") or ""
                text = a.get_text(" ", strip=True) or ""
                combo = f"{href} {text}".lower()
                if re.search(r"login|sign[- ]?in|auth|anmelden|einloggen",
                             combo, re.I):
                    norm = self.normalize_url(href) or href
                    if not norm:
                        continue
                    if self.scope and not self.is_in_scope_url(norm):
                        federated_login_links.append(norm)
                    else:
                        internal_login_links.append(norm)

        # v3.2: fix — sso_providers_detected se extrae de sso_signals,
        # no de la lista `sso` que antes nunca se llenaba
        sso_signals = self.detect_sso_signals()
        sso_providers_detected = sorted(set(
            sig.get("provider") for sig in sso_signals if sig.get("provider")
        ))

        all_text = (self.main_html or "").lower()
        if re.search(r"oauth|redirect_uri|response_type=code|client_id",
                     all_text):
            oauth_signals = True
        if re.search(r"openid|id_token|\.well-known/openid", all_text):
            oidc_signals = True
        if re.search(r"samlrequest|samlresponse|relaystate", all_text):
            saml_signals = True
        if re.search(r"recaptcha|hcaptcha|turnstile", all_text):
            captcha_detected = True
            if "recaptcha" in all_text:
                captcha_providers.append("recaptcha")
            if "hcaptcha" in all_text:
                captcha_providers.append("hcaptcha")
            if "turnstile" in all_text:
                captcha_providers.append("turnstile")

        if html_info.get("csrf_meta"):
            csrf_mechanisms.append("token_in_meta")
        for form in forms_detected:
            if any("csrf" in (x or "").lower()
                   for x in form.get("hidden_inputs", [])):
                csrf_mechanisms.append("token_in_hidden_input")
                break
            if any("authenticity_token" in (x or "").lower()
                   for x in form.get("hidden_inputs", [])):
                csrf_mechanisms.append("rails_authenticity_token")
                break
            if any("__requestverificationtoken" in (x or "").lower()
                   for x in form.get("hidden_inputs", [])):
                csrf_mechanisms.append("aspnet_antiforgery")
                break
            if any("csrfmiddlewaretoken" in (x or "").lower()
                   for x in form.get("hidden_inputs", [])):
                csrf_mechanisms.append("django_csrf_middleware")
                break

        cookie_names = [c.get("name", "") for c in http_info.get("cookies", [])]
        if any("csrf" in x.lower() or "xsrf" in x.lower() for x in cookie_names):
            csrf_mechanisms.append("csrf_cookie")

        session_cookie = next(
            (x for x in cookie_names
             if re.search(r"session|sess|connect\.sid|jsessionid|"
                          r"phpsessid|asp\.net_sessionid",
                          x, re.I)),
            None,
        )

        if isinstance(path_info.get("openid_configuration"), dict):
            probe = path_info.get("openid_configuration") or {}
            # v3.4: solo señal real si el discovery document es válido
            if probe.get("oidc_valid"):
                oauth_signals = True
                oidc_signals = True

        return {
            "login_links": self.dedupe(internal_login_links)[:15],
            "internal_login_links": self.dedupe(internal_login_links)[:15],
            "federated_login_links": self.dedupe(federated_login_links)[:15],
            "forms_detected": forms_detected,
            "sso_providers_detected": sso_providers_detected[:20],
            "sso_signals": sso_signals,
            "oauth_signals": oauth_signals,
            "oidc_signals": oidc_signals,
            "saml_signals": saml_signals,
            "session_cookie_name": session_cookie,
            "csrf_mechanisms": self.dedupe(csrf_mechanisms),
            "captcha_detected": captcha_detected,
            "captcha_providers": self.dedupe(captcha_providers),
        }

    # --------------------------------------------------------------
    # Detección de servicios especiales (ArcGIS, ES, Firebase, S3, Actuator)
    # --------------------------------------------------------------
    def detect_special_services(self, html_info: Dict[str, Any],
                                assets_info: Dict[str, Any],
                                path_info: Dict[str, Any]) -> Dict[str, Any]:
        all_text = "\n".join(text for _, text in self.observed_texts)
        low = all_text.lower()
        out: Dict[str, Any] = {}

        # ArcGIS
        arcgis_hits: List[str] = []
        for pat in (r"/rest/services/", r"/featureserver", r"/mapserver",
                    r"arcgis/core", r"esri/"):
            if re.search(pat, low):
                arcgis_hits.append(pat)
        if arcgis_hits:
            urls = sorted(set(re.findall(
                r"https?://[^\s'\"<>]+/(?:rest/services|FeatureServer|MapServer)[^\s'\"<>]*",
                all_text, re.I,
            )))[:20]
            out["arcgis"] = {"hits": arcgis_hits, "urls": urls}

        # Elasticsearch / OpenSearch
        es_hits: List[str] = []
        for pat in (r"_search", r"_cat/indices", r"_cluster/health",
                    r"elasticsearch", r"opensearch"):
            if re.search(pat, low):
                es_hits.append(pat)
        if es_hits:
            urls = sorted(set(re.findall(
                r"https?://[^\s'\"<>]+/(?:_search|_cat|_cluster)[^\s'\"<>]*",
                all_text, re.I,
            )))[:20]
            out["elasticsearch"] = {"hits": es_hits, "urls": urls}

        # Firebase
        fb_urls = sorted(set(re.findall(
            r"\bhttps?://[a-z0-9-]+\.firebaseio\.com[^\s'\"<>]*",
            all_text, re.I,
        )))
        fb_firestore = sorted(set(re.findall(
            r"\bhttps?://firestore\.googleapis\.com[^\s'\"<>]*",
            all_text, re.I,
        )))
        if fb_urls or fb_firestore or re.search(r"firebaseapp\.com", low):
            out["firebase"] = {
                "realtime_db_urls": fb_urls[:10],
                "firestore_urls": fb_firestore[:10],
                "present": True,
            }

        # S3 buckets
        s3_hits = sorted(set(re.findall(
            r"\bhttps?://[a-z0-9.\-]+\.s3[a-z0-9\-\.]*\.amazonaws\.com[^\s'\"<>]*",
            all_text, re.I,
        )))
        s3_uris = sorted(set(re.findall(
            r"\bs3://[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9][^\s'\"<>]*",
            all_text, re.I,
        )))
        if s3_hits or s3_uris:
            out["s3"] = {"https_urls": s3_hits[:10], "s3_uris": s3_uris[:10]}

        # Spring Actuator (si apareció en path_probes)
        actuator_hits = []
        for k in list(path_info.keys()):
            if "actuator" in k:
                probe = path_info.get(k) or {}
                if probe.get("status_code") in (200, 401):
                    actuator_hits.append({
                        "path": k,
                        "status": probe.get("status_code"),
                        "url": probe.get("url"),
                    })
        if actuator_hits:
            out["spring_actuator"] = actuator_hits

        # .git exposed
        git_hit = path_info.get("_git_head")
        if isinstance(git_hit, dict) and git_hit.get("status_code") == 200:
            body_marker = git_hit.get("body_sample") or ""
            if "ref:" in body_marker or "refs/heads" in body_marker:
                out["git_exposed"] = git_hit

        # .env exposed
        env_hit = path_info.get("_env")
        if isinstance(env_hit, dict) and env_hit.get("status_code") == 200:
            out["env_exposed"] = env_hit

        # Hasura GraphQL Engine (tiene endpoints específicos)
        if re.search(r"x-hasura-|/v1/graphql|hasura", low):
            hasura_urls = sorted(set(re.findall(
                r"https?://[^\s'\"<>]+/v1/graphql[^\s'\"<>]*",
                all_text, re.I,
            )))
            out["hasura"] = {"urls": hasura_urls[:10]}

        # Kubernetes signals
        if re.search(r"x-kubernetes-|kube-apiserver|/api/v1/namespaces", low):
            out["kubernetes_hint"] = True

        # Cloud functions / serverless URLs en JS → útil para mapear backend
        cloud_fn_urls: List[str] = []
        cloud_fn_urls.extend(re.findall(
            r"https?://[a-z0-9-]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com[^\s'\"<>]*",
            all_text, re.I))
        cloud_fn_urls.extend(re.findall(
            r"https?://[a-z0-9-]+\.lambda-url\.[a-z0-9-]+\.on\.aws[^\s'\"<>]*",
            all_text, re.I))
        cloud_fn_urls.extend(re.findall(
            r"https?://[a-z0-9-]+\.run\.app[^\s'\"<>]*",
            all_text, re.I))
        cloud_fn_urls.extend(re.findall(
            r"https?://[a-z0-9-]+\.azurewebsites\.net[^\s'\"<>]*",
            all_text, re.I))
        cloud_fn_urls.extend(re.findall(
            r"https?://[a-z0-9-]+\.cloudfunctions\.net[^\s'\"<>]*",
            all_text, re.I))
        if cloud_fn_urls:
            out["cloud_functions"] = sorted(set(cloud_fn_urls))[:20]

        return out

    # --------------------------------------------------------------
    # Open redirect / SSRF param hints
    # --------------------------------------------------------------
    def detect_open_redirect_params(self,
                                    html_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        seen: set = set()
        endpoints = html_info.get("page_endpoints", [])
        # También escanear forms hidden_inputs
        for ep in endpoints:
            url = ep.get("url") or ""
            if not url or "?" not in url:
                continue
            try:
                qs = urlparse(url).query
                params = [k for k, _ in parse_qsl(qs, keep_blank_values=True)]
            except Exception:
                continue
            suspect = [p for p in params
                       if p.lower() in OPEN_REDIRECT_PARAMS]
            if suspect:
                key = (url, tuple(suspect))
                if key in seen:
                    continue
                seen.add(key)
                hits.append({
                    "url": url,
                    "suspect_params": suspect,
                    "source": ep.get("source", "page_endpoint"),
                    "note": "Posible open-redirect / SSRF — validar",
                })
        for form in html_info.get("forms", []):
            for hidden in form.get("hidden_inputs", []):
                if (hidden or "").lower() in OPEN_REDIRECT_PARAMS:
                    hits.append({
                        "url": form.get("action"),
                        "suspect_params": [hidden],
                        "source": "form_hidden",
                        "note": "Hidden input con nombre de redirect conocido",
                    })
        return hits[:50]

    # --------------------------------------------------------------
    # Subresource Integrity + mixed content
    # --------------------------------------------------------------
    def analyze_sri_and_mixed_content(self,
                                      html_info: Dict[str, Any]) -> Dict[str, Any]:
        missing_sri: List[str] = []
        mixed_http_resources: List[str] = []
        final_is_https = self.final_url.startswith("https://")
        target_host = urlparse(self.final_url).netloc.lower()
        for entry in html_info.get("script_entries", []):
            url = entry.get("url") or ""
            if not url:
                continue
            host = urlparse(url).netloc.lower()
            external = host and host != target_host
            if external and not entry.get("integrity"):
                missing_sri.append(url)
            if final_is_https and url.startswith("http://"):
                mixed_http_resources.append(url)
        for css in html_info.get("css_links", []):
            url = css.get("url") or ""
            if not url:
                continue
            host = urlparse(url).netloc.lower()
            external = host and host != target_host
            if external and not css.get("integrity"):
                missing_sri.append(url)
            if final_is_https and url.startswith("http://"):
                mixed_http_resources.append(url)
        return {
            "missing_sri": self.dedupe(missing_sri)[:40],
            "mixed_content": self.dedupe(mixed_http_resources)[:40],
        }

    # --------------------------------------------------------------
    # Path probes (concurrente)
    # --------------------------------------------------------------
    def path_probes(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        base = self.origin(self.final_url)
        paths = list(PROBE_PATHS_CORE)
        if self.extra_probes:
            paths.extend(PROBE_PATHS_EXTRA)

        tasks: List[Tuple[str, str]] = []
        for p in paths:
            tasks.append((p, base + p))

        with ThreadPoolExecutor(max_workers=self.concurrency) as ex:
            futures = {ex.submit(self.single_probe, url, p): (p, url)
                       for p, url in tasks}
            for fut in as_completed(futures):
                path, url = futures[fut]
                name = self.probe_name(path)
                try:
                    out[name] = fut.result()
                except Exception as exc:
                    out[name] = {"url": url, "error": str(exc)}
        return out

    def is_probably_html(self, body: str,
                         content_type: Optional[str] = None) -> bool:
        body_low = (body or "").strip().lower()[:400]
        ct_low = (content_type or "").lower()
        if "html" in ct_low:
            return True
        html_markers = ["<!doctype html", "<html", "<head", "<body",
                        "<script", "<title"]
        return any(marker in body_low for marker in html_markers)

    def is_valid_oidc_discovery_document(self, parsed: Any) -> bool:
        """True solo si el JSON contiene los campos mínimos de un OIDC discovery real."""
        if not isinstance(parsed, dict):
            return False
        return bool(
            parsed.get("issuer")
            and (
                parsed.get("authorization_endpoint")
                or parsed.get("token_endpoint")
                or parsed.get("jwks_uri")
                or parsed.get("userinfo_endpoint")
            )
        )

    def probe_is_meaningful(self, probe_name: str, probe: Dict[str, Any]) -> bool:
        """True si el probe devuelve algo realmente interesante, no un fallback HTML."""
        if not isinstance(probe, dict):
            return False
        status = probe.get("status_code")
        if status not in {200, 401, 403}:
            return False
        body_sample = probe.get("body_sample") or ""
        content_type = probe.get("content_type") or ""
        interesting = probe.get("interesting")
        # GraphQL solo si está confirmado
        if probe_name == "graphql":
            gql = probe.get("graphql_probe") or {}
            return bool(gql.get("confirmed"))
        # OIDC solo si el discovery document es válido
        if probe_name == "openid_configuration":
            return bool(probe.get("oidc_valid"))
        # security.txt solo si hay campos RFC 9116 reales
        if probe_name == "security_txt":
            return bool(interesting)
        # Resto: si es HTML fallback, no sirve
        if self.is_probably_html(body_sample, content_type):
            return False
        return bool(interesting)

    def analyze_graphql_response(self, status_code: Optional[int],
                                 content_type: Optional[str],
                                 body: str, method: str) -> Dict[str, Any]:
        body = body or ""
        body_low = body.lower()
        ct_low = (content_type or "").lower()
        indicators: List[str] = []
        confidence = "none"
        confirmed = False
        if self.is_probably_html(body, content_type):
            return {
                "method": method,
                "status_code": status_code,
                "content_type": content_type,
                "confirmed": False,
                "confidence": "none",
                "indicators": ["html_fallback_or_page"],
                "is_probably_html": True,
            }

        if "json" in ct_low:
            indicators.append("json_content_type")

        strong_patterns = [
            r"must provide query string",
            r"cannot query field",
            r"syntax error",
            r"graphql",
            r"introspectionquery",
            r'"errors"\s*:',
            r'"data"\s*:',
            r'"extensions"\s*:',
            r"__typename",
        ]
        for pat in strong_patterns:
            if re.search(pat, body_low, re.I):
                indicators.append(f"body:{pat}")

        parsed_json = None
        if body and ("json" in ct_low or body[:1] == "{"):
            try:
                parsed_json = json.loads(body)
            except Exception:
                parsed_json = None
        if isinstance(parsed_json, dict):
            if any(k in parsed_json for k in ("errors", "data", "extensions")):
                indicators.append("json_graphql_shape")
            errs = parsed_json.get("errors")
            if isinstance(errs, list) and errs:
                indicators.append("json_errors_array")

        strong_hits = len([x for x in indicators if x != "json_content_type"])
        if strong_hits >= 2:
            confirmed = True
            confidence = "high"
        elif strong_hits == 1 and "json_content_type" in indicators:
            confirmed = True
            confidence = "medium"
        elif strong_hits == 1:
            confidence = "low"
        elif indicators:
            confidence = "low"

        return {
            "method": method,
            "status_code": status_code,
            "content_type": content_type,
            "confirmed": confirmed,
            "confidence": confidence,
            "indicators": indicators[:12],
            "is_probably_html": False,
        }

    def single_probe(self, url: str, path: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "url": url, "status_code": None, "content_type": None,
            "interesting": [],
        }
        try:
            get_paths = {
                "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
                "/.well-known/openid-configuration",
                "/.well-known/oauth-authorization-server",
                "/.well-known/security.txt",
                "/graphql", "/api/docs", "/swagger.json", "/openapi.json",
                "/.env", "/.env.local", "/.git/HEAD", "/.git/config",
                "/server-status", "/actuator", "/actuator/health",
                "/actuator/env", "/actuator/info", "/actuator/mappings",
                "/actuator/prometheus", "/metrics", "/health", "/healthz",
                "/phpinfo.php", "/wp-json/wp/v2/users",
                "/crossdomain.xml", "/clientaccesspolicy.xml",
            }
            method = "GET" if path in get_paths else "HEAD"
            resp = self.session.request(method, url, timeout=self.timeout,
                                        allow_redirects=True)
            result["status_code"] = resp.status_code
            result["content_type"] = resp.headers.get("Content-Type")
            body = ""
            if method == "GET":
                body = resp.text[:4000]
                result["body_sample"] = body[:600]
                if path == "/robots.txt":
                    disallow = re.findall(
                        r"^Disallow:\s*(.+)$", body, re.M | re.I)
                    result["interesting"] = disallow[:30]
                elif path in ("/sitemap.xml", "/sitemap_index.xml"):
                    locs = re.findall(r"<loc>([^<]+)</loc>", body, re.I)
                    result["interesting"] = locs[:30]
                elif path == "/.well-known/openid-configuration":
                    # v3.4: validar que sea un discovery document real, no HTML login
                    result["oidc_valid"] = False
                    result["oidc_discovery"] = None
                    if resp.status_code == 200 and not self.is_probably_html(
                        body, resp.headers.get("Content-Type")
                    ):
                        try:
                            parsed = resp.json()
                            if self.is_valid_oidc_discovery_document(parsed):
                                result["oidc_valid"] = True
                                result["oidc_discovery"] = {
                                    "issuer": parsed.get("issuer"),
                                    "authorization_endpoint": parsed.get("authorization_endpoint"),
                                    "token_endpoint": parsed.get("token_endpoint"),
                                    "userinfo_endpoint": parsed.get("userinfo_endpoint"),
                                    "jwks_uri": parsed.get("jwks_uri"),
                                    "grant_types_supported": parsed.get("grant_types_supported"),
                                    "scopes_supported": parsed.get("scopes_supported"),
                                }
                                result["interesting"] = result["oidc_discovery"]
                            else:
                                result["interesting"] = []
                        except Exception:
                            result["interesting"] = []
                    else:
                        result["interesting"] = []
                elif path == "/.well-known/security.txt":
                    # v3.3: solo parsear si es un 200 real, no un 404 HTML
                    if resp.status_code == 200 and not self.is_probably_html(
                        body, resp.headers.get("Content-Type")
                    ):
                        lines = [x.strip() for x in body.splitlines() if x.strip()]
                        useful = [
                            line for line in lines
                            if re.match(
                                r"^(Contact|Expires|Encryption|Acknowledgments|"
                                r"Policy|Hiring|Preferred-Languages|Canonical):",
                                line, re.I,
                            )
                        ]
                        result["interesting"] = useful[:20]
                    else:
                        result["interesting"] = []
                elif path == "/graphql":
                    get_probe = self.analyze_graphql_response(
                        resp.status_code, resp.headers.get("Content-Type"),
                        body, "GET")
                    post_probe = None
                    if not get_probe.get("confirmed"):
                        try:
                            post_resp = self.session.post(
                                url,
                                timeout=self.timeout,
                                allow_redirects=True,
                                headers={"Content-Type": "application/json",
                                         "Accept": "application/json"},
                                json={"query": "query __ReconTypename { __typename }"},
                            )
                            post_body = post_resp.text[:4000]
                            post_probe = self.analyze_graphql_response(
                                post_resp.status_code,
                                post_resp.headers.get("Content-Type"),
                                post_body, "POST")
                        except Exception as post_exc:
                            post_probe = {
                                "method": "POST",
                                "confirmed": False,
                                "confidence": "none",
                                "indicators": [f"post_error:{post_exc}"],
                                "is_probably_html": False,
                            }
                    best_probe = (post_probe if
                                  (post_probe and post_probe.get("confirmed"))
                                  else get_probe)
                    result["graphql_probe"] = {
                        "confirmed": bool(best_probe.get("confirmed")),
                        "confidence": best_probe.get("confidence", "none"),
                        "methods": [x for x in [get_probe, post_probe] if x],
                    }
                    if best_probe.get("confirmed"):
                        result["interesting"] = [
                            f"graphql_confirmed:"
                            f"{best_probe.get('confidence', 'unknown')}"
                        ]
                elif path in ("/.env", "/.env.local"):
                    if re.search(r"^[A-Z][A-Z0-9_]*=", body, re.M):
                        result["interesting"] = ["env_like_body"]
                elif path == "/.git/HEAD":
                    if body.startswith("ref:"):
                        result["interesting"] = ["git_head_exposed"]
                elif path.startswith("/actuator"):
                    if "json" in (result.get("content_type") or "").lower():
                        try:
                            parsed = resp.json()
                            if isinstance(parsed, dict):
                                keys = list(parsed.keys())[:15]
                                result["interesting"] = {"json_keys": keys}
                        except Exception:
                            pass
        except Exception as exc:
            result["error"] = str(exc)
        return result

    # --------------------------------------------------------------
    # Priority scoring + top targets
    # --------------------------------------------------------------
    def build_priority_scores(
        self,
        http_info: Dict[str, Any],
        html_info: Dict[str, Any],
        tech_stack: Dict[str, Any],
        assets_info: Dict[str, Any],
        auth_surface: Dict[str, Any],
        path_info: Dict[str, Any],
        scope_hints: Dict[str, Any],
        download_info: Dict[str, Any],
        secrets_info: Dict[str, Any],
        special: Dict[str, Any],
        csp_info: CSPPolicy,
        cookies_sec: Dict[str, Any],
        redirect_params: List[Dict[str, Any]],
        custom_stack: Optional[Dict[str, Any]] = None,
        param_intel: Optional[Dict[str, Any]] = None,
        tech_probes_info: Optional[Dict[str, Any]] = None,
        wayback_info: Optional[Dict[str, Any]] = None,
        ct_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        custom_stack = custom_stack or {}
        param_intel = param_intel or {}
        tech_probes_info = tech_probes_info or {}
        wayback_info = wayback_info or {}
        ct_info = ct_info or {}
        host_score = 0
        reasons: List[str] = []

        js_assets = assets_info.get("js", [])
        usable_sourcemaps = [
            x for x in js_assets
            if (x.get("source_map_status") or {}).get("parses_as_sourcemap")
        ]
        reachable_broken_sourcemaps = [
            x for x in js_assets
            if (x.get("source_map_status") or {}).get("reachable")
            and not (x.get("source_map_status") or {}).get("parses_as_sourcemap")
        ]
        if usable_sourcemaps:
            host_score += 4
            reasons.append(f"{len(usable_sourcemaps)} sourcemap(s) usable(s)")
        elif reachable_broken_sourcemaps:
            host_score += 1
            reasons.append(
                f"{len(reachable_broken_sourcemaps)} sourcemap(s) "
                "alcanzable(s) pero no usable(s)"
            )

        if auth_surface.get("oauth_signals") or auth_surface.get("saml_signals"):
            host_score += 3
            reasons.append("flujo OAuth/OIDC/SAML detectado")
        hv = (param_intel.get("summary") or {}).get("high_value_count", 0)
        if hv >= 5:
            host_score += 3
            reasons.append(f"{hv} parámetros de alto valor minados")
        elif hv >= 1:
            host_score += 1
            reasons.append(f"{hv} parámetro(s) de alto valor minado(s)")

        tsp_findings = [f for f in tech_probes_info.get("findings", []) if f.get("signals_hit")]
        if tsp_findings:
            host_score += min(5, len(tsp_findings))
            reasons.append(f"{len(tsp_findings)} tech-specific probe(s) con hits")

        if wayback_info.get("enabled") and wayback_info.get("total_urls", 0) >= 20:
            host_score += 2
            reasons.append(f"{wayback_info.get('total_urls')} URLs históricas en Wayback")
        if ct_info.get("enabled") and ct_info.get("total_subdomains", 0) >= 10:
            host_score += 2
            reasons.append(f"{ct_info.get('total_subdomains')} subdominios via CT logs")

        graphql_probe = (path_info.get("graphql", {}) or {}).get("graphql_probe") or {}
        if graphql_probe.get("confirmed"):
            host_score += 3
            reasons.append(
                f"GraphQL confirmado ({graphql_probe.get('confidence', 'unknown')})"
            )

        page_endpoints = html_info.get("page_endpoints", [])
        high_value_page_eps = [x for x in page_endpoints
                               if x.get("score", 0) >= 4]
        if high_value_page_eps:
            host_score += 2
            reasons.append(
                f"{len(high_value_page_eps)} endpoint(s) interesantes "
                "en HTML/inline"
            )

        if (auth_surface.get("login_links")
                or any(f.get("has_password_field")
                       for f in auth_surface.get("forms_detected", []))):
            host_score += 2
            reasons.append("superficie auth visible")

        if scope_hints.get("scope_hostnames"):
            host_score += 2
            reasons.append(
                f"{len(scope_hints.get('scope_hostnames', []))} hostname(s) "
                "en scope observado(s)"
            )

        if download_info.get("downloaded_count"):
            host_score += min(2, download_info.get("downloaded_count", 0))
            reasons.append(
                f"{download_info.get('downloaded_count', 0)} asset(s) "
                "interesantes descargados"
            )

        waf = http_info.get("waf_signals") or []
        cdn = http_info.get("cdn_signals") or []
        if waf:
            host_score += 1
            reasons.append(f"WAF detectado: {', '.join(waf[:3])}")
        if cdn and not waf:
            host_score += 1
            reasons.append(f"CDN detectado: {', '.join(cdn[:3])}")

        # Secrets bonus
        sev = (secrets_info or {}).get("by_severity") or {}
        if sev.get("high"):
            host_score += 4
            reasons.append(f"{sev.get('high')} secreto(s) high-severity detectados")
        elif sev.get("medium"):
            host_score += 2
            reasons.append(f"{sev.get('medium')} secreto(s) medium-severity detectados")

        # CORS reflect
        cors = (http_info.get("cors_reflect_test") or {})
        if cors.get("exploitable_hint"):
            host_score += 4
            reasons.append("CORS reflected Origin con credenciales (explotable)")
        elif cors.get("wildcard_with_creds"):
            host_score += 3
            reasons.append("CORS * con credenciales")

        # Servicios especiales
        if special.get("arcgis"):
            host_score += 2
            reasons.append("ArcGIS REST/FeatureServer expuesto en HTML/JS")
        if special.get("elasticsearch"):
            host_score += 2
            reasons.append("Elasticsearch/OpenSearch endpoints referenciados")
        if special.get("firebase"):
            host_score += 2
            reasons.append("Firebase Realtime DB / Firestore referenciado")
        if special.get("spring_actuator"):
            host_score += 3
            reasons.append("Spring Actuator endpoints alcanzables")
        if special.get("git_exposed"):
            host_score += 4
            reasons.append(".git/HEAD expuesto")
        if special.get("env_exposed"):
            host_score += 4
            reasons.append(".env expuesto")

        if redirect_params:
            host_score += 1
            reasons.append(
                f"{len(redirect_params)} endpoint(s) con params "
                "de open-redirect/SSRF"
            )

        if (csp_info.unsafe_inline and csp_info.unsafe_eval) or not csp_info.raw:
            host_score += 1
            reasons.append("CSP débil/ausente (inline+eval o sin CSP)")

        if (cookies_sec.get("summary") or {}).get("session_without_httponly"):
            host_score += 1
            reasons.append("Cookie de sesión sin HttpOnly")

        if not js_assets:
            host_score -= 3
            reasons.append("sin JS relevante inventariado")

        # ----- Bonus por categorías nuevas del tech_stack -----

        # Dev tools público-facing: muy alto, suelen ser hallazgos directos
        dev_tools_high = [d for d in tech_stack.get("dev_tools", [])
                          if d.get("confidence") == "high"]
        if dev_tools_high:
            host_score += 4
            reasons.append(
                f"{len(dev_tools_high)} dev tool(s) público-facing: "
                f"{', '.join(d['name'] for d in dev_tools_high[:3])}"
            )
        elif tech_stack.get("dev_tools"):
            host_score += 2
            reasons.append(
                f"{len(tech_stack['dev_tools'])} dev tool(s) detectado(s)"
            )

        # Network appliances / VPN SSL / admin panels: HIGH — CVE-bait
        net_app_high = [n for n in tech_stack.get("network_appliances", [])
                        if n.get("confidence") in ("high", "medium")]
        if net_app_high:
            host_score += 5
            reasons.append(
                f"⚠️ {len(net_app_high)} network/VPN appliance expuesto: "
                f"{', '.join(n['name'] for n in net_app_high[:3])}"
            )

        # IdPs (auth stack mapping)
        idps_detected = tech_stack.get("idps", [])
        if idps_detected:
            host_score += 2
            reasons.append(
                f"{len(idps_detected)} IdP detectado(s): "
                f"{', '.join(i['name'] for i in idps_detected[:3])}"
            )

        # CMS (nivel base)
        cms_detected = tech_stack.get("cms", [])
        if cms_detected:
            host_score += 1
            reasons.append(
                f"CMS: {', '.join(c['name'] for c in cms_detected[:3])}"
            )

        # Custom stack hints
        if custom_stack.get("has_custom_stack_signals"):
            host_score += 1
            reasons.append(
                "señales de stack propio/interno (headers/cookies/paths)"
            )

        host_score = max(0, min(20, host_score))

        # Asset rankings
        asset_rankings = []
        for asset in js_assets:
            score = 0
            asset_reasons = []
            filename = (asset.get("filename") or "").lower()
            role = (asset.get("asset_role") or "").lower()
            sm_status = asset.get("source_map_status") or {}
            if role != "vendor":
                score += 2
                asset_reasons.append("no parece vendor")
            if any(x in filename for x in
                   ["main", "app", "index", "bundle", "entry"]):
                score += 2
                asset_reasons.append("nombre de bundle principal")
            if sm_status.get("parses_as_sourcemap"):
                score += 4
                asset_reasons.append("sourcemap usable")
                if sm_status.get("has_sources_content"):
                    score += 1
                    asset_reasons.append("sourcesContent presente")
            elif asset.get("source_map_declared"):
                score += 1
                asset_reasons.append("declara sourcemap")
                if sm_status.get("reachable") and not sm_status.get(
                        "parses_as_sourcemap"):
                    asset_reasons.append("sourcemap no parsea como .map real")
            if asset.get("size_kb") and asset.get("size_kb") > 40:
                score += 1
                asset_reasons.append("bundle con tamaño interesante")
            if self.is_interesting_asset(asset):
                score += 1
                asset_reasons.append("marcado como interesante")
            # v3.1: penalizar assets fuera de scope y vendors conocidos
            asset_url = asset.get("url") or ""
            if self.scope and not self.is_in_scope_url(asset_url):
                score -= 5
                asset_reasons.append("fuera de scope")
            if role == "vendor":
                score -= 4
                asset_reasons.append("vendor conocido")
            asset_url_for_action = asset.get("url") or ""
            if self.scope and not self.is_in_scope_url(asset_url_for_action):
                recommended_action = "ignore"
            elif score >= 5:
                recommended_action = "download_and_analyze"
            elif score >= 3:
                recommended_action = "review"
            else:
                recommended_action = "low_priority"
            asset_rankings.append({
                "url": asset.get("url"),
                "filename": asset.get("filename"),
                "score": max(0, min(10, score)),
                "reasons": asset_reasons,
                "recommended_action": recommended_action,
            })
        asset_rankings.sort(
            key=lambda x: (-x["score"], str(x.get("filename") or "")))

        # Top targets
        top_targets: List[Dict[str, Any]] = []
        for item in asset_rankings[:5]:
            if item["score"] >= 3:
                top_targets.append({
                    "type": "asset",
                    "target": item.get("url"),
                    "score": item["score"],
                    "why": item["reasons"],
                })
        for ep in page_endpoints[:8]:
            if ep.get("score", 0) >= 4:
                top_targets.append({
                    "type": "page_endpoint",
                    "target": ep.get("url"),
                    "score": min(9, ep.get("score", 0) + 1),
                    "why": [
                        f"detectado desde {ep.get('source')}",
                        f"method_hint={ep.get('method_hint')}",
                    ],
                })
        # v3.4: solo sube a top_targets si el discovery es válido, no por status 200
        openid_probe = path_info.get("openid_configuration") or {}
        if openid_probe.get("oidc_valid"):
            top_targets.append({
                "type": "path",
                "target": openid_probe.get("url"),
                "score": 8,
                "why": ["OIDC well-known válido"],
            })
        if graphql_probe.get("confirmed"):
            top_targets.append({
                "type": "path",
                "target": (path_info.get("graphql") or {}).get("url"),
                "score": 7,
                "why": [
                    f"GraphQL confirmado "
                    f"({graphql_probe.get('confidence', 'unknown')})"
                ],
            })
        if special.get("git_exposed"):
            top_targets.append({
                "type": "leak",
                "target": special["git_exposed"].get("url"),
                "score": 10,
                "why": [".git/HEAD expuesto — dump total posible"],
            })
        if special.get("env_exposed"):
            top_targets.append({
                "type": "leak",
                "target": special["env_exposed"].get("url"),
                "score": 10,
                "why": [".env expuesto"],
            })
        if special.get("spring_actuator"):
            for h in special["spring_actuator"][:3]:
                top_targets.append({
                    "type": "path",
                    "target": h.get("url"),
                    "score": 8,
                    "why": [f"Spring Actuator {h.get('path')} "
                            f"status={h.get('status')}"],
                })
        if (http_info.get("cors_reflect_test") or {}).get("exploitable_hint"):
            top_targets.append({
                "type": "misconfig",
                "target": self.final_url,
                "score": 9,
                "why": ["CORS reflected Origin + credentials"],
            })

        for d in dev_tools_high[:4]:
            top_targets.append({
                "type": "dev_tool",
                "target": self.final_url,
                "score": 8,
                "why": [f"{d['name']} detectado público-facing"],
            })

        for n in net_app_high[:4]:
            top_targets.append({
                "type": "network_appliance",
                "target": self.final_url,
                "score": 9,
                "why": [
                    f"{n['name']} — revisar CVEs conocidos de este appliance"
                ],
            })

        top_targets = sorted(
            top_targets,
            key=lambda x: (-x["score"], str(x.get("target") or "")),
        )[:15]

        return {
            "host_priority": {
                "score": host_score,
                "label": ("high" if host_score >= 12
                          else ("medium" if host_score >= 6 else "low")),
                "reasons": reasons,
            },
            "asset_rankings": asset_rankings[:15],
            "top_targets": top_targets,
        }

    # --------------------------------------------------------------
    # Scope hints, analyzer handoff, notes
    # --------------------------------------------------------------

    def _param_matches_any_category(self, name: str) -> bool:
        return any(re.fullmatch(pat, name, re.I) for _, _, pats in PARAM_CATEGORIES for pat in pats)

    def _classify_param(self, name: str) -> List[str]:
        cats: List[str] = []
        for cat_name, _, patterns in PARAM_CATEGORIES:
            for pat in patterns:
                if re.fullmatch(pat, name, re.I):
                    cats.append(cat_name)
                    break
        return cats

    def _score_param(self, name: str, cats: List[str], frequency: int, methods: set) -> int:
        score = 0
        if cats:
            best_weight = max(weight for cat_name, weight, _ in PARAM_CATEGORIES if cat_name in cats)
            score += best_weight
        if frequency >= 10:
            score += 3
        elif frequency >= 5:
            score += 2
        elif frequency >= 2:
            score += 1
        if "url_qs" in methods:
            score += 2
        if "form_input" in methods:
            score += 1
        if "fetch_arg" in methods:
            score += 2
        if len(cats) >= 2:
            score += 2
        return min(score, 20)

    def _associate_endpoint_for_param(self, param_name: str, text_sources: List[Tuple[str, str]], fetch_endpoints: List[Tuple[str, str]]) -> List[str]:
        found: List[str] = []
        param_re = re.compile(rf'''(https?://[^\s"'`<>]+|/[a-zA-Z0-9/_\-.]+)\?[^\s"'`<>]*\b{re.escape(param_name)}=''', re.I)
        for _, text in text_sources:
            if not text:
                continue
            for m in param_re.finditer(text):
                url = m.group(1)
                if url not in found:
                    found.append(url)
                if len(found) >= 5:
                    break
            if len(found) >= 5:
                break
        if not found and fetch_endpoints:
            for endpoint, _source in fetch_endpoints:
                for _, text in text_sources:
                    if text and param_name in text and endpoint in text:
                        if endpoint not in found:
                            found.append(endpoint)
                        break
                if len(found) >= 3:
                    break
        return found

    def _param_test_hints(self, categories: List[str]) -> List[str]:
        hints_map = {
            "idor_id": "try swapping value to other user's id / uuid; test without auth",
            "ssrf_url": "try internal URLs, metadata IPs, alternate schemes if accepted",
            "ssrf_file_fetch": "try image/file fetch to internal URLs and SVGs",
            "open_redirect": "try //evil.com, encoded variants and whitelist bypasses",
            "path_traversal": "try ../, encoded traversal and absolute paths",
            "cmd_injection": "try separators like ; | & $() and newline injection",
            "mass_assignment": "try adding the field in POST/PUT bodies with escalated values",
            "xss_content": "test reflection then stored contexts, HTML entities and SVG",
            "sqli_hint": "test sort/order/filter parameters for SQL behavior",
            "debug_flag": "try boolean values and compare verbose/error responses",
            "deserialization": "inspect format and test structured payload handling",
            "auth_token": "look for token leakage, replay, weak verification or exposure",
        }
        return [hints_map[c] for c in categories if c in hints_map]

    def mine_parameters(self, html_info: Dict[str, Any], assets_info: Dict[str, Any]) -> Dict[str, Any]:
        with self._time_feature("parameter_mining") as stats:
            text_sources: List[Tuple[str, str]] = []
            text_sources.extend(self.observed_texts)
            for url, body in self.asset_bodies.items():
                text_sources.append((f"asset_full:{Path(urlparse(url).path).name}", body))
            for txt in self.inline_script_texts:
                text_sources.append(("inline_script", txt))
            candidates: Dict[str, Dict[str, Any]] = {}
            def _bump(name: str, source: str, method: str):
                if not name:
                    return
                name = name.strip()
                if len(name) < MIN_PARAM_LEN or len(name) > MAX_PARAM_LEN:
                    return
                if name.lower() in PARAM_STOPLIST:
                    return
                if len(name) <= 3 and name.islower() and "_" not in name and not self._param_matches_any_category(name):
                    return
                entry = candidates.setdefault(name, {"frequency": 0, "sources": set(), "methods": set()})
                entry["frequency"] += 1
                entry["sources"].add(source)
                entry["methods"].add(method)

            fetch_endpoints: List[Tuple[str, str]] = []
            for source, text in text_sources:
                if not text:
                    continue
                for m in PARAM_FROM_URL_RE.finditer(text):
                    _bump(m.group(1), source, "url_qs")
                for m in FETCH_CALL_RE.finditer(text):
                    endpoint = m.group(1)
                    fetch_endpoints.append((endpoint, source))
                    tail = text[m.end():m.end()+600]
                    brace = re.search(r"\{([^{}]{0,500})\}", tail)
                    if brace:
                        for km in PARAM_FROM_JS_OBJECT_RE.finditer(brace.group(1)):
                            _bump(km.group(1), source, "fetch_arg")
                for ctx in re.finditer(r"(?:body|params|data|json|query|payload|options)\s*:\s*\{([^{}]{0,800})\}", text, re.I):
                    for km in PARAM_FROM_JS_OBJECT_RE.finditer(ctx.group(1)):
                        _bump(km.group(1), source, "js_obj")

            for form in html_info.get("forms", []):
                for inp in form.get("inputs", []):
                    nm = inp.get("name")
                    if nm:
                        _bump(nm, "html_form", "form_input")

            custom_headers: List[str] = []
            seen_headers = set()
            storage_keys: List[Dict[str, Any]] = []
            seen_storage = set()
            storage_re = re.compile(r'(localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*[\'\"]([a-zA-Z_][a-zA-Z0-9_\-.]{1,80})[\'\"]')
            for source, text in text_sources:
                if not text:
                    continue
                for m in PARAM_HEADER_RE.finditer(text):
                    h = m.group(1)
                    if h.lower() not in seen_headers:
                        seen_headers.add(h.lower())
                        custom_headers.append(h)
                for m in storage_re.finditer(text):
                    storage = "local" if "local" in m.group(1) else "session"
                    key = m.group(2)
                    sig = (storage, key)
                    if sig not in seen_storage:
                        seen_storage.add(sig)
                        storage_keys.append({"key": key, "storage": storage, "source": source})

            top_params: List[Dict[str, Any]] = []
            category_counts: Counter = Counter()
            for name, meta in candidates.items():
                cats = self._classify_param(name)
                if not cats and meta["frequency"] < 3:
                    continue
                score = self._score_param(name, cats, meta["frequency"], meta["methods"])
                for c in cats:
                    category_counts[c] += 1
                top_params.append({
                    "name": name,
                    "categories": cats,
                    "score": score,
                    "frequency": meta["frequency"],
                    "sources": sorted(meta["sources"])[:5],
                    "associated_endpoints": self._associate_endpoint_for_param(name, text_sources, fetch_endpoints)[:3],
                    "extraction_methods": sorted(meta["methods"]),
                })
            top_params.sort(key=lambda p: (-p["score"], -p["frequency"], p["name"]))
            top_params = top_params[:80]
            stats["items_found"] = len(top_params)
            high_value_count = sum(1 for p in top_params if p.get("score", 0) >= 10)
            return {
                "summary": {
                    "total_unique_params": len(candidates),
                    "by_category": dict(category_counts.most_common()),
                    "high_value_count": high_value_count,
                },
                "top_params": top_params,
                "custom_headers": sorted(custom_headers)[:40],
                "storage_keys": storage_keys[:40],
            }

    def _run_graphql_introspection(self, gql_url: str, tech_name: str = "GraphQL") -> Dict[str, Any]:
        result = {"tech": tech_name, "path": urlparse(gql_url).path, "url": gql_url, "method": "POST", "status_code": None, "signals_hit": [], "introspection_enabled": False, "types_found": 0, "error": None}
        introspection_query = "query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind } } }"
        try:
            resp = self.session.post(gql_url, timeout=self.timeout, allow_redirects=True, headers={"Content-Type": "application/json"}, json={"query": introspection_query})
            result["status_code"] = resp.status_code
            try:
                data = resp.json()
            except Exception:
                data = None
            if isinstance(data, dict):
                schema = (data.get("data") or {}).get("__schema")
                if isinstance(schema, dict):
                    result["introspection_enabled"] = True
                    result["signals_hit"].append("graphql_introspection_enabled")
                    result["types_found"] = len(schema.get("types") or [])
        except Exception as exc:
            result["error"] = str(exc)
        return result

    def run_tech_specific_probes(self, tech_stack: Dict[str, Any], path_info: Dict[str, Any]) -> Dict[str, Any]:
        with self._time_feature("tech_specific_probes") as stats:
            detected_techs: List[str] = []
            for category_key in ("frameworks", "cms", "hosted_platforms", "dev_tools", "network_appliances", "idps"):
                for obs in tech_stack.get(category_key, []):
                    if obs.get("confidence") not in ("high", "medium"):
                        continue
                    name = obs.get("name")
                    if name:
                        detected_techs.append(name)
            gql = (path_info.get("graphql") or {}).get("graphql_probe") or {}
            if gql.get("confirmed"):
                detected_techs.append("__graphql_confirmed")
            detected_techs = sorted(set(detected_techs))
            if self.tech_probe_only:
                detected_techs = [t for t in detected_techs if t in self.tech_probe_only]
            probes_to_run = [(t, TECH_SPECIFIC_PROBES[t]) for t in detected_techs if t in TECH_SPECIFIC_PROBES]
            if not probes_to_run and "__graphql_confirmed" not in detected_techs:
                stats["enabled"] = False
                return {"triggered_techs": [], "findings": []}
            base = self.origin(self.final_url)
            findings: List[Dict[str, Any]] = []
            triggered_techs: List[str] = []
            tasks: List[Tuple[str, str, str, str, List[Tuple[str, Optional[str], str]]]] = []
            for tech_name, spec in probes_to_run:
                for path, method, signals in spec.get("paths", []):
                    tasks.append((tech_name, base + path, path, method, signals))
                triggered_techs.append(tech_name)
            tasks = tasks[:MAX_TECH_PROBES_PER_RUN]
            def _run_probe(tech_name, url, path, method, signals):
                result = {"tech": tech_name, "path": path, "url": url, "method": method, "status_code": None, "content_type": None, "size": None, "signals_hit": [], "body_sample": None, "error": None}
                try:
                    if method == "POST":
                        resp = self.session.post(url, timeout=self.timeout, allow_redirects=True, headers={"Content-Type": "application/json"}, json={})
                    else:
                        resp = self.session.request(method, url, timeout=self.timeout, allow_redirects=True)
                    result["status_code"] = resp.status_code
                    result["content_type"] = resp.headers.get("Content-Type")
                    body = resp.text[:4000] if resp.text else ""
                    result["size"] = len(resp.content) if resp.content else 0
                    result["body_sample"] = body[:400] if body else None
                    for signal_name, pattern, where in signals:
                        hit = False
                        if where.startswith("status:"):
                            hit = (resp.status_code == int(where.split(":",1)[1]))
                        elif where.startswith("header:"):
                            hname = where.split(":",1)[1]
                            hval = resp.headers.get(hname, "")
                            hit = bool(pattern and re.search(pattern, hval, re.I))
                        elif where == "body":
                            hit = bool(pattern and re.search(pattern, body, re.I))
                        if hit:
                            result["signals_hit"].append(signal_name)
                except Exception as exc:
                    result["error"] = str(exc)
                    stats["errors"] += 1
                return result
            with ThreadPoolExecutor(max_workers=self.concurrency) as ex:
                futures = [ex.submit(_run_probe, *t) for t in tasks]
                for fut in as_completed(futures):
                    try:
                        r = fut.result()
                        if r.get("signals_hit") or (r.get("status_code") and r.get("status_code") not in (404, 503, 0) and not self.is_probably_html(r.get("body_sample") or "", r.get("content_type"))):
                            findings.append(r)
                    except Exception:
                        stats["errors"] += 1
            if "__graphql_confirmed" in detected_techs:
                gql_url = (path_info.get("graphql") or {}).get("url")
                if gql_url:
                    r = self._run_graphql_introspection(gql_url)
                    if r.get("introspection_enabled") or r.get("signals_hit"):
                        findings.append(r)
            stats["items_found"] = len(findings)
            return {"triggered_techs": triggered_techs, "findings": findings}

    def fetch_wayback_urls(self) -> Dict[str, Any]:
        if not self.wayback:
            return {"enabled": False}
        with self._time_feature("wayback") as stats:
            target_host = urlparse(self.final_url).netloc
            search_url = f"*.{self.scope}/*" if self.scope else f"{target_host}/*"
            params = {"url": search_url, "output": "json", "collapse": "urlkey", "fl": "timestamp,original,statuscode,mimetype", "limit": str(self.wayback_limit)}
            if self.wayback_since:
                params["from"] = self.wayback_since
            cdx_url = "http://web.archive.org/cdx/search/cdx"
            urls: List[Dict[str, Any]] = []
            hostnames = set()
            interesting_paths: List[str] = []
            try:
                resp = requests.get(cdx_url, params=params, timeout=30, headers={"User-Agent": f"recon_fingerprint/{__version__}"}, proxies={})
                if resp.status_code != 200:
                    stats["errors"] += 1
                    return {"enabled": True, "error": f"CDX returned status {resp.status_code}", "urls": []}
                data = resp.json()
                for row in data[1:] if len(data) > 1 else []:
                    if len(row) < 2:
                        continue
                    ts, original = row[0], row[1]
                    status_code = row[2] if len(row) >= 3 else None
                    mime = row[3] if len(row) >= 4 else None
                    parsed = urlparse(original)
                    if not self.is_in_scope_hostname(parsed.netloc):
                        continue
                    if mime and any(m in mime.lower() for m in ("image/", "font/", "text/css", "application/font")):
                        continue
                    if re.search(r"\.(?:png|jpe?g|gif|svg|webp|woff2?|ttf|eot|css)(?:\?|$)", original, re.I):
                        continue
                    urls.append({"url": original, "timestamp": ts, "status_code": status_code, "mime": mime})
                    hostnames.add(parsed.netloc.lower())
                    if self.looks_interesting_endpoint(original):
                        interesting_paths.append(original)
            except Exception as exc:
                stats["errors"] += 1
                return {"enabled": True, "error": str(exc), "urls": []}
            stats["items_found"] = len(urls)
            return {"enabled": True, "cdx_url": cdx_url, "search_pattern": search_url, "total_urls": len(urls), "urls": urls[:200], "hostnames_discovered": sorted(hostnames)[:80], "interesting_paths": self.dedupe(interesting_paths)[:100]}

    def fetch_ct_logs(self) -> Dict[str, Any]:
        if not self.ct_logs:
            return {"enabled": False}
        if not self.scope:
            return {"enabled": True, "error": "CT logs requires --scope to be set", "subdomains": []}
        with self._time_feature("ct_logs") as stats:
            subdomains = set()
            issuers: Counter = Counter()
            entries: List[Dict[str, Any]] = []
            try:
                resp = requests.get("https://crt.sh/", params={"q": f"%.{self.scope}", "output": "json"}, timeout=30, headers={"User-Agent": f"recon_fingerprint/{__version__}"}, proxies={})
                if resp.status_code != 200:
                    stats["errors"] += 1
                    return {"enabled": True, "error": f"crt.sh returned {resp.status_code}", "subdomains": []}
                data = resp.json()
                for entry in data[:self.ct_limit]:
                    name_value = entry.get("name_value") or ""
                    issuer = entry.get("issuer_name") or ""
                    for name in name_value.split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name and self.is_in_scope_hostname(name):
                            subdomains.add(name)
                    if issuer:
                        issuers[issuer[:80]] += 1
                    entries.append({"id": entry.get("id"), "common_name": entry.get("common_name"), "not_before": entry.get("not_before"), "not_after": entry.get("not_after"), "issuer": issuer[:80]})
            except Exception as exc:
                stats["errors"] += 1
                return {"enabled": True, "error": str(exc), "subdomains": []}
            stats["items_found"] = len(subdomains)
            return {"enabled": True, "total_entries": len(entries), "total_subdomains": len(subdomains), "subdomains": sorted(subdomains)[:200], "top_issuers": issuers.most_common(10), "sample_entries": entries[:30]}

    def build_scope_hints(self, html_info: Dict[str, Any],
                          assets_info: Dict[str, Any],
                          path_info: Dict[str, Any],
                          tls_info: Dict[str, Any],
                          wayback_info: Optional[Dict[str, Any]] = None,
                          ct_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        scope_hostnames: List[str] = []
        interesting_paths: List[str] = []
        observed_endpoints: List[str] = []

        all_text = "\n".join(text for _, text in self.observed_texts)
        if self.scope:
            scope_hostnames = sorted(set(re.findall(
                rf"[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*\.{re.escape(self.scope)}",
                all_text,
            )))
            # Agregar SAN DNS names del cert que caen en scope
            for san in (tls_info or {}).get("san_dns", []) or []:
                san_low = san.lower().lstrip("*.")
                if san_low.endswith(self.scope.lower()):
                    scope_hostnames.append(san_low)
            scope_hostnames = sorted(set(scope_hostnames))

        for js in assets_info.get("js", []):
            url = js.get("url") or ""
            if self.is_in_scope_url(url):
                observed_endpoints.append(url)
            sm_url = js.get("source_map_url")
            if sm_url and self.is_in_scope_url(sm_url):
                observed_endpoints.append(sm_url)
        # v3.1: solo agregamos page_endpoints in-scope a observed/interesting
        for ep in html_info.get("page_endpoints", []):
            ep_url = ep.get("url")
            if not ep_url:
                continue
            if self.scope and not self.is_in_scope_url(ep_url):
                continue
            observed_endpoints.append(ep_url)
            if ep.get("score", 0) >= 4:
                interesting_paths.append(ep_url)
        # v3.4: solo probes realmente útiles, no cualquier 200/401/403 HTML
        for probe_name, probe in path_info.items():
            if self.probe_is_meaningful(probe_name, probe):
                interesting_paths.append(probe.get("url"))

        historical_endpoints: List[str] = []
        ct_subdomains: List[str] = []
        if wayback_info and wayback_info.get("enabled"):
            for u in wayback_info.get("urls", [])[:200]:
                if u.get("url"):
                    historical_endpoints.append(u.get("url"))
            for h in wayback_info.get("hostnames_discovered", []):
                if self.is_in_scope_hostname(h):
                    scope_hostnames.append(h)
            for u in wayback_info.get("interesting_paths", [])[:100]:
                interesting_paths.append(u)
        if ct_info and ct_info.get("enabled"):
            for sub in ct_info.get("subdomains", []):
                ct_subdomains.append(sub)
                if self.is_in_scope_hostname(sub):
                    scope_hostnames.append(sub)
        scope_hostnames = sorted(set(scope_hostnames))

        return {
            "scope_hostnames": scope_hostnames[:200],
            "interesting_paths": self.dedupe([x for x in interesting_paths if x])[:120],
            "observed_endpoints": self.dedupe([x for x in observed_endpoints if x])[:160],
            "page_endpoints": html_info.get("page_endpoints", [])[:120],
            "page_actions": html_info.get("page_actions", [])[:120],
            "page_actions_external": html_info.get("page_actions_external", [])[:60],
            "tls_san_dns": (tls_info or {}).get("san_dns", [])[:50],
            "historical_endpoints": self.dedupe(historical_endpoints)[:200],
            "ct_discovered_subdomains": ct_subdomains[:200],
        }

    def build_analyzer_handoff(
        self,
        http_info: Dict[str, Any],
        html_info: Dict[str, Any],
        tech_stack: Dict[str, Any],
        assets_info: Dict[str, Any],
        auth_surface: Dict[str, Any],
        path_info: Dict[str, Any],
        scope_hints: Dict[str, Any],
        priorities: Dict[str, Any],
        secrets_info: Dict[str, Any],
        csp_info: CSPPolicy,
        cookies_sec: Dict[str, Any],
        special: Dict[str, Any],
        redirect_params: List[Dict[str, Any]],
        custom_stack: Optional[Dict[str, Any]] = None,
        param_intel: Optional[Dict[str, Any]] = None,
        tech_probes_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        custom_stack = custom_stack or {}
        param_intel = param_intel or {}
        tech_probes_info = tech_probes_info or {}

        def _handoff_endpoint_relevant(ep: Dict[str, Any]) -> bool:
            """Return True for endpoints worth handing to an LLM triage pass."""
            url = (ep.get("url") or "").strip()
            if not url:
                return False
            low = url.lower()
            if self.scope and not self.is_in_scope_url(url):
                return False
            if re.search(r"/(?:favicon\.ico|robots\.txt|sitemap(?:_index)?\.xml|manifest\.json)(?:$|[?#])", low):
                return False
            if re.search(r"\.(?:png|jpe?g|gif|svg|ico|webp|css|woff2?|ttf|eot|map)(?:$|[?#])", low):
                return False
            score = int(ep.get("score") or 0)
            if score >= 3:
                return True
            return bool(re.search(
                r"/(?:api|graphql|rest|web_api|admin|auth|oauth|login|logout|signup|register|callback|webhook|upload|download|import|export|search|user|users|account|profile|settings|config|status|health|metrics|manage|dashboard|staff|internal|permissions|sessions|notifications|projects)(?:/|$|[?#])",
                low,
            ))

        page_endpoint_candidates = [
            ep for ep in html_info.get("page_endpoints", [])
            if _handoff_endpoint_relevant(ep)
        ][:40]

        page_endpoint_score_by_url = {
            (ep.get("url") or ""): int(ep.get("score") or 0)
            for ep in html_info.get("page_endpoints", [])
            if ep.get("url")
        }
        interesting_path_set = set(scope_hints.get("interesting_paths", []) or [])

        def _handoff_observed_relevant(url: str) -> bool:
            """Filter historical/observed endpoints to those with score or useful context."""
            if not url:
                return False
            low = url.lower().strip()
            if self.scope and not self.is_in_scope_url(url):
                return False
            if url in interesting_path_set:
                return True
            if page_endpoint_score_by_url.get(url, 0) >= 3:
                return True
            if re.search(r"/(?:favicon\.ico|robots\.txt|sitemap(?:_index)?\.xml|manifest\.json)(?:$|[?#])", low):
                return False
            if re.search(r"\.(?:png|jpe?g|gif|svg|ico|webp|css|woff2?|ttf|eot|map)(?:$|[?#])", low):
                return False
            return bool(re.search(
                r"/(?:api|graphql|rest|web_api|admin|auth|oauth|login|logout|signup|register|callback|webhook|upload|download|import|export|search|user|users|account|profile|settings|config|status|health|metrics|manage|dashboard|staff|internal|permissions|sessions|notifications|projects)(?:/|$|[?#])",
                low,
            ))

        observed_endpoint_candidates = [
            u for u in scope_hints.get("observed_endpoints", [])
            if _handoff_observed_relevant(u)
        ][:60]

        top_assets = []
        # Handoff slim: keep only truly useful assets for downstream LLM triage.
        # Score < 5 was too noisy for Claude/AI handoffs.
        for item in priorities.get("asset_rankings", [])[:15]:
            if item.get("score", 0) < 5:
                continue
            top_assets.append({
                "url": item.get("url"),
                "filename": item.get("filename"),
                "score": item.get("score"),
                "reasons": item.get("reasons", []),
            })
            if len(top_assets) >= 10:
                break
        graphql: List[str] = []
        realtime: List[str] = []
        for ep in html_info.get("page_endpoints", []):
            url = ep.get("url") or ""
            if "graphql" in url.lower():
                graphql.append(url)
            if url.lower().startswith(("ws://", "wss://")):
                realtime.append(url)
        graphql_probe = (path_info.get("graphql", {}) or {}).get("graphql_probe") or {}
        if graphql_probe.get("confirmed"):
            graphql.append((path_info.get("graphql") or {}).get("url"))

        param_leads = []
        for p in (param_intel or {}).get("top_params", [])[:20]:
            if p.get("score", 0) < 6:
                continue
            param_leads.append({
                "name": p["name"],
                "score": p["score"],
                "categories": p.get("categories", []),
                "test_hints": self._param_test_hints(p.get("categories", [])),
                "associated_endpoints": p.get("associated_endpoints", []),
            })

        return {
            "target": self.final_url,
            "scope": self.scope,
            "host_priority": priorities.get("host_priority", {}),
            "top_targets": priorities.get("top_targets", []),
            "interesting_assets": top_assets,
            "auth_context": {
                "login_links": auth_surface.get("login_links", []),
                "internal_login_links": auth_surface.get("internal_login_links", []),
                "federated_login_links": auth_surface.get("federated_login_links", []),
                "session_cookie_name": auth_surface.get("session_cookie_name"),
                "csrf_mechanisms": auth_surface.get("csrf_mechanisms", []),
                "oauth_signals": auth_surface.get("oauth_signals"),
                "oidc_signals": auth_surface.get("oidc_signals"),
                "saml_signals": auth_surface.get("saml_signals"),
                "sso_providers_detected": auth_surface.get(
                    "sso_providers_detected", []),
                "captcha": {
                    "detected": auth_surface.get("captcha_detected"),
                    "providers": auth_surface.get("captcha_providers", []),
                },
            },
            "api_surface": {
                # Handoff slim: max 40 relevant page endpoints, not every in-scope URL.
                "page_endpoints": page_endpoint_candidates,
                "interesting_paths": scope_hints.get(
                    "interesting_paths", [])[:40],
                # Handoff slim: max 60 observed endpoints with score/context.
                "observed_endpoints": observed_endpoint_candidates,
                "page_actions": html_info.get("page_actions", [])[:80],
                "page_actions_external": html_info.get("page_actions_external", [])[:40],
                "page_endpoint_families": html_info.get("page_endpoint_families", [])[:40],
                "graphql_probe": graphql_probe,
            },
            "graphql": self.dedupe([x for x in graphql if x])[:20],
            "realtime": self.dedupe([x for x in realtime if x])[:20],
            # scope_hostnames/tls_san_dns intentionally omitted from analyzer_handoff.
            # They remain available in the full JSON under scope_hints.
            "frameworks": [x.get("name") for x in
                           tech_stack.get("frameworks", [])[:8]],
            "libraries": [x.get("name") for x in
                          tech_stack.get("libraries", [])[:10]],
            "tech_categories": {
                "frameworks": [f["name"] for f in
                               tech_stack.get("frameworks", [])[:8]],
                "cms": [c["name"] for c in tech_stack.get("cms", [])[:10]],
                "hosted_platforms": [h["name"] for h in
                                     tech_stack.get("hosted_platforms", [])[:8]],
                "dev_tools": [d["name"] for d in
                              tech_stack.get("dev_tools", [])[:10]],
                "network_appliances": [n["name"] for n in
                                       tech_stack.get("network_appliances", [])[:10]],
                "idps": [i["name"] for i in tech_stack.get("idps", [])[:10]],
            },
            "sso_signals": auth_surface.get("sso_signals", []),
            "custom_stack": custom_stack,
            "waf_signals": http_info.get("waf_signals", []),
            "cdn_signals": http_info.get("cdn_signals", []),
            "cors_reflect_test": http_info.get("cors_reflect_test", {}),
            "csp_summary": {
                "present": bool(csp_info.raw),
                "report_only": csp_info.report_only,
                "unsafe_inline": csp_info.unsafe_inline,
                "unsafe_eval": csp_info.unsafe_eval,
                "nonce_used": csp_info.nonce_used,
                "strict_dynamic": csp_info.strict_dynamic,
                "wildcard_directives": csp_info.wildcard_directives,
            },
            "cookies_security_summary": cookies_sec.get("summary", {}),
            "secrets_summary": {
                "count": secrets_info.get("count", 0),
                "by_severity": secrets_info.get("by_severity", {}),
            },
            "special_services": special,
            "open_redirect_hints": redirect_params,
            "param_leads": param_leads,
            "tech_probe_hits": [
                {"tech": f.get("tech"), "url": f.get("url"), "signals_hit": f.get("signals_hit", [])}
                for f in tech_probes_info.get("findings", [])[:30]
                if f.get("signals_hit")
            ],
        }

    def build_notes(
        self,
        http_info: Dict[str, Any],
        html_info: Dict[str, Any],
        tech_stack: Dict[str, Any],
        assets_info: Dict[str, Any],
        auth_surface: Dict[str, Any],
        path_info: Dict[str, Any],
        secrets_info: Dict[str, Any],
        csp_info: CSPPolicy,
        cookies_sec: Dict[str, Any],
        special: Dict[str, Any],
    ) -> List[str]:
        notes = []
        if tech_stack.get("sanitizers", {}).get("dompurify"):
            notes.append(
                "DOMPurify detectado; el analyzer debería bajar confidence "
                "de sinks HTML cuando corresponda."
            )
        if csp_info.raw and not csp_info.unsafe_inline:
            notes.append(
                "CSP sin unsafe-inline; XSS inline trivial es menos probable, "
                "priorizar gadgets JSONP/strict-dynamic bypass y DOM XSS."
            )
        if csp_info.raw and csp_info.unsafe_inline and csp_info.unsafe_eval:
            notes.append(
                "CSP presente pero con unsafe-inline + unsafe-eval — "
                "básicamente no protege contra XSS reflexivo/stored."
            )
        if not csp_info.raw:
            notes.append("Sin CSP — cualquier XSS es directo.")
        if csp_info.report_only:
            notes.append(
                "CSP está en report-only — no bloquea, solo reporta. "
                "Revisar report-uri/report-to como posible leak de paths."
            )
        if csp_info.wildcard_directives:
            notes.append(
                f"CSP tiene wildcards en: "
                f"{', '.join(csp_info.wildcard_directives[:4])}"
            )

        usable_sm = [x for x in assets_info.get("js", [])
                     if (x.get("source_map_status") or {}).get(
                         "parses_as_sourcemap")]
        broken_sm = [x for x in assets_info.get("js", [])
                     if (x.get("source_map_status") or {}).get("reachable")
                     and not (x.get("source_map_status") or {}).get(
                         "parses_as_sourcemap")]
        if usable_sm:
            notes.append(
                f"{len(usable_sm)} sourcemap(s) usables — bajar y correr "
                "analyzer sobre el código original si están en scope."
            )
        if broken_sm:
            notes.append(
                f"{len(broken_sm)} sourcemap(s) declarados pero no parsean "
                "como .map real — no los priorices como válidos."
            )

        if auth_surface.get("oauth_signals"):
            notes.append(
                "Señales de OAuth/OIDC — cruzar con flows/params en el "
                "bundle (redirect_uri, state, nonce handling)."
            )
        if auth_surface.get("saml_signals"):
            notes.append(
                "Señales SAML — revisar SAMLRequest/Response handling, "
                "RelayState, XML signature wrapping."
            )
        if auth_surface.get("captcha_detected"):
            notes.append(
                f"Captcha detectado ({', '.join(auth_surface.get('captcha_providers', []))}) "
                "— considerar ratelimit bypass via alternate endpoints."
            )

        graphql_probe = (path_info.get("graphql", {}) or {}).get("graphql_probe") or {}
        if graphql_probe.get("confirmed"):
            notes.append(
                f"GraphQL confirmado ({graphql_probe.get('confidence', 'unknown')}) "
                "— probar introspection, alias-based rate bypass, "
                "query depth/complexity limits."
            )
        elif (path_info.get("graphql") or {}).get("status_code") in {200, 400, 401, 403}:
            notes.append(
                "/graphql respondió pero no confirmado — no priorizar "
                "sin señales adicionales."
            )

        # Secrets
        sev = (secrets_info or {}).get("by_severity") or {}
        if sev.get("high"):
            notes.append(
                f"{sev.get('high')} secreto(s) HIGH severity — revisar "
                "el field `secrets.findings` antes de nada."
            )
        if sev.get("medium"):
            notes.append(f"{sev.get('medium')} secreto(s) medium severity.")

        # CORS
        cors = http_info.get("cors_reflect_test") or {}
        if cors.get("exploitable_hint"):
            notes.append(
                "CORS: reflected Origin + Access-Control-Allow-Credentials "
                "— potencialmente explotable para exfil cross-origin."
            )
        elif cors.get("wildcard_with_creds"):
            notes.append(
                "CORS: ACAO=* con ACAC=true — config inválida/peligrosa."
            )
        elif cors.get("null_origin_allowed"):
            notes.append(
                "CORS: permite Origin: null — explotable desde sandboxed iframes."
            )

        # Cookies
        cs = cookies_sec.get("summary") or {}
        if cs.get("session_without_httponly"):
            notes.append(
                "Cookie de sesión sin HttpOnly — XSS → token theft directo."
            )
        if cs.get("samesite_none_insecure"):
            notes.append(
                "Cookies con SameSite=None pero sin Secure — no se envían "
                "en contextos modernos, chequear comportamiento real."
            )
        if cs.get("missing_samesite"):
            notes.append(
                f"{cs.get('missing_samesite')} cookie(s) sin SameSite — "
                "CSRF potencialmente más fácil."
            )

        # Special services
        if special.get("git_exposed"):
            notes.append("⚠️ .git/HEAD EXPUESTO — dump total del repo posible.")
        if special.get("env_exposed"):
            notes.append("⚠️ .env EXPUESTO — probable leak de credenciales.")
        if special.get("spring_actuator"):
            notes.append(
                "Spring Actuator endpoints alcanzables — revisar /env, "
                "/heapdump, /mappings para leaks."
            )
        if special.get("arcgis"):
            notes.append(
                "ArcGIS REST/FeatureServer detectado — revisar permisos de "
                "servicios (read/write sin auth, admin endpoints, print task)."
            )
        if special.get("elasticsearch"):
            notes.append(
                "Elasticsearch/OpenSearch endpoints referenciados — "
                "probar Origin spoofing, writes sin auth y search/DSL injection."
            )
        if special.get("firebase"):
            notes.append(
                "Firebase Realtime DB / Firestore referenciado — probar "
                "rules con reads/writes anónimos (/.json)."
            )
        if special.get("hasura"):
            notes.append(
                "Hasura GraphQL detectado — probar introspection sin auth, "
                "role headers (X-Hasura-Role, X-Hasura-User-Id) y query "
                "permissions por rol anónimo."
            )
        if special.get("kubernetes_hint"):
            notes.append(
                "Headers/paths de Kubernetes detectados — revisar "
                "server-side misconfig (dashboard expuesto, kubelet, API)."
            )
        if special.get("cloud_functions"):
            notes.append(
                f"{len(special.get('cloud_functions', []))} cloud function "
                "URL(s) detectadas en frontend — mapear lambdas/cloud run "
                "como superficie de API, chequear auth y CORS por endpoint."
            )

        if http_info.get("waf_signals"):
            notes.append(
                f"WAF detectado: {', '.join(http_info.get('waf_signals', [])[:3])} "
                "— tener en cuenta para bypass techniques específicas."
            )
        if http_info.get("cdn_signals"):
            notes.append(
                f"CDN detectado: {', '.join(http_info.get('cdn_signals', [])[:3])} "
                "— revisar cache key normalization para cache poisoning."
            )
        if self.downloaded_assets:
            notes.append(
                "Assets interesantes descargados — revisar manifest y "
                "correr analyzer sobre ellos."
            )
        return notes

    # --------------------------------------------------------------
    # Helpers: endpoints, strings, scoring, sourcemaps
    # --------------------------------------------------------------
    def extract_interesting_strings_from_text(
            self, text: str,
            source: str = "inline_script") -> List[Dict[str, Any]]:
        found: List[Dict[str, Any]] = []

        absolute_patterns = [
            r"""https?://[^\s"'`<>]+""",
            r"""wss?://[^\s"'`<>]+""",
        ]
        # v3.3: relative patterns separados para poder filtrar hostname-como-path
        relative_patterns = [
            r"""(?<![A-Za-z0-9.])/(?:api|graphql|rest|internal|admin|auth|oauth|login|logout|signup|register|callback|webhook|upload|download|import|export|search|user|users|account|profile|settings|config|status|health|metrics|manage|dashboard|staff|permissions|invites|sessions|notifications|projects|areas|verification)[A-Za-z0-9/_\-.{}:$?=&]*"""
        ]

        for pat in absolute_patterns:
            for value in re.findall(pat, text, re.I):
                raw = html_unescape(value).strip()
                normalized = self.normalize_url(raw)
                if normalized and self.looks_interesting_endpoint(normalized):
                    found.append({"url": normalized, "source": source})

        for pat in relative_patterns:
            for value in re.findall(pat, text, re.I):
                raw = html_unescape(value).strip()
                # v3.5: evita '/api.whatsapp.com/...' como interno,
                # pero NO rompe '/index.hash.js'
                if self.looks_like_domain_in_leading_path(raw):
                    continue
                normalized = self.normalize_url(raw)
                if normalized and self.looks_interesting_endpoint(normalized):
                    found.append({"url": normalized, "source": source})

        return self.dedupe(found)[:120]

    def extract_realtime_strings_from_text(
            self, text: str,
            source: str = "inline_script") -> List[Dict[str, Any]]:
        found: List[Dict[str, Any]] = []
        for value in re.findall(r"""wss?://[^\s"'`<>]+""", text, re.I):
            found.append({"url": value, "source": source, "kind": "websocket"})
        if re.search(r"EventSource\s*\(", text):
            found.append({
                "url": "EventSource(...)",
                "source": source, "kind": "eventsource",
            })
        return self.dedupe(found)[:40]

    def looks_interesting_endpoint(self, value: str) -> bool:
        if not value:
            return False
        low = value.lower().strip()
        if low.startswith(("mailto:", "tel:", "javascript:", "data:")):
            return False
        if re.search(r"\.(?:png|jpg|jpeg|gif|svg|webp|css|woff2?|ttf|eot)"
                     r"(?:$|[?#])", low):
            return False
        keywords = [
            "api", "graphql", "auth", "login", "logout", "register",
            "signup", "signin", "token", "oauth", "openid", "saml",
            "callback", "redirect", "admin", "staff", "user", "users",
            "account", "profile", "settings", "config", "upload",
            "download", "export", "import", "report", "pdf", "file",
            "document", "documents", "invite", "member", "members",
            "role", "permission", "project", "projects", "workspace",
            "webhook", "internal", "manage", "dashboard",
        ]
        if low.startswith(("/", "./", "../", "http://", "https://",
                           "ws://", "wss://")):
            return any(k in low for k in keywords)
        return False

    def endpoint_method_hint(self, url: str, source: str) -> str:
        low = (url or "").lower()
        if source in {"form_action", "form"}:
            return "POST"
        if any(x in low for x in
               ["upload", "import", "create", "save", "submit"]):
            return "POST"
        if any(x in low for x in ["update", "edit", "patch"]):
            return "PATCH"
        if any(x in low for x in ["delete", "remove"]):
            return "DELETE"
        return "GET"

    def endpoint_score(self, url: str, source: str = "") -> int:
        score = 0
        low = (url or "").lower()
        keywords = [
            "graphql", "admin", "auth", "login", "logout", "token",
            "oauth", "openid", "callback", "upload", "download",
            "export", "report", "pdf", "user", "account", "profile",
            "settings", "invite", "role", "permission", "project",
            "webhook", "internal", "staff",
        ]
        for k in keywords:
            if k in low:
                score += 2
        if low.startswith(("ws://", "wss://")):
            score += 3
        if source in {"inline_script", "data-endpoint", "data-api",
                      "data-api-url", "form_action", "form"}:
            score += 1
        # params de open-redirect suman
        if "?" in low:
            try:
                qs = urlparse(low).query
                for k, _ in parse_qsl(qs, keep_blank_values=True):
                    if k in OPEN_REDIRECT_PARAMS:
                        score += 2
                        break
            except Exception:
                pass
        return min(12, score)

    def collect_page_endpoints(
        self,
        forms: List[Dict[str, Any]],
        links: List[Dict[str, Any]],
        iframes: List[Dict[str, Any]],
        data_endpoints: List[Dict[str, Any]],
        inline_endpoints: List[Dict[str, Any]],
        inline_realtime: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        endpoints: List[Dict[str, Any]] = []

        for form in forms:
            action = form.get("action") or ""
            if not action:
                continue
            # v3.1: scope filter — forms externos no son superficie nuestra
            if self.scope and not self.is_in_scope_url(action):
                continue
            endpoints.append({
                "url": action,
                "source": "form_action",
                "method_hint": form.get("method") or "POST",
                "score": self.endpoint_score(action, "form_action"),
            })

        for item in (links + iframes + data_endpoints
                     + inline_endpoints + inline_realtime):
            url = item.get("url") or ""
            source = item.get("source") or "html"
            if not url or not self.looks_interesting_endpoint(url):
                continue
            # v3.1: scope filter — descartamos externos aunque parezcan interesantes
            if self.scope and not self.is_in_scope_url(url):
                continue
            endpoints.append({
                "url": url,
                "source": source,
                "method_hint": self.endpoint_method_hint(url, source),
                "score": self.endpoint_score(url, source),
            })

        endpoints = self.dedupe(endpoints)
        endpoints.sort(
            key=lambda x: (-x.get("score", 0), str(x.get("url") or "")))
        return endpoints

    # --------------------------------------------------------------
    # Header / cookie / WAF helpers
    # --------------------------------------------------------------
    def lower_headers(self, headers: Any) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        try:
            items = headers.items()
        except Exception:
            return out
        for k, v in items:
            low = k.lower()
            if low == "set-cookie":
                out.setdefault(low, []).append(v)
            else:
                out[low] = v
        return out

    def extract_security_headers(self,
                                 headers: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "csp": headers.get("content-security-policy"),
            "csp_report_only": headers.get("content-security-policy-report-only"),
            "cors": headers.get("access-control-allow-origin"),
            "cors_credentials": headers.get("access-control-allow-credentials"),
            "hsts": headers.get("strict-transport-security"),
            "x_frame_options": headers.get("x-frame-options"),
            "x_content_type_options": headers.get("x-content-type-options"),
            "referrer_policy": headers.get("referrer-policy"),
            "permissions_policy": headers.get("permissions-policy"),
            "coop": headers.get("cross-origin-opener-policy"),
            "coep": headers.get("cross-origin-embedder-policy"),
            "corp": headers.get("cross-origin-resource-policy"),
        }
        return out

    def detect_waf(self, headers: Dict[str, Any],
                   body: str = "") -> List[str]:
        serial = json.dumps(headers, ensure_ascii=False).lower()
        body_low = (body or "")[:5000].lower()
        found = []
        for name, patterns in WAF_PATTERNS.items():
            if any(p in serial for p in patterns):
                found.append(name)
                continue
            # Body markers (solo strings distintivos que no estén en headers)
            body_markers = {
                "modsecurity": ["mod_security", "modsecurity"],
                "f5_bigip": ["the requested url was rejected"],
                "cloudflare": ["attention required! | cloudflare",
                               "cloudflare ray id"],
                "akamai": ["reference&#32;&#35;"],
                "imperva": ["_incapsula_resource"],
            }
            markers = body_markers.get(name, [])
            if markers and any(m in body_low for m in markers):
                found.append(name)
        return sorted(set(found))

    def detect_cdn(self, headers: Dict[str, Any]) -> List[str]:
        serial = json.dumps(headers, ensure_ascii=False).lower()
        found = []
        for name, patterns in CDN_PATTERNS.items():
            if any(p in serial for p in patterns):
                found.append(name)
        return sorted(set(found))

    def detect_server_hints(self,
                            headers: Dict[str, Any]) -> List[Dict[str, Any]]:
        hints = []
        server = headers.get("server")
        x_powered = headers.get("x-powered-by")
        x_aspnet = headers.get("x-aspnet-version")
        x_aspnetmvc = headers.get("x-aspnetmvc-version")
        for value, source in [
            (server, "server_header"),
            (x_powered, "x-powered-by"),
            (x_aspnet, "x-aspnet-version"),
            (x_aspnetmvc, "x-aspnetmvc-version"),
        ]:
            if not value:
                continue
            parts = re.split(r"[,;]", value)
            for part in parts:
                piece = part.strip()
                if not piece:
                    continue
                m = re.match(r"([A-Za-z0-9._-]+)(?:/([A-Za-z0-9._-]+))?",
                             piece)
                if m:
                    hints.append({
                        "name": m.group(1),
                        "version": m.group(2),
                        "source": source,
                    })
        return hints

    def serialize_cookies(self, jar: requests.cookies.RequestsCookieJar,
                          headers: Dict[str, Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        # Parse Set-Cookie crudos del header para no perder HttpOnly/SameSite
        raw_set_cookies = headers.get("set-cookie") or []
        if isinstance(raw_set_cookies, str):
            raw_set_cookies = [raw_set_cookies]
        parsed_by_name: Dict[str, Dict[str, Any]] = {}
        for raw in raw_set_cookies:
            try:
                first = raw.split(";", 1)[0]
                if "=" not in first:
                    continue
                name, _val = first.split("=", 1)
                name = name.strip()
                attrs: Dict[str, Any] = {
                    "name": name,
                    "http_only": False,
                    "secure": False,
                    "same_site": None,
                    "domain": None,
                    "path": None,
                }
                for part in raw.split(";")[1:]:
                    part = part.strip()
                    if not part:
                        continue
                    if "=" in part:
                        k, v = part.split("=", 1)
                        k_low = k.strip().lower()
                        if k_low == "samesite":
                            attrs["same_site"] = v.strip()
                        elif k_low == "domain":
                            attrs["domain"] = v.strip()
                        elif k_low == "path":
                            attrs["path"] = v.strip()
                        elif k_low == "expires":
                            attrs["expires"] = v.strip()
                        elif k_low == "max-age":
                            attrs["max_age"] = v.strip()
                    else:
                        low = part.lower()
                        if low == "httponly":
                            attrs["http_only"] = True
                        elif low == "secure":
                            attrs["secure"] = True
                parsed_by_name[name] = attrs
            except Exception:
                continue
        # Unir con jar (jar tiene domain/path pero no HttpOnly/SameSite)
        for c in jar:
            entry = {
                "name": c.name,
                "domain": c.domain,
                "path": c.path,
                "secure": c.secure,
                "expires": c.expires,
            }
            extra = parsed_by_name.get(c.name)
            if extra:
                entry["http_only"] = extra.get("http_only", False)
                entry["same_site"] = extra.get("same_site")
            else:
                entry["http_only"] = False
                entry["same_site"] = None
            out.append(entry)
        # Cookies que estaban en set-cookie raw pero no en jar (ej. rechazadas)
        jar_names = {c.name for c in jar}
        for name, attrs in parsed_by_name.items():
            if name not in jar_names:
                out.append(attrs)
        return out

    # --------------------------------------------------------------
    # URL normalization & asset classification
    # --------------------------------------------------------------
    def looks_like_relative_asset_filename(self, raw: str) -> bool:
        """True si parece filename de asset relativo (runtime.hash.js, etc.)."""
        low = (raw or "").lower().strip()
        if "/" in low:
            return False
        if "?" in low or "#" in low:
            low = low.split("?", 1)[0].split("#", 1)[0]
        return bool(re.search(
            r"\.(?:js|mjs|cjs|css|map|json|txt|xml|svg|png|jpe?g|gif|webp|ico|woff2?|ttf|eot)$",
            low, re.I,
        ))

    def looks_like_bare_external_url(self, raw: str) -> bool:
        """True si parece dominio externo sin esquema; False si es asset relativo."""
        raw = (raw or "").strip()
        if self.looks_like_relative_asset_filename(raw):
            return False
        return bool(re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:[:/?!#]|$)", raw))

    def looks_like_domain_in_leading_path(self, raw: str) -> bool:
        """
        Detecta '/api.whatsapp.com/send' (dominio externo escrito como path).

        NO matchea assets root-relative:
          /index.DMI47mgZ.min.js  → False
          /styles.abc123.css      → False
        SÍ matchea dominios externos:
          /api.whatsapp.com/send  → True
        """
        raw = (raw or "").strip()
        if not raw.startswith("/"):
            return False
        candidate = raw.lstrip("/")
        if not candidate:
            return False
        # Requiere path adicional después del primer segmento
        # — evita romper assets root-relative como /index.hash.js
        if "/" not in candidate:
            return False
        first_segment = candidate.split("/", 1)[0].strip().lower()
        if not first_segment or "." not in first_segment:
            return False
        # Si el primer segmento parece filename de asset, NO es dominio externo
        if self.looks_like_relative_asset_filename(first_segment):
            return False
        # Debe tener forma de hostname real: a.b, a.b.c, etc.
        if not re.match(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$", first_segment, re.I):
            return False
        return True

    def normalize_url(self, raw: str,
                      base: Optional[str] = None) -> Optional[str]:
        if not raw:
            return None
        raw = html_unescape(raw).strip()
        if raw.startswith(("data:", "javascript:", "mailto:", "tel:")):
            return None
        if raw == "#" or raw.startswith("#"):
            return None
        if raw.startswith("//"):
            parsed = urlparse(base or self.final_url)
            return f"{parsed.scheme}:{raw}"
        # v3.5: '/api.whatsapp.com/send' → externo real
        # '/index.DMI47mgZ.min.js'      → NO externo, asset root-relative
        if self.looks_like_domain_in_leading_path(raw):
            return f"https://{raw.lstrip('/')}"
        # v3.4: solo externa si parece dominio real, NO si es asset relativo
        # (runtime.ecbe48f95d996ad9.js, polyfills.hash.js, etc. NO son dominios)
        if self.looks_like_bare_external_url(raw):
            return f"https://{raw}"
        normalized = urljoin(base or self.final_url, raw)
        try:
            parsed = urlparse(normalized)
            if not parsed.scheme or not parsed.netloc:
                return normalized
            clean = parsed._replace(fragment="")
            return clean.geturl()
        except Exception:
            return normalized

    def is_in_scope_url(self, url: str) -> bool:
        """Only HTTP(S) URLs resolving to the declared host scope are in scope."""
        return self.scope_policy.matches_url(url, base_url=self.final_url)

    def split_actions_by_scope(
        self, actions: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Separa page_actions en internas (in-scope) y externas."""
        internal: List[Dict[str, Any]] = []
        external: List[Dict[str, Any]] = []
        for action in actions:
            action_url = action.get("url") or action.get("action") or ""
            if not action_url:
                continue
            if self.scope and not self.is_in_scope_url(action_url):
                external.append(action)
            else:
                internal.append(action)
        return self.dedupe(internal), self.dedupe(external)

    def canonical_endpoint_family(self, url: str) -> Optional[str]:
        """Normaliza una URL a su 'familia' canónica (path + param keys, sin valores)."""
        if not url:
            return None
        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower()
            path = parsed.path or "/"
            params = sorted(set(
                k.lower() for k, _ in parse_qsl(parsed.query, keep_blank_values=True)
            ))
            family = f"{parsed.scheme}://{host}{path}"
            if params:
                family += "?" + "&".join(params)
            return family
        except Exception:
            return url

    def build_endpoint_families(
        self, endpoints: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Agrupa endpoints por familia canónica para reducir ruido por params."""
        grouped: Dict[str, Dict[str, Any]] = {}
        for ep in endpoints:
            url = ep.get("url") or ""
            if not url:
                continue
            family = self.canonical_endpoint_family(url)
            if not family:
                continue
            if family not in grouped:
                grouped[family] = {
                    "family": family,
                    "count": 0,
                    "max_score": 0,
                    "sources": set(),
                    "method_hints": set(),
                    "samples": [],
                }
            bucket = grouped[family]
            bucket["count"] += 1
            bucket["max_score"] = max(bucket["max_score"], ep.get("score", 0))
            if ep.get("source"):
                bucket["sources"].add(ep["source"])
            if ep.get("method_hint"):
                bucket["method_hints"].add(ep["method_hint"])
            if len(bucket["samples"]) < 5:
                bucket["samples"].append(url)
        out = []
        for item in grouped.values():
            out.append({
                "family": item["family"],
                "count": item["count"],
                "max_score": item["max_score"],
                "sources": sorted(item["sources"]),
                "method_hints": sorted(item["method_hints"]),
                "samples": item["samples"],
            })
        out.sort(key=lambda x: (-x["max_score"], -x["count"], x["family"]))
        return out

    def keep_asset_url(self, url: str) -> bool:
        host = urlparse(url).netloc.lower()
        if any(skip in host for skip in SKIP_ASSET_DOMAINS):
            return False
        # Con scope activo, solo guardamos assets del scope (in-scope-only mode)
        if self.scope:
            scope = self.scope.lower().lstrip(".")
            if host and not (host == scope or host.endswith("." + scope)):
                return False
        return True

    def classify_asset_role(self, value: str) -> str:
        low = value.lower()
        # Vendors conocidos primero — orden importa: evita que "bundle" gane
        if re.search(
            r"jquery|bootstrap|popper|recaptcha|gtag|analytics|google"
            r"|fontawesome|lodash|underscore|moment|axios|react|vue|angular"
            r"|ember|backbone|d3|chart\.js|three\.js|swiper|slick|flickity"
            r"|lightslider|lightbox|flipsnack|twitter-bootstrap",
            low,
        ):
            return "vendor"
        if re.search(r"vendor|chunk-vendors|polyfill|runtime|node_modules", low):
            return "vendor"
        if re.search(r"main|app|index|entry", low):
            return "app"
        return "unknown"

    def extract_source_map_from_text(self, text: str) -> Optional[str]:
        tail = text[-1600:]
        m = re.search(r"sourceMappingURL=([^\s]+)", tail, re.I)
        return m.group(1).strip() if m else None

    def build_declared_only_sourcemap_status(
            self, url: Optional[str],
            base: Optional[str] = None) -> Dict[str, Any]:
        normalized = self.normalize_url(url, base=base) if url else None
        return {
            "declared": bool(url),
            "normalized_url": normalized,
            "reachable": None,
            "http_status": None,
            "content_type": None,
            "looks_like_json": None,
            "parses_as_sourcemap": None,
            "has_sources": None,
            "has_sources_content": None,
            "source_count": None,
            "sources_content_count": None,
            "is_probably_html_fallback": None,
            "error": None,
        }

    def build_local_sourcemap_status(self,
                                     url: Optional[str]) -> Dict[str, Any]:
        if not url:
            return self.build_declared_only_sourcemap_status(url)
        p = Path(url)
        status = self.build_declared_only_sourcemap_status(url)
        status["normalized_url"] = str(p)
        status["reachable"] = p.exists()
        status["http_status"] = 200 if p.exists() else None
        if not p.exists():
            status["error"] = "local_sourcemap_not_found"
            status["parses_as_sourcemap"] = False
            return status
        try:
            raw = p.read_text(encoding="utf-8", errors="ignore")
            status.update(self.analyze_sourcemap_payload(raw))
            status["content_type"] = "application/json"
        except Exception as exc:
            status["error"] = str(exc)
            status["parses_as_sourcemap"] = False
        return status

    def inspect_sourcemap(self, url: Optional[str]) -> Dict[str, Any]:
        status = self.build_declared_only_sourcemap_status(url)
        if not url:
            return status
        try:
            resp = self.session.get(url, timeout=self.timeout,
                                    allow_redirects=True, stream=True)
            status["reachable"] = resp.status_code == 200
            status["http_status"] = resp.status_code
            status["content_type"] = resp.headers.get("Content-Type")
            cl = resp.headers.get("Content-Length")
            if cl and cl.isdigit():
                status["content_length"] = int(cl)
            chunks = []
            total = 0
            for chunk in resp.iter_content(chunk_size=8192,
                                           decode_unicode=True):
                if not chunk:
                    continue
                if isinstance(chunk, bytes):
                    piece = chunk.decode("utf-8", errors="ignore")
                else:
                    piece = chunk
                chunks.append(piece)
                total += len(piece)
                if total >= 300_000:
                    break
            payload = "".join(chunks)
            status.update(self.analyze_sourcemap_payload(payload))
            if resp.status_code != 200:
                status["parses_as_sourcemap"] = False
            return status
        except Exception as exc:
            status["reachable"] = False
            status["parses_as_sourcemap"] = False
            status["error"] = str(exc)
            return status

    def analyze_sourcemap_payload(self, payload: str) -> Dict[str, Any]:
        snippet = (payload or "")[:400]
        out: Dict[str, Any] = {
            "looks_like_json": False,
            "parses_as_sourcemap": False,
            "has_sources": False,
            "has_sources_content": False,
            "source_count": 0,
            "sources_content_count": 0,
            "is_probably_html_fallback": False,
            "sample": snippet,
        }
        raw = (payload or "").lstrip()
        if not raw:
            out["error"] = "empty_response"
            return out
        if raw[:50].lower().startswith(("<!doctype html", "<html",
                                         "<head", "<body")):
            out["is_probably_html_fallback"] = True
            out["error"] = "html_fallback"
            return out
        if raw[:1] in {"{", "["}:
            out["looks_like_json"] = True
        try:
            parsed = json.loads(payload)
        except Exception as exc:
            out["error"] = f"json_parse_error: {exc}"
            return out
        if not isinstance(parsed, dict):
            out["error"] = "json_not_object"
            return out
        sources = parsed.get("sources") if isinstance(
            parsed.get("sources"), list) else []
        sources_content = parsed.get("sourcesContent") if isinstance(
            parsed.get("sourcesContent"), list) else []
        has_mappings = isinstance(parsed.get("mappings"), str)
        out["source_count"] = len(sources)
        out["sources_content_count"] = len(
            [x for x in sources_content if isinstance(x, str) and x.strip()])
        out["has_sources"] = bool(sources)
        out["has_sources_content"] = out["sources_content_count"] > 0
        out["parses_as_sourcemap"] = bool(
            has_mappings and sources and parsed.get("version") in {3, "3"})
        if not out["parses_as_sourcemap"] and has_mappings and sources:
            out["parses_as_sourcemap"] = True
        return out

    def check_accessible(self, url: Optional[str]) -> Optional[bool]:
        if not url:
            return None
        try:
            resp = self.session.head(url, timeout=self.timeout,
                                     allow_redirects=True)
            if resp.status_code == 405:
                resp = self.session.get(url, timeout=self.timeout,
                                        allow_redirects=True, stream=True)
            return resp.status_code == 200
        except Exception:
            return False

    def extract_version_near(self, text: str, pat: str) -> Optional[str]:
        try:
            m = re.search(pat, text, re.I)
            if not m:
                return None
            start = max(0, m.start() - 80)
            end = min(len(text), m.end() + 120)
            window = text[start:end]
            v = re.search(r"\bv?(\d+\.\d+(?:\.\d+)?)\b", window)
            return v.group(1) if v else None
        except Exception:
            return None

    def conf_from_hits(self, n: int) -> str:
        if n >= 3:
            return "high"
        if n == 2:
            return "medium"
        return "low"

    def conf_rank(self, value: str) -> int:
        return {"high": 0, "medium": 1, "low": 2}.get(value, 9)

    def dedupe(self, items: Iterable[Any]) -> List[Any]:
        seen = set()
        out = []
        for item in items:
            if isinstance(item, (dict, list)):
                key = json.dumps(item, ensure_ascii=False, sort_keys=True)
            else:
                key = str(item)
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out

    def origin(self, url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def probe_name(self, path: str) -> str:
        mapping = {
            "/robots.txt": "robots_txt",
            "/sitemap.xml": "sitemap_xml",
            "/sitemap_index.xml": "sitemap_index_xml",
            "/.well-known/openid-configuration": "openid_configuration",
            "/.well-known/oauth-authorization-server": "oauth_authorization_server",
            "/.well-known/security.txt": "security_txt",
            "/.well-known/change-password": "change_password",
            "/.well-known/assetlinks.json": "assetlinks_json",
            "/.well-known/apple-app-site-association": "apple_app_site_association",
            "/graphql": "graphql",
            "/api": "api_root",
            "/api/": "api_root_slash",
            "/api/v1": "api_v1",
            "/api/v2": "api_v2",
            "/api/docs": "api_docs",
            "/api-docs": "api_docs_dash",
            "/swagger": "swagger",
            "/swagger-ui": "swagger_ui",
            "/swagger-ui/index.html": "swagger_ui_index",
            "/swagger.json": "swagger_json",
            "/openapi.json": "openapi_json",
            "/openapi.yaml": "openapi_yaml",
            "/.env": "_env",
            "/.env.local": "_env_local",
            "/.git/HEAD": "_git_head",
            "/.git/config": "_git_config",
        }
        return mapping.get(path, path.strip("/").replace("/", "_").replace(".", "_"))

    def extract_sso_provider(self, combo: str) -> Optional[str]:
        combo = combo.lower()
        providers = [
            ("azure_ad_login", ["azure", "microsoft"]),
            ("google_login", ["google"]),
            ("facebook_login", ["facebook"]),
            ("apple_login", ["apple"]),
            ("github_login", ["github"]),
            ("okta_login", ["okta"]),
            ("auth0_login", ["auth0"]),
            ("keycloak_login", ["keycloak"]),
            ("sso_login", ["sso", "openid", "oauth"]),
            ("saml_login", ["saml"]),
        ]
        for name, pats in providers:
            if any(p in combo for p in pats):
                return name
        return None


# =============================================================================
# Markdown report builder
# =============================================================================

def build_md_report(result: Dict[str, Any]) -> str:
    """Genera un reporte Markdown compacto con lo más accionable."""
    lines: List[str] = []
    target = result.get("target", {})
    meta = result.get("meta", {})
    http = result.get("http", {})
    priorities = result.get("priorities", {})
    secrets = result.get("secrets", {})
    special = result.get("special_services", {})
    auth = result.get("auth_surface", {})
    csp = result.get("csp", {}) or {}
    cookies_sec = result.get("cookies_security", {}) or {}
    cors = http.get("cors_reflect_test", {}) or {}
    notes = result.get("notes", []) or []

    lines.append(f"# Recon Fingerprint — {target.get('final_url', '')}")
    lines.append("")
    lines.append(f"*Tool: recon_fingerprint v{meta.get('version', '?')} "
                 f"— {meta.get('timestamp', '')}*")
    lines.append("")
    lines.append(f"- **Input URL**: `{target.get('input_url', '')}`")
    lines.append(f"- **Final URL**: `{target.get('final_url', '')}`")
    lines.append(f"- **Status**: {http.get('status_code')} "
                 f"{http.get('http_version') or ''}")
    lines.append("")

    # Host priority
    hp = priorities.get("host_priority", {})
    lines.append("## 🎯 Host priority")
    lines.append("")
    lines.append(f"**Score**: `{hp.get('score', 0)}/20` — "
                 f"**label**: `{hp.get('label', '?')}`")
    lines.append("")
    for r in hp.get("reasons", []):
        lines.append(f"- {r}")
    lines.append("")

    # Top targets
    tt = priorities.get("top_targets", [])
    if tt:
        lines.append("## 🔝 Top targets")
        lines.append("")
        lines.append("| # | Score | Type | Target | Why |")
        lines.append("|---|-------|------|--------|-----|")
        for i, t in enumerate(tt[:15], 1):
            why = "; ".join(t.get("why", []))[:120]
            url = (t.get("target") or "")[:100]
            lines.append(f"| {i} | {t.get('score', 0)} | "
                         f"{t.get('type', '')} | `{url}` | {why} |")
        lines.append("")

    # WAF / CDN
    waf = http.get("waf_signals", [])
    cdn = http.get("cdn_signals", [])
    if waf or cdn:
        lines.append("## 🛡️ WAF / CDN")
        lines.append("")
        if waf:
            lines.append(f"- **WAF**: {', '.join(waf)}")
        if cdn:
            lines.append(f"- **CDN**: {', '.join(cdn)}")
        lines.append("")

    # CORS
    if cors.get("exploitable_hint") or cors.get("wildcard_with_creds") \
            or cors.get("null_origin_allowed") or cors.get("reflects_origin"):
        lines.append("## 🌐 CORS findings")
        lines.append("")
        if cors.get("exploitable_hint"):
            lines.append("- ⚠️ **Reflected Origin + credentials** — potencialmente explotable")
        if cors.get("wildcard_with_creds"):
            lines.append("- ⚠️ ACAO=`*` con credentials=true (config inválida)")
        if cors.get("null_origin_allowed"):
            lines.append("- ⚠️ Allow Origin: `null` permitido")
        lines.append(f"- ACAO observado: `{cors.get('access_control_allow_origin')}`")
        lines.append(f"- ACAC observado: `{cors.get('access_control_allow_credentials')}`")
        lines.append("")

    # CSP
    if csp.get("raw"):
        lines.append("## 🔒 CSP")
        lines.append("")
        lines.append(f"- **Report-only**: {csp.get('report_only')}")
        lines.append(f"- **unsafe-inline**: {csp.get('unsafe_inline')}")
        lines.append(f"- **unsafe-eval**: {csp.get('unsafe_eval')}")
        lines.append(f"- **nonce_used**: {csp.get('nonce_used')}")
        lines.append(f"- **strict-dynamic**: {csp.get('strict_dynamic')}")
        if csp.get("wildcard_directives"):
            lines.append(f"- **wildcard en**: "
                         f"{', '.join(csp.get('wildcard_directives', []))}")
        if csp.get("report_uri"):
            lines.append(f"- **report-uri**: "
                         f"{', '.join(csp.get('report_uri', []))}")
        lines.append("")

    # Cookies
    cs_summary = cookies_sec.get("summary", {})
    if cs_summary:
        lines.append("## 🍪 Cookies — issues")
        lines.append("")
        for k, v in cs_summary.items():
            lines.append(f"- `{k}`: {v}")
        lines.append("")

    # Secretos
    by_sev = secrets.get("by_severity", {})
    if secrets.get("count", 0) > 0:
        lines.append("## 🔑 Secrets detectados")
        lines.append("")
        lines.append(f"Total: **{secrets.get('count', 0)}** "
                     f"(high={by_sev.get('high', 0)}, "
                     f"medium={by_sev.get('medium', 0)}, "
                     f"low={by_sev.get('low', 0)}, "
                     f"info={by_sev.get('info', 0)})")
        lines.append("")
        lines.append("| Severity | Nombre | Source | Preview |")
        lines.append("|----------|--------|--------|---------|")
        for f in secrets.get("findings", [])[:20]:
            lines.append(f"| {f.get('severity')} | {f.get('name')} | "
                         f"`{f.get('source')}` | `{f.get('match_preview')}` |")
        lines.append("")

    # Special services
    if special:
        lines.append("## ⚙️ Servicios especiales detectados")
        lines.append("")
        for k, v in special.items():
            lines.append(f"- **{k}**: {_brief(v)}")
        lines.append("")

    # Auth surface
    if auth.get("oauth_signals") or auth.get("saml_signals") \
            or auth.get("login_links"):
        lines.append("## 🔐 Auth surface")
        lines.append("")
        lines.append(f"- OAuth signals: {auth.get('oauth_signals')}")
        lines.append(f"- OIDC signals: {auth.get('oidc_signals')}")
        lines.append(f"- SAML signals: {auth.get('saml_signals')}")
        lines.append(f"- Session cookie: "
                     f"`{auth.get('session_cookie_name')}`")
        lines.append(f"- CSRF mechanisms: "
                     f"{', '.join(auth.get('csrf_mechanisms', []))}")
        lines.append(f"- SSO providers: "
                     f"{', '.join(auth.get('sso_providers_detected', []))}")
        if auth.get("captcha_detected"):
            lines.append(f"- Captcha: "
                         f"{', '.join(auth.get('captcha_providers', []))}")
        if auth.get("login_links"):
            lines.append("- Login links:")
            for l in auth.get("login_links", [])[:8]:
                lines.append(f"  - `{l}`")
        lines.append("")

    # Tech stack
    tech = result.get("tech_stack", {})
    fw = [x.get("name") for x in tech.get("frameworks", [])]
    lib = [x.get("name") for x in tech.get("libraries", [])]
    if fw or lib:
        lines.append("## 🧱 Tech stack")
        lines.append("")
        if fw:
            lines.append(f"- **Frameworks**: {', '.join(fw)}")
        if lib:
            lines.append(f"- **Libraries**: {', '.join(lib[:20])}")
        lines.append("")

    # Dev tools
    dev_tools = tech.get("dev_tools", [])
    if dev_tools:
        lines.append("## 🛠️ Dev tools detectados")
        lines.append("")
        for d in dev_tools:
            lines.append(
                f"- **{d.get('name')}** — confianza `{d.get('confidence')}` "
                f"(source: {d.get('source')})"
            )
        lines.append("")

    # Network appliances
    net_apps = tech.get("network_appliances", [])
    if net_apps:
        lines.append("## 🔧 Network appliances / VPN SSL")
        lines.append("")
        for n in net_apps:
            lines.append(
                f"- **{n.get('name')}** — confianza `{n.get('confidence')}` "
                f"(source: {n.get('source')})"
            )
        lines.append("")

    # IdPs
    idps = tech.get("idps", [])
    if idps:
        lines.append("## 🪪 IdPs detectados")
        lines.append("")
        for i in idps:
            lines.append(
                f"- **{i.get('name')}** — confianza `{i.get('confidence')}`"
            )
        lines.append("")

    # CMS
    cms_list = tech.get("cms", [])
    if cms_list:
        lines.append("## 📰 CMS")
        lines.append("")
        for c in cms_list:
            lines.append(
                f"- **{c.get('name')}** — confianza `{c.get('confidence')}`"
            )
        lines.append("")

    # SSO signals
    sso_sig = result.get("auth_surface", {}).get("sso_signals", [])
    if sso_sig:
        lines.append("## 🔑 SSO providers")
        lines.append("")
        lines.append("| Provider | Categoría | Confianza |")
        lines.append("|----------|-----------|-----------|")
        for s in sso_sig:
            lines.append(
                f"| {s.get('provider')} | {s.get('category')} "
                f"| {s.get('confidence')} |"
            )
        lines.append("")

    # Custom stack hints
    cs = result.get("custom_stack", {})
    if cs and cs.get("has_custom_stack_signals"):
        lines.append("## 🧩 Custom stack hints")
        lines.append("")
        if cs.get("custom_headers"):
            lines.append(
                f"- **Headers custom**: "
                f"`{', '.join(cs['custom_headers'][:8])}`"
            )
        if cs.get("custom_cookies"):
            lines.append(
                f"- **Cookies custom**: "
                f"`{', '.join(cs['custom_cookies'][:8])}`"
            )
        if cs.get("internal_paths"):
            lines.append(
                f"- **Paths internos**: {len(cs['internal_paths'])}"
            )
        if cs.get("custom_generators"):
            lines.append("- **Generators/backend hints**:")
            for g in cs['custom_generators'][:5]:
                lines.append(
                    f"  - `{g.get('header')}`: `{g.get('value')}`"
                )
        lines.append("")

    # JWTs
    jwts = result.get("jwts", [])
    if jwts:
        lines.append("## 🪪 JWTs detectados")
        lines.append("")
        for j in jwts[:10]:
            lines.append(f"- `{j.get('preview')}` alg=`{j.get('algorithm')}` "
                         f"iss=`{j.get('issuer')}` aud=`{j.get('audience')}`")
        lines.append("")

    # Notes
    if notes:
        lines.append("## 📝 Notas")
        lines.append("")
        for n in notes:
            lines.append(f"- {n}")
        lines.append("")

    return "\n".join(lines)


def _brief(value: Any, limit: int = 120) -> str:
    try:
        s = json.dumps(value, ensure_ascii=False)
    except Exception:
        s = str(value)
    return s if len(s) <= limit else s[:limit] + "…"


# =============================================================================
# CLI
# =============================================================================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            f"Recon Fingerprint v{__version__} — recolector de contexto, "
            "no crawler. Hecho para bug bounty hunting."
        ),
    )
    p.add_argument("url", help="URL objetivo")
    p.add_argument("-o", "--output", default="fingerprint.json",
                   help="Archivo JSON de salida")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                   help="Timeout por request (default: %(default)s)")
    p.add_argument("--user-agent", default=DEFAULT_UA,
                   help="User-Agent")
    p.add_argument("--render", action="store_true",
                   help="Intenta render con Playwright si está disponible")
    p.add_argument("--local-js", nargs="*", default=[],
                   help="Bundles JS locales para enriquecer el fingerprint")
    p.add_argument("--max-assets", type=int, default=DEFAULT_MAX_ASSETS,
                   help="Máximo de assets JS/CSS a inspeccionar "
                        "(default: %(default)s)")
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                   help="Workers concurrentes para probes/assets "
                        "(default: %(default)s)")
    p.add_argument("--no-path-probes", action="store_true",
                   help="No hacer probes puntuales")
    p.add_argument("--no-source-map-check", action="store_true",
                   help="No verificar accesibilidad de sourcemaps")
    p.add_argument("--extra-probes", action="store_true",
                   help="Activa probes adicionales (.env, .git, actuator, etc)")
    p.add_argument("--no-tls-info", action="store_true",
                   help="No hacer fetch del cert TLS")
    p.add_argument("--scope", default=None,
                   help="Dominio raíz en scope, ej: target.tld (para extraer "
                        "hostnames del mismo scope desde HTML/JS/certs TLS)")
    p.add_argument("--yes", "-y", action="store_true",
                   help="Confirmar autorización explícita para los requests activos")
    p.add_argument("--download-interesting", action="store_true",
                   help="Descarga bundles/sourcemaps interesantes a disco")
    p.add_argument("--download-dir", default="downloads",
                   help="Directorio base para descargas de assets")
    p.add_argument("--proxy", default=None,
                   help="HTTP/HTTPS proxy, ej: http://127.0.0.1:8080 (Burp)")
    p.add_argument("--insecure", action="store_true",
                   help="No verificar certs TLS")
    p.add_argument("--handoff-output", default=None,
                   help="Guardar analyzer_handoff por separado en este JSON")
    p.add_argument("--md-report", default=None,
                   help="Guardar reporte Markdown legible en este archivo")
    p.add_argument("--json-pretty", action="store_true",
                   help="Pretty print completo a stdout")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Logs a stderr")
    p.add_argument("--no-param-mining", action="store_true",
                   help="Desactiva el minado de parámetros desde JS/HTML")
    p.add_argument("--no-tech-probes", action="store_true",
                   help="Desactiva probes específicos por tecnología detectada")
    p.add_argument("--wayback", action="store_true",
                   help="Consulta archive.org CDX para URLs históricas del target")
    p.add_argument("--wayback-limit", type=int, default=500,
                   help="Máximo de URLs a traer de Wayback (default: %(default)s)")
    p.add_argument("--wayback-since", default=None,
                   help="Fecha mínima YYYYMMDD para Wayback")
    p.add_argument("--ct-logs", action="store_true",
                   help="Consulta crt.sh para Certificate Transparency logs")
    p.add_argument("--ct-limit", type=int, default=300,
                   help="Máximo de entries a traer de crt.sh (default: %(default)s)")
    p.add_argument("--tech-probe-only", nargs="*", default=None,
                   help="Solo corre probes para las tech especificadas")
    return p.parse_args()


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = parse_args()
    try:
        target_host = urlparse(args.url).hostname
        if not target_host or urlparse(args.url).scheme.lower() not in {"http", "https"}:
            raise ScopeError("El target debe ser una URL HTTP(S) con hostname válido.")
        scope_value = args.scope or target_host
        scope_policy = HostScope.parse(scope_value)
        if not scope_policy.matches_url(args.url):
            raise ScopeError(f"El target no pertenece al scope {scope_value}.")
    except ScopeError as exc:
        raise SystemExit(f"Scope inválido: {exc}") from exc
    if args.yes:
        print(f"[!] Autorización afirmada con --yes para {args.url} (scope: {scope_value}).")
    else:
        try:
            answer = input(
                f"El fingerprint hará requests activos contra {args.url} "
                f"(scope: {scope_value}). ¿Tienes autorización explícita? (s/n): "
            ).strip().lower()
        except EOFError:
            raise SystemExit("No hay terminal para confirmar. Usa --yes solo con autorización confirmada.")
        if answer != "s":
            print("[*] Fingerprint cancelado por el operador.")
            return
    fp = Fingerprinter(
        target_url=args.url,
        timeout=args.timeout,
        user_agent=args.user_agent,
        render=args.render,
        local_js=args.local_js,
        max_assets=args.max_assets,
        scope=args.scope,
        no_path_probes=args.no_path_probes,
        no_source_map_check=args.no_source_map_check,
        download_interesting=args.download_interesting,
        download_dir=args.download_dir,
        extra_probes=args.extra_probes,
        concurrency=args.concurrency,
        proxy=args.proxy,
        insecure=args.insecure,
        no_tls_info=args.no_tls_info,
        verbose=args.verbose,
        no_param_mining=args.no_param_mining,
        no_tech_probes=args.no_tech_probes,
        wayback=args.wayback,
        wayback_limit=args.wayback_limit,
        wayback_since=args.wayback_since,
        ct_logs=args.ct_logs,
        ct_limit=args.ct_limit,
        tech_probe_only=args.tech_probe_only,
    )
    result = fp.run()

    out = Path(args.output)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(f"[+] Fingerprint JSON: {out}")

    if args.handoff_output:
        handoff_out = Path(args.handoff_output)
        handoff_out.write_text(
            json.dumps(result.get("analyzer_handoff", {}),
                       indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"[+] Analyzer handoff JSON: {handoff_out}")

    if args.md_report:
        md_out = Path(args.md_report)
        md_out.write_text(build_md_report(result), encoding="utf-8")
        print(f"[+] Markdown report: {md_out}")

    if args.json_pretty:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        # Resumen corto útil en consola
        hp = result.get("priorities", {}).get("host_priority", {})
        summary = {
            "final_url": result["target"]["final_url"],
            "status_code": result["http"]["status_code"],
            "host_priority": hp,
            "frameworks": [x["name"] for x in
                           result["tech_stack"].get("frameworks", [])],
            "libraries_top": [x["name"] for x in
                              result["tech_stack"].get("libraries", [])[:8]],
            "js_assets": len(result["assets"].get("js", [])),
            "usable_sourcemaps": len([
                x for x in result["assets"].get("js", [])
                if (x.get("source_map_status") or {}).get("parses_as_sourcemap")
            ]),
            "downloaded_assets": result.get("downloads", {}).get("downloaded_count", 0),
            "page_endpoints": len(
                result.get("html", {}).get("page_endpoints", [])),
            "waf_signals": result["http"].get("waf_signals", []),
            "cdn_signals": result["http"].get("cdn_signals", []),
            "cors_exploitable_hint": (
                result["http"].get("cors_reflect_test") or {}
            ).get("exploitable_hint"),
            "secrets": result.get("secrets", {}).get("by_severity", {}),
            "special_services": list(
                result.get("special_services", {}).keys()),
            "top_targets": result.get("priorities", {}).get("top_targets", [])[:5],
        }
        print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
