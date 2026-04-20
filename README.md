# SpringHawk

```
                       .^!?JJJJJ?!^.
                   :~?5G###BBBBBB###G5?~:
                :!YB##BGYJ?7777777?JYG##BY!:
              ^JB#BGY7^.               .^7YG#BJ^
            ^5##BJ~.    .~?JYYYYYYYYJ?~.    .~J##5^
           J##G7.    :!5B###BBGGGGBB###B5!:    .7G##J
          P##7.   .7G####G?^.        .^?G####G7.   .7##P
         B#G.   ^5###B5!.   ^?JYYJ?.   .!5B###5^   .G#B
        G##.   ?###G7.    ?B#########B?    .7G###?   .##G
       J##.   5##G^     !B####B##B####B!     ^G##5   .##J
       ##J   P##Y      ?###B?:    :?B###?      Y##P   J##
      :##Y   ###!     !###J.        .J###!     !###   Y##:
      .##B   G##7     J##G            G##J     7##G   B##.
       ###   J##B.    ?###Y.        .Y###?    .B##J   ###
       Y##Y   P###7    !B####B####B####B!    7###P   Y##Y
       .B##7   Y####?.   ^?G########G?^   .?####Y   7##B.
        .G##P   ^5####G?^.   .^~~^.   .^?G####5^   P##G.
          Y###!   .!5B####BGY?7777?YGB####B5!.   !###Y
           ~###G~    .^?5G##########G5?^.    ~G###~
             J####Y~.      .^~~~~~^.      .~Y####J
              .?B####BGY?7!^.       .^!7?YGB####B?.
                 ^?5G#########BBBBB#########G5?^
                     :~!7?JJYYYY5YYYY?7!~:

 ___            _             _   _               _
/ __|_ __ _ _ _(_)_ _  __ _ | | | |__ ___ __ ___| |__
\__ \ '_ \ '_| | ' \/ _' || |_| / _' \ V  V /| / /
|___/ .__/_| |_|_||_\__, | \___/\__,_|\_/\_/ |_\_\
    |_|              |___/

       
```

**Spring Boot Security Scanner** — pentest y auditoría de aplicaciones Spring Boot, tanto en local como en producción.

> Herramienta de uso exclusivo para pruebas autorizadas sobre tus propias aplicaciones.

---

## Instalación

```bash
git clone https://github.com/Juan1913/springhawk-Spring-Boot-Security-Scanner-.git
cd springhawk
make build
# Binario en dist/springhawk

# Instalar globalmente
sudo make install
```

**Requisitos:** Go 1.22+. El binario resultante es estático — no requiere dependencias en el sistema destino.

---

## Comandos

### `scan` — Escaneo remoto activo

```bash
springhawk scan -t https://example-app.com
```

Ejecuta tres fases en orden:
1. **Fingerprinting** — detecta si el target es Spring Boot
2. **Endpoint discovery** — prueba 500+ rutas sensibles concurrentemente
3. **Módulos de vulnerabilidad** — 18 CVEs y vectores en paralelo

```bash
# Opciones principales
-t, --target        URL objetivo
-f, --file          Archivo con URLs (una por línea, batch)
-p, --proxy         Proxy: http://host:port o socks5://host:port
-H, --header        Header HTTP personalizado (repetible)
    --timeout       Timeout por request en segundos (default: 10)
    --workers       Goroutines concurrentes (default: 20)
    --delay         Delay entre requests en ms (default: 0)
    --rate-limit    Requests/segundo por host (default: 50)
    --profile       aggressive | standard | stealth | safe
    --exploit       Activar explotación activa (webshell, RCE)
    --callback-host Host OAST para vulnerabilidades ciegas (Log4Shell, etc.)
    --modules       IDs de módulos a ejecutar (default: todos)
    --skip-modules  IDs de módulos a omitir
    --cookie        Cookie header
    --bearer-token  Bearer token para Authorization
    --format        terminal | json | html
-o, --output        Archivo de salida
```

**Perfiles de escaneo:**

| Perfil | Workers | Rate limit | Delay | Descripción |
|--------|---------|------------|-------|-------------|
| `aggressive` | 50 | 200 req/s | 0ms | Máxima velocidad |
| `standard` | 20 | 50 req/s | 0ms | Balanceado (default) |
| `stealth` | 3 | 5 req/s | 2000ms | Evasión de detección |
| `safe` | 10 | 20 req/s | 0ms | Mínimo impacto |

**Ejemplos:**

```bash
# Escaneo básico
springhawk scan -t https://mi-app.com

# Con explotación activa (requiere autorización)
springhawk scan -t https://mi-app.com --exploit

# Con callback para vulnerabilidades ciegas (Log4Shell)
springhawk scan -t https://mi-app.com --callback-host tu.oast.host --exploit

# Modo stealth con proxy Burp Suite
springhawk scan -t https://mi-app.com \
  --profile stealth \
  -p http://127.0.0.1:8080

# Batch con output JSON
springhawk scan -f targets.txt \
  --workers 50 \
  --format json \
  -o resultados.json

# Con autenticación
springhawk scan -t https://mi-app.com \
  --bearer-token "eyJhbGci..." \
  --cookie "JSESSIONID=abc123"

# Solo módulos específicos
springhawk scan -t https://mi-app.com \
  --modules "CVE-2022-22965,CVE-2022-22947,h2-console-rce"
```

---

### `analyze` — Análisis estático local

Analiza el código fuente de tu proyecto Spring Boot sin hacer ninguna petición de red.

```bash
springhawk analyze ./mi-proyecto-spring
```

Detecta:

| Categoría | Qué busca |
|-----------|-----------|
| **Dependencias** | Versiones con CVEs conocidos en `pom.xml` / `build.gradle` |
| **Configuración** | Actuators expuestos, H2 console, debug mode, SSL deshabilitado, CORS wildcard |
| **Secretos** | Passwords, JWT secrets, API keys, AWS keys, tokens hardcodeados |
| **Código fuente** | CSRF deshabilitado, `Runtime.exec()`, SQL con concatenación, `@CrossOrigin("*")`, `anyRequest().permitAll()` |

```bash
# Opciones
<path>            Ruta raíz del proyecto (requerido)
--dep-check       Verificar dependencias vulnerables (default: on)
--secret-scan     Buscar credenciales hardcodeadas (default: on)
--config-audit    Auditar application.properties/yml (default: on)
--code-review     Analizar patrones inseguros en código (default: on)
--min-severity    Severidad mínima a reportar: info|low|medium|high|critical
--format          terminal | json
-o, --output      Archivo de salida
```

**Ejemplos:**

```bash
# Análisis completo
springhawk analyze ./mi-app

# Solo dependencias y secretos, output JSON
springhawk analyze ./mi-app \
  --dep-check \
  --secret-scan \
  --no-code-review \
  --format json \
  -o analisis.json

# Solo hallazgos críticos y altos
springhawk analyze ./mi-app --min-severity high
```

---

## Módulos de vulnerabilidad

### CVEs de Spring Boot / Spring Cloud (11)

| ID | CVE | Descripción | CVSS |
|----|-----|-------------|------|
| `CVE-2022-22965` | Spring4Shell | RCE via ClassLoader → webshell JSP en Tomcat | 9.8 |
| `CVE-2022-22947` | Spring Cloud Gateway SpEL | RCE via route filter AddResponseHeader | 10.0 |
| `CVE-2022-22963` | Spring Cloud Function SpEL | RCE via `routing-expression` header | 9.8 |
| `CVE-2021-21234` | Logview LFI | Lectura arbitraria de archivos vía path traversal | 7.5 |
| `CVE-2018-1273` | Spring Data Commons | SpEL injection via parámetro de formulario | 9.8 |
| `CVE-2024-37084` | Spring Cloud Data Flow | SnakeYAML gadget RCE via package upload | 9.8 |
| `CVE-2025-41243` | Spring Cloud Gateway | Disclosure de env vars via SpEL en route filters | 7.5 |
| `snakeyaml-rce` | SnakeYAML RCE | Deserialización via `/actuator/env` + `/refresh` | 9.8 |
| `eureka-xstream-rce` | Eureka XStream | Deserialización XStream via Eureka property write | 9.8 |
| `jolokia-rce` | Jolokia JMX | RCE via `reloadByURL` / `createJNDIRealm` | 8.1 |
| `jeespring-2023-file-upload` | JeeSpring Upload | File upload sin auth → webshell JSP | 9.8 |

### Módulos web adicionales (7)

| ID | Descripción | CVSS |
|----|-------------|------|
| `h2-console-rce` | H2 Console expuesta → RCE via JDBC INIT script | 9.8 |
| `jwt-attacks` | JWT alg:none bypass + brute force de secret débil | 8.1 |
| `ssrf-actuator-env` | SSRF via escritura en `/actuator/env` (http.proxyHost) | 8.6 |
| `CVE-2021-44228` | Log4Shell JNDI injection (requiere `--callback-host`) | 10.0 |
| `swagger-exposure` | Swagger/OpenAPI docs expuestos — enumera todos los endpoints | 5.3 |
| `actuator-auth-bypass` | Bypass de Spring Security via path manipulation (`;/`, `//`, `/../`) | 7.5 |

---

## Formatos de salida

### Terminal (default)
Output coloreado por severidad: rojo (CRITICAL), amarillo (HIGH/MEDIUM), cyan (LOW).

### JSON (`--format json`)
```json
{
  "id": "CVE-2022-22965-...",
  "type": "VULNERABILITY",
  "severity": "CRITICAL",
  "cvss": 9.8,
  "cve_ids": ["CVE-2022-22965"],
  "title": "Spring4Shell: Remote Code Execution via ClassLoader",
  "url": "https://mi-app.com",
  "endpoint": "/",
  "evidence": "JSP webshell plantado en /hawk_1234.jsp — HTTP 200 confirmado.",
  "payload": "class.module.classLoader...",
  "remediation": "Upgrade Spring Framework a 5.3.18+.",
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
  "is_exploited": true,
  "extra_data": {
    "shell_url": "https://mi-app.com/hawk_1234.jsp",
    "shell_cmd": "https://mi-app.com/hawk_1234.jsp?cmd=id"
  }
}
```

---

## Configuración

Archivo opcional en `~/.springhawk.yaml`:

```yaml
defaults:
  workers: 20
  timeout: 10
  rate_limit: 50
  format: terminal

http:
  follow_redirects: true
  retry_count: 2

proxies:
  default: ""  # http://127.0.0.1:8080 para Burp Suite

api_keys:
  zoomeye: ""
  fofa_email: ""
  fofa_key: ""
  hunter: ""
  shodan: ""
  censys_id: ""
  censys_secret: ""
```

Variables de entorno también funcionan: `ZOOMEYE_KEY`, `SHODAN_KEY`, etc.

---

## Estructura del proyecto

```
springhawk/
├── cmd/                    # CLI (cobra)
│   ├── root.go
│   ├── scan.go
│   ├── analyze.go
│   └── version.go
├── internal/
│   ├── config/             # Configuración y perfiles
│   ├── engine/             # Worker pool, rate limiter, scanner orchestrator
│   ├── fingerprint/        # Detección de Spring Boot (favicon hash, error JSON)
│   ├── http/               # Cliente HTTP con proxy SOCKS5, UA rotation, WAF evasion
│   ├── vulns/
│   │   ├── cve/            # 11 módulos CVE
│   │   └── web/            # 7 módulos web adicionales
│   ├── analyzer/           # Análisis estático local
│   └── reporting/          # Terminal + JSON reporters
├── pkg/
│   ├── models/             # Structs: Finding, Target, ScanResult
│   └── utils/              # MurmurHash2, URL utils, semver
├── assets/
│   ├── wordlists/          # 500+ endpoints Spring Boot embebidos
│   └── signatures/         # DB de favicon hashes y versiones vulnerables
└── main.go
```

---

## Build

```bash
# Binario local
make build

# Todos los platforms (linux/darwin/windows × amd64/arm64)
make build-all

# Instalar en /usr/local/bin
sudo make install

# Tests
make test
```

---

## Flujo de trabajo recomendado

### Antes del deploy (local)
```bash
# 1. Analizar código fuente
springhawk analyze . --min-severity medium

# 2. Verificar dependencias vulnerables
springhawk analyze . --dep-check --no-code-review --no-secret-scan
```

### Después del deploy (staging/producción)
```bash
# 1. Escaneo básico (no destructivo)
springhawk scan -t https://staging.mi-app.com

# 2. Escaneo completo con explotación
springhawk scan -t https://staging.mi-app.com \
  --exploit \
  --callback-host mi.oast.host \
  --format json \
  -o pentest-$(date +%Y%m%d).json
```

---

## Aviso legal

Esta herramienta está diseñada para pruebas de seguridad **autorizadas** sobre sistemas propios o con permiso explícito del propietario. El uso no autorizado contra sistemas de terceros puede constituir un delito. El autor no se hace responsable del uso indebido.
