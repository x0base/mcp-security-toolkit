"""Return curated lists of sensitive paths to probe for a given tech stack.

Pure data lookup — no network, no probing. Returns paths only; the agent
or user decides what to do with them.

For authorized testing only.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

PATHS: dict[str, list[dict[str, str]]] = {
    "common": [
        {"path": "/.env", "why": "12-factor config leak (DB creds, API keys)"},
        {"path": "/.env.local", "why": "12-factor local override"},
        {"path": "/.env.production", "why": "12-factor prod config"},
        {"path": "/.git/config", "why": "exposed git repo"},
        {"path": "/.git/HEAD", "why": "exposed git repo (alternate probe)"},
        {"path": "/.svn/entries", "why": "exposed svn repo"},
        {"path": "/.DS_Store", "why": "macOS directory listing leak"},
        {"path": "/robots.txt", "why": "disclosed paths"},
        {"path": "/sitemap.xml", "why": "endpoint inventory"},
        {"path": "/crossdomain.xml", "why": "flash CORS policy"},
        {"path": "/clientaccesspolicy.xml", "why": "silverlight CORS policy"},
        {"path": "/security.txt", "why": "RFC 9116 contact"},
        {"path": "/.well-known/security.txt", "why": "RFC 9116 contact"},
        {"path": "/server-status", "why": "Apache mod_status info disclosure"},
        {"path": "/server-info", "why": "Apache mod_info"},
        {"path": "/backup.zip", "why": "common backup leak name"},
        {"path": "/backup.tar.gz", "why": "common backup leak name"},
        {"path": "/db.sql", "why": "common DB dump leak name"},
    ],
    "php": [
        {"path": "/phpinfo.php", "why": "info disclosure"},
        {"path": "/info.php", "why": "info disclosure"},
        {"path": "/test.php", "why": "leftover test endpoint"},
        {"path": "/config.php.bak", "why": "editor backup leak"},
        {"path": "/wp-config.php.bak", "why": "WordPress config backup"},
        {"path": "/composer.json", "why": "dependency inventory"},
        {"path": "/composer.lock", "why": "exact dependency versions"},
        {"path": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "why": "CVE-2017-9841 PHPUnit RCE"},
    ],
    "wordpress": [
        {"path": "/wp-admin/", "why": "admin UI exposure"},
        {"path": "/wp-login.php", "why": "login endpoint"},
        {"path": "/xmlrpc.php", "why": "XML-RPC enabled (brute / pingback abuse)"},
        {"path": "/wp-json/wp/v2/users", "why": "user enumeration via REST API"},
        {"path": "/wp-content/debug.log", "why": "WP debug log leak"},
        {"path": "/wp-config.php", "why": "WP config (often blocked, sometimes leaked via .bak)"},
        {"path": "/readme.html", "why": "WordPress version fingerprint"},
    ],
    "dotnet": [
        {"path": "/web.config", "why": ".NET config"},
        {"path": "/web.config.bak", "why": "editor backup leak"},
        {"path": "/Trace.axd", "why": "ASP.NET trace handler"},
        {"path": "/elmah.axd", "why": "ELMAH error log handler"},
        {"path": "/_vti_pvt/service.cnf", "why": "FrontPage extensions"},
    ],
    "java": [
        {"path": "/WEB-INF/web.xml", "why": "Java web app descriptor"},
        {"path": "/WEB-INF/classes/application.properties", "why": "Spring properties"},
        {"path": "/actuator", "why": "Spring Boot actuator index"},
        {"path": "/actuator/env", "why": "Spring env (CVE-2018-1273-family)"},
        {"path": "/actuator/heapdump", "why": "memory dump (full credentials)"},
        {"path": "/actuator/health", "why": "actuator presence probe"},
        {"path": "/actuator/mappings", "why": "endpoint inventory"},
        {"path": "/manager/html", "why": "Tomcat manager UI"},
        {"path": "/host-manager/html", "why": "Tomcat host-manager UI"},
    ],
    "node": [
        {"path": "/package.json", "why": "dep inventory"},
        {"path": "/package-lock.json", "why": "exact dep versions"},
        {"path": "/yarn.lock", "why": "exact dep versions"},
        {"path": "/.npmrc", "why": "npm registry / token leak"},
        {"path": "/server.js", "why": "exposed source"},
    ],
    "python": [
        {"path": "/requirements.txt", "why": "dep inventory"},
        {"path": "/Pipfile.lock", "why": "exact dep versions"},
        {"path": "/poetry.lock", "why": "exact dep versions"},
        {"path": "/settings.py", "why": "django settings leak"},
        {"path": "/manage.py", "why": "django entry"},
        {"path": "/console", "why": "Werkzeug debug console (Flask)"},
    ],
    "k8s": [
        {"path": "/metrics", "why": "Prometheus metrics often unauthed"},
        {"path": "/healthz", "why": "k8s health probe"},
        {"path": "/api/v1/namespaces/default/pods", "why": "kube-apiserver if exposed"},
    ],
    "docker": [
        {"path": "/v2/", "why": "Docker registry index"},
        {"path": "/v2/_catalog", "why": "Docker registry image enumeration"},
    ],
    "ci": [
        {"path": "/.github/workflows/", "why": "exposed CI configs"},
        {"path": "/.gitlab-ci.yml", "why": "exposed CI configs"},
        {"path": "/jenkins/script", "why": "Jenkins script console"},
    ],
}


class FileEntry(BaseModel):
    path: str
    why: str


class FilesReport(BaseModel):
    stacks_requested: list[str]
    paths: list[FileEntry] = Field(default_factory=list)
    note: str = (
        "Paths only. This tool does not probe the target. "
        "For authorized testing only — fetching these against systems you do not own "
        "may be unlawful."
    )


def sensitive_files_list(stack: str = "common", include_common: bool = True) -> dict:
    """Return curated sensitive-path lists for a given tech stack.

    Args:
        stack: Comma-separated stack hints. Supported keys:
            common, php, wordpress, dotnet, java, node, python, k8s, docker, ci.
        include_common: If True (default), always include the `common` set.

    Returns:
        FilesReport with `paths` (each {path, why}). No network is performed.
    """
    if not isinstance(stack, str):
        return {"error": "stack must be a string"}

    requested = [s.strip().lower() for s in stack.split(",") if s.strip()]
    if not requested:
        requested = ["common"]
    if include_common and "common" not in requested:
        requested = ["common", *requested]

    seen: set[str] = set()
    out: list[FileEntry] = []
    for s in requested:
        for entry in PATHS.get(s, []):
            if entry["path"] not in seen:
                seen.add(entry["path"])
                out.append(FileEntry(**entry))

    return FilesReport(stacks_requested=requested, paths=out).model_dump()
