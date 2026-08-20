"""
╔══════════════════════════════════════════════════════════════╗
║              WEB VULNERABILITY SCANNER MODULE                ║
║                   v2.0 - Security Edition                    ║
╚══════════════════════════════════════════════════════════════╝
Módulo de varredura de vulnerabilidades web.
Uso autorizado apenas em sistemas com permissão explícita.
"""

import requests
import re
import time
import json
import sys
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
from typing import Optional
from colorama import Fore, Back, Style, init

# ─────────────────────────────────────────────
#  INICIALIZAÇÃO
# ─────────────────────────────────────────────
init(autoreset=True)
requests.packages.urllib3.disable_warnings()  # Silencia avisos SSL


# ─────────────────────────────────────────────
#  ESTRUTURA DE RESULTADOS
# ─────────────────────────────────────────────
@dataclass
class ScanResult:
    category: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    url: str = ""
    status_code: Optional[int] = None


@dataclass
class ScanReport:
    target: str
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    results: list[ScanResult] = field(default_factory=list)

    def add(self, result: ScanResult):
        self.results.append(result)

    def summary(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for r in self.results:
            counts[r.severity] = counts.get(r.severity, 0) + 1
        return counts

    def duration(self) -> float:
        return round(self.end_time - self.start_time, 2)


# ─────────────────────────────────────────────
#  CONSTANTES DE ESTILO / PALETA DE CORES
# ─────────────────────────────────────────────
class Color:
    BANNER   = Fore.CYAN   + Style.BRIGHT
    SECTION  = Fore.BLUE   + Style.BRIGHT
    SUCCESS  = Fore.GREEN  + Style.BRIGHT
    WARNING  = Fore.YELLOW + Style.BRIGHT
    DANGER   = Fore.RED    + Style.BRIGHT
    CRITICAL = Back.RED    + Fore.WHITE + Style.BRIGHT
    INFO     = Fore.WHITE  + Style.DIM
    RESET    = Style.RESET_ALL

SEVERITY_COLOR = {
    "CRITICAL": Color.CRITICAL,
    "HIGH":     Color.DANGER,
    "MEDIUM":   Color.WARNING,
    "LOW":      Fore.YELLOW,
    "INFO":     Color.INFO,
}

SEVERITY_ICON = {
    "CRITICAL": "",
    "HIGH":     "",
    "MEDIUM":   "",
    "LOW":      "",
    "INFO":     "",
}


# ─────────────────────────────────────────────
#  UTILITÁRIOS DE EXIBIÇÃO
# ─────────────────────────────────────────────
def _print_banner():
    print(Color.BANNER + """
╔══════════════════════════════════════════════════════════════╗
║                  WEB VULNERABILITY SCANNER                   ║
║                  create by: plascoy                          ║
╚══════════════════════════════════════════════════════════════╝""")

def _print_section(title: str):
    print(Color.SECTION + f"\n  ┌─ {title.upper()} {'─' * (54 - len(title))}")

def _print_result(result: ScanResult):
    icon  = SEVERITY_ICON.get(result.severity, "•")
    color = SEVERITY_COLOR.get(result.severity, "")
    url_info = f"  →  {result.url}" if result.url else ""
    code_info = f"  [{result.status_code}]" if result.status_code else ""
    print(color + f"  │  {icon} [{result.severity:<8}] {result.title}")
    if result.detail:
        print(Color.INFO  + f"  │           {result.detail}{url_info}{code_info}")

def _print_ok(msg: str):
    print(Color.SUCCESS + f"  │   {msg}")

def _print_info(msg: str):
    print(Color.INFO + f"  │  ℹ  {msg}")

def _print_report(report: ScanReport):
    summary = report.summary()
    total   = len(report.results)
    print(Color.BANNER + """
╔══════════════════════════════════════════════════════════════╗
║                        RELATÓRIO FINAL                       ║
╚══════════════════════════════════════════════════════════════╝""")
    print(Color.INFO + f"  Alvo    : {report.target}")
    print(Color.INFO + f"  Duração : {report.duration()}s")
    print(Color.INFO + f"  Total   : {total} resultado(s)\n")

    # Tabela de severidade
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = summary.get(sev, 0)
        if count:
            bar   = " " * count
            color = SEVERITY_COLOR.get(sev, "")
            print(color + f"  {sev:<8}  {bar}  ({count})")

    # Listagem detalhada de achados críticos/altos
    flagged = [r for r in report.results if r.severity in ("CRITICAL", "HIGH")]
    if flagged:
        print(Color.DANGER + "\n     ACHADOS CRÍTICOS / ALTOS:")
        for r in flagged:
            print(Color.DANGER + f"     • {r.title}")
            if r.url:
                print(Color.INFO + f"       {r.url}")
    else:
        print(Color.SUCCESS + "\n     Nenhum achado crítico ou alto encontrado.")

    print(Color.BANNER + "\n" + "═" * 64 + "\n")


# ─────────────────────────────────────────────
#  SCANNER PRINCIPAL
# ─────────────────────────────────────────────
class WebVulnScanner:
    """
    Scanner de vulnerabilidades web modular.

    Parâmetros
    ----------
    target : str
        URL ou domínio alvo.
    verbose : bool
        Exibe resultados negativos (seguros) também.
    timeout : int
        Timeout por requisição em segundos.
    delay : float
        Delay entre requisições para evitar rate-limiting.
    """

    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    )

    # ── Caminhos expostos e suas severidades ──────────────────
    SENSITIVE_PATHS = [
        ("/admin/",           "HIGH",     "Painel admin exposto"),
        ("/administrator/",   "HIGH",     "Painel Joomla admin exposto"),
        ("/wp-admin/",        "HIGH",     "Painel WordPress admin exposto"),
        ("/wp-login.php",     "MEDIUM",   "Página de login WordPress"),
        ("/login",            "LOW",      "Página de login genérica"),
        ("/phpinfo.php",      "CRITICAL", "PHP Info exposto (vazamento de configuração)"),
        ("/.git/",            "CRITICAL", "Repositório Git exposto"),
        ("/.git/config",      "CRITICAL", "Configuração Git exposta"),
        ("/.env",             "CRITICAL", "Arquivo .env exposto (credenciais)"),
        ("/.env.production",  "CRITICAL", "Arquivo .env.production exposto"),
        ("/.htaccess",        "HIGH",     "Arquivo .htaccess acessível"),
        ("/config.php",       "CRITICAL", "Arquivo de configuração PHP exposto"),
        ("/config.json",      "CRITICAL", "Arquivo de configuração JSON exposto"),
        ("/backup/",          "HIGH",     "Diretório de backup exposto"),
        ("/db_backup/",       "HIGH",     "Backup de banco de dados exposto"),
        ("/uploads/",         "MEDIUM",   "Diretório de uploads acessível"),
        ("/server-status",    "MEDIUM",   "Status do servidor Apache exposto"),
        ("/actuator/",        "HIGH",     "Spring Boot Actuator exposto"),
        ("/api/v1/users",     "MEDIUM",   "Endpoint de usuários API exposto"),
        ("/swagger-ui.html",  "LOW",      "Swagger UI exposto"),
        ("/robots.txt",       "INFO",     "robots.txt encontrado (verificar caminhos)"),
        ("/sitemap.xml",      "INFO",     "sitemap.xml encontrado"),
    ]

    # ── Headers de segurança esperados ────────────────────────
    SECURITY_HEADERS = {
        "X-Frame-Options":          ("MEDIUM", "Proteção contra Clickjacking ausente"),
        "X-Content-Type-Options":   ("LOW",    "Sniffing de Content-Type permitido"),
        "X-XSS-Protection":         ("LOW",    "Header XSS-Protection ausente"),
        "Strict-Transport-Security":("MEDIUM", "HSTS não configurado"),
        "Content-Security-Policy":  ("HIGH",   "Content-Security-Policy ausente"),
        "Referrer-Policy":          ("LOW",    "Referrer-Policy ausente"),
        "Permissions-Policy":       ("LOW",    "Permissions-Policy ausente"),
    }

    # ── Payloads de SQLi ──────────────────────────────────────
    SQLI_PAYLOADS = [
        ("'",              r"(sql|mysql|syntax error|unclosed|ORA-|pg_query|sqlite)"),
        ("\"",             r"(sql|mysql|syntax error|unclosed|ORA-|pg_query|sqlite)"),
        ("1' OR '1'='1",   r"(sql|mysql|syntax error|unclosed|ORA-|pg_query|sqlite)"),
        ("1\" OR \"1\"=\"1", r"(sql|mysql|syntax error|unclosed|ORA-|pg_query|sqlite)"),
        ("' OR 1=1--",     r"(sql|mysql|syntax error|unclosed|ORA-|pg_query|sqlite)"),
        ("'; DROP TABLE",  r"(sql|mysql|syntax error|unclosed|ORA-|pg_query|sqlite)"),
    ]

    # ── Payloads de XSS ───────────────────────────────────────
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "\"><script>alert(1)</script>",
        "javascript:alert(1)",
        "<svg/onload=alert(1)>",
    ]

    def __init__(
        self,
        target: str,
        verbose: bool = False,
        timeout: int = 8,
        delay: float = 0.2,
    ):
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        self.target  = target.rstrip("/")
        self.verbose = verbose
        self.timeout = timeout
        self.delay   = delay
        self.report  = ScanReport(target=self.target)

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.USER_AGENT})
        self.session.verify = False

    # ── Helpers internos ──────────────────────────────────────
    def _get(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            time.sleep(self.delay)
            return self.session.get(url, timeout=self.timeout, **kwargs)
        except requests.exceptions.ConnectionError:
            if self.verbose:
                _print_info(f"Conexão recusada: {url}")
        except requests.exceptions.Timeout:
            if self.verbose:
                _print_info(f"Timeout: {url}")
        except Exception as e:
            if self.verbose:
                _print_info(f"Erro em {url}: {e}")
        return None

    def _add(self, severity, category, title, detail="", url="", status_code=None):
        result = ScanResult(
            category=category,
            severity=severity,
            title=title,
            detail=detail,
            url=url,
            status_code=status_code,
        )
        self.report.add(result)
        _print_result(result)

    # ── Módulos de varredura ───────────────────────────────────

    def check_server_info(self):
        """Coleta informações do servidor via cabeçalhos de resposta."""
        _print_section("Informações do Servidor")
        response = self._get(self.target)
        if not response:
            _print_info("Não foi possível obter informações do servidor.")
            return

        server  = response.headers.get("Server", "")
        powered = response.headers.get("X-Powered-By", "")
        tech    = response.headers.get("X-Generator", "")

        if server:
            self._add("INFO", "Server", f"Servidor: {server}", "Cabeçalho Server revelado")
        if powered:
            self._add("MEDIUM", "Server", f"X-Powered-By: {powered}",
                      "Tecnologia backend exposta (facilita fingerprint)")
        if tech:
            self._add("LOW", "Server", f"X-Generator: {tech}", "CMS/framework identificado")

        # Detecta versões conhecidas vulneráveis
        combined = f"{server} {powered}".lower()
        if re.search(r"apache/[01]\.|apache/2\.[0-3]\.", combined):
            self._add("HIGH", "Server", "Versão Apache possivelmente desatualizada",
                      f"Detectada: {server}")
        if re.search(r"nginx/[01]\.", combined):
            self._add("HIGH", "Server", "Versão Nginx possivelmente desatualizada",
                      f"Detectada: {server}")
        if re.search(r"php/[5-7]\.[0-3]\.", combined):
            self._add("CRITICAL", "Server", "PHP desatualizado (EOL)",
                      f"Detectado: {powered}")

    def check_sensitive_paths(self):
        """Verifica caminhos sensíveis e arquivos expostos."""
        _print_section("Caminhos e Arquivos Sensíveis")
        found_any = False

        for path, severity, desc in self.SENSITIVE_PATHS:
            url = f"{self.target}{path}"
            response = self._get(url, allow_redirects=False)
            if response is None:
                continue

            if response.status_code in (200, 301, 302, 403):
                # 403 = existe mas bloqueado — ainda é relevante
                effective_severity = severity if response.status_code == 200 else "LOW"
                detail = "Acessível" if response.status_code == 200 else f"Bloqueado (HTTP {response.status_code})"
                self._add(effective_severity, "Paths", desc, detail,
                          url=url, status_code=response.status_code)
                found_any = True
            elif self.verbose:
                _print_ok(f"{desc} — não encontrado ({response.status_code})")

        if not found_any:
            _print_ok("Nenhum caminho sensível encontrado.")

    def check_security_headers(self):
        """Verifica presença de headers de segurança HTTP."""
        _print_section("Headers de Segurança")
        response = self._get(self.target)
        if not response:
            return

        headers = response.headers
        all_ok  = True

        for header, (severity, missing_msg) in self.SECURITY_HEADERS.items():
            if header in headers:
                if self.verbose:
                    _print_ok(f"{header}: {headers[header][:60]}")
            else:
                self._add(severity, "Headers", missing_msg, f"Header ausente: {header}")
                all_ok = False

        # Informacional: cookie sem flags
        for cookie in response.cookies:
            flags = []
            if not cookie.secure:
                flags.append("Secure ausente")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                flags.append("HttpOnly ausente")
            if flags:
                self._add("MEDIUM", "Headers",
                          f"Cookie '{cookie.name}' com flags inseguros",
                          ", ".join(flags))
                all_ok = False

        if all_ok:
            _print_ok("Todos os headers de segurança presentes.")

    def check_sql_injection(self):
        """Testa parâmetros comuns para sinais de SQL Injection."""
        _print_section("SQL Injection")
        found = False

        for payload, pattern in self.SQLI_PAYLOADS:
            for param in ("id", "q", "search", "user", "page", "cat"):
                url = f"{self.target}?{param}={payload}"
                response = self._get(url)
                if response and re.search(pattern, response.text, re.IGNORECASE):
                    self._add("CRITICAL", "SQLi",
                              f"Possível SQL Injection via parâmetro '{param}'",
                              f"Payload: {payload!r}  |  Padrão: {pattern}",
                              url=url)
                    found = True
                    break  # Um achado por payload é suficiente

        if not found:
            _print_ok("Nenhuma evidência óbvia de SQL Injection encontrada.")

    def check_xss(self):
        """Testa reflexão de payloads XSS em parâmetros de busca."""
        _print_section("Cross-Site Scripting (XSS)")
        found = False

        for payload in self.XSS_PAYLOADS:
            for param in ("q", "search", "query", "term", "s", "name"):
                url = f"{self.target}?{param}={payload}"
                response = self._get(url)
                if response and payload in response.text:
                    self._add("HIGH", "XSS",
                              f"Possível XSS Refletido via parâmetro '{param}'",
                              f"Payload refletido: {payload[:40]}",
                              url=url)
                    found = True
                    break

        if not found:
            _print_ok("Nenhuma reflexão de XSS óbvia encontrada.")

    def check_open_redirect(self):
        """Verifica parâmetros de redirecionamento aberto."""
        _print_section("Open Redirect")
        payloads = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
        ]
        params = ["redirect", "url", "next", "return", "goto", "target", "redir"]
        found  = False

        for payload in payloads:
            for param in params:
                url      = f"{self.target}?{param}={payload}"
                response = self._get(url, allow_redirects=False)
                if response and response.status_code in (301, 302):
                    location = response.headers.get("Location", "")
                    if "evil.com" in location:
                        self._add("HIGH", "Redirect",
                                  f"Open Redirect via '{param}'",
                                  f"Redireciona para: {location}",
                                  url=url, status_code=response.status_code)
                        found = True

        if not found:
            _print_ok("Nenhum Open Redirect óbvio encontrado.")

    def check_cors(self):
        """Verifica configuração permissiva de CORS."""
        _print_section("CORS (Cross-Origin Resource Sharing)")
        headers_evil = {"Origin": "https://evil.com"}
        response = self._get(self.target, headers=headers_evil)
        if not response:
            return

        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            self._add("MEDIUM", "CORS", "CORS permissivo: Access-Control-Allow-Origin: *",
                      "Qualquer origem pode fazer requisições")
        elif "evil.com" in acao:
            self._add("HIGH", "CORS", "CORS reflete origem arbitrária",
                      "Servidor espelha Origin do atacante")
            if acac.lower() == "true":
                self._add("CRITICAL", "CORS",
                          "CORS + credentials habilitados com origem arbitrária",
                          "Permite roubo de sessão cross-origin")
        else:
            _print_ok(f"CORS configurado: {acao or 'não presente'}")

    def check_https(self):
        """Verifica HTTPS e redirecionamento HTTP→HTTPS."""
        _print_section("HTTPS / TLS")
        parsed = urlparse(self.target)

        if parsed.scheme == "https":
            _print_ok("Alvo usa HTTPS.")
        else:
            self._add("HIGH", "HTTPS", "Alvo não usa HTTPS",
                      "Tráfego transmitido em texto claro")

        # Testa se HTTP redireciona para HTTPS
        http_url  = self.target.replace("https://", "http://")
        response  = self._get(http_url, allow_redirects=False)
        if response:
            location = response.headers.get("Location", "")
            if response.status_code in (301, 302) and location.startswith("https://"):
                _print_ok("HTTP redireciona para HTTPS corretamente.")
            elif parsed.scheme == "https":
                self._add("MEDIUM", "HTTPS",
                          "HTTP não redireciona para HTTPS",
                          "Usuários em HTTP ficam sem proteção")

    # ── Execução completa ──────────────────────────────────────

    def scan(self) -> ScanReport:
        """Executa todos os módulos de varredura e retorna o relatório."""
        _print_banner()
        print(Color.INFO + f"  Alvo   : {self.target}")
        print(Color.INFO + f"  Modo   : {'Verbose' if self.verbose else 'Normal'}")
        print(Color.INFO + f"  Timeout: {self.timeout}s  |  Delay: {self.delay}s\n")

        modules = [
            self.check_server_info,
            self.check_https,
            self.check_security_headers,
            self.check_sensitive_paths,
            self.check_sql_injection,
            self.check_xss,
            self.check_open_redirect,
            self.check_cors,
        ]

        for module in modules:
            try:
                module()
            except KeyboardInterrupt:
                print(Color.WARNING + "\n  [!] Varredura interrompida pelo usuário.")
                break
            except Exception as e:
                print(Color.WARNING + f"\n  [!] Erro no módulo {module.__name__}: {e}")

        self.report.end_time = time.time()
        _print_report(self.report)
        return self.report


# ─────────────────────────────────────────────
#  FUNÇÃO DE CONVENIÊNCIA (compatível com v1)
# ─────────────────────────────────────────────
def web_vuln_scan(
    target: str,
    verbose: bool = False,
    timeout: int = 8,
    delay: float = 0.2,
) -> ScanReport:
    """
    Executa uma varredura completa de vulnerabilidades web.

    Parâmetros
    ----------
    target : str
        URL ou domínio alvo (ex: "exemplo.com" ou "https://exemplo.com").
    verbose : bool
        Exibe resultados negativos (sem vulnerabilidade) também.
    timeout : int
        Timeout por requisição (segundos).
    delay : float
        Delay entre requisições (segundos).

    Retorno
    -------
    ScanReport
        Objeto com todos os achados e estatísticas.

    Exemplo
    -------
    >>> report = web_vuln_scan("https://meu-site.com", verbose=True)
    >>> print(report.summary())
    """
    scanner = WebVulnScanner(target, verbose=verbose, timeout=timeout, delay=delay)
    return scanner.scan()


# ─────────────────────────────────────────────
#  CLI SIMPLES (uso direto via terminal)
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description=" Web Vulnerability Scanner v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exemplo:\n  python web_vuln_scanner.py https://exemplo.com -v",
    )
    parser.add_argument("target",           help="URL ou domínio alvo")
    parser.add_argument("-v", "--verbose",  action="store_true", help="Modo verbose")
    parser.add_argument("-t", "--timeout",  type=int,   default=8,   help="Timeout (s)")
    parser.add_argument("-d", "--delay",    type=float, default=0.2, help="Delay entre req. (s)")
    parser.add_argument("--json",           metavar="FILE", help="Salvar relatório em JSON")

    args = parser.parse_args()

    report = web_vuln_scan(
        target=args.target,
        verbose=args.verbose,
        timeout=args.timeout,
        delay=args.delay,
    )

    if args.json:
        data = {
            "target":   report.target,
            "duration": report.duration(),
            "summary":  report.summary(),
            "results": [
                {
                    "severity":    r.severity,
                    "category":    r.category,
                    "title":       r.title,
                    "detail":      r.detail,
                    "url":         r.url,
                    "status_code": r.status_code,
                }
                for r in report.results
            ],
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(Color.SUCCESS + f"\n    Relatório JSON salvo em: {args.json}")
