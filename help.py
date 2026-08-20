from colorama import init, Fore, Style

init(autoreset=True)

ASCII_ART = [
"████  ████  ████████  ████      ██████████  ██",
"████  ████  ████      ████      ████  ████  ██",
"██████████  ████████  ████      ██████████  ██",
"██████████  ████      ████      ██████████  ██",
"████  ████  ████████  ████████  ████          ",
"████  ████  ████████  ████████  ████        ██",
]

def banner():

    colors = [
        Fore.CYAN,
        Fore.MAGENTA,
        Fore.GREEN,
        Fore.YELLOW,
        Fore.CYAN,
        Fore.MAGENTA
    ]

    print("\n")

    for i, line in enumerate(ASCII_ART):
        color = colors[i % len(colors)]
        print(color + Style.BRIGHT + line)

    print(Fore.CYAN + Style.BRIGHT + "\n         PLASC0Y SECURITY FRAMEWORK ")
    print(Fore.WHITE + "      Advanced Scanner • Recon • Exploitation Toolkit")
    print(Fore.BLUE + "═" * 80)


def line():
    print(Fore.BLUE + "═" * 80)


def section(name, color):
    print("\n" + color + Style.BRIGHT + f"◆ {name}")
    print(color + "─" * 80)


def item(cmd, desc, color):
    print(
        color + Style.BRIGHT + f"  {cmd:<24}" +
        Fore.WHITE + f"➜  {desc}"
    )


def show_help():

    line()
    banner()

    print(Fore.YELLOW + Style.BRIGHT + "\n[ USAGE ]")
    print(Fore.WHITE + "  python plascoy.py -u <target> [options]\n")

    # ================= CORE =================
    section("CORE OPTIONS", Fore.CYAN)
    item("-u, --url <target>", "Target URL or domain (required)", Fore.CYAN)
    item("-h, --help", "Show help panel", Fore.CYAN)
    item("--verbose", "Enable debug output", Fore.CYAN)

    # ================= SSL =================
    section("SSL / TLS SCANNING", Fore.YELLOW)
    item("--tls", "Scan TLS versions and ciphers", Fore.YELLOW)
    item("--testssl", "Full SSL/TLS analysis", Fore.YELLOW)

    # ================= NETWORK =================
    section("NETWORK SCANNING", Fore.MAGENTA)
    item("--ports", "Port scan (1-1024)", Fore.MAGENTA)
    item("--dns", "DNS enumeration", Fore.MAGENTA)
    item("--subdomain", "Subdomain discovery", Fore.MAGENTA)
    item("--whois", "WHOIS lookup", Fore.MAGENTA)

    # ================= WEB =================
    section("WEB APPLICATION SCANNING", Fore.GREEN)
    item("--tech", "Detect technologies", Fore.GREEN)
    item("--headers", "Security headers analysis", Fore.GREEN)
    item("--dirbrute", "Directory brute force", Fore.GREEN)
    item("--webvuln", "Web vulnerability scan", Fore.GREEN)

    # ================= VULN =================
    section("VULNERABILITY SCANNING", Fore.RED)
    item("--sqli", "SQL Injection testing", Fore.RED)
    item("--xss", "Cross-Site Scripting testing", Fore.RED)
    item("--csrf", "CSRF detection", Fore.RED)
    item("--lfi", "Local File Inclusion", Fore.RED)
    item("--ssrf", "Server-Side Request Forgery", Fore.RED)
    item("--xxe", "XML External Entity", Fore.RED)
    item("--cve", "CVE checker + NVD cache", Fore.RED)

    # ================= TOOLS =================
    section("EXTERNAL TOOLS", Fore.CYAN)
    item("--nmap", "Run Nmap scan", Fore.CYAN)
    item("--gobuster", "Directory brute force", Fore.CYAN)
    item("--ffuf", "Fast fuzzing engine", Fore.CYAN)
    item("--whatweb", "Technology detection", Fore.CYAN)

    # ================= ACTIONS =================
    section("ACTIONS", Fore.GREEN)
    item("--all", "Run complete scan suite", Fore.GREEN)
    item("--audit", "Quick security audit", Fore.GREEN)
    item("--recon", "Reconnaissance mode", Fore.GREEN)
    item("--output <format>", "Export report (txt/json/html)", Fore.GREEN)

    # ================= EXAMPLES =================
    section("EXAMPLES", Fore.YELLOW)

    print(Fore.WHITE + "  python plascoy.py -u google.com --tls")
    print(Fore.WHITE + "  python plascoy.py -u target.com --sqli --xss")
    print(Fore.WHITE + "  python plascoy.py -u site.com --all --verbose")

    # ================= FOOTER =================
    line()

    print(
        Fore.GREEN + Style.BRIGHT +
        "                    SYSTEM READY"
    )

    print(
        Fore.CYAN +
        "             PLASC0Y ACTIVE • SECURITY FRAMEWORK"
    )

    line()
