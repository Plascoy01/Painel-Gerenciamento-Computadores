# PLASCOV Security Framework

A complete security scanner for web applications, infrastructure and API recon. Built to run real tests with the modules included in the project.

## O que é

PLASCOV é uma ferramenta de análise de vulnerabilidade desenvolvida para executar scans reais e encontrar problemas em aplicações web, serviços, DNS e TLS.

## Principais recursos

- **Port Scan**: Descobre portas abertas e serviços
- **TLS/SSL**: Analisa protocolos, cifras e certificados
- **Detecção de tecnologias**: Identifica frameworks e servidores web
- **Análise de headers**: Verifica cabeçalhos de segurança HTTP
- **DNS e subdomínios**: Enumera DNS, WHOIS, subdomínios e transferências de zona
- **Brute force de diretórios**: Busca diretórios ocultos
- **Scan de vulnerabilidades web**: SQLi, XSS, CSRF, LFI, RFI, SSRF, XXE e mais
- **Scanner de API**: Verifica endpoints expostos e APIs comuns
- **Detecção de CMS e serviços**: Verifica CMS, firewall, banco de dados e servidor
- **Geração de relatório**: exporta resultados em JSON, HTML, CSV e TXT
- **Integração com ferramentas externas**: Gobuster, ffuf, Nmap, WhatWeb
- **Modos avançados**: recon, audit, fuzz, external, report

## Instalação

1. Crie um ambiente virtual:
   ```bash
   python3 -m venv plascoy_env
   source plascoy_env/bin/activate
   ```

2. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

3. (Opcional) Instale ferramentas externas, se quiser usar as integrações:
   ```bash
   sudo apt update
   sudo apt install gobuster ffuf nmap whatweb
   ```

## Como usar

```bash
python plascoy.py -u <target> [options]
```

### Alvo

Use domínio ou URL, por exemplo:

- `example.com`
- `https://example.com`
- `http://test.local`

### Comandos básicos

- `-u, --url <target>`: alvo
- `-h, --help`: mostra a ajuda
- `--verbose`: mostra saída detalhada
- `--output <format>`: exporta relatório em `json`, `html`, `csv` ou `txt`

## Opções disponíveis

### Scans principais

- `--tls`: TLS/SSL
- `--ports`: portas
- `--tech`: tecnologias
- `--headers`: headers de segurança
- `--dns`: DNS
- `--dirbrute`: brute force de diretórios
- `--webvuln`: vulnerabilidades web
- `--vuln`: scan geral de vulnerabilidades
- `--all`: scan completo

### Scans de vulnerabilidade

- `--sqli`: SQL Injection
- `--xss`: Cross-Site Scripting
- `--csrf`: CSRF
- `--lfi`: LFI/RFI
- `--cmdinj`: Command Injection
- `--redirect`: Open Redirect
- `--upload`: upload inseguro
- `--cors`: CORS básico
- `--cors-adv`: CORS avançado
- `--hostheader`: host header injection
- `--ssrf`: SSRF
- `--xxe`: XXE
- `--deserial`: deserialização insegura
- `--api`: scan de API
- `--cve`: verificação de CVEs

### Scans avançados

- `--ssti`: SSTI
- `--idor`: IDOR
- `--jwt`: análise de JWT
- `--http-methods`: métodos HTTP
- `--dirlisting`: listagem de diretório
- `--backup`: arquivos de backup expostos
- `--git`: repositório `.git` exposto
- `--env`: arquivos `.env` expostos
- `--robots`: robots.txt
- `--sitemap`: sitemap.xml
- `--params`: mineração de parâmetros
- `--js`: análise de JavaScript
- `--cookies`: análise de cookies

### Modos especiais

- `--crawl`: rastreia site para descobrir endpoints
- `--fuzz <type>`: fuzzing com `xss`, `sqli`, `lfi`, `xxe`, `all`, `random`
- `--external`: executa ferramentas externas disponíveis
- `--recon`: executa DNS, subdomínios, WHOIS, headers, tecnologia e mais
- `--audit`: executa um checklist rápido de vulnerabilidades críticas
- `--report`: gera relatório integrado com os scans executados
- `--report-gen`: cria um relatório JSON com os resultados

## Exemplos de uso

```bash
# Scan completo
python plascoy.py -u example.com --all

# Recon completo
python plascoy.py -u example.com --recon --report

# Auditoria rápida de vulnerabilidades
python plascoy.py -u example.com --audit

# Scan API e CORS avançado
python plascoy.py -u example.com --api --cors-adv

# Relatório em HTML
python plascoy.py -u example.com --all --report --output html

# Usar ferramentas externas quando instaladas
python plascoy.py -u example.com --external
python plascoy.py -u example.com --gobuster --ffuf --nmap --whatweb
```

## Dicas

- Comece com `--recon` para coletar informações do alvo.
- Use `--audit` para um teste rápido de segurança.
- Combine `--all` com `--report` para gerar relatórios de resultado.
- Se não quiser usar ferramentas externas, não use `--external`, `--gobuster`, `--ffuf`, `--nmap` ou `--whatweb`.

## Requisitos

- Python 3.6+
- `requirements.txt` com dependências do projeto

## Créditos

- Desenvolvido por `meun0me` e `plascoy`

## Aviso

Use esta ferramenta apenas em ambientes autorizados. Testes em sistemas sem permissão são ilegais e antiéticos.
