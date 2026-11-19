<div align="center">

# 🛡️ NetGuard Audit — Zero-Dependency Security, TLS & Secret Leak Auditor

[![Live Demo](https://img.shields.io/badge/🌐_Live_Web_Scanner-Testar_Online-10b981?style=for-the-badge)](https://wallisonws.github.io/netguard-audit/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero_(Stdlib_Only)-38bdf8?style=for-the-badge)](#)
[![GitHub Stars](https://img.shields.io/github/stars/WallisonWS/netguard-audit?style=for-the-badge&color=f59e0b)](https://github.com/WallisonWS/netguard-audit/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-6366f1?style=for-the-badge)](LICENSE)

**Auditor de Segurança instantâneo (Python 3 + Windows PowerShell Nativo) sem nenhuma dependência externa: avalie TLS & HTTP Security Headers com Nota `A+` a `F`, escaneie repositórios Git contra vazamento de credenciais e audite portas críticas expostas gerando relatórios executivos em HTML.**

[🌐 **Scanner Web Online**](https://wallisonws.github.io/netguard-audit/) • [⚡ **DevSecOps Toolkit (12 Tools)**](https://github.com/WallisonWS/devsecops-toolkit) • [📚 **Awesome Secure Infrastructure**](https://github.com/WallisonWS/awesome-secure-infrastructure)

</div>

---

## ✨ Principais Motores de Auditoria

| Motor | Comando | O Que Audita |
| :--- | :--- | :--- |
| **🌐 Web & TLS Security Grader** | `audit-web <url>` | Validade/Expiração de Certificado SSL/TLS, versão do protocolo, **7 HTTP Security Headers críticos** (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `COOP`), detecção de fingerprinting (`Server`/`X-Powered-By`) e **Score 0–100 (Nota A+ a F)**. |
| **🔎 Git Repo & `.env` Secret Scanner** | `audit-repo <path>` | Escaneia recursivamente repositórios contra vazamento de **AWS Keys (`AKIA...`)**, **GitHub PATs**, **OpenAI/Stripe Keys**, **Google API Keys**, **Chaves Privadas SSH/RSA**, **URIs de Banco de Dados com Senha**, **Slack Webhooks** e **JWTs hardcoded**. |
| **🔌 Critical TCP Port Exposure Scan** | `audit-ports <host>` | Varredura concorrente de portas de alto risco (**SSH 22, Telnet 23, SMB 445, RTSP 554, MSSQL 1433, MySQL 3306, RDP 3389, PostgreSQL 5432, Redis 6379, MongoDB 27017**) com classificação de severidade. |
| **📊 Executive HTML Scorecard** | `--html report.html` | Exporta um relatório executivo em HTML (Dark Mode) pronto para envio à diretoria, clientes ou anexar em auditorias de conformidade. |

---

## 🚀 Quick Start (0 segundos de instalação)

```bash
git clone https://github.com/WallisonWS/netguard-audit.git
cd netguard-audit
```

### 🐧 Linux / macOS / CI-CD (Python 3 Standard Library)
```bash
# 1) Auditar TLS & HTTP Security Headers + Gerar Relatório HTML Executivo
python3 netguard.py audit-web https://github.com --html audit-web.html

# 2) Escanear diretório atual contra vazamento de credenciais antes do git push
python3 netguard.py audit-repo . --html audit-secrets.html

# 3) Auditar exposição de portas críticas em um servidor/firewall
python3 netguard.py audit-ports 192.168.1.1 --html audit-ports.html
```

### 🪟 Windows PowerShell Nativo (Não precisa nem de Python!)
```powershell
# Auditar cabeçalhos HTTP de segurança
.\netguard.ps1 -Mode audit-web -Target "https://github.com"

# Escanear repositório local contra vazamento de segredos
.\netguard.ps1 -Mode audit-repo -Target "."

# Verificar portas críticas abertas
.\netguard.ps1 -Mode audit-ports -Target "127.0.0.1"
```

---

<div align="center">
  Gostou? Deixe uma <b>⭐ Star</b> para apoiar ferramentas open-source de cibersegurança! • Criado por <b><a href="https://github.com/WallisonWS">Wallison Araujo (@WallisonWS)</a></b>.
</div>
