#!/usr/bin/env python3
"""
GODS Recon Intelligence Engine -- Configuration
"""

RECON_VERSION = "v8.51E"


# ── Tool registry ──
TOOLS = {
    "nmap":"nmap", "rustscan":"rustscan", "masscan":"masscan", "naabu":"naabu",
    "httpx":"httpx", "curl":"curl", "wget":"wget", "whatweb":"whatweb",
    "nikto":"nikto", "nuclei":"nuclei", "gobuster":"gobuster", "ffuf":"ffuf",
    "feroxbuster":"feroxbuster", "dirsearch":"dirsearch", "wfuzz":"wfuzz",
    "gau":"gau", "waybackurls":"waybackurls", "hakrawler":"hakrawler", "katana":"katana",
    "subfinder":"subfinder", "amass":"amass", "dnsx":"dnsx", "dig":"dig", "host":"host",
    "whois":"whois", "wafw00f":"wafw00f", "openssl":"openssl", "sslscan":"sslscan",
    "testssl":"testssl.sh", "zap":"zap-cli",
    "msfconsole":"msfconsole", "msfvenom":"msfvenom",
}

# Tool categories for dependency/module status
TOOL_CATEGORIES = {
    "portscan": ["nmap", "rustscan", "masscan", "naabu"],
    "webscan": ["gobuster", "ffuf", "feroxbuster", "dirsearch", "wfuzz", "nikto", "nuclei", "zap"],
    "dns": ["dnsx", "dig", "host"],
    "tls": ["openssl", "sslscan", "testssl"],
    "headers": ["curl", "wget"],
    "whois": ["whois"],
    "subdomain": ["subfinder", "amass"],
    "techdetect": ["httpx", "whatweb"],
    "wafdetect": ["wafw00f"],
    "certtransparency": ["curl"],
    "metasploit": ["msfconsole", "msfvenom"],
}

TOOL_PURPOSES = {
    "NETWORK": ["nmap", "rustscan", "masscan", "naabu"],
    "HTTP": ["httpx", "curl", "wget"],
    "WEB": ["whatweb", "nikto", "nuclei", "wafw00f", "zap"],
    "DISCOVERY": ["gobuster", "ffuf", "feroxbuster", "dirsearch", "wfuzz"],
    "URLS": ["gau", "waybackurls", "hakrawler", "katana"],
    "DOMAINS": ["subfinder", "amass"],
    "DNS": ["dnsx", "dig", "host"],
    "DOMAIN INFO": ["whois"],
    "TLS": ["openssl", "sslscan", "testssl"],
    "METASPLOIT": ["msfconsole", "msfvenom"],
}

REQUIRED_TOOLS = []
OPTIONAL_TOOLS = list(TOOLS)

WORDLISTS = {
    "gobuster_dir": "/usr/share/wordlists/dirb/common.txt",
    "gobuster_dns": "/usr/share/wordlists/dnsrecon/subdomains-top1mil-5000.txt",
    "fallback_dir": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
}

TIMEOUTS = {
    "nmap_quick": 60,
    "nmap_full": 900,
    "gobuster": 120,
    "dns": 30,
    "tls": 60,
    "headers": 15,
    "whois": 20,
    "subdomain": 180,
    "techdetect": 30,
    "wafdetect": 45,
    "certtransparency": 30,
}

PORTSCAN_PRESETS = {
    "common": {"nmap_args": "-sV -T4 --top-ports 1000", "desc": "Top 1000 most common TCP ports", "timeout_key": "nmap_quick"},
    "full":   {"nmap_args": "-sV -T4 -p-", "desc": "All 65535 TCP ports", "timeout_key": "nmap_full"},
    "quick":  {"nmap_args": "-sV -T4 -F", "desc": "Top 100 TCP ports (fast)", "timeout_key": "nmap_quick"},
    "stealth":{"nmap_args": "-sS -T2 -p-", "desc": "Stealth SYN scan, all ports, slow timing", "timeout_key": "nmap_full"},
}

NMAP_TIMING = {
    "0": "T0 (Paranoid)",
    "1": "T1 (Sneaky)",
    "2": "T2 (Polite)",
    "3": "T3 (Normal)",
    "4": "T4 (Aggressive)",
    "5": "T5 (Insane)",
}

WEBSCAN_PRESETS = {
    "common":     {"wordlist": WORDLISTS["gobuster_dir"], "extensions": "", "threads": 50, "desc": "Common directories/files"},
    "aggressive": {"wordlist": WORDLISTS["gobuster_dir"], "extensions": "php,html,txt,bak,zip,sql", "threads": 100, "desc": "Aggressive with extensions"},
    "minimal":    {"wordlist": WORDLISTS["gobuster_dir"], "extensions": "", "threads": 20, "desc": "Minimal, slow and quiet"},
}

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
SUBDOMAIN_SOURCES = ["crt.sh", "subfinder", "amass"]

# Severity rules for auto-correlator
SEVERITY_RULES = {
    "CRITICAL": [
        "SSLv2/SSLv3 enabled",
        "expired certificate",
        "zone transfer allowed",
        ".git directory exposed",
        ".env file exposed",
        "private key exposed",
    ],
    "HIGH": [
        "open RDP port 3389",
        "directory listing enabled",
        "admin panel found",
        "backup file found",
        "sensitive file exposed",
        "TLS 1.0/1.1 enabled",
    ],
    "MEDIUM": [
        "open database port",
        "weak TLS cipher",
        "server version disclosed",
        "wildcard DNS",
        "WAF bypass possible",
        "missing HSTS header",
        "missing CSP header",
    ],
    "LOW": [
        "missing X-Frame-Options",
        "missing X-Content-Type-Options",
        "missing Referrer-Policy",
        "missing Permissions-Policy",
        "verbose server banner",
        "open FTP port 21",
        "open Telnet port 23",
    ],
    "INFO": [
        "missing X-XSS-Protection",
        "DNS TXT record present",
        "open SSH port 22",
        "open HTTP port 80",
        "open HTTPS port 443",
        "self-signed certificate",
    ],
}
