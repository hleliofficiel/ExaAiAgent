# ExaaiAgnt Docker Image Build Guide

## بناء الصورة

```bash
# الانتقال إلى مجلد المشروع
cd /path/to/ExaAi

# بناء الصورة
docker build -t exaai-sandbox:1.0 -f containers/Dockerfile .

# أو مع اسم مخصص للنشر
docker build -t ghcr.io/yourusername/exaai-sandbox:1.0 -f containers/Dockerfile .
```

## نشر الصورة (اختياري)

```bash
# Docker Hub
docker login
docker push yourusername/exaai-sandbox:1.0

# GitHub Container Registry
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
docker push ghcr.io/yourusername/exaai-sandbox:1.0
```

## استخدام الصورة

```bash
# تعيين صورة مخصصة
export EXAAI_IMAGE="exaai-sandbox:1.0"

# تشغيل ExaaiAgnt
exaaiagnt --target https://example.com
```

## الأدوات المضمنة

### Reconnaissance

- subfinder, amass, dnsenum, dnsrecon, fierce, massdns
- theharvester, assetfinder, httpx

### Port Scanning

- nmap, masscan, rustscan

### Web Scanning

- nikto, whatweb, wapiti, zaproxy
- ffuf, gobuster, dirb, dirsearch, feroxbuster

### Vulnerability

- nuclei, sqlmap, xsser, dalfox
- wpscan, joomscan

### SSL/TLS

- sslscan, testssl.sh

### Git Security

- gitleaks, trufflehog, git-dumper

### Browser

- chromium, playwright

### Proxy

- mitmproxy, caido

### Wordlists

- SecLists, rockyou
