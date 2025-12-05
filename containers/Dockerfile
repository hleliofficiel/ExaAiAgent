FROM kalilinux/kali-rolling:latest

LABEL maintainer="ExaaiAgnt Team"
LABEL description="ExaaiAgnt - AI Agent Penetration Testing Environment with Comprehensive Security Tools"
LABEL version="1.0.0"

# Update and install base packages
RUN apt-get update && \
    apt-get install -y kali-archive-keyring sudo && \
    apt-get update && \
    apt-get upgrade -y

# Create pentester user
RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Create directories
RUN mkdir -p /home/pentester/configs \
             /home/pentester/wordlists \
             /home/pentester/output \
             /home/pentester/scripts \
             /home/pentester/tools \
             /app/runtime \
             /app/tools \
             /app/certs && \
    chown -R pentester:pentester /app/certs /home/pentester/tools

# ============================================
# CORE SYSTEM PACKAGES
# ============================================
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    # Base utilities
    wget curl git vim nano unzip tar \
    apt-transport-https ca-certificates gnupg lsb-release \
    build-essential software-properties-common \
    gcc libc6-dev pkg-config libpcap-dev libssl-dev \
    # Python
    python3 python3-pip python3-dev python3-venv python3-setuptools \
    # Go
    golang-go \
    # Networking utilities
    net-tools dnsutils whois \
    # Text processing
    jq parallel ripgrep grep \
    less man-db procps htop \
    # Network tools
    iproute2 iputils-ping netcat-traditional socat proxychains4 \
    # Node.js
    nodejs npm pipx \
    # System
    libcap2-bin gdb tmux \
    # Browser dependencies
    libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libatspi2.0-0 \
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libxkbcommon0 libpango-1.0-0 libcairo2 libasound2 \
    fonts-unifont fonts-noto-color-emoji fonts-freefont-ttf fonts-dejavu-core ttf-bitstream-vera \
    libnss3-tools chromium

# ============================================
# RECONNAISSANCE TOOLS
# ============================================
RUN apt-get install -y --no-install-recommends \
    # DNS & Subdomain
    subfinder amass dnsenum dnsrecon fierce massdns \
    # Asset Discovery
    nmap ncat ndiff masscan \
    # HTTP probing
    httpx-toolkit \
    # Email harvesting
    theharvester

# ============================================
# WEB SCANNING & FUZZING TOOLS
# ============================================
RUN apt-get install -y --no-install-recommends \
    # Web scanners
    nikto whatweb wapiti zaproxy \
    # Directory fuzzing
    ffuf gobuster dirb dirbuster \
    # Vulnerability scanners
    nuclei sqlmap \
    # CMS scanners
    wpscan joomscan \
    # SSL/TLS
    sslscan testssl.sh

# ============================================
# EXPLOITATION TOOLS
# ============================================
RUN apt-get install -y --no-install-recommends \
    # XSS
    xsser \
    # Git security
    gitleaks

# Set nmap capabilities
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

# ============================================
# SSL CERTIFICATES
# ============================================
USER pentester
RUN openssl ecparam -name prime256v1 -genkey -noout -out /app/certs/ca.key && \
    openssl req -x509 -new -key /app/certs/ca.key \
    -out /app/certs/ca.crt \
    -days 3650 \
    -subj "/C=US/ST=CA/O=ExaaiAgnt Security/CN=ExaaiAgnt Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" && \
    openssl pkcs12 -export \
    -out /app/certs/ca.p12 \
    -inkey /app/certs/ca.key \
    -in /app/certs/ca.crt \
    -passout pass:"" \
    -name "ExaaiAgnt Root CA" && \
    chmod 644 /app/certs/ca.crt && \
    chmod 600 /app/certs/ca.key && \
    chmod 600 /app/certs/ca.p12

USER root
RUN cp /app/certs/ca.crt /usr/local/share/ca-certificates/ca.crt && \
    update-ca-certificates

# ============================================
# POETRY & PYTHON ENVIRONMENT
# ============================================
RUN curl -sSL https://install.python-poetry.org | POETRY_HOME=/opt/poetry python3 - && \
    ln -s /opt/poetry/bin/poetry /usr/local/bin/poetry && \
    chmod +x /usr/local/bin/poetry && \
    python3 -m venv /app/venv && \
    chown -R pentester:pentester /app/venv /opt/poetry

# ============================================
# GO TOOLS (Additional)
# ============================================
USER pentester
WORKDIR /tmp

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/OJ/gobuster/v3@latest && \
    go install -v github.com/RustScan/RustScan@latest || true

# Update nuclei templates
RUN nuclei -update-templates || true

# ============================================
# PYTHON TOOLS (pipx)
# ============================================
RUN pipx install arjun && \
    pipx install dirsearch && \
    pipx inject dirsearch setuptools && \
    pipx install wafw00f && \
    pipx install semgrep && \
    pipx install bandit && \
    pipx install mitmproxy && \
    pipx install xsstrike || true

# ============================================
# NPM TOOLS
# ============================================
ENV NPM_CONFIG_PREFIX=/home/pentester/.npm-global
RUN mkdir -p /home/pentester/.npm-global

RUN npm install -g retire@latest && \
    npm install -g eslint@latest && \
    npm install -g js-beautify@latest && \
    npm install -g jshint@latest

# ============================================
# CUSTOM TOOLS FROM GIT
# ============================================
WORKDIR /home/pentester/tools
RUN git clone --depth 1 https://github.com/aravind0x7/JS-Snooper.git && \
    chmod +x JS-Snooper/js_snooper.sh && \
    git clone --depth 1 https://github.com/xchopath/jsniper.sh.git && \
    chmod +x jsniper.sh/jsniper.sh && \
    git clone --depth 1 https://github.com/ticarpi/jwt_tool.git && \
    chmod +x jwt_tool/jwt_tool.py && \
    git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git && \
    git clone --depth 1 https://github.com/arthaud/git-dumper.git

# ============================================
# WORDLISTS
# ============================================
USER root
RUN mkdir -p /usr/share/wordlists && \
    cd /usr/share/wordlists && \
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git && \
    wget -q https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O rockyou.txt || true

# ============================================
# ADDITIONAL SECURITY TOOLS
# ============================================
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# ============================================
# PROXY TOOLS (Caido)
# ============================================
WORKDIR /app
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        CAIDO_ARCH="x86_64"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        CAIDO_ARCH="aarch64"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    wget -O caido-cli.tar.gz https://caido.download/releases/v0.48.0/caido-cli-v0.48.0-linux-${CAIDO_ARCH}.tar.gz && \
    tar -xzf caido-cli.tar.gz && \
    chmod +x caido-cli && \
    rm caido-cli.tar.gz && \
    mv caido-cli /usr/local/bin/

# ============================================
# CLEANUP
# ============================================
RUN apt-get autoremove -y && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# ============================================
# ENVIRONMENT VARIABLES
# ============================================
ENV PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/venv/bin:$PATH"
ENV VIRTUAL_ENV="/app/venv"
ENV POETRY_HOME="/opt/poetry"
ENV EXAAI_SANDBOX_MODE=true
ENV PYTHONPATH=/app
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# ============================================
# WORKSPACE SETUP
# ============================================
RUN mkdir -p /workspace && chown -R pentester:pentester /workspace /app

# Copy project files
COPY pyproject.toml poetry.lock ./

USER pentester

# Install Python dependencies
RUN poetry install --no-root --without dev
RUN poetry run playwright install chromium

# Install JWT tool requirements
RUN /app/venv/bin/pip install -r /home/pentester/tools/jwt_tool/requirements.txt && \
    ln -s /home/pentester/tools/jwt_tool/jwt_tool.py /home/pentester/.local/bin/jwt_tool

# Install git-dumper requirements
RUN /app/venv/bin/pip install -r /home/pentester/tools/git-dumper/requirements.txt || true

RUN echo "# ExaaiAgnt Sandbox Environment" > README.md

# ============================================
# COPY EXAAIAGNT FILES
# ============================================
COPY exaaiagnt/__init__.py exaaiagnt/
COPY exaaiagnt/runtime/tool_server.py exaaiagnt/runtime/__init__.py exaaiagnt/runtime/runtime.py /app/exaaiagnt/runtime/

COPY exaaiagnt/tools/__init__.py exaaiagnt/tools/registry.py exaaiagnt/tools/executor.py exaaiagnt/tools/argument_parser.py /app/exaaiagnt/tools/

COPY exaaiagnt/tools/browser/ /app/exaaiagnt/tools/browser/
COPY exaaiagnt/tools/file_edit/ /app/exaaiagnt/tools/file_edit/
COPY exaaiagnt/tools/notes/ /app/exaaiagnt/tools/notes/
COPY exaaiagnt/tools/python/ /app/exaaiagnt/tools/python/
COPY exaaiagnt/tools/terminal/ /app/exaaiagnt/tools/terminal/
COPY exaaiagnt/tools/proxy/ /app/exaaiagnt/tools/proxy/

# PATH setup
RUN echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:$PATH"' >> /home/pentester/.bashrc && \
    echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:$PATH"' >> /home/pentester/.profile

USER root
COPY containers/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER pentester
WORKDIR /workspace

ENTRYPOINT ["docker-entrypoint.sh"]
