FROM python:3.12-slim

# wireproxy – userspace WireGuard klient s HTTP proxy (bez NET_ADMIN, bez kernel modulu)
ARG WIREPROXY_VERSION=v1.0.9
ARG WIREPROXY_SHA256_AMD64=beea2016a34e24762d539d7ff727188ab6709e58072d7a69085c5d4f0ae665dc
ARG WIREPROXY_SHA256_ARM64=5fdf917567e690369aadfc3422397633848f758f726de2132de187e3d4fe0213
RUN set -eux; arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) sum="$WIREPROXY_SHA256_AMD64";; arm64) sum="$WIREPROXY_SHA256_ARM64";; *) echo "nepodporovaná architektura $arch"; exit 1;; esac; \
    python -c "import urllib.request,sys;urllib.request.urlretrieve(sys.argv[1],'/tmp/wp.tgz')" \
      "https://github.com/whyvl/wireproxy/releases/download/${WIREPROXY_VERSION}/wireproxy_linux_${arch}.tar.gz"; \
    echo "$sum  /tmp/wp.tgz" | sha256sum -c -; \
    tar -xzf /tmp/wp.tgz -C /usr/local/bin wireproxy; rm /tmp/wp.tgz; wireproxy -v

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY static ./static
RUN useradd -r -u 10001 app && mkdir -p /app/data /app/keys && chown -R app /app/data /app/keys
USER app
VOLUME ["/app/data", "/app/keys"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/login')" || exit 1
ARG APP_VERSION=dev
ARG APP_BUILD_DATE=
ENV APP_VERSION=${APP_VERSION} APP_BUILD_DATE=${APP_BUILD_DATE}
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
