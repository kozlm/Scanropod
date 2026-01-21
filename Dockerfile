# deklaracja buildera do kompilacji projektu oraz instalacji Nuclei
FROM golang:1.25 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o scanropod ./cmd/server

RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.4.10
#--------------------------------------

# deklaracja finalnego obrazu
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# instalacja wymaganych pakietów apt-get
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    tar \
    git \
    perl \
    python3 \
    python3-pip \
    openjdk-17-jre-headless \
 && rm -rf /var/lib/apt/lists/*

# pobranie archiwum ZAP
ARG ZAP_VERSION=2.16.1
RUN set -eux; \
    wget -q "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" -O /tmp/ZAP.tar.gz; \
    mkdir -p /usr/local/share/zaproxy; \
    tar -xzf /tmp/ZAP.tar.gz -C /usr/local/share/zaproxy --strip-components=1; \
    ln -sf /usr/local/share/zaproxy/zap.sh /usr/local/bin/zap; \
    rm /tmp/ZAP.tar.gz

# pobranie archiwum Nikto
RUN set -eux; \
    wget -q "https://github.com/sullo/nikto/archive/refs/tags/2.5.0.tar.gz" -O /tmp/nikto.tar.gz; \
    mkdir -p /usr/local/share/nikto; \
    tar -xzf /tmp/nikto.tar.gz -C /usr/local/share/nikto --strip-components=1; \
    chmod +x /usr/local/share/nikto/program/nikto.pl; \
    ln -sf /usr/local/share/nikto/program/nikto.pl /usr/local/bin/nikto; \
    rm /tmp/nikto.tar.gz

# instalacja Wapiti przez pip
RUN python3 -m pip install --no-cache-dir --break-system-packages "wapiti3==3.2.10"

# kopiowanie Nuclei and pliku wykonywalnego projektu z buildera
COPY --from=builder /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=builder /src/scanropod /usr/local/bin/scanropod
# pobranie szablonów Nuclei
RUN nuclei -update-templates

# kopiowanie plików konfiguracyjnych
COPY config config

# dodanie uprawnień do wykonywania plików
RUN chmod +x /usr/local/bin/scanropod /usr/local/bin/nuclei

# eksponowanie portu 8000
EXPOSE 8443

# uruchomienie aplikacji jako ENTRYPOINT
ENTRYPOINT ["/usr/local/bin/scanropod"]
# domyślne uruchomienie bez klucza API
CMD ["--no-api-key"]