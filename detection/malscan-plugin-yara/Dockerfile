ARG tool_version=v4.0.2
FROM malscan/debian as build

LABEL MAINTAINER=cincan.io

ARG tool_version
ENV TOOL_VERSION=$tool_version

RUN apt-get update && apt-get install -y \
    git  \
    automake \
    libtool \
    make \
    gcc \
    pkg-config \
    libssl-dev \
    libmagic-dev \
    libjansson-dev \
    && git clone --depth 1 --branch "${TOOL_VERSION}" https://github.com/VirusTotal/yara.git /yara \
    && git clone --depth 1 https://github.com/Yara-Rules/rules.git /rules \
    && cd /yara \
    && ./bootstrap.sh \
    && ./configure --enable-cuckoo --enable-magic --enable-dotnet \
    && make && make install && make check \
    && apt-get --purge autoremove -y git automake libtool make gcc \
    && apt-get clean \
    && rm -rf /yara /var/lib/apt/lists/* /var/cache/apt/archives /tmp/* /var/tmp/* 

COPY . /go/src/github.com/LiamHellend/malscan-plugin-yara
WORKDIR /go/src/github.com/LiamHellend/malscan-plugin-yara

ADD https://golang.org/dl/go1.15.7.linux-amd64.tar.gz .

RUN tar -C /usr/local -xzf go1.15.7.linux-amd64.tar.gz \
    && export PATH=$PATH:/usr/local/go/bin \
    && echo deb http://ftp.de.debian.org/debian stretch main >> /etc/apt/sources.list \ 
    && apt-get update -y \
    && apt-get install gccgo -y \
    && go build -o /bin/avscan .

WORKDIR /malware

ENTRYPOINT [ "/bin/avscan" ]
CMD ["--help"]
