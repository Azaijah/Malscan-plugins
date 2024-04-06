# ****BUILD GOLANG AVSCAN APP***
FROM golang:1.13.3 as golang

COPY . /go/src/github.com/LiamHellend/malscan-plugin-manalyze

WORKDIR /go/src/github.com/LiamHellend/malscan-plugin-manalyze

RUN CGO_ENABLED=0 go build -o /bin/avscan .

# ***BUILD PLUGIN***
#Use the plugin base image
FROM malscan/alpine

LABEL maintainer "liamhellend@gmail.com"


#Do manalyze plugin specific acitivies 

WORKDIR /opt

RUN echo "Installing dependencies" \
    && apk add boost-dev \
    && apk add boost-regex \
    && apk add boost-program_options \
    && apk add openssl-dev \
    && apk add build-base \
    && apk add cmake \
    && apk add git

RUN echo "Building manalyze from manalyze repo" \
    && git clone https://github.com/JusticeRage/Manalyze.git \
    && cd Manalyze \
    && cmake . \
    && make 

COPY --from=golang /bin/avscan /bin/avscan

#COPY testmal /malware

WORKDIR /malware

ENTRYPOINT [ "/bin/avscan" ]
CMD ["--help"]


