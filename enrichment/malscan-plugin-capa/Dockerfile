# ****BUILD GOLANG AVSCAN APP***
FROM golang:1.13.3 as golang

COPY . /go/src/github.com/LiamHellend/malscan-plugin-capa

WORKDIR /go/src/github.com/LiamHellend/malscan-plugin-capa

RUN go build -o /bin/avscan .

# ***BUILD PLUGIN***
#Use the plugin base image
FROM malscan/ubuntu
LABEL maintainer "liamhellend@gmail.com"

#Do floss plugin specific acitivies 

ADD https://github.com/fireeye/capa/releases/download/v1.4.1/capa-v1.4.1-linux.zip /opt/capa.zip

WORKDIR /opt

#Install floss 
RUN echo "Installing capa" \
    && apt-get install -y zip  \
    && unzip capa.zip \
    && rm -rf capa.zip

COPY --from=golang /bin/avscan /bin/avscan

COPY wannacry /malware/wannacry

WORKDIR /malware

ENTRYPOINT [ "/bin/avscan" ]
CMD ["--help"]
  
