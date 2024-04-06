# ****BUILD GOLANG AVSCAN APP***
FROM golang:1.13.3 as golang

COPY . /go/src/github.com/LiamHellend/malscan-plugin-floss

WORKDIR /go/src/github.com/LiamHellend/malscan-plugin-floss

RUN go build -o /bin/avscan .

# ***BUILD PLUGIN***
#Use the plugin base image
FROM malscan/ubuntu
LABEL maintainer "liamhellend@gmail.com"

#Do floss plugin specific acitivies 

#Install floss 
RUN echo "Installing floss" \
    && apt-get install -y wget \
    && cd /opt \
    && wget https://s3.amazonaws.com/build-artifacts.floss.flare.fireeye.com/travis/linux/dist/floss \
    && chmod +x floss

COPY --from=golang /bin/avscan /bin/avscan

WORKDIR /malware

ENTRYPOINT [ "/bin/avscan" ]
CMD ["--help"]
  
