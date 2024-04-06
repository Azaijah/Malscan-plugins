# ****BUILD GOLANG AVSCAN APP***
FROM golang:1.13.3 as golang

COPY . /go/src/github.com/LiamHellend/malscan-plugin-clamav

WORKDIR /go/src/github.com/LiamHellend/malscan-plugin-clamav

RUN go build -o /bin/avscan .

# ***BUILD PLUGIN***
#Use the plugin base image
FROM malscan/alpine
LABEL maintainer "liamhellend@gmail.com"

#Do clamav plugin specific acitivies 

#Install clamav and update the clamav database
RUN echo "Installing clamav" \
    && apk add clamav \
    && freshclam

COPY --from=golang /bin/avscan /bin/avscan

WORKDIR /malware

ENTRYPOINT [ "/bin/avscan" ]
CMD ["--help"]
  
