# ****BUILD GOLANG AVSCAN APP***
FROM golang:1.13.3 as golang

COPY . /go/src/github.com/LiamHellend/malscan-plugin-sophos

WORKDIR /go/src/github.com/LiamHellend/malscan-plugin-sophos

RUN go build -o /bin/avscan .

# ***BUILD PLUGIN***
#Use the plugin base image
FROM malscan/ubuntu

LABEL maintainer "liamhellend@gmail.com"

#Sophos cannot be directly download 
COPY sav-linux-free-9.tgz /opt 

WORKDIR /opt

RUN echo "Installing sophos" \
    && tar xzvf sav-linux-free-9.tgz \
    && ./sophos-av/install.sh /opt/sophos --update-free --automatic --acceptlicence --autostart=False --enableOnBoot=False --ignore-existing-installation --update-source-type=s 

RUN echo "Updating sophos database" \
    && sh /opt/sophos/update/savupdate.sh

COPY --from=golang /bin/avscan /bin/avscan

WORKDIR /malware

ENTRYPOINT ["/usr/local/bin/tini", "-s" , "--", "/bin/avscan" ]
CMD [ "--help" ]

