# ****BUILD GOLANG AVSCAN APP***
FROM golang:1.13.3 as golang

COPY . /go/src/github.com/LiamHellend/malscan-plugin-fsecure

WORKDIR /go/src/github.com/LiamHellend/malscan-plugin-fsecure

RUN go build -o /bin/avscan .

# ***BUILD PLUGIN***
#Use the plugin base image
FROM malscan/ubuntu
LABEL maintainer "liamhellend@gmail.com"

#Do fsecure plugin specific acitivies 

WORKDIR /tmp

ENV FSECURE_VERSION_PARTIAL 11.10
ENV FSECURE_VERSION_FULL 11.10.68

RUN echo "===> Installing F-Secure" \
  && buildDeps='wget rpm' \
  && apt-get update -qq \
  && apt-get install -yq $buildDeps lib32stdc++6 psmisc \
  && echo "===> Install F-Secure..." \
  && wget -q https://download.f-secure.com/corpro/ls/ls${FSECURE_VERSION_PARTIAL}/fsls-${FSECURE_VERSION_FULL}-rtm.tar.gz \
  && tar zxvf fsls-${FSECURE_VERSION_FULL}-rtm.tar.gz \
  && cd fsls-${FSECURE_VERSION_FULL}-rtm \
  && chmod a+x fsls-${FSECURE_VERSION_FULL} \
  && ./fsls-${FSECURE_VERSION_FULL} --auto standalone lang=en --command-line-only \
  && fsav --version

RUN echo "===> Updating F-Secure" \
  && cd /tmp \
  && wget -q http://download.f-secure.com/latest/fsdbupdate9.run \
  && mv fsdbupdate9.run /opt/f-secure/ 

RUN echo "===> Removing files not required" \
  && apt-get purge -y --auto-remove $buildDeps && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.gnupg

RUN echo "===> Updating F-Secure Database" \
  && mkdir -p /opt/malscan \
  && /etc/init.d/fsaua start \
  && /etc/init.d/fsupdate start \
  && /opt/f-secure/fsav/bin/dbupdate /opt/f-secure/fsdbupdate9.run; exit 0

COPY update.sh /opt/malscan/update
COPY --from=golang /bin/avscan /bin/avscan

WORKDIR /malware

ENTRYPOINT ["/usr/local/bin/tini", "--", "/bin/avscan" ]
CMD ["--help"]
  
