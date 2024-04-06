FROM alpine:3.10

LABEL maintainer "liamhellend@gmail.com"

RUN apk update
RUN apk add tini su-exec

RUN set -x \
    && echo "Creating malscan user and malware folder" \
    && addgroup malscan \ 
    && adduser -S -G malscan malscan \
    && mkdir /malware \
    && chown -R malscan:malscan /malware

RUN mkdir -p /var/log/malscan \
    && chown malscan /var/log/malscan

COPY eicar.com.txt /malware/EICAR



