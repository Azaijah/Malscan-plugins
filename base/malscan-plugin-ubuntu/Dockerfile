FROM krallin/ubuntu-tini:trusty

LABEL maintainer "liamhellend@gmail.com"

RUN apt-get update && apt-get upgrade -y

RUN set -x \
    && echo "Creating malscan user and malware folder" \
    && groupadd malscan \ 
    && useradd -r -g malscan malscan \
    && mkdir /malware \
    && chown -R malscan:malscan /malware

RUN mkdir -p /var/log/malscan \
    && chown malscan /var/log/malscan

COPY eicar.com.txt /malware/EICAR




