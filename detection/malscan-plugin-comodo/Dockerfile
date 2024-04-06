# ****BUILD GOLANG AVSCAN APP***
FROM golang:1.13.3 as golang

COPY . /go/src/github.com/LiamHellend/malscan-plugin-comodo

WORKDIR /go/src/github.com/LiamHellend/malscan-plugin-comodo

RUN go build -o /bin/avscan .

# ***BUILD PLUGIN***
#Use the plugin base image
FROM malscan/ubuntu
LABEL maintainer "liamhellend@gmail.com"

#Do comodo plugin specific acitivies 

RUN echo "Installing dependencies" \
  && apt-get update -y \
  && apt-get install -y build-essential \
  && apt-get install -y libssl-dev \
  && apt-get install -y libfontconfig1 \
  && apt-get install -y libfreetype6 \
  && apt-get install -y ibglib2.0-0 \
  && apt-get install -y libice6 \
  && apt-get install -y libsm6 \
  && apt-get install -y libssl0.9.8 \
  && apt-get install -y libx11-6 \
  && apt-get install -y libxext6 \
  && apt-get install -y libxrender1 \
  && apt-get install -y wget 
  

WORKDIR /tmp

RUN  echo "Installing comodo" \
  && wget http://download.comodo.com/cis/download/installs/linux/cav-linux_x64.deb \
  && DEBIAN_FRONTEND=noninteractive dpkg -i cav-linux_x64.deb \
  && DEBIAN_FRONTEND=noninteractive /opt/COMODO/post_setup.sh 

RUN  echo "Updating comodo" 
#ADD http://download.comodo.com/av/updates58/sigs/bases/bases.cav /opt/COMODO/scanners/bases.cav

#use for testing only or if comodo download is not working (seems to happen often, unfortunately this issue is purely on comodo's side)
#This will likely cause some builds and updates to fail
COPY bases.cav /opt/COMODO/scanners/bases.cav 

COPY --from=golang /bin/avscan /bin/avscan

WORKDIR /malware

ENTRYPOINT ["/usr/local/bin/tini", "-s",  "--", "/bin/avscan" ]
CMD ["--help"]

