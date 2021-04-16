FROM ubuntu:16.04
ENTRYPOINT ["/root/run.sh"]

RUN apt-get -y update
RUN apt-get -y install curl openssl lbzip2 patch make gcc m4

RUN cd && curl -O https://factorable.net/fastgcd-1.0.tar.gz
RUN cd && tar xvzf fastgcd-1.0.tar.gz
COPY gmp-location.patch /root/
RUN cd ~/fastgcd && patch < ../gmp-location.patch && ./install.sh

COPY run.sh /root/
