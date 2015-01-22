# EXA BGP
#
# Vertion 3.4.5

FROM ubuntu:14.04

MAINTAINER Naoto Hanaue <hanaue.naoto@po.ntts.co.jp>

RUN apt-get update
RUN apt-get install -qy --no-install-recommends wget python

ENV HOME /root
WORKDIR /root

RUN wget --no-check-certificate https://github.com/Exa-Networks/exabgp/archive/3.4.5.tar.gz
RUN tar xzvf 3.4.5.tar.gz
RUN rm 3.4.5.tar.gz
RUN mv exabgp-3.4.5/ /usr/local/exabgp

ADD exabgp.env /usr/local/exabgp/etc/exabgp/exabgp.env