FROM centos:7
WORKDIR /opt
ENV LANG=en_US.utf8

RUN export GOPROXY=https://goproxy.io \
    && yum install -y wget \
    && yum install -y gcc \
    && yum install -y make \
    && yum install -y git \
    && wget https://dl.google.com/go/go1.13.linux-amd64.tar.gz && tar -C /usr/local -xzf go1.13.linux-amd64.tar.gz \
    && export PATH=$PATH:/usr/local/go/bin && source /etc/profile\
    && rm -rf *.tar.gz \
    && git clone https://gitee.com/mingshitech-coconet/jumpserver-koko.git /opt \
    && cd /opt/ && make linux \
    && cd /opt/build \
    && mv kokodir/ /opt/koko/ \
    && rm -rf /usr/local/go \
    && export PATH=$PATH && source /etc/profile

RUN chmod 755 entrypoint.sh

CMD [ "./entrypoint.sh" ]
