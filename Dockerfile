FROM centos:7
WORKDIR /opt
ENV LANG=en_US.utf8

RUN mkdir baoleiji-koko
COPY . baoleiji-koko/
COPY entrypoint.sh .

RUN export GOPROXY=https://goproxy.io \
    && yum install -y wget gcc make \
    && wget https://dl.google.com/go/go1.13.linux-amd64.tar.gz && tar -C /usr/local -xzf go1.13.linux-amd64.tar.gz \
    && export PATH=$PATH:/usr/local/go/bin && source /etc/profile\
    && rm -rf *.tar.gz \
    && cd /opt/baoleiji-koko/ && make linux \
    && cd /opt/baoleiji-koko/build \
    && mv kokodir/ /opt/koko/ \
    && rm -rf /usr/local/go \
    && export PATH=$PATH && source /etc/profile

RUN chmod 755 entrypoint.sh

CMD [ "./entrypoint.sh" ]
