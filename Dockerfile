FROM debian:jessie-slim
MAINTAINER Aloys Augustin <aloys@scalr.com>

RUN apt-get update && \
    apt-get install -y nginx supervisor uwsgi python-pip uwsgi-plugin-python && \
    mkdir -p /var/log/supervisor && \
    mkdir /run/uwsgi && \
    (useradd nginx || true) && \
    (groupadd nginx || true)

ADD . /opt/webhook/

RUN cd /opt/webhook/ && \
    pip install -r requirements.txt && \
    cp config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf && \
    cp config/nginx.conf /etc/nginx/nginx.conf

EXPOSE 5000
CMD ["/usr/bin/supervisord"]
