ARG NGINX_VERSION=1.21.3


FROM debian:bullseye-slim as base_image
LABEL stage=builder
RUN apt-get update \
	&& apt-get install -y curl build-essential


FROM base_image as build_image
LABEL stage=builder
ENV LD_LIBRARY_PATH=/usr/local/lib
ARG NGINX_VERSION
ADD . /root/dl/nginx-cloudflare-jwt-checker
RUN set -x \
	&& apt-get update && apt-get upgrade -y \
	&& apt-get install -y libjwt-dev libjwt0 libjansson-dev libjansson4 libpcre2-dev zlib1g-dev libpcre3-dev libcurl4-openssl-dev libgnutls-openssl-dev libssl-dev \
	&& mkdir -p /root/dl
WORKDIR /root/dl
RUN set -x \
	&& curl -O http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz \
	&& tar -xzf nginx-$NGINX_VERSION.tar.gz \
	&& rm nginx-$NGINX_VERSION.tar.gz \
	&& ln -sf nginx-$NGINX_VERSION nginx \
	&& cd /root/dl/nginx \
	&& ./configure --with-compat --add-dynamic-module=../nginx-cloudflare-jwt-checker \
	&& make modules

FROM nginx:${NGINX_VERSION}
LABEL stage=builder
RUN mkdir /tmp/libs && cd /tmp/libs && apt-get update && apt-get -y -d -o dir::cache=`pwd` install libjansson4 libjwt0


LABEL stage=
COPY --from=build_image /root/dl/nginx/objs/ngx_http_jwt_cf_module.so /tmp/libs/