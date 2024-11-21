ARG NGINX_VERSION=1.16.1
ARG BITNAMI_NGINX_REVISION=r106
ARG BITNAMI_NGINX_TAG=${NGINX_VERSION}-debian-10-${BITNAMI_NGINX_REVISION}
ARG HEADER_MORE_VERSION=0.37
ARG VTS_VERSION=0.2.2
ARG GOIP2_VERSION=3.4
ARG SUBTITUTIONS_FILTER_VERSION=0.6.4

FROM bitnami/nginx:${BITNAMI_NGINX_TAG} AS builder
USER root
## Redeclare NGINX_VERSION so it can be used as a parameter inside this build stage
ARG NGINX_VERSION
ARG HEADER_MORE_VERSION
ARG VTS_VERSION
ARG GOIP2_VERSION
ARG SUBTITUTIONS_FILTER_VERSION
## Install required packages and build dependencies
RUN install_packages wget build-essential zip libpcre3-dev zlib1g-dev libssl-dev libmaxminddb-dev libgeoip-dev git \
    apt-utils autoconf automake libtool libcurl4-openssl-dev libgeoip-dev liblmdb-dev libpcre++-dev libxml2-dev libyajl-dev pkgconf
## Download NGINX, verify integrity and extract
RUN cd /tmp && \
    wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar xzf nginx-${NGINX_VERSION}.tar.gz
## Download and extract header-more module src
RUN cd /tmp/nginx-${NGINX_VERSION} && \
    wget https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v${HEADER_MORE_VERSION}.zip && \
    unzip v${HEADER_MORE_VERSION}.zip
## Download and extract vts module
RUN cd /tmp/nginx-${NGINX_VERSION} && \
    wget https://github.com/vozlt/nginx-module-vts/archive/refs/tags/v${VTS_VERSION}.zip && \
    unzip v${VTS_VERSION}.zip
## Download and extract goip2 module    
RUN cd /tmp/nginx-${NGINX_VERSION} && \
    wget https://github.com/leev/ngx_http_geoip2_module/archive/refs/tags/${GOIP2_VERSION}.zip && \
    unzip ${GOIP2_VERSION}.zip  
## Download and extract subtitutions filter module    
RUN cd /tmp/nginx-${NGINX_VERSION} && \
    wget https://github.com/yaoweibin/ngx_http_substitutions_filter_module/archive/refs/tags/v${SUBTITUTIONS_FILTER_VERSION}.zip && \
    unzip v${SUBTITUTIONS_FILTER_VERSION}.zip    
## Compile libmodsecurity for ModSecurity module
RUN git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity && \
    cd ModSecurity && \
    git submodule init && \
    git submodule update && \
    ./build.sh && \
    ./configure --with-maxmind=no && \
    make -j$(nproc --all) && \
    make install 
## Download Nginx connector for ModSecurity
RUN cd /tmp/nginx-${NGINX_VERSION} && git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git
## Compile NGINX with desired module
RUN cd /tmp/nginx-${NGINX_VERSION} && \
    rm -rf /opt/bitnami/nginx && \
    ./configure --prefix=/opt/bitnami/nginx --add-dynamic-module=headers-more-nginx-module-${HEADER_MORE_VERSION} \
    --with-http_ssl_module --with-http_stub_status_module --with-http_gzip_static_module --with-mail --with-http_realip_module \
    --with-http_v2_module --with-mail_ssl_module --with-http_gunzip_module --with-http_auth_request_module --with-http_sub_module \
    --with-http_geoip_module --add-module=nginx-module-vts-${VTS_VERSION} --add-dynamic-module=ngx_http_geoip2_module-${GOIP2_VERSION} \
    --add-module=ngx_http_substitutions_filter_module-${SUBTITUTIONS_FILTER_VERSION}  --add-dynamic-module=ModSecurity-nginx && \
    make -j$(nproc --all) && \
    make install

FROM bitnami/nginx:${BITNAMI_NGINX_TAG}
USER root

RUN install_packages libxml2 liblmdb0 libyajl2

COPY --from=builder /usr/local/modsecurity/lib/libmodsecurity.so.3.0.13 /usr/local/modsecurity/lib/libmodsecurity.so.3.0.13 
COPY --from=builder /usr/local/modsecurity/lib/libmodsecurity.so  /usr/local/modsecurity/lib/libmodsecurity.so
COPY --from=builder /usr/local/modsecurity/lib/libmodsecurity.so.3 /usr/local/modsecurity/lib/libmodsecurity.so.3

COPY --from=builder /opt/bitnami/nginx/modules/ngx_http_headers_more_filter_module.so /opt/bitnami/nginx/modules/ngx_http_headers_more_filter_module.so
COPY --from=builder /opt/bitnami/nginx/modules/ngx_http_modsecurity_module.so /opt/bitnami/nginx/modules/ngx_http_modsecurity_module.so

COPY --from=builder /opt/bitnami/nginx/sbin/nginx /opt/bitnami/nginx/sbin/nginx

USER 1001
