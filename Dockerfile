FROM nginx:latest
RUN apt-get update && apt-get install -y wget && apt-get install -y build-essential libssl-dev
WORKDIR /tmp
RUN wget https://www.openssl.org/source/openssl-1.1.1k.tar.gz && tar -xf openssl-1.1.1k.tar.gz && cd openssl-1.1.1k && \
    ./config && make -j$(nproc) && make install
RUN apt-get install -y git
RUN git clone https://github.com/openresty/luajit2.git && cd luajit2 && make -j$(nproc) && make install
RUN rm -rf /tmp/*
CMD ["nginx", "-g", "daemon off;"]