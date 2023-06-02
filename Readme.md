###### 目前有场景需要对用户端进行客户端证书鉴权，第三方对应的浏览器需要导入证书，否则就会报400错误，只有当校验成功后才能往下进行反向代理，此处就不强调如何生成证书和对应的LUA脚本实现，只简单概括对Nginx的编译，和Nginx的简单配置校验证书合法性。
 ### 一. [Nginx配置](#jump_nginx_conf)
 ### 二. [Centos下Nginx编译](#build_nginx_centos)
### 三. [Nginx编译成docker镜像](#build_nginx_docker)
<a id="jump_nginx_conf"></a>
## nginx校验客户端证书配置，点击展开
<details>
  <summary>**此处只简单校验， 高阶校验可使用lua脚本实现，此处不做说明**</summary>
  <p> - 测试 测试测试</p>
  <pre><code>
http {
  # lua_package_path "/root/nginx-lua-0.6.0/?.lua;;";
    include       mime.types;
    default_type  application/octet-stream;
    #lua_package_path "/usr/local/nginx/verify/?.lua;;";  # 指定 Lua 脚本文件路径
    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';
    #lua_package_path '/root/skywalking-nginx-lua-0.6.0/?.lua;;';
    #init_by_lua_block {
    #   local sw = require "skywalking"
    #  sw.start()
    #}
    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;
  server {
    listen 443 ssl;
    server_name 192.168.37.139;
    ssl_certificate /usr/local/nginx/certificate/your_certificate.pem;
    ssl_certificate_key /usr/local/nginx/certificate/your_private_key.pem;
    ssl_client_certificate  /usr/local/nginx/certificate/ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;
       # 验证客户端证书的方法
    # 1. 验证证书是否由指定的 CA 签发
    # 2. 验证证书的公共名称是否与指定的名称匹配
    # 3. 验证证书是否在有效期内
    # 4. 验证证书的扩展属性是否满足要求
    # 5. 验证证书的 CRL 列表
    #ssl_verify_client_optional on;
    #ssl_client_certificate /path/to/client.crt;
    # ssl_crl /path/to/crl.pem;

    # 调用 Lua 脚本验证客户端证书
    # access_by_lua /usr/local/nginx/verify/verify_client_cert.lua;
    # 指定 SSL/TLS 协议和加密算法
    ssl_protocols TLSv1.2;
    ssl_ciphers HIGH:!aNULL:!MD5;
    location / {
#access_by_lua '
#local verify = require "verify_client_cert"
#verify.verify_cert()
#';
        proxy_pass https://192.168.37.1:8834;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_ssl_verify off;
        proxy_ssl_session_reuse on;
      # 解析证书信息
	proxy_set_header X-SSL-Client-S-DN $ssl_client_s_dn;
      # 解析状态
        proxy_set_header X-CLIENT-VERIFY $ssl_client_verify;
	# 关键参数：这个变量开启后,才能自定义错误页面，当后端返回404，nginx拦截错误定义错误页面
	proxy_intercept_errors on;

    }
}



}</code></pre>
</details>

<a id="build_nginx_centos"></a>
##  Centos环境下编译
### 1.先从官网下载Nginx源码：[官网](http://nginx.org/en/)

下载好之后把文件上传到centos下，我下载的是这个“nginx-1.20.1.tar.gz”。

![nginxpath.png](./_resources/nginxpath.png)
### 2.获取LuaJIT、lua-nginx-module、ngx_devel_kit源码文件
```
wget http://luajit.org/download/LuaJIT-2.1.0-beta3.tar.gz
wget https://github.com/simpl/ngx_devel_kit/archive/v0.3.0.tar.gz
wget https://github.com/openresty/lua-nginx-module/archive/v0.10.13.tar.gz
```
### 3.创建放置源码目录与nginx目录
```
mkdir /opt/makecode
mkdir /etc/nginx
```
### 4.解压源码文件
```
tar xvf LuaJIT-2.1.0-beta3.tar.gz -C /opt/
tar xvf nginx-1.17.5.tar.gz -C /opt/
tar xvf v0.10.13.tar.gz -C /opt/
tar xvf v0.3.0.tar.gz -C /opt/
```

### 5.切换目录并对解压目录改名
```
cd /opt
mv nginx-1.17.5/ /opt/nginx 
mv LuaJIT-2.1.0-beta3/ /opt/luaJIT 
mv lua-nginx-module-0.10.13/ /etc/nginx/lua-nginx-module
mv ngx_devel_kit-0.3.0/ /etc/nginx/ngx_devel_kit
```
### 6.编译LuaJIT
```
cd /opt/luaJIT 
make PREFIX=/opt/luajit
make install PREFIX=/opt/luajit
```

### 7.安装Nginx编译环境
```
yum -y install gcc automake autoconf libtool make
yum -y install gcc-c++
yum -y install zlib zlib-devel openssl openssl-devel pcre pcre-devel
```
### 8.编译安装nginx
#### 安装的模块要注意路径问题，否则会找不到模块导致失败
```
cd /opt/nginx 
./configure --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --http-client-body-temp-path=/var/cache/nginx/client_temp --http-proxy-temp-path=/var/cache/nginx/proxy_temp --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp --http-scgi-temp-path=/var/cache/nginx/scgi_temp --user=nginx --group=nginx --with-compat --with-file-aio --with-threads --with-http_addition_module --with-http_auth_request_module --with-http_dav_module --with-http_flv_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_mp4_module --with-http_random_index_module --with-http_realip_module --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module --with-http_stub_status_module --with-http_sub_module --with-http_v2_module --with-mail --with-mail_ssl_module --with-stream --with-stream_realip_module --with-stream_ssl_module --with-stream_ssl_preread_module --with-cc-opt='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -m64 -mtune=generic -fPIC' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -pie' --add-module=/etc/nginx/lua-nginx-module --add-module=/etc/nginx/ngx_devel_kit
```
```
make -j2
make install 
```
### 9.查看Nginx编译结果
```nginx -V```


![nginxbuild.png](./_resources/nginxbuild.png)


#### 注意nginx -V区分大小写，大写的V才能查看编译了什么

<a id="build_nginx_centos"></a>
## 编译Nginx成Docker
``` 
Dockerfile

FROM nginx:latest
RUN apt-get update && apt-get install -y wget && apt-get install -y build-essential libssl-dev
WORKDIR /tmp
RUN wget https://www.openssl.org/source/openssl-1.1.1k.tar.gz && tar -xf openssl-1.1.1k.tar.gz && cd openssl-1.1.1k && \
    ./config && make -j$(nproc) && make install
RUN apt-get install -y git
RUN git clone https://github.com/openresty/luajit2.git && cd luajit2 && make -j$(nproc) && make install
RUN rm -rf /tmp/*
CMD ["nginx", "-g", "daemon off;"]
```
#### 编译过程中可能遇到网络失败情况，可以使用已经编译好的镜像
[github](https://)
