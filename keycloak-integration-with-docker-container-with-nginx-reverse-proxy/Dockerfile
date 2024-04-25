FROM ubuntu:latest
RUN apt update && apt install nginx -y
RUN rm -rf etc/nginx/sites-enabled/default
COPY main.conf /etc/nginx/sites-enabled/main.conf
RUN mkdir -p /etc/nginx/ssl-certificate
COPY ca_bundle.crt /etc/nginx/ssl-certificate/ca_bundle.crt
COPY certificate.crt /etc/nginx/ssl-certificate/certificate.crt
COPY private.key /etc/nginx/ssl-certificate/private.key
RUN ln -sf /dev/stdout /var/log/nginx/dcm4che.januo.io.access.log \
        && ln -sf /var/log/nginx/dcm4che.januo.io.error.log 
EXPOSE 80 443
CMD ["nginx", "-g", "daemon off;"]
