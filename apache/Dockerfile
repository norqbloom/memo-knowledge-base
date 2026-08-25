FROM httpd:2.4-alpine

ENV TZ=Asia/Tokyo

RUN apk add --no-cache tzdata

COPY apache/httpd.conf /usr/local/apache2/conf/httpd.conf
COPY app/memo/static/ /usr/local/apache2/htdocs/static/
