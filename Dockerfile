FROM golang:1.20 as builder

WORKDIR /workdir
COPY . /workdir

RUN \
  make


FROM ubuntu:jammy

VOLUME "/data"
EXPOSE 8080

COPY --from=builder /workdir/bin/dnsadmin /usr/bin/
COPY --from=builder /workdir/www/ /var/www/html/

CMD ["/usr/bin/dnsadmin", "-data", "/data", "-www", "/var/www/html", "-address", "0.0.0.0:8080"]
