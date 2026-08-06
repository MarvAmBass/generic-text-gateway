FROM alpine:3.20

RUN apk add --no-cache python3

COPY gtg_client /usr/lib/generic-text-client/gtg_client
COPY packaging/bin/gtg-client /usr/bin/gtg-client
RUN chmod +x /usr/bin/gtg-client

# Inside a container the loopback default is useless — bind all interfaces of the
# container; with network_mode: host, override to localhost (see docker-compose.yml).
ENV GTC_LISTEN=0.0.0.0:8082 \
    GTC_STATE_DIR=/var/lib/generic-text-client

VOLUME /var/lib/generic-text-client
EXPOSE 8082

HEALTHCHECK --interval=60s --timeout=5s \
  CMD wget -q -T 4 -O /dev/null http://127.0.0.1:8082/healthz || exit 1

ENTRYPOINT ["/usr/bin/gtg-client"]
