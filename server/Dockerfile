FROM alpine:3.20

RUN apk add --no-cache python3 py3-pyserial openssl usb-modeswitch

COPY gtg_server /usr/lib/generic-text-gateway/gtg_server
COPY packaging/bin/gtg-server /usr/bin/gtg-server
RUN chmod +x /usr/bin/gtg-server

# Inside a container the loopback default is useless — bind all interfaces of the
# container; publish/limit exposure via compose. Override GTG_LISTEN as needed.
ENV GTG_LISTEN=0.0.0.0:8443 \
    GTG_DATA_DIR=/var/lib/generic-text-gateway

VOLUME /var/lib/generic-text-gateway
EXPOSE 8443

HEALTHCHECK --interval=60s --timeout=5s --start-period=30s \
  CMD wget -q -T 4 --no-check-certificate -O /dev/null https://127.0.0.1:8443/healthz || exit 1

ENTRYPOINT ["/usr/bin/gtg-server"]
CMD ["run"]
