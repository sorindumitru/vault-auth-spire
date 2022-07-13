FROM gcr.io/spiffe-io/spire-agent:1.3.2 as spire-agent

FROM docker.io/vault:1.11.0

COPY --from=spire-agent /opt/spire/bin/spire-agent /opt/spire/bin/
COPY agent.conf /opt/spire/conf/agent/
COPY agent-ca.crt /opt/spire/conf/agent/
COPY agent-ca.key /opt/spire/conf/agent/

COPY --chown=vault config/* /vault/config/
COPY supervisord.conf /opt/supervisord/

RUN apk --no-cache add supervisor

ENV VAULT_ADDR="https://127.0.0.1:8200" \
    VAULT_CACRT="/vault/config/ca.crt" \
    SPIFFE_ENDPOINT_SOCKET="unix:///tmp/spire-agent/public/api.sock"

ENTRYPOINT ["/usr/bin/dumb-init", "supervisord", "--nodaemon", "--configuration", "/opt/supervisord/supervisord.conf"]
CMD []
