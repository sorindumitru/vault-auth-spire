#!/usr/bin/env bats

server_run() {
    docker-compose exec spire-server /opt/spire/bin/spire-server "$@"
}

vault_run() {
    if [[ "$1" == "--token" ]]; then
      
        local VAULT_TOKEN="$2"
        shift 2
        docker-compose exec -T --env VAULT_TOKEN=${VAULT_TOKEN} vault vault "$@"
    else
        docker-compose exec -T vault vault "$@"
    fi
}

vault_root_run() {
    docker-compose exec -T --env VAULT_TOKEN=${VAULT_ROOT_TOKEN} vault vault "$@"
}

wait_for_server() {
    elapsed_time=0
    until server_run healthcheck &>/dev/null; do
        sleep 1
        if (( ++elapsed_time >= 15 )); then
            echo "Timed out waiting for spire-server to be healthy"
            exit 1
        fi
    done
}

register_spire_agent() {
    local agent_ca_fingerprint=$(openssl x509 -in spire-agent/agent-ca.crt -outform DER | openssl sha1 -r | awk '{print $1}')
    local x509pop_selector="x509pop:ca:fingerprint:${agent_ca_fingerprint}"

    server_run entry create -node -spiffeID "spiffe://example.com/agent" -selector "${x509pop_selector}"
}

unseal_vault() {
    sleep 3
    initoutput=$(vault_run operator init -key-shares=1 -key-threshold=1 -format=json)
    vault_run operator unseal $(echo "$initoutput" | jq -r .unseal_keys_hex[0])
    export VAULT_ROOT_TOKEN=$(echo "${initoutput}" | jq -r .root_token)
}

setup_file() {
    docker-compose down -v
    docker-compose build
    docker-compose up -d spire-server
    wait_for_server

    docker-compose exec spire-server sh -c "/opt/spire/bin/spire-server bundle show -format=spiffe > /runtime/example.com"

    docker-compose up -d vault
    unseal_vault

    vault_root_run secrets enable -version=2 kv
    vault_root_run policy write spiffe-policy -<<EOF
path "kv/data/secret/*" {
  capabilities = ["read", "update", "create"]
}
EOF
}

teardown_file() {
    docker-compose down -v
}

@test "Enable plugin" {
    vault_root_run plugin register -sha256="$(shasum -a 256 '../vault-auth-spire' | cut -d' ' -f1)" -args="--settings-file=/vault/config/vault-auth-spire.json" -command="vault-auth-spire" auth spire
    vault_root_run auth enable -path="spire" spire
}

@test "Login with X509-SVID" {
    server_run x509 mint -spiffeID "spiffe://example.com/vault/user" -write /runtime
    run vault_run write -client-cert=/runtime/svid.pem -client-key=/runtime/key.pem -force auth/spire/login
    [ "$status" -eq 0 ]
}

@test "Login with wrong X509-SVID key" {
    server_run x509 mint -spiffeID "spiffe://example.com/vault/user" -write /runtime
    run vault_run write -client-cert=/runtime/svid.pem -client-key=/vault/config/ca.key -force auth/spire/login
    [ "$status" -ne 0 ]
}

@test "Login with non X509-SVID certificate" {
    server_run x509 mint -spiffeID "spiffe://example.com/vault/user" -write /runtime
    run vault_run write -client-cert=/vault/config/server.crt -client-key=/vault/config/server.key -force auth/spire/login
    [ "$status" -ne 0 ]
}

@test "X509-SVID: can write own secret" {
    server_run x509 mint -spiffeID "spiffe://example.com/vault/user" -write /runtime
    TOKEN=$(vault_run write -client-cert=/runtime/svid.pem -client-key=/runtime/key.pem -format=json -force auth/spire/login | jq -r .auth.client_token)
    vault_run --token "${TOKEN}" kv put -mount=kv secret/test value=test
}

@test "X509-SVID: can not write other secret" {
    server_run x509 mint -spiffeID "spiffe://example.com/vault/user" -write /runtime
    TOKEN=$(vault_run write -client-cert=/runtime/svid.pem -client-key=/runtime/key.pem -format=json -force auth/spire/login | jq -r .auth.client_token)
    run vault_run --token "${TOKEN}" kv put -mount=kv not-my-secret/test value=test
    [ "$status" -ne 0 ]
}

@test "Login with JWT-SVID" {
    JWTSVID=$(server_run jwt mint -spiffeID "spiffe://example.com/vault/user" -audience "vault")
    run vault_run write auth/spire/login jwt-svid="${JWTSVID}"
    [ "$status" -eq 0 ]
}

@test "JWT-SVID: can write own secret" {
    JWTSVID=$(server_run jwt mint -spiffeID "spiffe://example.com/vault/user" -audience "vault")
    TOKEN=$(vault_run write -format=json auth/spire/login jwt-svid="${JWTSVID}" | jq -r .auth.client_token)
    vault_run --token "${TOKEN}" kv put -mount=kv secret/test value=test
}

@test "JWT-SVID: can not write other secret" {
    JWTSVID=$(server_run jwt mint -spiffeID "spiffe://example.com/vault/user" -audience "vault")
    TOKEN=$(vault_run write -format=json auth/spire/login jwt-svid="${JWTSVID}" | jq -r .auth.client_token)
    run vault_run --token "${TOKEN}" kv put -mount=kv not-my-secret/test value=test
    [ "$status" -ne 0 ]
}
