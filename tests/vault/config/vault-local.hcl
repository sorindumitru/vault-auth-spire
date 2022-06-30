storage "inmem" {
}

listener "tcp" {
  address = "127.0.0.1:8200"
  tls_cert_file = "/vault/config/server.crt"
  tls_key_file = "/vault/config/server.key"
}

api_addr = "https://127.0.0.1:8200"
plugin_directory = "/vault/plugins"
disable_mlock = true
