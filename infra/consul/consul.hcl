datacenter = "dc1"
data_dir = "/consul/data"
log_level = "INFO"

server = true
bootstrap_expect = 1
ui_config {
  enabled = true
}

bind_addr = "0.0.0.0"
client_addr = "0.0.0.0"

# Internal mTLS only (docs/SECURITY/INTERNAL_TLS.md): the HTTP API is served
# over HTTPS with a client certificate from the internal-services Sub CA.
# Plain HTTP, gRPC and DNS are off; Connect is not used.
ports {
  http     = -1
  https    = 8501
  grpc     = -1
  grpc_tls = -1
  dns      = -1
}

tls {
  defaults {
    ca_file         = "/etc/vecta-tls/internal-ca.crt"
    cert_file       = "/etc/vecta-tls/tls.crt"
    key_file        = "/etc/vecta-tls/tls.key"
    verify_incoming = true
    verify_outgoing = true
    tls_min_version = "TLSv1_3"
  }
  internal_rpc {
    verify_server_hostname = false
  }
}

connect {
  enabled = false
}

telemetry {
  prometheus_retention_time = "24h"
  disable_hostname = true
}
