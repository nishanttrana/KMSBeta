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

ports {
  grpc = 8502
  dns = 8600
}

connect {
  enabled = true
}

telemetry {
  prometheus_retention_time = "24h"
  disable_hostname = true
}
