package consul

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/consul/api"
)

type Registrar struct {
	client    *api.Client
	serviceID string
	name      string
	address   string
	port      int
}

func NewRegistrar(address string, serviceID string, name string, host string, port int) (*Registrar, error) {
	cfg := api.DefaultConfig()
	cfg.Address = address
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	serviceHost := strings.TrimSpace(os.Getenv("CONSUL_SERVICE_ADDRESS"))
	if strings.Contains(serviceHost, "$") {
		serviceHost = strings.TrimSpace(os.ExpandEnv(serviceHost))
	}
	if strings.Contains(serviceHost, "$") {
		serviceHost = ""
	}
	if serviceHost == "" {
		serviceHost = host
	}
	return &Registrar{
		client:    client,
		serviceID: serviceID,
		name:      name,
		address:   serviceHost,
		port:      port,
	}, nil
}

func (r *Registrar) Register(_ context.Context) error {
	checkType := strings.ToLower(strings.TrimSpace(os.Getenv("CONSUL_HEALTH_CHECK_TYPE")))
	if checkType == "" {
		checkType = "grpc"
	}
	check := &api.AgentServiceCheck{
		Interval:                       "10s",
		DeregisterCriticalServiceAfter: "1m",
	}
	switch checkType {
	case "grpc":
		check.GRPC = fmt.Sprintf("%s:%d", r.address, r.port)
		check.GRPCUseTLS = envBool("CONSUL_GRPC_USE_TLS", false)
	case "tcp":
		check.TCP = fmt.Sprintf("%s:%d", r.address, r.port)
	default:
		check.GRPC = fmt.Sprintf("%s:%d", r.address, r.port)
	}

	return r.client.Agent().ServiceRegister(&api.AgentServiceRegistration{
		ID:      r.serviceID,
		Name:    r.name,
		Address: r.address,
		Port:    r.port,
		Check:   check,
	})
}

func (r *Registrar) Deregister(_ context.Context) error {
	return r.client.Agent().ServiceDeregister(r.serviceID)
}

func envBool(key string, d bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return d
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return d
	}
}
