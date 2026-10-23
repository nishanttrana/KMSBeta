// Command terraform-provider-vecta is the Terraform provider for Vecta KMS:
// keys and their access assignments as code (docs/TERRAFORM.md).
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/nishanttrana/KMSBeta/sdk/terraform-provider-vecta/internal/provider"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	debug := flag.Bool("debug", false, "run with support for debuggers like delve")
	flag.Parse()
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/nishanttrana/vecta",
		Debug:   *debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
