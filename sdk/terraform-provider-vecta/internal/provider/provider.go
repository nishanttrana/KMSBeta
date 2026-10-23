// Package provider is the Vecta KMS Terraform provider: keys and their
// access assignments, through the Go SDK (sdk/go).
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nishanttrana/KMSBeta/sdk/go/vecta"
)

// New returns the provider factory providerserver.Serve takes.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &vectaProvider{version: version} }
}

type vectaProvider struct{ version string }

type providerModel struct {
	BaseURL  types.String `tfsdk:"base_url"`
	TenantID types.String `tfsdk:"tenant_id"`
	ClientID types.String `tfsdk:"client_id"`
	APIKey   types.String `tfsdk:"api_key"`
	Token    types.String `tfsdk:"token"`
	CAPEM    types.String `tfsdk:"ca_pem"`
}

func (p *vectaProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "vecta"
	resp.Version = p.version
}

func (p *vectaProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Vecta KMS keys and key access, as the REST client named here. The client needs a role with the key permissions it uses (docs/CI_CD_AUTOMATION.md).",
		Attributes: map[string]schema.Attribute{
			"base_url":  schema.StringAttribute{Optional: true, Description: "The KMS edge, https://<host>. Default: VECTA_URL."},
			"tenant_id": schema.StringAttribute{Optional: true, Description: "Default: VECTA_TENANT_ID."},
			"client_id": schema.StringAttribute{Optional: true, Description: "The REST client's registration ID. Default: VECTA_CLIENT_ID."},
			"api_key":   schema.StringAttribute{Optional: true, Sensitive: true, Description: "The REST client's API key. Default: VECTA_API_KEY."},
			"token":     schema.StringAttribute{Optional: true, Sensitive: true, Description: "A bearer token instead of client_id/api_key. Default: VECTA_TOKEN."},
			"ca_pem":    schema.StringAttribute{Optional: true, Description: "PEM of the KMS certificate's CA, when it is the KMS's own. Default: the file named by VECTA_CA_FILE."},
		},
	}
}

func orEnv(v types.String, env string) string {
	if !v.IsNull() && !v.IsUnknown() && v.ValueString() != "" {
		return v.ValueString()
	}
	return os.Getenv(env)
}

func (p *vectaProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	ca := []byte(orEnv(cfg.CAPEM, "VECTA_CA_PEM"))
	if len(ca) == 0 {
		if f := os.Getenv("VECTA_CA_FILE"); f != "" {
			raw, err := os.ReadFile(f)
			if err != nil {
				resp.Diagnostics.AddError("Can't read VECTA_CA_FILE", err.Error())
				return
			}
			ca = raw
		}
	}
	c, err := vecta.New(vecta.Config{
		BaseURL: orEnv(cfg.BaseURL, "VECTA_URL"), TenantID: orEnv(cfg.TenantID, "VECTA_TENANT_ID"),
		ClientID: orEnv(cfg.ClientID, "VECTA_CLIENT_ID"), APIKey: orEnv(cfg.APIKey, "VECTA_API_KEY"),
		Token: orEnv(cfg.Token, "VECTA_TOKEN"), CAPEM: ca,
	})
	if err != nil {
		resp.Diagnostics.AddError("Vecta KMS provider configuration", err.Error())
		return
	}
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *vectaProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{newKeyResource, newKeyAccessResource}
}

func (p *vectaProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newKeyDataSource}
}
