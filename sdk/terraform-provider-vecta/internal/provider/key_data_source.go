package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nishanttrana/KMSBeta/sdk/go/vecta"
)

// data "vecta_key": a key the client can see, by ID.

type keyDataSource struct{ c *vecta.Client }

func newKeyDataSource() datasource.DataSource { return &keyDataSource{} }

func (d *keyDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_key"
}

func (d *keyDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	computed := func() schema.StringAttribute { return schema.StringAttribute{Computed: true} }
	resp.Schema = schema.Schema{
		Description: "A Vecta KMS key the client can see.",
		Attributes: map[string]schema.Attribute{
			"id":              schema.StringAttribute{Required: true},
			"name":            computed(),
			"algorithm":       computed(),
			"purpose":         computed(),
			"key_type":        computed(),
			"description":     computed(),
			"owner":           computed(),
			"labels":          schema.MapAttribute{Computed: true, ElementType: types.StringType},
			"tags":            schema.SetAttribute{Computed: true, ElementType: types.StringType},
			"current_version": schema.Int64Attribute{Computed: true},
			"kcv":             computed(),
			"status":          computed(),
		},
	}
}

func (d *keyDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData != nil {
		d.c = req.ProviderData.(*vecta.Client)
	}
}

func (d *keyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m keyModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	k, err := d.c.GetKey(ctx, m.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Reading the key", err.Error())
		return
	}
	resp.Diagnostics.Append(fill(ctx, &m, k)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// diagError turns diagnostics into an error for helpers that return one.
func diagError(d diag.Diagnostics) error {
	var msgs []string
	for _, e := range d.Errors() {
		msgs = append(msgs, e.Summary()+": "+e.Detail())
	}
	return errors.New(strings.Join(msgs, "; "))
}
