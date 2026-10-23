package provider

import (
	"context"
	"fmt"
	"maps"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nishanttrana/KMSBeta/sdk/go/vecta"
)

// vecta_key: a key in the KMS. Its material never leaves the KMS and never
// enters Terraform state. Destroying the resource deactivates the key (no
// new encryption or signing; existing ciphertext still decrypts): Terraform
// never destroys key material. Destroy a key in the KMS itself, with its
// confirmations.

type keyResource struct{ c *vecta.Client }

func newKeyResource() resource.Resource { return &keyResource{} }

type keyModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	Algorithm      types.String `tfsdk:"algorithm"`
	Purpose        types.String `tfsdk:"purpose"`
	KeyType        types.String `tfsdk:"key_type"`
	Description    types.String `tfsdk:"description"`
	Owner          types.String `tfsdk:"owner"`
	Labels         types.Map    `tfsdk:"labels"`
	Tags           types.Set    `tfsdk:"tags"`
	CurrentVersion types.Int64  `tfsdk:"current_version"`
	KCV            types.String `tfsdk:"kcv"`
	Status         types.String `tfsdk:"status"`
}

func (r *keyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_key"
}

func keyComputedString(desc string) schema.StringAttribute {
	return schema.StringAttribute{Computed: true, Description: desc, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}}
}

func (r *keyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		Description: "A Vecta KMS key. Destroying it deactivates the key; key material is never destroyed by Terraform.",
		Attributes: map[string]schema.Attribute{
			"id":              keyComputedString("The key's ID."),
			"name":            schema.StringAttribute{Required: true},
			"algorithm":       schema.StringAttribute{Required: true, PlanModifiers: replace, Description: "For example AES-256, ECDSA-P256, RSA-3072."},
			"purpose":         schema.StringAttribute{Required: true, Description: "encrypt, sign, wrap, mac or derive."},
			"key_type":        schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace(), stringplanmodifier.UseStateForUnknown()}, Description: "symmetric or asymmetric; inferred from the algorithm when unset."},
			"description":     schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"owner":           schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"labels":          schema.MapAttribute{Optional: true, Computed: true, ElementType: types.StringType, Description: "The tenant's metadata profiles may require labels or fill defaults."},
			"tags":            schema.SetAttribute{Optional: true, Computed: true, ElementType: types.StringType},
			"current_version": schema.Int64Attribute{Computed: true, PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()}},
			"kcv":             keyComputedString("The key check value of the current version."),
			"status":          schema.StringAttribute{Computed: true},
		},
	}
}

func (r *keyResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.c = req.ProviderData.(*vecta.Client)
	}
}

// fill copies the key as the KMS stores it into the model.
func fill(ctx context.Context, m *keyModel, k vecta.Key) diag.Diagnostics {
	var diags diag.Diagnostics
	m.ID, m.Name, m.Algorithm, m.Purpose = types.StringValue(k.ID), types.StringValue(k.Name), types.StringValue(k.Algorithm), types.StringValue(k.Purpose)
	m.KeyType, m.Description, m.Owner = types.StringValue(k.KeyType), types.StringValue(k.Description), types.StringValue(k.Owner)
	m.CurrentVersion, m.KCV, m.Status = types.Int64Value(int64(k.CurrentVersion)), types.StringValue(k.KCV), types.StringValue(k.Status)
	labels := map[string]attr.Value{}
	for name, v := range k.Labels {
		labels[name] = types.StringValue(v)
	}
	lv, d := types.MapValue(types.StringType, labels)
	diags.Append(d...)
	m.Labels = lv
	tags := []attr.Value{}
	for _, t := range k.Tags {
		tags = append(tags, types.StringValue(t))
	}
	tv, d := types.SetValue(types.StringType, tags)
	diags.Append(d...)
	m.Tags = tv
	return diags
}

func stringMap(ctx context.Context, m types.Map) (map[string]string, diag.Diagnostics) {
	out := map[string]string{}
	if m.IsNull() || m.IsUnknown() {
		return out, nil
	}
	diags := m.ElementsAs(ctx, &out, false)
	return out, diags
}

func stringSet(ctx context.Context, s types.Set) ([]string, diag.Diagnostics) {
	out := []string{}
	if s.IsNull() || s.IsUnknown() {
		return out, nil
	}
	diags := s.ElementsAs(ctx, &out, false)
	return out, diags
}

// profileChangedLabels explains, in place of Terraform's "inconsistent
// result" error, a key whose labels the tenant's metadata profiles changed
// from the configured ones (a default label filled in).
func profileChangedLabels(planned types.Map, k vecta.Key) diag.Diagnostics {
	var diags diag.Diagnostics
	if planned.IsNull() || planned.IsUnknown() {
		return diags
	}
	want := map[string]string{}
	if d := planned.ElementsAs(context.Background(), &want, false); d.HasError() {
		return d
	}
	if maps.Equal(want, k.Labels) || (len(want) == 0 && len(k.Labels) == 0) {
		return diags
	}
	diags.AddError("The tenant's metadata profile changed the key's labels",
		fmt.Sprintf("The KMS stored labels %v for %s. Put them in the configuration (or leave labels unset), then run terraform untaint on the key so it is kept rather than replaced.", k.Labels, k.ID))
	return diags
}

func known(v types.String) bool { return !v.IsNull() && !v.IsUnknown() }

func (r *keyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan keyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	labels, d := stringMap(ctx, plan.Labels)
	resp.Diagnostics.Append(d...)
	tags, d := stringSet(ctx, plan.Tags)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := vecta.CreateKeyInput{Name: plan.Name.ValueString(), Algorithm: plan.Algorithm.ValueString(), Purpose: plan.Purpose.ValueString(), Labels: labels, Tags: tags}
	if known(plan.KeyType) {
		in.KeyType = plan.KeyType.ValueString()
	}
	if known(plan.Description) {
		in.Description = plan.Description.ValueString()
	}
	if known(plan.Owner) {
		in.Owner = plan.Owner.ValueString()
	}
	id, err := r.c.CreateKey(ctx, in)
	if err != nil {
		resp.Diagnostics.AddError("Creating the key", err.Error())
		return
	}
	k, err := r.c.GetKey(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Reading the created key", err.Error())
		return
	}
	resp.Diagnostics.Append(profileChangedLabels(plan.Labels, k)...)
	resp.Diagnostics.Append(fill(ctx, &plan, k)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *keyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state keyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	k, err := r.c.GetKey(ctx, state.ID.ValueString())
	if vecta.IsNotFound(err) {
		// Gone, or no longer visible to this client: plan it again.
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading the key", err.Error())
		return
	}
	resp.Diagnostics.Append(fill(ctx, &state, k)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *keyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state keyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Only what changed is sent (PATCH): metadata Terraform doesn't manage
	// stays as stored.
	var u vecta.KeyUpdate
	str := func(p, s types.String) *string {
		if known(p) && p.ValueString() != s.ValueString() {
			v := p.ValueString()
			return &v
		}
		return nil
	}
	u.Name, u.Purpose, u.Description, u.Owner = str(plan.Name, state.Name), str(plan.Purpose, state.Purpose), str(plan.Description, state.Description), str(plan.Owner, state.Owner)
	if !plan.Labels.IsUnknown() && !plan.Labels.Equal(state.Labels) {
		labels, d := stringMap(ctx, plan.Labels)
		resp.Diagnostics.Append(d...)
		u.Labels = &labels
	}
	if !plan.Tags.IsUnknown() && !plan.Tags.Equal(state.Tags) {
		tags, d := stringSet(ctx, plan.Tags)
		resp.Diagnostics.Append(d...)
		u.Tags = &tags
	}
	if resp.Diagnostics.HasError() {
		return
	}
	k, err := r.c.UpdateKey(ctx, state.ID.ValueString(), u)
	if err != nil {
		resp.Diagnostics.AddError("Updating the key", err.Error())
		return
	}
	resp.Diagnostics.Append(profileChangedLabels(plan.Labels, k)...)
	resp.Diagnostics.Append(fill(ctx, &plan, k)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *keyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state keyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	k, err := r.c.GetKey(ctx, id)
	if vecta.IsNotFound(err) {
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading the key before deactivating it", err.Error())
		return
	}
	switch k.Status {
	case "deactivated", "compromised", "destroy-pending", "deleted":
		// Already out of use: nothing to do. Any other refusal (a protected
		// system key, a policy) is an error, never a quiet success.
	default:
		if err := r.c.DeactivateKey(ctx, id); err != nil {
			resp.Diagnostics.AddError("Deactivating the key", err.Error())
			return
		}
	}
	resp.Diagnostics.AddWarning("The key was deactivated, not destroyed",
		"Terraform never destroys key material: data encrypted under "+id+" still decrypts. Destroy the key in the KMS when nothing needs it.")
}

func (r *keyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
