package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nishanttrana/KMSBeta/sdk/go/vecta"
)

// vecta_key_access: a key's access assignments, all of them. The resource
// owns the key's grant list: grants made outside it are replaced on the
// next apply, and destroying it removes every grant.

type keyAccessResource struct{ c *vecta.Client }

func newKeyAccessResource() resource.Resource { return &keyAccessResource{} }

type grantModel struct {
	SubjectType types.String `tfsdk:"subject_type"`
	SubjectID   types.String `tfsdk:"subject_id"`
	Operations  types.Set    `tfsdk:"operations"`
}

type keyAccessModel struct {
	ID    types.String `tfsdk:"id"`
	KeyID types.String `tfsdk:"key_id"`
	Grant types.Set    `tfsdk:"grant"`
}

var grantAttrTypes = map[string]attr.Type{
	"subject_type": types.StringType,
	"subject_id":   types.StringType,
	"operations":   types.SetType{ElemType: types.StringType},
}

func (r *keyAccessResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_key_access"
}

func (r *keyAccessResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Every access assignment of one key. Grants made outside Terraform are replaced; destroying this removes them all.",
		Attributes: map[string]schema.Attribute{
			"id":     schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"key_id": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"grant": schema.SetNestedAttribute{
				Required: true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"subject_type": schema.StringAttribute{Required: true, Description: "user, group or client (a REST client's registration ID)."},
					"subject_id":   schema.StringAttribute{Required: true},
					"operations":   schema.SetAttribute{Required: true, ElementType: types.StringType, Description: "For example encrypt, decrypt, sign, verify, wrap, unwrap, read, all."},
				}},
			},
		},
	}
}

func (r *keyAccessResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.c = req.ProviderData.(*vecta.Client)
	}
}

func (m keyAccessModel) grants(ctx context.Context) ([]vecta.Grant, error) {
	var gs []grantModel
	if d := m.Grant.ElementsAs(ctx, &gs, false); d.HasError() {
		return nil, diagError(d)
	}
	out := make([]vecta.Grant, 0, len(gs))
	for _, g := range gs {
		ops, d := stringSet(ctx, g.Operations)
		if d.HasError() {
			return nil, diagError(d)
		}
		out = append(out, vecta.Grant{SubjectType: g.SubjectType.ValueString(), SubjectID: g.SubjectID.ValueString(), Operations: ops})
	}
	return out, nil
}

func grantSet(gs []vecta.Grant) (types.Set, error) {
	objs := []attr.Value{}
	for _, g := range gs {
		ops := []attr.Value{}
		for _, o := range g.Operations {
			ops = append(ops, types.StringValue(o))
		}
		opSet, d := types.SetValue(types.StringType, ops)
		if d.HasError() {
			return types.Set{}, diagError(d)
		}
		obj, d := types.ObjectValue(grantAttrTypes, map[string]attr.Value{
			"subject_type": types.StringValue(g.SubjectType), "subject_id": types.StringValue(g.SubjectID), "operations": opSet,
		})
		if d.HasError() {
			return types.Set{}, diagError(d)
		}
		objs = append(objs, obj)
	}
	s, d := types.SetValue(types.ObjectType{AttrTypes: grantAttrTypes}, objs)
	if d.HasError() {
		return types.Set{}, diagError(d)
	}
	return s, nil
}

func (r *keyAccessResource) apply(ctx context.Context, plan *keyAccessModel) error {
	grants, err := plan.grants(ctx)
	if err != nil {
		return err
	}
	if err := r.c.SetKeyAccess(ctx, plan.KeyID.ValueString(), grants); err != nil {
		return err
	}
	plan.ID = plan.KeyID
	return nil
}

func (r *keyAccessResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan keyAccessModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Setting the key's access", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *keyAccessResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state keyAccessModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	gs, err := r.c.GetKeyAccess(ctx, state.KeyID.ValueString())
	if vecta.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading the key's access", err.Error())
		return
	}
	set, err := grantSet(gs)
	if err != nil {
		resp.Diagnostics.AddError("Reading the key's access", err.Error())
		return
	}
	state.Grant, state.ID = set, state.KeyID
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *keyAccessResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan keyAccessModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.apply(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Setting the key's access", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *keyAccessResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state keyAccessModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.c.SetKeyAccess(ctx, state.KeyID.ValueString(), nil); err != nil && !vecta.IsNotFound(err) {
		resp.Diagnostics.AddError("Removing the key's grants", err.Error())
	}
}

func (r *keyAccessResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("key_id"), req, resp)
}
