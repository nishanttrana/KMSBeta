package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	cloudkmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// gcpKMSDouble is a gRPC KeyManagementService for the calls import uses:
// import jobs hold an RSA-3072 key; ImportCryptoKeyVersion unwraps with it
// (RSA_OAEP_3072_SHA256) and the version then encrypts with that material.
type gcpKMSDouble struct {
	cloudkmspb.UnimplementedKeyManagementServiceServer
	mu       sync.Mutex
	jobs     map[string]*rsa.PrivateKey
	keys     map[string]*cloudkmspb.CryptoKey
	versions map[string]*cloudkmspb.CryptoKeyVersion
	material map[string][]byte
	policies map[string]*iampb.Policy
}

// gcpIAMDouble is the IAM policy service on the same connection, as
// Google serves it.
type gcpIAMDouble struct {
	iampb.UnimplementedIAMPolicyServer
	d *gcpKMSDouble
}

func (i gcpIAMDouble) GetIamPolicy(_ context.Context, r *iampb.GetIamPolicyRequest) (*iampb.Policy, error) {
	i.d.mu.Lock()
	defer i.d.mu.Unlock()
	if p := i.d.policies[r.GetResource()]; p != nil {
		return p, nil
	}
	return &iampb.Policy{Version: 1}, nil
}

func (i gcpIAMDouble) SetIamPolicy(_ context.Context, r *iampb.SetIamPolicyRequest) (*iampb.Policy, error) {
	i.d.mu.Lock()
	defer i.d.mu.Unlock()
	i.d.policies[r.GetResource()] = r.GetPolicy()
	return r.GetPolicy(), nil
}

func (d *gcpKMSDouble) ListCryptoKeyVersions(_ context.Context, r *cloudkmspb.ListCryptoKeyVersionsRequest) (*cloudkmspb.ListCryptoKeyVersionsResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := &cloudkmspb.ListCryptoKeyVersionsResponse{}
	for name, v := range d.versions {
		if strings.HasPrefix(name, r.GetParent()+"/") {
			out.CryptoKeyVersions = append(out.CryptoKeyVersions, v)
		}
	}
	out.TotalSize = int32(len(out.CryptoKeyVersions))
	return out, nil
}

func (d *gcpKMSDouble) UpdateCryptoKey(_ context.Context, r *cloudkmspb.UpdateCryptoKeyRequest) (*cloudkmspb.CryptoKey, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	k := d.keys[r.GetCryptoKey().GetName()]
	if len(r.GetUpdateMask().GetPaths()) != 1 || r.GetUpdateMask().GetPaths()[0] != "labels" {
		return nil, status.Error(codes.InvalidArgument, "the double updates labels only")
	}
	k.Labels = r.GetCryptoKey().GetLabels()
	return k, nil
}

func newGCPDouble(t *testing.T) (*gcpKMSDouble, []option.ClientOption) {
	d := &gcpKMSDouble{jobs: map[string]*rsa.PrivateKey{}, keys: map[string]*cloudkmspb.CryptoKey{},
		versions: map[string]*cloudkmspb.CryptoKeyVersion{}, material: map[string][]byte{}, policies: map[string]*iampb.Policy{}}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	cloudkmspb.RegisterKeyManagementServiceServer(srv, d)
	iampb.RegisterIAMPolicyServer(srv, gcpIAMDouble{d: d})
	go srv.Serve(lis) //nolint:errcheck
	t.Cleanup(srv.Stop)
	return d, []option.ClientOption{option.WithEndpoint(lis.Addr().String()), option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials()))}
}

func (d *gcpKMSDouble) CreateCryptoKey(_ context.Context, r *cloudkmspb.CreateCryptoKeyRequest) (*cloudkmspb.CryptoKey, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !r.GetSkipInitialVersionCreation() || !r.GetCryptoKey().GetImportOnly() {
		return nil, status.Error(codes.InvalidArgument, "the double makes import-only keys without a version")
	}
	k := r.GetCryptoKey()
	k.Name = r.GetParent() + "/cryptoKeys/" + r.GetCryptoKeyId()
	d.keys[k.Name] = k
	return k, nil
}

func (d *gcpKMSDouble) CreateImportJob(_ context.Context, r *cloudkmspb.CreateImportJobRequest) (*cloudkmspb.ImportJob, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	priv := must(rsa.GenerateKey(pkgcrypto.Reader, 3072))
	name := r.GetParent() + "/importJobs/" + r.GetImportJobId()
	d.jobs[name] = priv
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	return &cloudkmspb.ImportJob{Name: name, ImportMethod: r.GetImportJob().GetImportMethod(), State: cloudkmspb.ImportJob_PENDING_GENERATION,
		PublicKey: &cloudkmspb.ImportJob_WrappingPublicKey{Pem: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}}, nil
}

func (d *gcpKMSDouble) GetImportJob(_ context.Context, r *cloudkmspb.GetImportJobRequest) (*cloudkmspb.ImportJob, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	priv := d.jobs[r.GetName()]
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	return &cloudkmspb.ImportJob{Name: r.GetName(), State: cloudkmspb.ImportJob_ACTIVE,
		PublicKey: &cloudkmspb.ImportJob_WrappingPublicKey{Pem: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}}, nil
}

func (d *gcpKMSDouble) ImportCryptoKeyVersion(_ context.Context, r *cloudkmspb.ImportCryptoKeyVersionRequest) (*cloudkmspb.CryptoKeyVersion, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	material, err := pkgcrypto.UnwrapCloudImport(d.jobs[r.GetImportJob()], r.GetWrappedKey(), pkgcrypto.CloudWrapRSAOAEPSHA256)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	name := r.GetCryptoKeyVersion()
	if name == "" {
		n := 1
		for v := range d.versions {
			if strings.HasPrefix(v, r.GetParent()+"/") {
				n++
			}
		}
		name = fmt.Sprintf("%s/cryptoKeyVersions/%d", r.GetParent(), n)
	} else if d.versions[name].GetState() != cloudkmspb.CryptoKeyVersion_DESTROYED {
		return nil, status.Error(codes.FailedPrecondition, "only a destroyed version takes material again")
	}
	v := &cloudkmspb.CryptoKeyVersion{Name: name, State: cloudkmspb.CryptoKeyVersion_PENDING_IMPORT, Algorithm: r.GetAlgorithm()}
	d.versions[name], d.material[name] = v, material
	return &cloudkmspb.CryptoKeyVersion{Name: name, State: cloudkmspb.CryptoKeyVersion_PENDING_IMPORT}, nil
}

func (d *gcpKMSDouble) GetCryptoKeyVersion(_ context.Context, r *cloudkmspb.GetCryptoKeyVersionRequest) (*cloudkmspb.CryptoKeyVersion, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v := d.versions[r.GetName()]
	if v.State == cloudkmspb.CryptoKeyVersion_PENDING_IMPORT {
		v.State = cloudkmspb.CryptoKeyVersion_ENABLED
	}
	return v, nil
}

func (d *gcpKMSDouble) UpdateCryptoKeyPrimaryVersion(_ context.Context, r *cloudkmspb.UpdateCryptoKeyPrimaryVersionRequest) (*cloudkmspb.CryptoKey, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	k := d.keys[r.GetName()]
	k.Primary = d.versions[r.GetName()+"/cryptoKeyVersions/"+r.GetCryptoKeyVersionId()]
	return k, nil
}

func (d *gcpKMSDouble) GetCryptoKey(_ context.Context, r *cloudkmspb.GetCryptoKeyRequest) (*cloudkmspb.CryptoKey, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.keys[r.GetName()], nil
}

func (d *gcpKMSDouble) primaryMaterial(key string) ([]byte, string, error) {
	p := d.keys[key].GetPrimary()
	if p == nil || d.versions[p.GetName()].GetState() != cloudkmspb.CryptoKeyVersion_ENABLED {
		return nil, "", status.Error(codes.FailedPrecondition, "the primary version is not enabled")
	}
	return d.material[p.GetName()], p.GetName(), nil
}

func (d *gcpKMSDouble) Encrypt(_ context.Context, r *cloudkmspb.EncryptRequest) (*cloudkmspb.EncryptResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	m, name, err := d.primaryMaterial(r.GetName())
	if err != nil {
		return nil, err
	}
	return &cloudkmspb.EncryptResponse{Name: name, Ciphertext: gcmSeal(m, r.GetPlaintext())}, nil
}

func (d *gcpKMSDouble) Decrypt(_ context.Context, r *cloudkmspb.DecryptRequest) (*cloudkmspb.DecryptResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	m, _, err := d.primaryMaterial(r.GetName())
	if err != nil {
		return nil, err
	}
	pt, err := gcmOpen(m, r.GetCiphertext())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &cloudkmspb.DecryptResponse{Plaintext: pt}, nil
}

func (d *gcpKMSDouble) DestroyCryptoKeyVersion(_ context.Context, r *cloudkmspb.DestroyCryptoKeyVersionRequest) (*cloudkmspb.CryptoKeyVersion, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v := d.versions[r.GetName()]
	v.State = cloudkmspb.CryptoKeyVersion_DESTROY_SCHEDULED
	return v, nil
}

// destroyNow is the end of Google's scheduled destruction.
func (d *gcpKMSDouble) destroyNow(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.versions[name].State = cloudkmspb.CryptoKeyVersion_DESTROYED
	delete(d.material, name)
}

func (d *gcpKMSDouble) RestoreCryptoKeyVersion(_ context.Context, r *cloudkmspb.RestoreCryptoKeyVersionRequest) (*cloudkmspb.CryptoKeyVersion, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v := d.versions[r.GetName()]
	v.State = cloudkmspb.CryptoKeyVersion_DISABLED
	return v, nil
}

func (d *gcpKMSDouble) UpdateCryptoKeyVersion(_ context.Context, r *cloudkmspb.UpdateCryptoKeyVersionRequest) (*cloudkmspb.CryptoKeyVersion, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v := d.versions[r.GetCryptoKeyVersion().GetName()]
	v.State = r.GetCryptoKeyVersion().GetState()
	return v, nil
}

// Google Cloud KMS over its real gRPC API: import-only key, import job,
// versions whose material is the KMS's; destroy, then restore during the
// scheduled destruction and, once destroyed, re-import into the same version.
func TestBYOKGoogleCloudImportJobs(t *testing.T) {
	svc, _, kc, _ := newCloudService(t)
	d, opts := newGCPDouble(t)
	gcpPollEvery = 10 * time.Millisecond
	svc.byokProviders[ProviderGCP] = &gcpProvider{options: opts}
	setCred(svc, "cred-gcp-double", "gcp", map[string]string{"project_id": "proj", "location": "europe-west1", "key_ring": "vecta"})
	acct, err := svc.RegisterAccount(attachCtx("t1"), RegisterCloudAccountRequest{TenantID: "t1", Provider: ProviderGCP, Name: "gcp", DefaultRegion: "europe-west1", ConnectionID: "cred-gcp-double"})
	if err != nil {
		t.Fatal(err)
	}
	kc.Seed("t1", "key-1", "AES-256")
	ctx := context.Background()
	run, key, err := svc.CreateBYOK(ctx, "t1", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "key-1"})
	if err != nil {
		t.Fatalf("create: %v %v", err, stepNames(run))
	}
	if string(d.material[key.CurrentMatID]) != string(kc.material("t1", "key-1", 1)) {
		t.Fatal("Google holds different material than KMS version 1")
	}
	if run, key, err = svc.RunBYOK(ctx, "t1", key.ID, OpRotate, "alice", BYOKOperationRequest{}); err != nil {
		t.Fatalf("rotate: %v %v", err, stepNames(run))
	}
	if !strings.HasSuffix(key.CurrentMatID, "/cryptoKeyVersions/2") || d.keys[key.CloudKeyID].GetPrimary().GetName() != key.CurrentMatID {
		t.Fatalf("version 2 is not primary: %s", key.CurrentMatID)
	}
	v2 := key.CurrentMatID
	if _, _, err = svc.RunBYOK(ctx, "t1", key.ID, OpRevoke, "alice", BYOKOperationRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, key, err = svc.RunBYOK(ctx, "t1", key.ID, OpRestore, "alice", BYOKOperationRequest{}); err != nil || d.versions[v2].GetState() != cloudkmspb.CryptoKeyVersion_ENABLED {
		t.Fatalf("restore during scheduled destruction: %v", err)
	}
	if _, _, err = svc.RunBYOK(ctx, "t1", key.ID, OpRevoke, "alice", BYOKOperationRequest{}); err != nil {
		t.Fatal(err)
	}
	d.destroyNow(v2)
	if run, key, err = svc.RunBYOK(ctx, "t1", key.ID, OpRestore, "alice", BYOKOperationRequest{}); err != nil {
		t.Fatalf("restore of a destroyed version: %v %v", err, stepNames(run))
	}
	if string(d.material[v2]) != string(kc.material("t1", "key-1", 2)) || key.CurrentMatID != v2 {
		t.Fatal("the destroyed version did not get KMS version 2 back")
	}
}

// The console over Google's real gRPC API: versions, labels as tags, the
// primary version's state, and the key's IAM policy.
func TestConsoleGoogleCloud(t *testing.T) {
	svc, _, kc, _ := newCloudService(t)
	d, opts := newGCPDouble(t)
	gcpPollEvery = 10 * time.Millisecond
	svc.byokProviders[ProviderGCP] = &gcpProvider{options: opts}
	setCred(svc, "cred-gcp-double", "gcp", map[string]string{"project_id": "proj", "location": "europe-west1", "key_ring": "vecta"})
	acct, err := svc.RegisterAccount(attachCtx("t1"), RegisterCloudAccountRequest{TenantID: "t1", Provider: ProviderGCP, Name: "gcp", ConnectionID: "cred-gcp-double"})
	if err != nil {
		t.Fatal(err)
	}
	kc.Seed("t1", "key-1", "AES-256")
	_, k, err := svc.CreateBYOK(context.Background(), "t1", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "key-1"})
	if err != nil {
		t.Fatal(err)
	}
	rt, _ := consoleRouter(svc)
	op := func(name string, params map[string]string) (int, consoleOut) {
		return runOp(t, rt, rw, name, map[string]interface{}{"account_id": acct.ID, "key": k.CloudKeyID, "params": params})
	}
	if code, out := op("list-versions", nil); code != 200 || !strings.Contains(string(out.Result), "cryptoKeyVersions/1") {
		t.Fatalf("list-versions %d %s", code, out.Result)
	}
	if code, out := op("tag-key", map[string]string{"tag_key": "team", "tag_value": "payments"}); code != 200 || !strings.HasPrefix(out.CLI, "gcloud kms keys update") {
		t.Fatalf("tag %d %+v", code, out)
	}
	if _, out := op("list-tags", nil); !strings.Contains(string(out.Result), "payments") {
		t.Fatal("label missing")
	}
	if code, out := op("disable-key", nil); code != 200 || d.versions[k.CurrentMatID].GetState() != cloudkmspb.CryptoKeyVersion_DISABLED {
		t.Fatalf("primary version not disabled: %d %+v", code, out)
	}
	if code, _ := op("encrypt", map[string]string{"plaintext_b64": b64s("x")}); code != http.StatusBadGateway {
		t.Fatalf("encrypt with a disabled primary: %d", code)
	}
	op("enable-key", nil)
	enc := struct {
		C string `json:"ciphertext_b64"`
	}{}
	_, out := op("encrypt", map[string]string{"plaintext_b64": b64s("hello")})
	_ = json.Unmarshal(out.Result, &enc)
	if _, out := op("decrypt", map[string]string{"ciphertext_b64": enc.C}); !strings.Contains(string(out.Result), "hello") {
		t.Fatalf("decrypt %s", out.Result)
	}
	pol := `{"bindings":[{"role":"roles/cloudkms.cryptoKeyEncrypterDecrypter","members":["serviceAccount:app@proj.iam.gserviceaccount.com"]}]}`
	if code, out := op("put-key-policy", map[string]string{"policy": pol}); code != 200 {
		t.Fatalf("set IAM policy %d %+v", code, out)
	}
	if _, out := op("get-key-policy", nil); !strings.Contains(string(out.Result), "app@proj") {
		t.Fatalf("IAM policy %s", out.Result)
	}
	if code, _ := op("create-grant", map[string]string{"grantee": "x", "operations": "Encrypt"}); code != http.StatusConflict {
		t.Fatalf("Google has no grants: %d", code)
	}
}
