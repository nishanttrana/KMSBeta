package main

var supportedOperations = []string{
	"Create",
	"Register",
	"Get",
	"GetAttributes",
	"Locate",
	"Activate",
	"Revoke",
	"Destroy",
	"ReKey",
	"Encrypt",
	"Decrypt",
	"Sign",
	"MAC",
	"Query",
}

var supportedObjectTypes = []string{
	"SymmetricKey",
	"PublicKey",
	"PrivateKey",
	"Certificate",
	"SecretData",
	"OpaqueData",
}

var supportedProfiles = []string{
	"Basic Server",
	"Symmetric Key Lifecycle",
	"Asymmetric Key Lifecycle",
}

func queryCapabilities() map[string]interface{} {
	return map[string]interface{}{
		"kmip_version": "2.1",
		"profiles":     supportedProfiles,
		"operations":   supportedOperations,
		"object_types": supportedObjectTypes,
		"compatibility": map[string]interface{}{
			"vmware_vsphere": true,
			"netapp_ontap":   true,
			"oracle_tde":     true,
		},
	}
}
