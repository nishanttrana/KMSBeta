package main

var supportedOperations = []string{
	"Create", "CreateKeyPair",
	"Register", "Import",
	"Get", "GetAttributes", "GetAttributeList", "ModifyAttribute", "DeleteAttribute",
	"Locate",
	"Activate", "Revoke", "Destroy",
	"Archive", "Recover",
	"ReKey", "DeriveKey",
	"Export", "Certify", "ReCertify",
	"Check", "Validate",
	"Encrypt", "Decrypt",
	"Sign", "SignatureVerify",
	"MAC", "MACVerify", "Hash",
	"GetUsageAllocation",
	"Query", "DiscoverVersions",
}

var supportedObjectTypes = []string{
	"SymmetricKey",
	"PublicKey",
	"PrivateKey",
	"SecretData",
	"Certificate",
	"OpaqueObject",
	"SplitKey",
	"PGPKey",
	"Template",
}

var supportedProfiles = []string{
	"Complete Server",
	"Basic Cryptographic Server KMIP v3.2",
	"Baseline Server KMIP v3.2",
	"Symmetric Key Lifecycle",
	"Asymmetric Key Lifecycle",
	"Certificate Management",
	"Opaque Data Management",
}

func queryCapabilities() map[string]interface{} {
	return map[string]interface{}{
		"kmip_version": "3.2",
		"profiles":     supportedProfiles,
		"operations":   supportedOperations,
		"object_types": supportedObjectTypes,
		"compatibility": map[string]interface{}{
			"vmware_vsphere": true,
			"netapp_ontap":   true,
			"oracle_tde":     true,
			"mysql_enterprise": true,
			"mongodb_enterprise": true,
		},
	}
}
