package tsa

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// OIDs per RFC 3161 and related standards.
var (
	// Hash algorithm OIDs
	OIDsha256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDsha384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDsha512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// Signature algorithm OIDs
	OIDrsaEncryption       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDsha256WithRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDsha384WithRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDsha512WithRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDecdsaWithSHA256     = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDecdsaWithSHA384     = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDecdsaWithSHA512     = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// CMS/PKCS#7 OIDs
	OIDsignedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDcontentTypeData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDtSTInfo         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

	// Attribute OIDs
	OIDcontentType    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDmessageDigest  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDsigningTime    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	// Default TSA policy OID (iso.org.dod.internet.private.enterprise.example)
	OIDdefaultTSAPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
)

// TimeStampReq represents an RFC 3161 TimeStampReq (Section 2.4.1).
//
//	TimeStampReq ::= SEQUENCE {
//	   version        INTEGER { v1(1) },
//	   messageImprint MessageImprint,
//	   reqPolicy      TSAPolicyId OPTIONAL,
//	   nonce          INTEGER OPTIONAL,
//	   certReq        BOOLEAN DEFAULT FALSE,
//	   extensions     [0] IMPLICIT Extensions OPTIONAL
//	}
type TimeStampReq struct {
	Version        int              `asn1:"default:1"`
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
}

// MessageImprint is the hash of the data to be timestamped.
//
//	MessageImprint ::= SEQUENCE {
//	   hashAlgorithm  AlgorithmIdentifier,
//	   hashedMessage  OCTET STRING
//	}
type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// TimeStampResp represents an RFC 3161 TimeStampResp (Section 2.4.2).
//
//	TimeStampResp ::= SEQUENCE {
//	   status          PKIStatusInfo,
//	   timeStampToken  ContentInfo OPTIONAL
//	}
type TimeStampResp struct {
	Status         PKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// PKIStatusInfo represents the status of a timestamp request.
//
//	PKIStatusInfo ::= SEQUENCE {
//	   status        PKIStatus,
//	   statusString  PKIFreeText OPTIONAL,
//	   failInfo      PKIFailureInfo OPTIONAL
//	}
type PKIStatusInfo struct {
	Status       int
	StatusString []string         `asn1:"optional"`
	FailInfo     asn1.BitString   `asn1:"optional"`
}

// PKIStatus values per RFC 3161.
const (
	PKIStatusGranted                = 0
	PKIStatusGrantedWithMods        = 1
	PKIStatusRejection              = 2
	PKIStatusWaiting                = 3
	PKIStatusRevocationWarning      = 4
	PKIStatusRevocationNotification = 5
)

// PKIFailureInfo bits per RFC 3161.
const (
	PKIFailBadAlg             = 0
	PKIFailBadRequest         = 2
	PKIFailBadDataFormat      = 5
	PKIFailTimeNotAvailable   = 14
	PKIFailUnacceptedPolicy   = 15
	PKIFailUnacceptedExtension = 16
	PKIFailAddInfoNotAvailable = 17
	PKIFailSystemFailure      = 25
)

// TSTInfo represents the TSTInfo structure (Section 2.4.2).
//
//	TSTInfo ::= SEQUENCE {
//	   version        INTEGER { v1(1) },
//	   policy         TSAPolicyId,
//	   messageImprint MessageImprint,
//	   serialNumber   INTEGER,
//	   genTime        GeneralizedTime,
//	   accuracy       Accuracy OPTIONAL,
//	   ordering       BOOLEAN DEFAULT FALSE,
//	   nonce          INTEGER OPTIONAL,
//	   tsa            [0] GeneralName OPTIONAL,
//	   extensions     [1] IMPLICIT Extensions OPTIONAL
//	}
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	Accuracy       Accuracy  `asn1:"optional"`
	Ordering       bool      `asn1:"optional,default:false"`
	Nonce          *big.Int  `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"optional,tag:0"`
}

// Accuracy represents the accuracy of the time source.
//
//	Accuracy ::= SEQUENCE {
//	   seconds  INTEGER OPTIONAL,
//	   millis   [0] INTEGER OPTIONAL,
//	   micros   [1] INTEGER OPTIONAL
//	}
type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

// ContentInfo is a CMS ContentInfo structure.
//
//	ContentInfo ::= SEQUENCE {
//	   contentType ContentType,
//	   content     [0] EXPLICIT ANY DEFINED BY contentType
//	}
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// SignedData is a CMS SignedData structure (simplified for TSA use).
//
//	SignedData ::= SEQUENCE {
//	   version          CMSVersion,
//	   digestAlgorithms SET OF DigestAlgorithmIdentifier,
//	   encapContentInfo EncapsulatedContentInfo,
//	   certificates     [0] IMPLICIT CertificateSet OPTIONAL,
//	   crls             [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//	   signerInfos      SET OF SignerInfo
//	}
type SignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      []SignerInfo  `asn1:"set"`
}

// EncapsulatedContentInfo holds the content being signed.
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// SignerInfo identifies the signer and contains the signature.
type SignerInfo struct {
	Version            int
	SID                IssuerAndSerialNumber
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        []Attribute `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

// IssuerAndSerialNumber identifies a certificate.
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// Attribute is a CMS attribute.
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}
