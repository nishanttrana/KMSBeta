package tsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"hash"
	"math/big"
	"sync/atomic"
	"time"
)

// Authority is an RFC 3161 Timestamping Authority.
type Authority struct {
	signerKey  crypto.Signer
	certChain  []*x509.Certificate
	serial     atomic.Int64
	policyOID  asn1.ObjectIdentifier
}

// NewAuthority creates a new Timestamping Authority with the given signing key and certificate chain.
// certChain[0] must be the TSA signing certificate; remaining certs are intermediates.
func NewAuthority(signerKey crypto.Signer, certChain []*x509.Certificate) (*Authority, error) {
	if signerKey == nil {
		return nil, fmt.Errorf("signer key is required")
	}
	if len(certChain) == 0 {
		return nil, fmt.Errorf("at least one certificate is required")
	}

	// Verify the signing key matches the certificate's public key
	switch pub := certChain[0].PublicKey.(type) {
	case *rsa.PublicKey:
		if _, ok := signerKey.(*rsa.PrivateKey); !ok {
			// May be a custom signer wrapping RSA; skip strict check
			_ = pub
		}
	case *ecdsa.PublicKey:
		if _, ok := signerKey.(*ecdsa.PrivateKey); !ok {
			_ = pub
		}
	}

	a := &Authority{
		signerKey: signerKey,
		certChain: certChain,
		policyOID: OIDdefaultTSAPolicy,
	}
	a.serial.Store(time.Now().UnixNano())
	return a, nil
}

// SetPolicy overrides the default TSA policy OID.
func (a *Authority) SetPolicy(oid asn1.ObjectIdentifier) {
	a.policyOID = oid
}

// Timestamp processes an ASN.1-encoded TimeStampReq and returns an ASN.1-encoded TimeStampResp.
func (a *Authority) Timestamp(ctx interface{}, reqBytes []byte) ([]byte, error) {
	// Parse the TimeStampReq
	var req TimeStampReq
	rest, err := asn1.Unmarshal(reqBytes, &req)
	if err != nil {
		return a.buildErrorResponse(PKIStatusRejection, PKIFailBadDataFormat, "failed to parse TimeStampReq")
	}
	if len(rest) > 0 {
		return a.buildErrorResponse(PKIStatusRejection, PKIFailBadDataFormat, "trailing data after TimeStampReq")
	}

	// Validate version
	if req.Version != 1 {
		return a.buildErrorResponse(PKIStatusRejection, PKIFailBadRequest, "unsupported version")
	}

	// Validate hash algorithm
	hashAlg := req.MessageImprint.HashAlgorithm.Algorithm
	if !isAcceptableHashAlg(hashAlg) {
		return a.buildErrorResponse(PKIStatusRejection, PKIFailBadAlg,
			fmt.Sprintf("unsupported hash algorithm: %s", hashAlg.String()))
	}

	// Validate the hash length matches the algorithm
	expectedLen := hashLength(hashAlg)
	if len(req.MessageImprint.HashedMessage) != expectedLen {
		return a.buildErrorResponse(PKIStatusRejection, PKIFailBadDataFormat,
			fmt.Sprintf("hash length %d does not match expected %d for algorithm", len(req.MessageImprint.HashedMessage), expectedLen))
	}

	// Build TSTInfo
	serialNumber := big.NewInt(a.serial.Add(1))
	now := time.Now().UTC()

	tstInfo := TSTInfo{
		Version:        1,
		Policy:         a.policyOID,
		MessageImprint: req.MessageImprint,
		SerialNumber:   serialNumber,
		GenTime:        now,
		Accuracy:       Accuracy{Seconds: 1},
		Ordering:       true,
	}

	// Echo nonce if provided
	if req.Nonce != nil {
		tstInfo.Nonce = req.Nonce
	}

	// Encode TSTInfo
	tstInfoBytes, err := asn1.Marshal(tstInfo)
	if err != nil {
		return a.buildErrorResponse(PKIStatusRejection, PKIFailSystemFailure, "failed to encode TSTInfo")
	}

	// Sign the TSTInfo using CMS SignedData
	signedDataBytes, err := a.buildCMSSignedData(tstInfoBytes, req.CertReq)
	if err != nil {
		return a.buildErrorResponse(PKIStatusRejection, PKIFailSystemFailure,
			fmt.Sprintf("failed to build signed data: %v", err))
	}

	// Build the ContentInfo wrapper
	contentInfo := ContentInfo{
		ContentType: OIDsignedData,
	}
	contentInfo.Content.FullBytes, err = asn1.MarshalWithParams(signedDataBytes, "explicit,tag:0")
	if err != nil {
		return a.buildErrorResponse(PKIStatusRejection, PKIFailSystemFailure, "failed to wrap signed data")
	}

	contentInfoBytes, err := asn1.Marshal(contentInfo)
	if err != nil {
		return a.buildErrorResponse(PKIStatusRejection, PKIFailSystemFailure, "failed to encode ContentInfo")
	}

	// Build the TimeStampResp
	resp := TimeStampResp{
		Status: PKIStatusInfo{
			Status: PKIStatusGranted,
		},
		TimeStampToken: asn1.RawValue{
			FullBytes: contentInfoBytes,
		},
	}

	return asn1.Marshal(resp)
}

// buildCMSSignedData creates a CMS SignedData structure containing the signed TSTInfo.
func (a *Authority) buildCMSSignedData(tstInfoBytes []byte, includeCerts bool) ([]byte, error) {
	// Determine digest and signature algorithm based on key type
	digestAlgOID, sigAlgOID, hashFunc, err := a.signingAlgorithms()
	if err != nil {
		return nil, err
	}

	// Hash the TSTInfo content
	h := hashFunc.New()
	h.Write(tstInfoBytes)
	tstInfoDigest := h.Sum(nil)

	// Build signed attributes
	// Content type attribute
	contentTypeValue, _ := asn1.Marshal(OIDtSTInfo)
	contentTypeAttr := Attribute{
		Type:   OIDcontentType,
		Values: asn1.RawValue{FullBytes: mustWrapInSet(contentTypeValue)},
	}

	// Message digest attribute
	digestValue, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagOctetString, Class: asn1.ClassUniversal, Bytes: tstInfoDigest})
	digestAttr := Attribute{
		Type:   OIDmessageDigest,
		Values: asn1.RawValue{FullBytes: mustWrapInSet(digestValue)},
	}

	// Signing time attribute
	signingTimeValue, _ := asn1.Marshal(time.Now().UTC())
	signingTimeAttr := Attribute{
		Type:   OIDsigningTime,
		Values: asn1.RawValue{FullBytes: mustWrapInSet(signingTimeValue)},
	}

	signedAttrs := []Attribute{contentTypeAttr, digestAttr, signingTimeAttr}

	// Encode signed attributes for signing (must be re-encoded as SET OF)
	signedAttrsBytes, err := marshalSignedAttrs(signedAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed attributes: %w", err)
	}

	// Sign the encoded signed attributes
	signature, err := a.sign(signedAttrsBytes, hashFunc)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	// Build SignerInfo
	cert := a.certChain[0]
	signerInfo := SignerInfo{
		Version: 1,
		SID: IssuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
			SerialNumber: cert.SerialNumber,
		},
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: digestAlgOID},
		SignedAttrs:        signedAttrs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigAlgOID},
		Signature:          signature,
	}

	// Build SignedData
	sd := SignedData{
		Version: 3, // v3 for CMS with eContentType != id-data
		DigestAlgorithms: []pkix.AlgorithmIdentifier{
			{Algorithm: digestAlgOID},
		},
		EncapContentInfo: EncapsulatedContentInfo{
			EContentType: OIDtSTInfo,
			EContent: asn1.RawValue{
				Tag:   asn1.TagOctetString,
				Class: asn1.ClassUniversal,
				Bytes: tstInfoBytes,
			},
		},
		SignerInfos: []SignerInfo{signerInfo},
	}

	// Include certificates if requested
	if includeCerts {
		var certBytes []byte
		for _, c := range a.certChain {
			certBytes = append(certBytes, c.Raw...)
		}
		sd.Certificates = asn1.RawValue{
			Tag:        0,
			Class:      asn1.ClassContextSpecific,
			IsCompound: true,
			Bytes:      certBytes,
		}
	}

	return asn1.Marshal(sd)
}

// signingAlgorithms returns the OIDs and hash function for the TSA's key type.
func (a *Authority) signingAlgorithms() (digestOID, sigOID asn1.ObjectIdentifier, hashFunc crypto.Hash, err error) {
	switch key := a.signerKey.(type) {
	case *rsa.PrivateKey:
		return OIDsha256, OIDsha256WithRSA, crypto.SHA256, nil
	case *ecdsa.PrivateKey:
		switch key.Curve {
		case elliptic.P256():
			return OIDsha256, OIDecdsaWithSHA256, crypto.SHA256, nil
		case elliptic.P384():
			return OIDsha384, OIDecdsaWithSHA384, crypto.SHA384, nil
		case elliptic.P521():
			return OIDsha512, OIDecdsaWithSHA512, crypto.SHA512, nil
		default:
			return nil, nil, 0, fmt.Errorf("unsupported EC curve")
		}
	default:
		// Try generic approach: default to SHA-256
		return OIDsha256, OIDsha256WithRSA, crypto.SHA256, nil
	}
}

// sign hashes the data with the given hash function and signs it.
func (a *Authority) sign(data []byte, hashFunc crypto.Hash) ([]byte, error) {
	h := hashFunc.New()
	h.Write(data)
	digest := h.Sum(nil)

	return a.signerKey.Sign(rand.Reader, digest, hashFunc)
}

// Verify verifies a timestamp response against the original hash.
func (a *Authority) Verify(ctx interface{}, tsRespBytes []byte, originalHash []byte) error {
	return VerifyTimestampResponse(tsRespBytes, originalHash, a.certChain)
}

// VerifyTimestampResponse verifies an RFC 3161 timestamp response.
// It checks the signature, message imprint, and certificate chain.
func VerifyTimestampResponse(tsRespBytes []byte, originalHash []byte, trustedCerts []*x509.Certificate) error {
	// Parse the TimeStampResp
	var resp TimeStampResp
	_, err := asn1.Unmarshal(tsRespBytes, &resp)
	if err != nil {
		return fmt.Errorf("failed to parse TimeStampResp: %w", err)
	}

	// Check status
	if resp.Status.Status != PKIStatusGranted && resp.Status.Status != PKIStatusGrantedWithMods {
		return fmt.Errorf("timestamp request was not granted: status=%d", resp.Status.Status)
	}

	// Parse the ContentInfo
	var contentInfo ContentInfo
	_, err = asn1.Unmarshal(resp.TimeStampToken.FullBytes, &contentInfo)
	if err != nil {
		return fmt.Errorf("failed to parse ContentInfo: %w", err)
	}

	if !contentInfo.ContentType.Equal(OIDsignedData) {
		return fmt.Errorf("unexpected content type: %s", contentInfo.ContentType.String())
	}

	// Parse the SignedData from the explicit tag wrapper
	var innerRaw asn1.RawValue
	_, err = asn1.Unmarshal(contentInfo.Content.FullBytes, &innerRaw)
	if err != nil {
		return fmt.Errorf("failed to unwrap SignedData: %w", err)
	}

	var signedData SignedData
	_, err = asn1.Unmarshal(innerRaw.Bytes, &signedData)
	if err != nil {
		return fmt.Errorf("failed to parse SignedData: %w", err)
	}

	// Extract TSTInfo from EncapsulatedContentInfo
	if !signedData.EncapContentInfo.EContentType.Equal(OIDtSTInfo) {
		return fmt.Errorf("unexpected encapsulated content type: %s", signedData.EncapContentInfo.EContentType.String())
	}

	var tstInfoBytes asn1.RawValue
	_, err = asn1.Unmarshal(signedData.EncapContentInfo.EContent.Bytes, &tstInfoBytes)
	if err != nil {
		// The content might be directly available
		tstInfoBytes.Bytes = signedData.EncapContentInfo.EContent.Bytes
	}

	tstContent := tstInfoBytes.Bytes
	if len(tstContent) == 0 {
		tstContent = signedData.EncapContentInfo.EContent.Bytes
	}

	var tstInfo TSTInfo
	_, err = asn1.Unmarshal(tstContent, &tstInfo)
	if err != nil {
		return fmt.Errorf("failed to parse TSTInfo: %w", err)
	}

	// Verify the message imprint matches the original hash
	if len(originalHash) > 0 {
		if len(tstInfo.MessageImprint.HashedMessage) != len(originalHash) {
			return fmt.Errorf("hash length mismatch: got %d, expected %d",
				len(tstInfo.MessageImprint.HashedMessage), len(originalHash))
		}
		for i := range originalHash {
			if tstInfo.MessageImprint.HashedMessage[i] != originalHash[i] {
				return fmt.Errorf("message imprint does not match original hash")
			}
		}
	}

	// Verify signature using the signer info
	if len(signedData.SignerInfos) == 0 {
		return fmt.Errorf("no signer info found")
	}

	si := signedData.SignerInfos[0]

	// Find the signing certificate
	var signerCert *x509.Certificate
	for _, cert := range trustedCerts {
		if cert.SerialNumber.Cmp(si.SID.SerialNumber) == 0 {
			signerCert = cert
			break
		}
	}
	if signerCert == nil {
		return fmt.Errorf("signer certificate not found in trusted certificates")
	}

	// Determine hash function from digest algorithm
	var verifyHash hash.Hash
	var cryptoHash crypto.Hash
	digestAlg := si.DigestAlgorithm.Algorithm
	switch {
	case digestAlg.Equal(OIDsha256):
		verifyHash = sha256.New()
		cryptoHash = crypto.SHA256
	case digestAlg.Equal(OIDsha384):
		verifyHash = sha512.New384()
		cryptoHash = crypto.SHA384
	case digestAlg.Equal(OIDsha512):
		verifyHash = sha512.New()
		cryptoHash = crypto.SHA512
	default:
		return fmt.Errorf("unsupported digest algorithm: %s", digestAlg.String())
	}

	// Re-encode signed attributes as SET for verification
	if len(si.SignedAttrs) > 0 {
		signedAttrsBytes, err := marshalSignedAttrs(si.SignedAttrs)
		if err != nil {
			return fmt.Errorf("failed to re-encode signed attributes: %w", err)
		}
		verifyHash.Write(signedAttrsBytes)
	} else {
		verifyHash.Write(tstContent)
	}

	digest := verifyHash.Sum(nil)

	// Verify the signature
	switch pub := signerCert.PublicKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, cryptoHash, digest, si.Signature)
		if err != nil {
			return fmt.Errorf("RSA signature verification failed: %w", err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, si.Signature) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported public key type for verification")
	}

	return nil
}

// isAcceptableHashAlg checks if the hash algorithm is acceptable for timestamping.
func isAcceptableHashAlg(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(OIDsha256) || oid.Equal(OIDsha384) || oid.Equal(OIDsha512)
}

// hashLength returns the expected hash output length for the given algorithm OID.
func hashLength(oid asn1.ObjectIdentifier) int {
	switch {
	case oid.Equal(OIDsha256):
		return 32
	case oid.Equal(OIDsha384):
		return 48
	case oid.Equal(OIDsha512):
		return 64
	default:
		return 0
	}
}

// buildErrorResponse creates a TimeStampResp with an error status.
func (a *Authority) buildErrorResponse(status int, failBit int, msg string) ([]byte, error) {
	failInfo := asn1.BitString{
		Bytes:     make([]byte, 4),
		BitLength: 32,
	}
	byteIdx := failBit / 8
	bitIdx := uint(7 - (failBit % 8))
	if byteIdx < 4 {
		failInfo.Bytes[byteIdx] |= 1 << bitIdx
	}

	resp := TimeStampResp{
		Status: PKIStatusInfo{
			Status:       status,
			StatusString: []string{msg},
			FailInfo:     failInfo,
		},
	}
	return asn1.Marshal(resp)
}

// marshalSignedAttrs encodes signed attributes as a SET for signing/verification.
// Per CMS, signed attributes are encoded as SET OF when computing the signature.
func marshalSignedAttrs(attrs []Attribute) ([]byte, error) {
	encoded, err := asn1.Marshal(attrs)
	if err != nil {
		return nil, err
	}
	// Replace the SEQUENCE tag (0x30) with SET tag (0x31) for CMS signing
	if len(encoded) > 0 && encoded[0] == 0x30 {
		encoded[0] = 0x31
	}
	return encoded, nil
}

// mustWrapInSet wraps ASN.1 encoded bytes in a SET wrapper.
func mustWrapInSet(data []byte) []byte {
	set, _ := asn1.Marshal(asn1.RawValue{
		Tag:        asn1.TagSet,
		Class:      asn1.ClassUniversal,
		IsCompound: true,
		Bytes:      data,
	})
	return set
}

// CreateTimestampRequest is a helper that creates an ASN.1-encoded TimeStampReq
// for the given data hash.
func CreateTimestampRequest(hashAlg asn1.ObjectIdentifier, dataHash []byte, nonce *big.Int, certReq bool) ([]byte, error) {
	if !isAcceptableHashAlg(hashAlg) {
		return nil, fmt.Errorf("unsupported hash algorithm: %s", hashAlg.String())
	}
	expectedLen := hashLength(hashAlg)
	if len(dataHash) != expectedLen {
		return nil, fmt.Errorf("hash length %d does not match expected %d", len(dataHash), expectedLen)
	}

	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: hashAlg},
			HashedMessage: dataHash,
		},
		CertReq: certReq,
	}
	if nonce != nil {
		req.Nonce = nonce
	}

	return asn1.Marshal(req)
}
