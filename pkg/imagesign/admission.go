package imagesign

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"crypto/ecdsa"
	"crypto/rsa"
)

// AdmissionPolicy defines requirements for image signature validation.
type AdmissionPolicy struct {
	RequiredSigners   []string `json:"required_signers"`
	AllowedRegistries []string `json:"allowed_registries"`
	Enforce           bool     `json:"enforce"`
}

// AdmissionValidator validates Kubernetes admission requests for image signatures.
type AdmissionValidator struct {
	trustedKeys map[string]crypto.PublicKey // signerID -> public key
	policy      AdmissionPolicy
	store       *Store
}

// NewAdmissionValidator creates an AdmissionValidator with the given trusted keys and policy.
func NewAdmissionValidator(trustedKeys map[string]crypto.PublicKey, policy AdmissionPolicy, store *Store) *AdmissionValidator {
	if trustedKeys == nil {
		trustedKeys = make(map[string]crypto.PublicKey)
	}
	return &AdmissionValidator{
		trustedKeys: trustedKeys,
		policy:      policy,
		store:       store,
	}
}

// AddTrustedKey registers a trusted signer public key.
func (av *AdmissionValidator) AddTrustedKey(signerID string, key crypto.PublicKey) {
	av.trustedKeys[signerID] = key
}

// --- Kubernetes Admission Review structures ---

// AdmissionReview is a simplified admission.k8s.io/v1 AdmissionReview.
type AdmissionReview struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Request    *AdmissionRequest `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

// AdmissionRequest holds the incoming admission request.
type AdmissionRequest struct {
	UID    string          `json:"uid"`
	Object json.RawMessage `json:"object"`
}

// AdmissionResponse holds the admission decision.
type AdmissionResponse struct {
	UID     string                `json:"uid"`
	Allowed bool                  `json:"allowed"`
	Status  *AdmissionStatusResult `json:"status,omitempty"`
}

// AdmissionStatusResult provides reason details for denied requests.
type AdmissionStatusResult struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// podSpec is a minimal representation of a Kubernetes Pod for image extraction.
type podSpec struct {
	Kind string `json:"kind"`
	Spec struct {
		Containers     []containerSpec `json:"containers"`
		InitContainers []containerSpec `json:"initContainers"`
	} `json:"spec"`
	// For Deployment/StatefulSet etc.
	SpecTemplate *struct {
		Spec struct {
			Containers     []containerSpec `json:"containers"`
			InitContainers []containerSpec `json:"initContainers"`
		} `json:"spec"`
	} `json:"template,omitempty"`
}

type containerSpec struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

// ValidateAdmission parses a Kubernetes AdmissionReview, validates image signatures,
// and returns an AdmissionReview response.
func (av *AdmissionValidator) ValidateAdmission(ctx context.Context, admissionReview []byte) ([]byte, error) {
	var review AdmissionReview
	if err := json.Unmarshal(admissionReview, &review); err != nil {
		return nil, fmt.Errorf("imagesign/admission: unmarshal review: %w", err)
	}

	if review.Request == nil {
		return nil, errors.New("imagesign/admission: missing request in AdmissionReview")
	}

	response := &AdmissionResponse{
		UID:     review.Request.UID,
		Allowed: true,
	}

	// Extract images from the pod spec
	images, err := extractImages(review.Request.Object)
	if err != nil {
		if av.policy.Enforce {
			response.Allowed = false
			response.Status = &AdmissionStatusResult{
				Message: fmt.Sprintf("failed to extract images: %v", err),
				Code:    400,
			}
		}
		return marshalResponse(review, response)
	}

	// Validate each image
	var violations []string
	for _, image := range images {
		if err := av.validateImage(ctx, image); err != nil {
			violations = append(violations, fmt.Sprintf("%s: %v", image, err))
		}
	}

	if len(violations) > 0 && av.policy.Enforce {
		response.Allowed = false
		response.Status = &AdmissionStatusResult{
			Message: fmt.Sprintf("image signature validation failed: %s", strings.Join(violations, "; ")),
			Code:    403,
		}
	}

	return marshalResponse(review, response)
}

// validateImage checks that the image comes from an allowed registry and has a valid signature.
func (av *AdmissionValidator) validateImage(ctx context.Context, image string) error {
	// Check allowed registries
	if len(av.policy.AllowedRegistries) > 0 {
		allowed := false
		for _, registry := range av.policy.AllowedRegistries {
			if strings.HasPrefix(image, registry) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("registry not in allow list")
		}
	}

	// Look up signatures from the store
	if av.store == nil {
		return errors.New("no signature store configured")
	}

	// Extract image ref and tag/digest
	imageRef, digest := parseImageReference(image)
	if digest == "" {
		// If no digest specified, try to look up by image ref alone
		records, err := av.store.ListByImage(ctx, imageRef)
		if err != nil {
			return fmt.Errorf("lookup signatures: %w", err)
		}
		if len(records) == 0 {
			return errors.New("no signature found")
		}
		// Use the most recent signature's digest
		digest = records[0].Digest
	}

	records, err := av.store.GetByDigest(ctx, digest)
	if err != nil {
		return fmt.Errorf("lookup signatures: %w", err)
	}
	if len(records) == 0 {
		return errors.New("no signature found for digest")
	}

	// Verify at least one signature matches a trusted key
	verified := false
	for _, rec := range records {
		for signerID, pubKey := range av.trustedKeys {
			// Check required signers
			if len(av.policy.RequiredSigners) > 0 {
				found := false
				for _, rs := range av.policy.RequiredSigners {
					if rs == signerID {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}

			sigBytes, err := base64.StdEncoding.DecodeString(rec.Signature)
			if err != nil {
				continue
			}

			if verifySignatureBytes(imageRef, rec.Digest, sigBytes, pubKey) == nil {
				verified = true
				break
			}
		}
		if verified {
			break
		}
	}

	if !verified {
		return errors.New("no valid signature from a trusted signer")
	}
	return nil
}

// verifySignatureBytes wraps the signature verification for admission use.
func verifySignatureBytes(imageRef, digest string, signature []byte, pubKey crypto.PublicKey) error {
	return Verify(context.Background(), imageRef, digest, signature, pubKey)
}

// extractImages pulls container image references from a Kubernetes object.
func extractImages(raw json.RawMessage) ([]string, error) {
	var pod podSpec
	if err := json.Unmarshal(raw, &pod); err != nil {
		return nil, fmt.Errorf("unmarshal object: %w", err)
	}

	var images []string
	addContainerImages := func(containers []containerSpec) {
		for _, c := range containers {
			if c.Image != "" {
				images = append(images, c.Image)
			}
		}
	}

	// Direct pod
	addContainerImages(pod.Spec.Containers)
	addContainerImages(pod.Spec.InitContainers)

	// Templated workload (Deployment, StatefulSet, etc.)
	if pod.SpecTemplate != nil {
		addContainerImages(pod.SpecTemplate.Spec.Containers)
		addContainerImages(pod.SpecTemplate.Spec.InitContainers)
	}

	if len(images) == 0 {
		return nil, errors.New("no container images found in object")
	}
	return images, nil
}

// parseImageReference splits an image reference into the ref and digest parts.
// Returns (imageRef, digest). Digest may be empty if not present.
func parseImageReference(image string) (string, string) {
	// Check for digest separator
	if idx := strings.Index(image, "@sha256:"); idx >= 0 {
		return image[:idx], image[idx+1:] // digest includes "sha256:"
	}
	return image, ""
}

// marshalResponse builds the final AdmissionReview response JSON.
func marshalResponse(review AdmissionReview, response *AdmissionResponse) ([]byte, error) {
	review.Response = response
	review.Request = nil // Response-only review

	respBytes, err := json.Marshal(review)
	if err != nil {
		return nil, fmt.Errorf("imagesign/admission: marshal response: %w", err)
	}
	return respBytes, nil
}

// ExtractImagesFromPod is exported for testing: extracts images from raw pod JSON.
func ExtractImagesFromPod(raw []byte) ([]string, error) {
	return extractImages(raw)
}

// ValidatePublicKey checks that a key is a supported type for verification.
func ValidatePublicKey(key crypto.PublicKey) error {
	switch key.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
		return nil
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}
}
