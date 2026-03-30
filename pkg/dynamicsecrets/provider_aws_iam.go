package dynamicsecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// AWSIAMProviderConfig configures the AWS IAM dynamic credentials provider.
type AWSIAMProviderConfig struct {
	Region          string
	AccessKeyID     string // admin credentials (empty = use default chain)
	SecretAccessKey string
	PolicyARN       string // IAM policy to attach to generated users
	PathPrefix      string // IAM path prefix for generated users (default "/dynamic/")
}

// AWSIAMProvider generates ephemeral AWS IAM users with access keys.
type AWSIAMProvider struct {
	client    *iam.Client
	policyARN string
	pathPrefix string
}

// NewAWSIAMProvider creates a provider that manages dynamic AWS IAM users.
func NewAWSIAMProvider(ctx context.Context, cfg AWSIAMProviderConfig) (*AWSIAMProvider, error) {
	if cfg.PolicyARN == "" {
		return nil, fmt.Errorf("dynamicsecrets/aws_iam: policy ARN is required")
	}
	if cfg.PathPrefix == "" {
		cfg.PathPrefix = "/dynamic/"
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}

	var opts []func(*awsconfig.LoadOptions) error
	opts = append(opts, awsconfig.WithRegion(cfg.Region))

	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("dynamicsecrets/aws_iam: load aws config: %w", err)
	}

	return &AWSIAMProvider{
		client:     iam.NewFromConfig(awsCfg),
		policyARN:  cfg.PolicyARN,
		pathPrefix: cfg.PathPrefix,
	}, nil
}

func (p *AWSIAMProvider) Generate(ctx context.Context, req LeaseRequest) (*Credential, error) {
	userName := fmt.Sprintf("v-dyn-%s-%s", sanitizeIdentifier(req.Role), randomHex(8))
	expiresAt := time.Now().Add(req.TTL)

	// Step 1: Create IAM user
	createUserOut, err := p.client.CreateUser(ctx, &iam.CreateUserInput{
		UserName: aws.String(userName),
		Path:     aws.String(p.pathPrefix),
		Tags: []iamTypes.Tag{
			{Key: aws.String("managed-by"), Value: aws.String("vecta-kms-dynamic-secrets")},
			{Key: aws.String("tenant-id"), Value: aws.String(req.TenantID)},
			{Key: aws.String("expires-at"), Value: aws.String(expiresAt.UTC().Format(time.RFC3339))},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("dynamicsecrets/aws_iam: create user: %w", err)
	}

	// Step 2: Attach policy
	_, err = p.client.AttachUserPolicy(ctx, &iam.AttachUserPolicyInput{
		UserName:  aws.String(userName),
		PolicyArn: aws.String(p.policyARN),
	})
	if err != nil {
		// Cleanup: delete user on policy attach failure
		_, _ = p.client.DeleteUser(ctx, &iam.DeleteUserInput{UserName: aws.String(userName)})
		return nil, fmt.Errorf("dynamicsecrets/aws_iam: attach policy: %w", err)
	}

	// Step 3: Create access key
	createKeyOut, err := p.client.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		// Cleanup
		_, _ = p.client.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{
			UserName: aws.String(userName), PolicyArn: aws.String(p.policyARN),
		})
		_, _ = p.client.DeleteUser(ctx, &iam.DeleteUserInput{UserName: aws.String(userName)})
		return nil, fmt.Errorf("dynamicsecrets/aws_iam: create access key: %w", err)
	}

	credID := "awscred_" + randomHex(16)
	leaseID := "awslease_" + randomHex(16)

	_ = createUserOut // used for ARN if needed in future

	return &Credential{
		ID:        credID,
		TenantID:  req.TenantID,
		Provider:  "aws_iam",
		Username:  userName,
		Password:  aws.ToString(createKeyOut.AccessKey.SecretAccessKey),
		Token:     aws.ToString(createKeyOut.AccessKey.AccessKeyId),
		Endpoint:  "https://iam.amazonaws.com",
		ExpiresAt: expiresAt,
		LeaseID:   leaseID,
	}, nil
}

func (p *AWSIAMProvider) Revoke(ctx context.Context, credentialID string) error {
	// credentialID here is the IAM username for direct revocation
	return p.RevokeByUsername(ctx, credentialID)
}

// RevokeByUsername removes an IAM user, its access keys, and detaches policies.
func (p *AWSIAMProvider) RevokeByUsername(ctx context.Context, username string) error {
	// List and delete all access keys
	listKeysOut, err := p.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return fmt.Errorf("dynamicsecrets/aws_iam: list access keys for %q: %w", username, err)
	}
	for _, key := range listKeysOut.AccessKeyMetadata {
		_, err := p.client.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
			UserName:    aws.String(username),
			AccessKeyId: key.AccessKeyId,
		})
		if err != nil {
			return fmt.Errorf("dynamicsecrets/aws_iam: delete access key %q: %w", aws.ToString(key.AccessKeyId), err)
		}
	}

	// Detach managed policy
	_, err = p.client.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{
		UserName:  aws.String(username),
		PolicyArn: aws.String(p.policyARN),
	})
	if err != nil {
		return fmt.Errorf("dynamicsecrets/aws_iam: detach policy from %q: %w", username, err)
	}

	// Delete the user
	_, err = p.client.DeleteUser(ctx, &iam.DeleteUserInput{
		UserName: aws.String(username),
	})
	if err != nil {
		return fmt.Errorf("dynamicsecrets/aws_iam: delete user %q: %w", username, err)
	}

	return nil
}
