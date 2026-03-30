package sprawlscanner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	maxS3ObjectSize = 10 * 1024 * 1024 // 10MB
)

// binaryContentTypes lists content types that should be skipped during scanning.
var binaryContentTypes = map[string]bool{
	"application/octet-stream":    true,
	"application/zip":             true,
	"application/gzip":            true,
	"application/x-tar":           true,
	"application/pdf":             true,
	"image/png":                   true,
	"image/jpeg":                  true,
	"image/gif":                   true,
	"image/webp":                  true,
	"video/mp4":                   true,
	"audio/mpeg":                  true,
	"application/x-executable":    true,
	"application/x-mach-binary":   true,
	"application/java-archive":    true,
	"application/wasm":            true,
}

// S3Client abstracts the AWS S3 API calls needed for scanning.
type S3Client interface {
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
}

// S3Source scans AWS S3 buckets for secrets.
type S3Source struct {
	client S3Client
}

// NewS3Source creates a new S3 bucket scan source.
func NewS3Source(client S3Client) *S3Source {
	return &S3Source{client: client}
}

// Name returns the source identifier.
func (s *S3Source) Name() string {
	return "s3"
}

// Scan scans an S3 bucket for secrets.
// ConnectionConfig should contain:
//   - "bucket": the S3 bucket name (required)
//   - "prefix": optional key prefix to limit the scan
//   - "region": optional AWS region override
func (s *S3Source) Scan(ctx context.Context, config ScanConfig) ([]Finding, error) {
	bucket := config.ConnectionConfig["bucket"]
	if bucket == "" {
		return nil, fmt.Errorf("bucket is required in connection_config")
	}
	prefix := config.ConnectionConfig["prefix"]

	var allFindings []Finding
	var continuationToken *string

	for {
		if ctx.Err() != nil {
			return allFindings, ctx.Err()
		}

		input := &s3.ListObjectsV2Input{
			Bucket:            aws.String(bucket),
			ContinuationToken: continuationToken,
		}
		if prefix != "" {
			input.Prefix = aws.String(prefix)
		}

		output, err := s.client.ListObjectsV2(ctx, input)
		if err != nil {
			return allFindings, fmt.Errorf("failed to list S3 objects: %w", err)
		}

		for _, obj := range output.Contents {
			if ctx.Err() != nil {
				return allFindings, ctx.Err()
			}

			key := aws.ToString(obj.Key)

			// Skip objects too large
			if obj.Size != nil && *obj.Size > maxS3ObjectSize {
				continue
			}
			// Skip zero-size (directory markers)
			if obj.Size != nil && *obj.Size == 0 {
				continue
			}

			// Check content type via HEAD
			if s.isBinaryObject(ctx, bucket, key) {
				continue
			}

			findings, err := s.scanObject(ctx, bucket, key, config)
			if err != nil {
				continue // skip objects we cannot read
			}
			allFindings = append(allFindings, findings...)
		}

		if !aws.ToBool(output.IsTruncated) {
			break
		}
		continuationToken = output.NextContinuationToken
	}

	return allFindings, nil
}

// isBinaryObject checks if an S3 object has a binary content type.
func (s *S3Source) isBinaryObject(ctx context.Context, bucket, key string) bool {
	head, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return false // assume text if we can't determine
	}

	ct := aws.ToString(head.ContentType)
	if ct == "" {
		return false
	}

	// Check known binary types
	if binaryContentTypes[ct] {
		return true
	}

	// Skip anything that doesn't look like text
	if !strings.HasPrefix(ct, "text/") &&
		!strings.Contains(ct, "json") &&
		!strings.Contains(ct, "xml") &&
		!strings.Contains(ct, "yaml") &&
		!strings.Contains(ct, "yml") &&
		ct != "application/javascript" &&
		ct != "application/x-sh" {
		return true
	}

	return false
}

// scanObject downloads and scans a single S3 object.
func (s *S3Source) scanObject(ctx context.Context, bucket, key string, config ScanConfig) ([]Finding, error) {
	output, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get object s3://%s/%s: %w", bucket, key, err)
	}
	defer output.Body.Close()

	// Limit the read to maxS3ObjectSize
	reader := io.LimitReader(output.Body, maxS3ObjectSize)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	location := fmt.Sprintf("s3://%s/%s", bucket, key)
	var findings []Finding
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		lineFindings := ScanLine(line, lineNum, location, config.Patterns)
		for i := range lineFindings {
			lineFindings[i].SourceType = "s3"
			lineFindings[i].TenantID = config.TenantID
		}
		findings = append(findings, lineFindings...)
	}

	return findings, scanner.Err()
}
