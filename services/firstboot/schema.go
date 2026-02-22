package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v3"
)

const (
	defaultDeploymentSchemaPath = "/opt/vecta/infra/deployment/deployment.schema.json"
	fallbackDeploymentSchemaRel = "infra/deployment/deployment.schema.json"
)

func validateDeploymentSchema(deploymentYAML []byte) error {
	schemaPath, err := resolveDeploymentSchemaPath()
	if err != nil {
		return err
	}

	var raw any
	if err := yaml.Unmarshal(deploymentYAML, &raw); err != nil {
		return fmt.Errorf("decode deployment yaml: %w", err)
	}
	normalized := normalizeYAML(raw)
	payload, err := json.Marshal(normalized)
	if err != nil {
		return fmt.Errorf("marshal deployment payload: %w", err)
	}

	result, err := gojsonschema.Validate(
		gojsonschema.NewReferenceLoader(pathToFileURI(schemaPath)),
		gojsonschema.NewBytesLoader(payload),
	)
	if err != nil {
		return fmt.Errorf("validate schema: %w", err)
	}
	if result.Valid() {
		return nil
	}

	details := make([]string, 0, len(result.Errors()))
	for _, issue := range result.Errors() {
		details = append(details, issue.String())
	}
	return errors.New(strings.Join(details, "; "))
}

func resolveDeploymentSchemaPath() (string, error) {
	candidates := []string{
		strings.TrimSpace(os.Getenv("FIRSTBOOT_DEPLOYMENT_SCHEMA_PATH")),
		defaultDeploymentSchemaPath,
		fallbackDeploymentSchemaRel,
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		path := candidate
		if !filepath.IsAbs(path) {
			abs, err := filepath.Abs(path)
			if err != nil {
				continue
			}
			path = abs
		}
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		return path, nil
	}
	return "", errors.New("deployment schema not found; set FIRSTBOOT_DEPLOYMENT_SCHEMA_PATH")
}

func pathToFileURI(path string) string {
	slashed := filepath.ToSlash(path)
	if strings.HasPrefix(slashed, "/") {
		return "file://" + slashed
	}
	return "file:///" + slashed
}

func normalizeYAML(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = normalizeYAML(val)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[fmt.Sprint(k)] = normalizeYAML(val)
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, val := range t {
			out = append(out, normalizeYAML(val))
		}
		return out
	default:
		return t
	}
}
