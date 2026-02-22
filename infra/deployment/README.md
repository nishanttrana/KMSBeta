# Deployment Configuration

- `deployment.yaml`: active feature profile configuration.
- `deployment.schema.json`: JSON schema for `deployment.yaml`.

The first-boot wizard writes this file and `infra/scripts/parse-deployment.sh` converts it to Docker Compose profiles.
