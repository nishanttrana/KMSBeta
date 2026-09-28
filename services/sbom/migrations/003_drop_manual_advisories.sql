-- 003: remove the offline advisory store (2.19.0-beta).
--
-- CVE tracking is the job of the customer's vulnerability-management tool,
-- which consumes the SBOM this service exports (CycloneDX/SPDX). The KMS no
-- longer matches its components against Trivy, OSV or hand-entered
-- advisories; the routes, the Vulnerabilities tab and the bundled Trivy
-- binary are removed with this table.

DROP TABLE IF EXISTS sbom_manual_advisories;
