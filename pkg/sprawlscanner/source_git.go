package sprawlscanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GitSource scans git repositories for secrets in current files and commit history.
type GitSource struct{}

// NewGitSource creates a new git repository scan source.
func NewGitSource() *GitSource {
	return &GitSource{}
}

// Name returns the source identifier.
func (g *GitSource) Name() string {
	return "git"
}

// Scan scans a git repository for secrets.
// ConnectionConfig should contain:
//   - "repo_url": URL to clone (mutually exclusive with local_path)
//   - "local_path": path to an existing local repo
//   - "scan_history": "true" to also scan git history (default: false)
//   - "branch": branch to scan (default: all)
func (g *GitSource) Scan(ctx context.Context, config ScanConfig) ([]Finding, error) {
	repoURL := config.ConnectionConfig["repo_url"]
	localPath := config.ConnectionConfig["local_path"]
	scanHistory := config.ConnectionConfig["scan_history"] == "true"

	if repoURL == "" && localPath == "" {
		return nil, fmt.Errorf("either repo_url or local_path is required")
	}

	// Clone if needed
	repoDir := localPath
	if repoURL != "" {
		tmpDir, err := os.MkdirTemp("", "sprawlscan-git-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp dir: %w", err)
		}
		defer os.RemoveAll(tmpDir)

		repoDir = tmpDir

		cmd := exec.CommandContext(ctx, "git", "clone", "--depth=1", repoURL, tmpDir)
		if scanHistory {
			// Full clone needed for history scanning
			cmd = exec.CommandContext(ctx, "git", "clone", repoURL, tmpDir)
		}
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("git clone failed: %w: %s", err, string(output))
		}
	}

	var allFindings []Finding

	// Scan current files
	findings, err := g.scanCurrentFiles(ctx, repoDir, config)
	if err != nil {
		return nil, fmt.Errorf("file scan failed: %w", err)
	}
	allFindings = append(allFindings, findings...)

	// Scan git history if requested
	if scanHistory {
		histFindings, err := g.scanHistory(ctx, repoDir, config)
		if err != nil {
			// Non-fatal: return what we have
			return allFindings, fmt.Errorf("history scan failed (partial results returned): %w", err)
		}
		allFindings = append(allFindings, histFindings...)
	}

	return allFindings, nil
}

// scanCurrentFiles walks all files in the repo and scans each line.
func (g *GitSource) scanCurrentFiles(ctx context.Context, repoDir string, config ScanConfig) ([]Finding, error) {
	var findings []Finding

	// Get list of tracked files (respects .gitignore)
	cmd := exec.CommandContext(ctx, "git", "-C", repoDir, "ls-files", "-z")
	output, err := cmd.Output()
	if err != nil {
		// Fallback: walk the directory manually
		return g.walkAndScan(ctx, repoDir, config)
	}

	files := strings.Split(string(output), "\x00")
	for _, relPath := range files {
		if relPath == "" {
			continue
		}
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}

		fullPath := filepath.Join(repoDir, relPath)

		// Skip binary files
		if isBinaryFile(fullPath) {
			continue
		}

		fileFindings, err := g.scanFile(fullPath, relPath, config)
		if err != nil {
			continue // skip files we cannot read
		}
		for i := range fileFindings {
			fileFindings[i].SourceType = "git"
			fileFindings[i].TenantID = config.TenantID
		}
		findings = append(findings, fileFindings...)
	}

	return findings, nil
}

// walkAndScan is a fallback that walks the filesystem directly.
func (g *GitSource) walkAndScan(ctx context.Context, repoDir string, config ScanConfig) ([]Finding, error) {
	var findings []Finding

	err := filepath.Walk(repoDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Skip .git directory
		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		// Skip binary files
		if isBinaryFile(path) {
			return nil
		}

		relPath, _ := filepath.Rel(repoDir, path)
		fileFindings, err := g.scanFile(path, relPath, config)
		if err != nil {
			return nil
		}
		for i := range fileFindings {
			fileFindings[i].SourceType = "git"
			fileFindings[i].TenantID = config.TenantID
		}
		findings = append(findings, fileFindings...)
		return nil
	})

	return findings, err
}

// scanFile scans a single file line by line against all patterns.
func (g *GitSource) scanFile(fullPath, relPath string, config ScanConfig) ([]Finding, error) {
	f, err := os.Open(fullPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []Finding
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024) // 1MB line buffer
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		lineFindings := ScanLine(line, lineNum, relPath, config.Patterns)
		findings = append(findings, lineFindings...)
	}

	return findings, scanner.Err()
}

// scanHistory uses git log -p to scan diffs in commit history.
func (g *GitSource) scanHistory(ctx context.Context, repoDir string, config ScanConfig) ([]Finding, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", repoDir, "log", "-p", "--all", "--diff-filter=A", "--no-color")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start git log: %w", err)
	}

	var findings []Finding
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	currentFile := ""
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()

		// Track current file in diff
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			lineNum = 0
			continue
		}

		// Only scan added lines in diffs
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			lineNum++
			content := line[1:] // strip leading +
			location := fmt.Sprintf("%s (history)", currentFile)
			lineFindings := ScanLine(content, lineNum, location, config.Patterns)
			for i := range lineFindings {
				lineFindings[i].SourceType = "git_history"
				lineFindings[i].TenantID = config.TenantID
			}
			findings = append(findings, lineFindings...)
		}
	}

	_ = cmd.Wait()
	return findings, scanner.Err()
}

// isBinaryFile checks if a file is binary by reading the first 512 bytes.
func isBinaryFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return true // treat unreadable files as binary
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return true
	}

	// Check for null bytes, which indicate binary content
	return bytes.Contains(buf[:n], []byte{0})
}
