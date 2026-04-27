package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gogithub "github.com/google/go-github/v85/github"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// enabledPlugins lists the plugins to run.
// "lockfile" is an osv-scanner preset that covers all lock file / manifest
// extractors across every ecosystem. Unwanted ecosystems are trimmed via
// disabledPlugins below.
// GitHub Actions workflow scanning is not supported by osv-scanner at this time.
var enabledPlugins = []string{
	"lockfile", // all lock file extractors (go, npm, dotnet, python, java, ruby, rust, …)
	"sbom",     // SPDX / CycloneDX files
}

// disabledPlugins removes ecosystems we don't care about from the "lockfile" preset.
var disabledPlugins = []string{
	// Java
	"java/gradlelockfile",
	"java/gradleverificationmetadataxml",
	"java/pomxml",
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <github-org> [--plugins <file>] [--ignore-repos <file>] [--slack-channel <channel-id>] [--log-level debug|info|warn|error]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Set GITHUB_TOKEN env var for private repos or to avoid rate limits.\n")
		fmt.Fprintf(os.Stderr, "Set SLACK_TOKEN env var (xoxb-...) to enable Slack file upload.\n")
		os.Exit(1)
	}

	org := os.Args[1]
	token := os.Getenv("GITHUB_TOKEN")

	// Parse optional flags
	logLevel := slog.LevelWarn
	var ignoreRepos map[string]struct{}
	var slackChannel string
	for i := 2; i < len(os.Args)-1; i++ {
		switch os.Args[i] {
		case "--plugins":
			enabled, disabled, err := loadPluginsFile(os.Args[i+1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to read plugins file: %v\n", err)
				os.Exit(1)
			}
			enabledPlugins = enabled
			disabledPlugins = disabled
			fmt.Printf("Loaded %d enabled, %d disabled plugins from %s\n", len(enabledPlugins), len(disabledPlugins), os.Args[i+1])
		case "--ignore-repos":
			var err error
			ignoreRepos, err = loadIgnoreRepos(os.Args[i+1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to read ignore-repos file: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Ignoring %d repos from %s\n", len(ignoreRepos), os.Args[i+1])
		case "--slack-channel":
			slackChannel = os.Args[i+1]
		case "--log-level":
			if err := logLevel.UnmarshalText([]byte(os.Args[i+1])); err != nil {
				fmt.Fprintf(os.Stderr, "Invalid log level %q: use debug, info, warn, or error\n", os.Args[i+1])
				os.Exit(1)
			}
		}
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	ctx := context.Background()

	ghClient := gogithub.NewClient(nil)
	if token != "" {
		ghClient = ghClient.WithAuthToken(token)
	}

	fmt.Printf("Fetching repos for org: %s\n", org)
	repos, err := listOrgRepos(ctx, ghClient, org)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list repos: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Found %d repos\n", len(repos))

	var skippedRepos []string
	if len(ignoreRepos) > 0 {
		filtered := repos[:0]
		for _, r := range repos {
			if _, skip := ignoreRepos[r.GetName()]; skip {
				skippedRepos = append(skippedRepos, r.GetName())
			} else {
				filtered = append(filtered, r)
			}
		}
		sort.Strings(skippedRepos)
		fmt.Printf("Scanning %d repos (%d ignored)\n", len(filtered), len(skippedRepos))
		repos = filtered
	}
	fmt.Println()

	outFile, err := os.Create("scan-results.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()

	fmt.Fprintf(outFile, "OSV Scanner Results\n")
	fmt.Fprintf(outFile, "Org:            %s\n", org)
	fmt.Fprintf(outFile, "Scan time:      %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(outFile, "Repos scanned:  %d\n", len(repos))
	fmt.Fprintf(outFile, "Repos ignored:  %d\n", len(skippedRepos))
	if len(skippedRepos) > 0 {
		fmt.Fprintf(outFile, "\nIgnored repos:\n")
		for _, name := range skippedRepos {
			fmt.Fprintf(outFile, "  - %s\n", name)
		}
	}
	fmt.Fprintf(outFile, "%s\n\n", strings.Repeat("=", 80))

	// Use a single temp dir; clone each repo into a subdir, remove after scan.
	tmpDir, err := os.MkdirTemp("", "osv-scan-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	totalVulns := 0
	reposWithVulns := 0
	var vulnRepos []repoVulnCount

	var cloneAuth *githttp.BasicAuth
	if token != "" {
		cloneAuth = &githttp.BasicAuth{
			Username: "x-access-token",
			Password: token,
		}
	}

	for i, repo := range repos {
		repoName := repo.GetName()
		cloneURL := repo.GetCloneURL()

		fmt.Printf("[%d/%d] %s\n", i+1, len(repos), repoName)

		repoDir := filepath.Join(tmpDir, repoName)

		_, cloneErr := gogit.PlainCloneContext(ctx, repoDir, false, &gogit.CloneOptions{
			URL:   cloneURL,
			Auth:  cloneAuth,
			Depth: 1,
		})
		if cloneErr != nil {
			if errors.Is(cloneErr, gogit.ErrRepositoryNotExists) || cloneErr.Error() == "remote repository is empty" {
				fmt.Printf("  → empty, skipping\n")
				fmt.Fprintf(outFile, "## %s\n  Empty repository, skipped\n\n", repoName)
			} else {
				msg := fmt.Sprintf("clone failed: %v", cloneErr)
				fmt.Fprintf(os.Stderr, "  %s\n", msg)
				fmt.Fprintf(outFile, "## %s\n  ERROR: %s\n\n", repoName, msg)
			}
			continue
		}

		results, scanErr := osvscanner.DoScan(osvscanner.ScannerActions{
			DirectoryPaths: []string{repoDir},
			Recursive:      true,
			ExperimentalScannerActions: osvscanner.ExperimentalScannerActions{
				PluginsNoDefaults: true,
				PluginsEnabled:    enabledPlugins,
				PluginsDisabled:   disabledPlugins,
			},
		})

		count := writeRepoResults(outFile, org, repoName, repoDir, results, scanErr)
		totalVulns += count
		if count > 0 {
			reposWithVulns++
			vulnRepos = append(vulnRepos, repoVulnCount{repoName, count})
			fmt.Printf("  → %d vulnerability/ies found\n", count)
		} else {
			fmt.Printf("  → clean\n")
		}

		// Remove cloned repo before proceeding to the next one.
		os.RemoveAll(repoDir)
	}

	// Summary footer
	fmt.Fprintf(outFile, "%s\n", strings.Repeat("=", 80))
	fmt.Fprintf(outFile, "SUMMARY\n")
	fmt.Fprintf(outFile, "Repos scanned:             %d\n", len(repos))
	fmt.Fprintf(outFile, "Repos with vulnerabilities: %d\n", reposWithVulns)
	fmt.Fprintf(outFile, "Total vulnerabilities:      %d\n", totalVulns)

	fmt.Printf("\nDone. Results written to scan-results.txt\n")
	fmt.Printf("Repos with vulnerabilities: %d / %d\n", reposWithVulns, len(repos))
	fmt.Printf("Total vulnerabilities:      %d\n", totalVulns)

	if slackChannel != "" {
		slackToken := os.Getenv("SLACK_TOKEN")
		if slackToken == "" {
			fmt.Fprintln(os.Stderr, "SLACK_TOKEN env var not set, skipping Slack upload")
		} else if err := uploadToSlack(slackToken, slackChannel, org, len(repos), len(skippedRepos), reposWithVulns, totalVulns, vulnRepos); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to upload to Slack: %v\n", err)
		} else {
			fmt.Println("Slack file uploaded.")
			os.Remove("scan-results.txt")
		}
	}
}

type repoVulnCount struct {
	name  string
	count int
}

func uploadToSlack(token, channel, org string, scanned, ignored, reposWithVulns, totalVulns int, vulnRepos []repoVulnCount) error {
	fileBytes, err := os.ReadFile("scan-results.txt")
	if err != nil {
		return fmt.Errorf("read scan-results.txt: %w", err)
	}

	filename := fmt.Sprintf("osv-scan-%s-%s.txt", org, time.Now().Format("2006-01-02"))

	// Step 1: get an upload URL from Slack.
	uploadURL, fileID, err := slackGetUploadURL(token, filename, len(fileBytes))
	if err != nil {
		return fmt.Errorf("get upload URL: %w", err)
	}

	// Step 2: PUT the file content directly to the upload URL.
	putReq, err := http.NewRequest(http.MethodPost, uploadURL, bytes.NewReader(fileBytes))
	if err != nil {
		return err
	}
	putReq.Header.Set("Content-Type", "application/octet-stream")
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		return fmt.Errorf("upload file: %w", err)
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload file: HTTP %d", putResp.StatusCode)
	}

	// Step 3: complete the upload — share to channel with summary comment.
	var comment strings.Builder
	if totalVulns == 0 {
		comment.WriteString(fmt.Sprintf(":white_check_mark: *OSV Scanner — %s*\n", org))
		comment.WriteString(fmt.Sprintf("No vulnerabilities found across %d repos.", scanned))
	} else {
		comment.WriteString(fmt.Sprintf(":warning: *OSV Scanner — %s*\n", org))
		stats := fmt.Sprintf("Repos scanned: %d", scanned)
		if ignored > 0 {
			stats += fmt.Sprintf(" (%d ignored)", ignored)
		}
		stats += fmt.Sprintf(" | Repos with vulnerabilities: %d | Total vulnerabilities: %d", reposWithVulns, totalVulns)
		comment.WriteString(stats + "\n")
		comment.WriteString("*Affected repos:*\n")
		for _, r := range vulnRepos {
			comment.WriteString(fmt.Sprintf("• %s — %d\n", r.name, r.count))
		}
	}

	if err := slackCompleteUpload(token, channel, fileID, fmt.Sprintf("OSV Scanner — %s", org), comment.String()); err != nil {
		return fmt.Errorf("complete upload: %w", err)
	}
	return nil
}

func slackGetUploadURL(token, filename string, length int) (uploadURL, fileID string, err error) {
	form := url.Values{}
	form.Set("filename", filename)
	form.Set("length", fmt.Sprintf("%d", length))
	req, err := http.NewRequest(http.MethodPost, "https://slack.com/api/files.getUploadURLExternal", strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var result struct {
		OK        bool   `json:"ok"`
		Error     string `json:"error"`
		UploadURL string `json:"upload_url"`
		FileID    string `json:"file_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", err
	}
	if !result.OK {
		return "", "", fmt.Errorf("slack API error: %s", result.Error)
	}
	return result.UploadURL, result.FileID, nil
}

func slackCompleteUpload(token, channel, fileID, title, comment string) error {
	body, _ := json.Marshal(map[string]any{
		"files":           []map[string]string{{"id": fileID, "title": title}},
		"channel_id":      channel,
		"initial_comment": comment,
	})
	req, err := http.NewRequest(http.MethodPost, "https://slack.com/api/files.completeUploadExternal", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if !result.OK {
		return fmt.Errorf("slack API error: %s", result.Error)
	}
	return nil
}

// loadIgnoreRepos reads a list of repo names to skip — one name per line.
// Lines starting with # and blank lines are ignored.
func loadIgnoreRepos(path string) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	repos := make(map[string]struct{})
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		repos[line] = struct{}{}
	}
	return repos, nil
}

// loadPluginsFile reads a plugin list from a file — one plugin name per line.
// Lines starting with # and blank lines are ignored.
// Lines starting with - are added to the disabled list (e.g. "-java/pomxml").
func loadPluginsFile(path string) (enabled, disabled []string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-") {
			disabled = append(disabled, strings.TrimPrefix(line, "-"))
		} else {
			enabled = append(enabled, line)
		}
	}
	if len(enabled) == 0 {
		return nil, nil, fmt.Errorf("no enabled plugins found in %s", path)
	}
	return enabled, disabled, nil
}

func listOrgRepos(ctx context.Context, client *gogithub.Client, org string) ([]*gogithub.Repository, error) {
	var all []*gogithub.Repository
	opts := &gogithub.RepositoryListByOrgOptions{
		Type:        "all",
		ListOptions: gogithub.ListOptions{PerPage: 100},
	}
	for {
		page, resp, err := client.Repositories.ListByOrg(ctx, org, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

func writeRepoResults(f *os.File, org, repoName, repoDir string, results models.VulnerabilityResults, scanErr error) int {
	fmt.Fprintf(f, "## %s\n", repoName)

	if scanErr != nil && !errors.Is(scanErr, osvscanner.ErrVulnerabilitiesFound) {
		if errors.Is(scanErr, osvscanner.ErrNoPackagesFound) {
			fmt.Fprintf(f, "  No package manifests found\n\n")
		} else {
			fmt.Fprintf(f, "  Scan error: %v\n\n", scanErr)
		}
		return 0
	}

	flattened := results.Flatten()

	var vulns []models.VulnerabilityFlattened
	for _, v := range flattened {
		if v.Vulnerability != nil {
			vulns = append(vulns, v)
		}
	}

	if len(vulns) == 0 {
		fmt.Fprintf(f, "  No vulnerabilities found\n\n")
		return 0
	}

	headers := []string{"OSV URL", "CVSS", "ECOSYSTEM", "PACKAGE", "VERSION", "FIXED VERSION", "SOURCE"}
	rows := make([][]string, 0, len(vulns))
	for _, v := range vulns {
		vuln := v.Vulnerability
		osvURL := "https://osv.dev/" + vuln.GetId()
		cvss := cvssBaseScore(vuln.GetSeverity())
		ecosystem := string(v.Package.Ecosystem)
		pkg := v.Package.Name
		version := v.Package.Version
		fixed := fixedVersion(vuln.GetAffected(), ecosystem, pkg)
		src := strings.TrimPrefix(v.Source.Path, repoDir+string(filepath.Separator))
		rows = append(rows, []string{osvURL, cvss, ecosystem, pkg, version, fixed, src})
	}

	renderTable(f, headers, rows)
	fmt.Fprintln(f)
	return len(vulns)
}

// cvssBaseScore returns the highest CVSS base score from a list of severities,
// formatted to one decimal place (e.g. "6.6"). Returns "" if none computable.
func cvssBaseScore(severities []*osvschema.Severity) string {
	best := -1.0
	for _, s := range severities {
		score := s.GetScore()
		var val float64
		switch {
		case strings.HasPrefix(score, "CVSS:3.0"):
			if v, err := gocvss30.ParseVector(score); err == nil {
				val = v.BaseScore()
			}
		case strings.HasPrefix(score, "CVSS:3.1"):
			if v, err := gocvss31.ParseVector(score); err == nil {
				val = v.BaseScore()
			}
		default:
			continue
		}
		if val > best {
			best = val
		}
	}
	if best < 0 {
		return ""
	}
	return fmt.Sprintf("%.1f", best)
}

// fixedVersion returns the first fixed version found for the given package across
// all affected entries in the vulnerability.
func fixedVersion(affected []*osvschema.Affected, ecosystem, pkg string) string {
	for _, a := range affected {
		if a.GetPackage().GetEcosystem() != ecosystem || a.GetPackage().GetName() != pkg {
			continue
		}
		for _, r := range a.GetRanges() {
			for _, e := range r.GetEvents() {
				if f := e.GetFixed(); f != "" {
					return f
				}
			}
		}
	}
	return ""
}

// renderTable writes a Unicode box-drawing table to f.
func renderTable(f *os.File, headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	bar := func(left, mid, right, fill string) string {
		var b strings.Builder
		b.WriteString(left)
		for i, w := range widths {
			b.WriteString(strings.Repeat(fill, w+2))
			if i < len(widths)-1 {
				b.WriteString(mid)
			}
		}
		b.WriteString(right)
		return b.String()
	}

	printRow := func(row []string) {
		fmt.Fprint(f, "│")
		for i, cell := range row {
			fmt.Fprintf(f, " %-*s │", widths[i], cell)
		}
		fmt.Fprintln(f)
	}

	fmt.Fprintln(f, bar("╭", "┬", "╮", "─"))
	printRow(headers)
	fmt.Fprintln(f, bar("├", "┼", "┤", "─"))
	for _, row := range rows {
		printRow(row)
	}
	fmt.Fprintln(f, bar("╰", "┴", "╯", "─"))
}
