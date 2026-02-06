// Package grypedb provides a vulnerability source backed by the Grype vulnerability database.
// The database is a SQLite file that can be downloaded from Anchore's CDN or used locally.
package grypedb

import (
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/vulns"

	_ "modernc.org/sqlite"
)

const (
	// LatestDBURL is the URL to fetch the latest database listing
	LatestDBURL = "https://grype.anchore.io/databases/v6/listing.json"

	DefaultTimeout = 60 * time.Second
)

// Source implements vulns.Source using a local Grype database.
type Source struct {
	db           *sql.DB
	dbDir        string
	httpClient   *http.Client
	autoDownload bool
}

// Option configures a Source.
type Option func(*Source)

// WithHTTPClient sets a custom HTTP client for downloading the database.
func WithHTTPClient(c *http.Client) Option {
	return func(s *Source) {
		s.httpClient = c
	}
}

// WithAutoDownload enables automatic downloading of the database if missing.
func WithAutoDownload() Option {
	return func(s *Source) {
		s.autoDownload = true
	}
}

// New creates a new Grype database source.
// If dbPath points to a directory, it looks for vulnerability.db inside it.
// If dbPath points to a file, it uses that file directly.
// With WithAutoDownload(), downloads the database if missing.
func New(dbPath string, opts ...Option) (*Source, error) {
	s := &Source{
		httpClient: &http.Client{Timeout: DefaultTimeout},
	}
	for _, opt := range opts {
		opt(s)
	}

	// Determine if path is a directory or file
	info, err := os.Stat(dbPath)
	if err == nil && info.IsDir() {
		s.dbDir = dbPath
		dbPath = filepath.Join(dbPath, "vulnerability.db")
	} else if err == nil {
		s.dbDir = filepath.Dir(dbPath)
	} else if os.IsNotExist(err) {
		// Path doesn't exist - treat as directory for auto-download
		s.dbDir = dbPath
		dbPath = filepath.Join(dbPath, "vulnerability.db")
	} else {
		return nil, fmt.Errorf("checking path: %w", err)
	}

	// Check if database exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		if !s.autoDownload {
			return nil, fmt.Errorf("database not found at %s (use WithAutoDownload to fetch automatically)", dbPath)
		}
		// Download the database
		downloadedPath, err := Download(context.Background(), s.dbDir)
		if err != nil {
			return nil, fmt.Errorf("downloading database: %w", err)
		}
		dbPath = downloadedPath
	}

	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Verify it's a valid grype v6 database
	var model int
	err = db.QueryRow("SELECT model FROM db_metadata").Scan(&model)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("reading db metadata: %w", err)
	}
	if model != 6 {
		_ = db.Close()
		return nil, fmt.Errorf("unsupported database model version: %d (expected 6)", model)
	}

	s.db = db
	return s, nil
}

// Download downloads the latest Grype database to the specified directory.
// Returns the path to the downloaded database file.
func Download(ctx context.Context, destDir string) (string, error) {
	client := &http.Client{Timeout: DefaultTimeout}

	// Fetch listing to get latest database URL
	req, err := http.NewRequestWithContext(ctx, "GET", LatestDBURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating listing request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching listing: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("listing request failed with status %d", resp.StatusCode)
	}

	var listing dbListing
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil {
		return "", fmt.Errorf("decoding listing: %w", err)
	}

	if len(listing.Available) == 0 {
		return "", fmt.Errorf("no databases available in listing")
	}

	// Get the most recent database
	latest := listing.Available[0]

	// Download the database archive
	req, err = http.NewRequestWithContext(ctx, "GET", latest.URL, nil)
	if err != nil {
		return "", fmt.Errorf("creating download request: %w", err)
	}

	resp, err = client.Do(req)
	if err != nil {
		return "", fmt.Errorf("downloading database: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	// Create destination directory
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", fmt.Errorf("creating destination directory: %w", err)
	}

	dbPath := filepath.Join(destDir, "vulnerability.db")
	outFile, err := os.Create(dbPath)
	if err != nil {
		return "", fmt.Errorf("creating output file: %w", err)
	}
	defer func() { _ = outFile.Close() }()

	// Decompress if gzipped
	var reader io.Reader = resp.Body
	if strings.HasSuffix(latest.URL, ".gz") {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return "", fmt.Errorf("creating gzip reader: %w", err)
		}
		defer func() { _ = gzReader.Close() }()
		reader = gzReader
	}

	if _, err := io.Copy(outFile, reader); err != nil {
		return "", fmt.Errorf("writing database: %w", err)
	}

	return dbPath, nil
}

// Name returns "grype".
func (s *Source) Name() string {
	return "grype"
}

// Close closes the database connection.
func (s *Source) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Query returns vulnerabilities affecting the package identified by the PURL.
func (s *Source) Query(ctx context.Context, p *purl.PURL) ([]vulns.Vulnerability, error) {
	ecosystem := purlTypeToGrypeEcosystem(p.Type)
	if ecosystem == "" {
		return nil, nil
	}

	// Query affected_package_handles joined with packages
	query := `
		SELECT DISTINCT
			vh.name,
			vh.blob_id,
			vh.published_date,
			vh.modified_date
		FROM affected_package_handles aph
		JOIN packages pkg ON aph.package_id = pkg.id
		JOIN vulnerability_handles vh ON aph.vulnerability_id = vh.id
		WHERE pkg.ecosystem = ? COLLATE NOCASE
		AND pkg.name = ? COLLATE NOCASE
	`

	rows, err := s.db.QueryContext(ctx, query, ecosystem, p.FullName())
	if err != nil {
		return nil, fmt.Errorf("querying database: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []vulns.Vulnerability
	for rows.Next() {
		var name string
		var blobID int64
		var publishedDate, modifiedDate sql.NullTime

		if err := rows.Scan(&name, &blobID, &publishedDate, &modifiedDate); err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}

		v := vulns.Vulnerability{
			ID: name,
		}
		if publishedDate.Valid {
			v.Published = publishedDate.Time
		}
		if modifiedDate.Valid {
			v.Modified = modifiedDate.Time
		}

		// Fetch blob for additional details
		blob, err := s.getBlob(ctx, blobID)
		if err == nil && blob != nil {
			if blob.Summary != "" {
				v.Summary = blob.Summary
			}
			if blob.Detail != "" {
				v.Details = blob.Detail
			}
			v.Aliases = blob.Aliases
			for _, ref := range blob.References {
				v.References = append(v.References, vulns.Reference{
					Type: "WEB",
					URL:  ref.URL,
				})
			}
			for _, sev := range blob.Severities {
				v.Severity = append(v.Severity, vulns.Severity{
					Type:  sev.Scheme,
					Score: sev.Value,
				})
			}
		}

		// Add affected package info
		affected := vulns.Affected{
			Package: vulns.Package{
				Ecosystem: purl.EcosystemToOSV(p.Type),
				Name:      p.FullName(),
				PURL:      p.String(),
			},
		}
		v.Affected = append(v.Affected, affected)

		results = append(results, v)
	}

	return results, rows.Err()
}

// QueryBatch queries multiple packages.
func (s *Source) QueryBatch(ctx context.Context, purls []*purl.PURL) ([][]vulns.Vulnerability, error) {
	results := make([][]vulns.Vulnerability, len(purls))
	for i, p := range purls {
		v, err := s.Query(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("querying %s: %w", p.String(), err)
		}
		results[i] = v
	}
	return results, nil
}

// Get fetches a specific vulnerability by ID.
func (s *Source) Get(ctx context.Context, id string) (*vulns.Vulnerability, error) {
	query := `
		SELECT vh.name, vh.blob_id, vh.published_date, vh.modified_date
		FROM vulnerability_handles vh
		WHERE vh.name = ? COLLATE NOCASE
	`

	var name string
	var blobID int64
	var publishedDate, modifiedDate sql.NullTime

	err := s.db.QueryRowContext(ctx, query, id).Scan(&name, &blobID, &publishedDate, &modifiedDate)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying database: %w", err)
	}

	v := &vulns.Vulnerability{
		ID: name,
	}
	if publishedDate.Valid {
		v.Published = publishedDate.Time
	}
	if modifiedDate.Valid {
		v.Modified = modifiedDate.Time
	}

	// Fetch blob for additional details
	blob, err := s.getBlob(ctx, blobID)
	if err == nil && blob != nil {
		if blob.Summary != "" {
			v.Summary = blob.Summary
		}
		if blob.Detail != "" {
			v.Details = blob.Detail
		}
		v.Aliases = blob.Aliases
		for _, ref := range blob.References {
			v.References = append(v.References, vulns.Reference{
				Type: "WEB",
				URL:  ref.URL,
			})
		}
		for _, sev := range blob.Severities {
			v.Severity = append(v.Severity, vulns.Severity{
				Type:  sev.Scheme,
				Score: sev.Value,
			})
		}
	}

	return v, nil
}

func (s *Source) getBlob(ctx context.Context, id int64) (*vulnerabilityBlob, error) {
	var value string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM blobs WHERE id = ?", id).Scan(&value)
	if err != nil {
		return nil, err
	}

	var blob vulnerabilityBlob
	if err := json.Unmarshal([]byte(value), &blob); err != nil {
		return nil, err
	}
	return &blob, nil
}

func purlTypeToGrypeEcosystem(purlType string) string {
	switch purlType {
	case "npm":
		return "npm"
	case "pypi":
		return "python"
	case "gem":
		return "ruby"
	case "cargo":
		return "rust"
	case "golang":
		return "go"
	case "maven":
		return "java"
	case "nuget":
		return "dotnet"
	case "composer":
		return "php"
	case "hex":
		return "erlang"
	case "pub":
		return "dart"
	case "apk":
		return "apk"
	case "deb":
		return "deb"
	case "rpm":
		return "rpm"
	default:
		return ""
	}
}

// Database types

type dbListing struct {
	Available []dbEntry `json:"available"`
}

type dbEntry struct {
	Built    time.Time `json:"built"`
	Version  int       `json:"version"`
	URL      string    `json:"url"`
	Checksum string    `json:"checksum"`
}

type vulnerabilityBlob struct {
	ID         string      `json:"id"`
	Summary    string      `json:"summary"`
	Detail     string      `json:"detail"`
	Aliases    []string    `json:"aliases"`
	References []reference `json:"references"`
	Severities []severity  `json:"severities"`
}

type reference struct {
	URL string `json:"url"`
}

type severity struct {
	Scheme string `json:"scheme"`
	Value  string `json:"value"`
	Source string `json:"source"`
}
