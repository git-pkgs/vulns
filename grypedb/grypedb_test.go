package grypedb

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDownloadVerifiesChecksum(t *testing.T) {
	dbContent := []byte("fake database content for checksum test")

	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	if _, err := gw.Write(dbContent); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	gzData := gzBuf.Bytes()

	h := sha256.Sum256(gzData)
	goodChecksum := "sha256:" + hex.EncodeToString(h[:])

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/listing.json" {
			listing := dbListing{
				Available: []dbEntry{{
					Built:    time.Now(),
					Version:  5,
					URL:      "http://" + r.Host + "/db.tar.gz",
					Checksum: goodChecksum,
				}},
			}
			_ = json.NewEncoder(w).Encode(listing)
			return
		}
		_, _ = w.Write(gzData)
	}))
	defer ts.Close()

	destDir := t.TempDir()
	path, err := downloadFrom(context.Background(), ts.URL+"/listing.json", destDir)
	if err != nil {
		t.Fatalf("download with good checksum failed: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, dbContent) {
		t.Error("downloaded content does not match expected")
	}
}

func TestDownloadRejectsChecksumMismatch(t *testing.T) {
	dbContent := []byte("database content")

	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, _ = gw.Write(dbContent)
	_ = gw.Close()
	gzData := gzBuf.Bytes()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/listing.json" {
			listing := dbListing{
				Available: []dbEntry{{
					Built:    time.Now(),
					Version:  5,
					URL:      "http://" + r.Host + "/db.tar.gz",
					Checksum: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
				}},
			}
			_ = json.NewEncoder(w).Encode(listing)
			return
		}
		_, _ = w.Write(gzData)
	}))
	defer ts.Close()

	destDir := t.TempDir()
	_, err := downloadFrom(context.Background(), ts.URL+"/listing.json", destDir)
	if err == nil {
		t.Fatal("expected checksum mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch error, got: %v", err)
	}
}
