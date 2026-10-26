//go:build integration

package storage_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aupv9/warden/backend/internal/storage"
)

// Same image and CORS flag as docker-compose.yml.
const (
	seaweedImage = "chrislusf/seaweedfs:4.48@sha256:4e61d15fd35994cb1e43e1e553dff106794841fd9a99ade2fc8c8bfce4d7872d"
	devOrigin    = "http://localhost:5173"
)

const (
	accessKey = "itest-access-key"
	secretKey = "itest-secret-key-0123456789"
)

var endpoint string

func TestMain(m *testing.M) {
	ctx := context.Background()
	cfg := fmt.Sprintf(`{"identities":[{"name":"warden","credentials":[{"accessKey":%q,"secretKey":%q}],"actions":["Read","Write","List","Tagging","Admin"]}]}`, accessKey, secretKey)
	c, err := testcontainers.Run(ctx, seaweedImage,
		testcontainers.WithCmd("server", "-s3", "-dir=/data", "-s3.config=/etc/seaweedfs/s3.json", "-s3.allowedOrigins="+devOrigin),
		testcontainers.WithFiles(testcontainers.ContainerFile{Reader: strings.NewReader(cfg), ContainerFilePath: "/etc/seaweedfs/s3.json", FileMode: 0o644}),
		testcontainers.WithExposedPorts("8333/tcp"),
		testcontainers.WithWaitStrategy(wait.ForHTTP("/").WithPort("8333/tcp").WithStatusCodeMatcher(func(int) bool { return true }).WithStartupTimeout(90*time.Second)),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start seaweedfs:", err)
		os.Exit(1)
	}
	code := func() int {
		defer func() { _ = testcontainers.TerminateContainer(c) }()
		host, _ := c.Host(ctx)
		port, err := c.MappedPort(ctx, "8333/tcp")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		endpoint = fmt.Sprintf("http://%s:%s", host, port.Port())
		return m.Run()
	}()
	os.Exit(code)
}

func client(t *testing.T, bucket string) *storage.Client {
	t.Helper()
	c, err := storage.New(storage.Config{Endpoint: endpoint, Bucket: bucket, AccessKey: accessKey, SecretKey: secretKey, ChecksumHeader: true, MaxObjectBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	// Warden never creates buckets (the operator does); the test uses the raw SDK.
	admin := s3.New(s3.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(endpoint), UsePathStyle: true,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}, nil
		}),
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// SeaweedFS may still be wiring its filer right after the port opens.
	for i := 0; ; i++ {
		if err = c.Ping(ctx); err == nil {
			break
		}
		_, _ = admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
		if i == 20 {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
	}
	return c
}

func put(t *testing.T, url string, headers map[string]string, body []byte) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestPresignedUploadRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := client(t, "warden-itest")
	body := bytes.Repeat([]byte("PK\x03\x04 warden "), 100)
	key := "scans/org/scan-1.zip"

	url, headers, err := c.PresignPut(ctx, key, int64(len(body)), sum(body), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(url, "content-length%3Bhost%3Bx-amz-checksum-sha256") {
		t.Fatalf("Content-Length and the checksum must be signed: %s", url)
	}
	if code := put(t, url, headers, body); code != http.StatusOK {
		t.Fatalf("PUT status %d", code)
	}
	size, err := c.Head(ctx, key)
	if err != nil || size != int64(len(body)) {
		t.Fatalf("head %d %v", size, err)
	}
	dest := filepath.Join(t.TempDir(), "src.zip")
	if err := c.Download(ctx, key, dest); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(got, body) {
		t.Fatal("downloaded body differs")
	}
	if err := c.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Head(ctx, key); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("head after delete: %v", err)
	}
	if err := c.Download(ctx, key, filepath.Join(t.TempDir(), "x")); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("download after delete: %v", err)
	}
	if err := c.Delete(ctx, key); err != nil {
		t.Fatalf("deleting a missing object must succeed: %v", err)
	}
}

// The store itself refuses a body other than the one the API presigned.
func TestPresignedUploadRejectsOtherBodies(t *testing.T) {
	ctx := context.Background()
	c := client(t, "warden-itest")
	body := bytes.Repeat([]byte("a"), 1000)
	key := "scans/org/scan-2.zip"
	url, headers, err := c.PresignPut(ctx, key, int64(len(body)), sum(body), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if code := put(t, url, headers, bytes.Repeat([]byte("a"), 5000)); code < 400 {
		t.Errorf("larger body accepted: %d", code)
	}
	if code := put(t, url, nil, body); code < 400 {
		t.Errorf("PUT without the signed checksum header accepted: %d", code)
	}
	if code := put(t, url, headers, bytes.Repeat([]byte("b"), 1000)); code < 400 {
		t.Errorf("same-size body with a different SHA-256 accepted: %d", code)
	}
	if _, err := c.Head(ctx, key); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("a rejected upload left an object: %v", err)
	}
}

func TestDownloadEnforcesMaxSize(t *testing.T) {
	ctx := context.Background()
	c := client(t, "warden-itest")
	body := bytes.Repeat([]byte("z"), (1<<20)+1)
	key := "scans/org/big.zip"
	url, headers, err := c.PresignPut(ctx, key, int64(len(body)), sum(body), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if code := put(t, url, headers, body); code != http.StatusOK {
		t.Fatalf("PUT status %d", code)
	}
	dest := filepath.Join(t.TempDir(), "big.zip")
	if err := c.Download(ctx, key, dest); !errors.Is(err, storage.ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Fatal("partial download left on disk")
	}
	_ = c.Delete(ctx, key)
}

// The dev store allows browser uploads from the web UI's origin only.
func TestUploadCORSPreflight(t *testing.T) {
	ctx := context.Background()
	c := client(t, "warden-itest-cors")
	url, _, err := c.PresignPut(ctx, "scans/org/cors.zip", 10, strings.Repeat("0", 64), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	preflight := func(origin string) *http.Response {
		req, _ := http.NewRequest(http.MethodOptions, url, nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "PUT")
		req.Header.Set("Access-Control-Request-Headers", "x-amz-checksum-sha256")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if resp := preflight(devOrigin); resp.Header.Get("Access-Control-Allow-Origin") != devOrigin {
		t.Fatalf("preflight: status %d, headers %v", resp.StatusCode, resp.Header)
	}
	if got := preflight("http://evil.example").Header.Get("Access-Control-Allow-Origin"); got == "http://evil.example" || got == "*" {
		t.Fatalf("preflight from another origin allowed: %q", got)
	}
}
