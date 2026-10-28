// Package storage is the S3-compatible object store client shared by the API
// (presigned uploads, HEAD on start) and the worker (download, delete). It works
// with AWS S3 (virtual-hosted URLs) and SeaweedFS/MinIO (path-style URLs).
package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/aupv9/warden/backend/internal/config"
)

// ErrNotFound is returned by Head and Download when the object doesn't exist.
var ErrNotFound = errors.New("storage: object not found")

// ErrTooLarge is returned by Download when the object exceeds Config.MaxObjectBytes.
var ErrTooLarge = errors.New("storage: object larger than the configured maximum")

// MaxPresignTTL caps presigned URL lifetimes (SigV4 allows up to 7 days; uploads need minutes).
const MaxPresignTTL = time.Hour

const defaultRegion = "us-east-1"

var (
	sha256Hex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	awsEndpoint = regexp.MustCompile(`^s3[.-]([a-z0-9-]+)\.amazonaws\.com$`)
)

type Config struct {
	// Endpoint is the store's base URL, e.g. http://localhost:8333 (SeaweedFS) or
	// https://s3.eu-west-1.amazonaws.com. Empty means AWS S3 in Region.
	Endpoint  string
	Bucket    string
	Region    string // default: inferred from an AWS endpoint, else us-east-1
	AccessKey string
	SecretKey string
	// PathStyle forces path-style URLs (http://host/bucket/key). Default: on for
	// any endpoint that isn't amazonaws.com.
	PathStyle *bool
	// ChecksumHeader adds x-amz-checksum-sha256 to presigned PUTs, so the store
	// itself rejects a body that doesn't match the declared SHA-256. AWS S3 and
	// SeaweedFS verify it; the worker verifies the hash again before extracting.
	ChecksumHeader bool
	// MaxObjectBytes caps Download (0 = no cap). The upload size is pinned by the
	// presigned URL, so this only trips if the store didn't enforce it.
	MaxObjectBytes int64
	// HTTPClient overrides the transport (tests).
	HTTPClient *http.Client
}

// FromSection maps Warden's storage settings onto a Config.
func FromSection(s config.StorageSection) Config {
	return Config{
		Endpoint:       s.Endpoint,
		Bucket:         s.Bucket,
		AccessKey:      s.AccessKey.Reveal(),
		SecretKey:      s.SecretKey.Reveal(),
		ChecksumHeader: true,
	}
}

type Client struct {
	s3      *s3.Client
	presign *s3.PresignClient
	bucket  string
	cfg     Config
}

func isAWSHost(host string) bool {
	return host == "s3.amazonaws.com" || strings.HasSuffix(host, ".amazonaws.com")
}

// New validates cfg and builds a client. It makes no network calls.
func New(cfg Config) (*Client, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("storage: bucket is required")
	}
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, errors.New("storage: access key and secret key are required")
	}
	pathStyle := false
	if cfg.Endpoint != "" {
		u, err := url.Parse(cfg.Endpoint)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("storage: endpoint must be an http(s) URL")
		}
		host := u.Hostname()
		if cfg.Region == "" {
			if m := awsEndpoint.FindStringSubmatch(host); m != nil {
				cfg.Region = m[1]
			}
		}
		pathStyle = !isAWSHost(host)
	}
	if cfg.Region == "" {
		cfg.Region = defaultRegion
	}
	if cfg.PathStyle != nil {
		pathStyle = *cfg.PathStyle
	}
	creds := aws.Credentials{AccessKeyID: cfg.AccessKey, SecretAccessKey: cfg.SecretKey, Source: "warden-config"}
	opts := s3.Options{
		Region: cfg.Region,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return creds, nil
		}),
		UsePathStyle: pathStyle,
		// The SDK's default "when supported" checksums add CRC headers that the
		// browser would have to replay and that not every S3-compatible store
		// accepts; integrity comes from the explicit SHA-256 instead.
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
		RetryMaxAttempts:           3,
	}
	if cfg.Endpoint != "" {
		opts.BaseEndpoint = aws.String(strings.TrimRight(cfg.Endpoint, "/"))
	}
	if cfg.HTTPClient != nil {
		opts.HTTPClient = cfg.HTTPClient
	}
	c := s3.New(opts)
	return &Client{s3: c, presign: s3.NewPresignClient(c), bucket: cfg.Bucket, cfg: cfg}, nil
}

func validKey(key string) error {
	if key == "" || len(key) > 1024 || strings.HasPrefix(key, "/") || strings.Contains(key, "..") {
		return fmt.Errorf("storage: invalid object key %q", key)
	}
	return nil
}

// PresignPut returns a URL for one PUT of exactly size bytes to key, valid for ttl,
// and the headers the uploader must send with it. Content-Length is part of the
// signature (the browser sets it from the body, so it isn't in headers); with
// ChecksumHeader the SHA-256 is too, and the store rejects a different body.
func (c *Client) PresignPut(ctx context.Context, key string, size int64, sha256Hex string, ttl time.Duration) (string, map[string]string, error) {
	if err := validKey(key); err != nil {
		return "", nil, err
	}
	if size <= 0 {
		return "", nil, errors.New("storage: size must be positive")
	}
	if ttl <= 0 || ttl > MaxPresignTTL {
		return "", nil, fmt.Errorf("storage: ttl must be in (0, %s]", MaxPresignTTL)
	}
	in := &s3.PutObjectInput{
		Bucket:        aws.String(c.bucket),
		Key:           aws.String(key),
		ContentLength: aws.Int64(size),
	}
	if c.cfg.ChecksumHeader {
		sum, err := checksumB64(sha256Hex)
		if err != nil {
			return "", nil, err
		}
		in.ChecksumSHA256 = aws.String(sum)
	}
	req, err := c.presign.PresignPutObject(ctx, in, s3.WithPresignExpires(ttl))
	if err != nil {
		return "", nil, fmt.Errorf("storage: presign: %w", err)
	}
	headers := map[string]string{}
	for k, v := range req.SignedHeader {
		switch strings.ToLower(k) {
		case "host", "content-length": // set by the HTTP client; browsers refuse to set them
			continue
		}
		headers[k] = strings.Join(v, ",")
	}
	return req.URL, headers, nil
}

func checksumB64(hexSum string) (string, error) {
	if !sha256Hex.MatchString(hexSum) {
		return "", errors.New("storage: sha256 must be 64 lowercase hex characters")
	}
	raw, _ := hex.DecodeString(hexSum)
	return base64.StdEncoding.EncodeToString(raw), nil
}

// Put stores body at key from the server side (artifacts Warden produces, such
// as SBOMs). The length is sent and signed, and with ChecksumHeader the store
// verifies the SHA-256 too.
func (c *Client) Put(ctx context.Context, key string, body []byte, sha256Hex, contentType string) error {
	if err := validKey(key); err != nil {
		return err
	}
	in := &s3.PutObjectInput{
		Bucket:        aws.String(c.bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
		ContentType:   aws.String(contentType),
	}
	if c.cfg.ChecksumHeader {
		sum, err := checksumB64(sha256Hex)
		if err != nil {
			return err
		}
		in.ChecksumSHA256 = aws.String(sum)
	}
	if _, err := c.s3.PutObject(ctx, in); err != nil {
		return fmt.Errorf("storage: put: %w", err)
	}
	return nil
}

// downloadName is what a presigned download may be saved as: no quotes,
// separators or control characters can reach the Content-Disposition header.
var downloadName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// PresignGet returns a URL valid for ttl that downloads key as an attachment
// named filename with the given content type, whatever the object's own
// metadata says: content derived from scanned code is never rendered inline.
func (c *Client) PresignGet(ctx context.Context, key string, ttl time.Duration, filename, contentType string) (string, error) {
	if err := validKey(key); err != nil {
		return "", err
	}
	if ttl <= 0 || ttl > MaxPresignTTL {
		return "", fmt.Errorf("storage: ttl must be in (0, %s]", MaxPresignTTL)
	}
	if !downloadName.MatchString(filename) {
		return "", fmt.Errorf("storage: invalid download name %q", filename)
	}
	req, err := c.presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket:                     aws.String(c.bucket),
		Key:                        aws.String(key),
		ResponseContentDisposition: aws.String(`attachment; filename="` + filename + `"`),
		ResponseContentType:        aws.String(contentType),
	}, s3.WithPresignExpires(ttl))
	if err != nil {
		return "", fmt.Errorf("storage: presign: %w", err)
	}
	return req.URL, nil
}

func isNotFound(err error) bool {
	var nsk *types.NoSuchKey
	var nf *types.NotFound
	if errors.As(err, &nsk) || errors.As(err, &nf) {
		return true
	}
	var re *smithyhttp.ResponseError
	return errors.As(err, &re) && re.HTTPStatusCode() == http.StatusNotFound
}

// Head returns the object's size, or ErrNotFound.
func (c *Client) Head(ctx context.Context, key string) (int64, error) {
	if err := validKey(key); err != nil {
		return 0, err
	}
	out, err := c.s3.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)})
	if isNotFound(err) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("storage: head: %w", err)
	}
	return aws.ToInt64(out.ContentLength), nil
}

// Download writes the object to dest, which must not exist (created 0600). On any
// error dest is removed. Returns ErrNotFound or ErrTooLarge where they apply.
func (c *Client) Download(ctx context.Context, key, dest string) (err error) {
	if err := validKey(key); err != nil {
		return err
	}
	out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)})
	if isNotFound(err) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("storage: get: %w", err)
	}
	defer out.Body.Close()
	limit := c.cfg.MaxObjectBytes
	if limit > 0 && aws.ToInt64(out.ContentLength) > limit {
		return ErrTooLarge
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(dest)
		}
	}()
	var src io.Reader = out.Body
	if limit > 0 {
		src = io.LimitReader(out.Body, limit+1)
	}
	n, err := io.Copy(f, src)
	if err != nil {
		return fmt.Errorf("storage: download: %w", err)
	}
	if limit > 0 && n > limit {
		return ErrTooLarge
	}
	return nil
}

// Delete removes the object. Deleting a missing object succeeds (S3 semantics).
func (c *Client) Delete(ctx context.Context, key string) error {
	if err := validKey(key); err != nil {
		return err
	}
	_, err := c.s3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)})
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("storage: delete: %w", err)
	}
	return nil
}

// Ping checks that the bucket exists and the credentials can reach it (readiness).
func (c *Client) Ping(ctx context.Context) error {
	if _, err := c.s3.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(c.bucket)}); err != nil {
		return fmt.Errorf("storage: bucket %q unavailable: %w", c.bucket, err)
	}
	return nil
}
