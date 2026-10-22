//go:build !cli

package main

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	s3ListPageBytes     = 8 << 20
	s3ListMaxPages      = 10000
	s3ListMaxObjects    = 1000000
	s3ListMetadataBytes = 64 << 20
	s3ListTimeout       = 10 * time.Minute
)

// List returns a complete recursive inventory or an error, never a successful
// partial inventory. Retention must not delete from an incomplete listing.
func (s3 *S3Storage) List(prefix string) ([]S3Object, error) {
	return s3.ListContext(context.Background(), prefix)
}

func (s3 *S3Storage) ListContext(ctx context.Context, prefix string) ([]S3Object, error) {
	return s3.listContext(ctx, prefix, "")
}

// ListFlatContext enumerates direct children only. In the ordinary-backup UI
// the delimiter keeps the much larger nested WAL inventory out of the request.
func (s3 *S3Storage) ListFlatContext(ctx context.Context, prefix string) ([]S3Object, error) {
	return s3.listContext(ctx, prefix, "/")
}

func (s3 *S3Storage) listContext(ctx context.Context, prefix, delimiter string) ([]S3Object, error) {
	if ctx == nil {
		return nil, errors.New("S3 listing requires a context")
	}
	ctx, cancel := context.WithTimeout(ctx, s3ListTimeout)
	defer cancel()
	client := s3HTTPClient(30 * time.Second)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Transport != nil {
		// Hosted tenants get a dedicated guarded transport. Reuse it across
		// pages, then release its idle sockets without touching shared clients.
		defer client.CloseIdleConnections()
	}
	values := url.Values{"list-type": {"2"}, "max-keys": {"1000"}}
	if prefix != "" {
		values.Set("prefix", prefix)
	}
	if delimiter != "" {
		values.Set("delimiter", delimiter)
	}
	var out []S3Object
	metadataBytes := 0
	seen := map[string]bool{}
	for page := 0; page < s3ListMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("S3 list canceled: %w", err)
		}
		result, err := s3.listPage(ctx, client, values)
		if err != nil {
			return nil, err
		}
		for _, object := range result.Contents {
			if object.Key == "" || !strings.HasPrefix(object.Key, prefix) || object.Size < 0 {
				return nil, errors.New("S3 list returned an invalid object or foreign prefix")
			}
			metadataBytes += len(object.Key) + len(object.LastModified)
			if len(out) >= s3ListMaxObjects || metadataBytes > s3ListMetadataBytes {
				return nil, errors.New("S3 list exceeds complete-inventory resource budget")
			}
			out = append(out, object)
		}
		if !*result.IsTruncated {
			return out, nil
		}
		next := result.NextContinuationToken
		if next == "" || len(next) > 16<<10 || seen[next] {
			return nil, errors.New("S3 list has a missing, repeated or oversized continuation token")
		}
		metadataBytes += len(next)
		if metadataBytes > s3ListMetadataBytes {
			return nil, errors.New("S3 list exceeds complete-inventory resource budget")
		}
		seen[next] = true
		values.Set("continuation-token", next)
	}
	return nil, errors.New("S3 list exceeds complete-inventory page budget")
}

type s3ListPage struct {
	XMLName               xml.Name   `xml:"ListBucketResult"`
	Contents              []S3Object `xml:"Contents"`
	IsTruncated           *bool      `xml:"IsTruncated"`
	NextContinuationToken string     `xml:"NextContinuationToken"`
}

func (s3 *S3Storage) listPage(ctx context.Context, client *http.Client, values url.Values) (*s3ListPage, error) {
	endpoint := s3.Endpoint
	awsNative := endpoint == "" || strings.Contains(endpoint, "amazonaws.com")
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://s3.%s.amazonaws.com", s3.Region)
	}
	// SigV4 canonical queries encode spaces as %20 (not form-encoding '+').
	// The opaque continuation token is never interpolated into query text.
	query := strings.ReplaceAll(values.Encode(), "+", "%20")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/%s?%s", endpoint, s3.Bucket, query), nil)
	if err != nil {
		return nil, fmt.Errorf("S3 list request: %w", err)
	}
	key, secret, token := s3.resolveCreds()
	if key != "" {
		if awsNative {
			if token != "" {
				req.Header.Set("X-Amz-Security-Token", token)
			}
			signAWSv4(req, nil, key, secret, s3.Region, "s3")
		} else {
			req.SetBasicAuth(key, secret)
		}
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("S3 list: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		// Do not copy storage error bodies (which may include sensitive details).
		return nil, fmt.Errorf("S3 list failed: HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, s3ListPageBytes+1))
	if err != nil {
		return nil, fmt.Errorf("S3 list body: %w", err)
	}
	if len(body) > s3ListPageBytes {
		return nil, errors.New("S3 list page exceeds size limit")
	}
	var result s3ListPage
	if err := xml.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("S3 list parse: %w", err)
	}
	if result.IsTruncated == nil || len(result.Contents) > 1000 {
		return nil, errors.New("S3 list page lacks completion metadata or exceeds requested size")
	}
	return &result, nil
}
