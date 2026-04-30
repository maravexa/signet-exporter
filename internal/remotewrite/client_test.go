package remotewrite

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/snappy"

	"github.com/maravexa/signet-exporter/internal/remotewrite/prompb"
)

// newTestClient returns a Client that talks to the given URL with auth=none.
// Bypasses NewClient because that path requires real TLS material.
func newTestClient(url string, timeout time.Duration) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: timeout},
		endpoint:   url,
		auth:       AuthConfig{Type: "none"},
		userAgent:  "signet-test/0.0.0",
	}
}

func sampleRequest() *prompb.WriteRequest {
	return &prompb.WriteRequest{
		Timeseries: []prompb.TimeSeries{{
			Labels:  []prompb.Label{{Name: "__name__", Value: "x"}},
			Samples: []prompb.Sample{{Value: 1, Timestamp: 1}},
		}},
	}
}

func TestClient_Send_Success(t *testing.T) {
	var hitsCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsCount.Add(1)
		if r.Method != http.MethodPost {
			t.Errorf("method: got %s", r.Method)
		}
		if r.Header.Get("Content-Encoding") != "snappy" {
			t.Errorf("Content-Encoding: got %q", r.Header.Get("Content-Encoding"))
		}
		if r.Header.Get("Content-Type") != "application/x-protobuf" {
			t.Errorf("Content-Type: got %q", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("X-Prometheus-Remote-Write-Version") != "0.1.0" {
			t.Errorf("RW-Version header missing")
		}
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "signet-") {
			t.Errorf("User-Agent: got %q", r.Header.Get("User-Agent"))
		}
		body, _ := io.ReadAll(r.Body)
		decompressed, err := snappy.Decode(nil, body)
		if err != nil {
			t.Errorf("snappy decode: %v", err)
		}
		var wr prompb.WriteRequest
		if err := wr.Unmarshal(decompressed); err != nil {
			t.Errorf("proto unmarshal: %v", err)
		}
		if len(wr.Timeseries) != 1 {
			t.Errorf("ts count: got %d", len(wr.Timeseries))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, 5*time.Second)
	if err := c.Send(context.Background(), sampleRequest()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if hitsCount.Load() != 1 {
		t.Errorf("expected exactly 1 hit, got %d", hitsCount.Load())
	}
}

func TestClient_Send_5xxRecoverable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("kaboom"))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, 5*time.Second)
	err := c.Send(context.Background(), sampleRequest())
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsRecoverable(err) {
		t.Errorf("5xx should be recoverable")
	}
	var se *SendError
	if !errors.As(err, &se) {
		t.Fatalf("not a SendError: %T", err)
	}
	if se.StatusCode != 500 {
		t.Errorf("status: got %d", se.StatusCode)
	}
	if !strings.Contains(se.Message, "kaboom") {
		t.Errorf("message: got %q", se.Message)
	}
}

func TestClient_Send_4xxNotRecoverable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("malformed"))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, 5*time.Second)
	err := c.Send(context.Background(), sampleRequest())
	if err == nil {
		t.Fatal("expected error")
	}
	if IsRecoverable(err) {
		t.Errorf("4xx should NOT be recoverable")
	}
}

func TestClient_Send_429Recoverable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, 5*time.Second)
	err := c.Send(context.Background(), sampleRequest())
	if !IsRecoverable(err) {
		t.Errorf("429 should be recoverable")
	}
	var se *SendError
	_ = errors.As(err, &se)
	if se.RetryAfter != 5*time.Second {
		t.Errorf("RetryAfter: got %s", se.RetryAfter)
	}
}

func TestClient_Send_NetworkErrorRecoverable(t *testing.T) {
	c := newTestClient("http://127.0.0.1:1/", 200*time.Millisecond)
	err := c.Send(context.Background(), sampleRequest())
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsRecoverable(err) {
		t.Errorf("network error should be recoverable")
	}
	var se *SendError
	_ = errors.As(err, &se)
	if se.StatusCode != 0 {
		t.Errorf("status should be 0 for network err, got %d", se.StatusCode)
	}
}

func TestClient_Send_BearerAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			t.Errorf("Authorization header: got %q", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, 5*time.Second)
	c.auth = AuthConfig{Type: "bearer"}
	tok := "secret-token"
	c.bearerToken.Store(&tok)

	if err := c.Send(context.Background(), sampleRequest()); err != nil {
		t.Fatalf("Send: %v", err)
	}
}
