package rawhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSendRejectsUntrustedTLSCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := Send(Request{
		TargetURL: server.URL,
		Payload:   []byte("GET / HTTP/1.1\r\nConnection: close\r\n\r\n"),
		Timeout:   time.Second,
	})
	if err == nil {
		t.Fatal("Send() accepted an untrusted TLS certificate")
	}
}
