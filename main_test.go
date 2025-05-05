package main

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestGetCertificate(t *testing.T) {
	tests := []struct {
		name       string
		address    string
		serverName string
		port       string
		wantErr    bool
	}{
		{
			name:       "Valid certificate fetch",
			address:    "www.drewbell.net",
			serverName: "www.drewbell.net",
			port:       "443",
			wantErr:    false,
		},
		{
			name:       "Invalid domain",
			address:    "invalid.domain.that.does.not.exist",
			serverName: "invalid.domain.that.does.not.exist",
			port:       "443",
			wantErr:    true,
		},
		{
			name:       "Invalid port",
			address:    "www.drewbell.net",
			serverName: "www.drewbell.net",
			port:       "44333",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := getCertificate(tt.address, tt.serverName, tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("getCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && cert == nil {
				t.Error("getCertificate() returned nil certificate when no error was expected")
			}
		})
	}
}

func TestVerifyCertificateHostname(t *testing.T) {
	// First get a real certificate to test with
	cert, err := getCertificate("www.drewbell.net", "www.drewbell.net", "443")
	if err != nil {
		t.Fatalf("Failed to get certificate for testing: %v", err)
	}

	tests := []struct {
		name     string
		cert     *x509.Certificate
		hostname string
		wantErr  bool
	}{
		{
			name:     "Valid hostname",
			cert:     cert,
			hostname: "www.drewbell.net",
			wantErr:  false,
		},
		{
			name:     "Invalid hostname",
			cert:     cert,
			hostname: "invalid.example.com",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyCertificateHostname(tt.cert, tt.hostname)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyCertificateHostname() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPrintCertificateInfo(t *testing.T) {
	// This is mainly a visual test, but we can at least verify it doesn't panic
	cert, err := getCertificate("www.drewbell.net", "www.drewbell.net", "443")
	if err != nil {
		t.Fatalf("Failed to get certificate for testing: %v", err)
	}

	// This shouldn't panic
	t.Run("Print certificate info", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("printCertificateInfo() panicked: %v", r)
			}
		}()

		printCertificateInfo(cert, "www.drewbell.net", "www.drewbell.net")
	})
}

// Helper function to check if a time is within a reasonable range
func TestCertificateValidity(t *testing.T) {
	cert, err := getCertificate("www.drewbell.net", "www.drewbell.net", "443")
	if err != nil {
		t.Fatalf("Failed to get certificate for testing: %v", err)
	}

	now := time.Now()
	if cert.NotBefore.After(now) {
		t.Error("Certificate is not yet valid")
	}
	if cert.NotAfter.Before(now) {
		t.Error("Certificate has expired")
	}
}
