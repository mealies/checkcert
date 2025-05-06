package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadCertificatesFromFile(t *testing.T) {
	// Create a temporary test certificate
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.pem")

	// Generate test certificate
	cert := generateTestCertificate(t)

	// Write certificate to file
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	err := os.WriteFile(certPath, certPEM, 0644)
	if err != nil {
		t.Fatalf("Failed to write test certificate: %v", err)
	}

	// Test loading the certificate
	certs, err := loadCertificatesFromFile(certPath)
	if err != nil {
		t.Fatalf("Failed to load certificates: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(certs))
	}

	// Test invalid file
	_, err = loadCertificatesFromFile("nonexistent.pem")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestHandleCertificateDirectory(t *testing.T) {
	// Create a temporary test directory
	tmpDir := t.TempDir()

	// Create test certificates
	certFiles := []string{"test1.pem", "test2.pem", "invalid.txt"}
	for _, filename := range certFiles {
		if filename == "invalid.txt" {
			err := os.WriteFile(filepath.Join(tmpDir, filename), []byte("invalid"), 0644)
			if err != nil {
				t.Fatalf("Failed to write invalid file: %v", err)
			}
			continue
		}

		cert := generateTestCertificate(t)
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		err := os.WriteFile(filepath.Join(tmpDir, filename), certPEM, 0644)
		if err != nil {
			t.Fatalf("Failed to write test certificate: %v", err)
		}
	}

	// Test directory handling
	err := handleCertificateDirectory(tmpDir)
	if err != nil {
		t.Fatalf("handleCertificateDirectory failed: %v", err)
	}

	// Test non-existent directory
	err = handleCertificateDirectory("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent directory")
	}
}

func generateTestCertificate(t *testing.T) *x509.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}
