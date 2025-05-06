package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func handleCertificateFile(path string) error {
	// Check if the path is a directory
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("error accessing path: %v", err)
	}

	if fileInfo.IsDir() {
		return handleCertificateDirectory(path)
	}

	// Handle single file
	certs, err := loadCertificatesFromFile(path)
	if err != nil {
		return err
	}

	fmt.Printf("\nChecking certificates in file: %s\n", path)
	for i, cert := range certs {
		fmt.Printf("\nCertificate %d:\n", i+1)
		fmt.Println("==============")
		printCertificateInfo(cert, filepath.Base(path), "")
	}

	// If we have multiple certificates, verify the chain
	if len(certs) > 1 {
		if err := verifyCertificateChain(certs); err != nil {
			fmt.Printf("\nWarning: Certificate chain validation failed: %v\n", err)
		} else {
			fmt.Printf("\nCertificate chain validation: OK\n")
		}
	}

	return nil
}

func handleCertificateDirectory(dirPath string) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("error reading directory: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue // Skip subdirectories
		}

		// Check common certificate extensions
		ext := filepath.Ext(entry.Name())
		if ext != ".crt" && ext != ".pem" && ext != ".cer" {
			continue
		}

		fullPath := filepath.Join(dirPath, entry.Name())
		if err := handleCertificateFile(fullPath); err != nil {
			fmt.Printf("Error processing %s: %v\n", fullPath, err)
		}
	}

	return nil
}

func loadCertificatesFromFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	var certificates []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			data = rest
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing certificate: %v", err)
		}

		certificates = append(certificates, cert)
		data = rest
	}

	if len(certificates) == 0 {
		// Try parsing as DER if no PEM certificates were found
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("no valid certificates found in file")
		}
		certificates = append(certificates, cert)
	}

	return certificates, nil
}

func verifyCertificateChain(certs []*x509.Certificate) error {
	if len(certs) < 2 {
		return fmt.Errorf("not enough certificates to form a chain")
	}

	intermediatePool := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediatePool.AddCert(certs[i])
	}

	opts := x509.VerifyOptions{
		Intermediates: intermediatePool,
		CurrentTime:   time.Now(),
	}

	_, err := certs[0].Verify(opts)
	return err
}
