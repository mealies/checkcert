package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	// Define command line flags
	address := flag.String("address", "", "Address to connect to")
	serverName := flag.String("sni", "", "Server Name Indication (SNI) hostname (defaults to address if not specified)")
	port := flag.String("port", "443", "Port to check (default: 443)")
	certFile := flag.String("cert", "", "Path to certificate file or directory to check")
	flag.Parse()

	// Check if we're examining a certificate file
	if *certFile != "" {
		if err := handleCertificateFile(*certFile); err != nil {
			fmt.Printf("Error checking certificate file: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Check if address is provided for remote certificate check
	if *address == "" {
		fmt.Println("Error: either -address or -cert must be provided")
		flag.Usage()
		os.Exit(1)
	}

	// If serverName is not specified, use the address
	sni := *address
	if *serverName != "" {
		sni = *serverName
	}

	cert, err := getCertificate(*address, sni, *port)
	if err != nil {
		fmt.Printf("Error checking certificate: %v\n", err)
		os.Exit(1)
	}

	// Print certificate details
	printCertificateInfo(cert, *address, sni)
}

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
func getCertificate(address, serverName, port string) (*x509.Certificate, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,       // Allow invalid certificates to check their details
		ServerName:         serverName, // Set SNI
	}

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create a dialer with context
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	// Create the base connection using DialContext
	rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, port))
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}

	// Wrap the connection with TLS
	conn := tls.Client(rawConn, conf)

	// Perform the TLS handshake with context
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Get the peer certificates
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	return certs[0], nil
}

func printCertificateInfo(cert *x509.Certificate, address, serverName string) {
	fmt.Println("\nConnection Details:")
	fmt.Println("==================")
	fmt.Printf("Connected to: %s\n", address)
	fmt.Printf("SNI Hostname: %s\n", serverName)

	fmt.Println("\nCertificate Details:")
	fmt.Println("====================")
	fmt.Printf("Subject: %s\n", cert.Subject)
	fmt.Printf("Issuer: %s\n", cert.Issuer)
	fmt.Printf("Valid From: %s\n", cert.NotBefore.Format(time.RFC850))
	fmt.Printf("Valid Until: %s\n", cert.NotAfter.Format(time.RFC850))
	fmt.Printf("Serial Number: %X\n", cert.SerialNumber)

	// Calculate days until expiration
	daysUntilExpiry := time.Until(cert.NotAfter).Hours() / 24
	fmt.Printf("Days until expiration: %.0f\n", daysUntilExpiry)

	// Print DNS names
	if len(cert.DNSNames) > 0 {
		fmt.Println("\nSubject Alternative Names:")
		for _, dns := range cert.DNSNames {
			fmt.Printf("- %s\n", dns)
		}
	}

	// Check if the SNI hostname matches the certificate
	if err := verifyCertificateHostname(cert, serverName); err != nil {
		fmt.Printf("\nWarning: %v\n", err)
	} else {
		fmt.Printf("\nHostname Verification: OK - Certificate is valid for %s\n", serverName)
	}
}

func verifyCertificateHostname(cert *x509.Certificate, hostname string) error {
	if err := cert.VerifyHostname(hostname); err != nil {
		return fmt.Errorf("hostname '%s' doesn't match certificate: %v", hostname, err)
	}
	return nil
}
