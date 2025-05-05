package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	// Define command line flags
	address := flag.String("address", "", "Address to connect to (required)")
	serverName := flag.String("sni", "", "Server Name Indication (SNI) hostname (defaults to address if not specified)")
	port := flag.String("port", "443", "Port to check (default: 443)")
	flag.Parse()

	if *address == "" {
		fmt.Println("Error: address is required")
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
