package tlscert_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/mdelapenya/tlscert"
)

func ExampleSelfSigned() {
	tmp := os.TempDir()
	certsDir := tmp + "/certs"
	defer os.RemoveAll(certsDir)

	if err := os.MkdirAll(certsDir, 0o755); err != nil {
		log.Fatal(err) // nolint: gocritic
	}

	// Generate a certificate for localhost and save it to disk.
	caCert := tlscert.SelfSignedFromRequest(tlscert.Request{
		Host:      "localhost",
		Name:      "ca-cert",
		ParentDir: certsDir,
	})
	if caCert == nil {
		log.Fatal("Failed to generate CA certificate")
	}

	cert := tlscert.SelfSignedFromRequest(tlscert.Request{
		Host:      "localhost",
		Name:      "client-cert",
		Parent:    caCert,
		ParentDir: certsDir,
	})
	if cert == nil {
		log.Fatal("Failed to generate certificate")
	}

	// create an http server that uses the generated certificate
	// and private key to serve requests over HTTPS

	server := &http.Server{
		Addr: ":8443",
	}

	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, err := w.Write([]byte("TLS works!\n"))
		if err != nil {
			log.Printf("Failed to write response: %v", err)
		}
	})

	go func() {
		_ = server.ListenAndServeTLS(cert.CertPath, cert.KeyPath)
	}()
	defer server.Close()

	// perform an HTTP request to the server, using the generated certificate

	const url = "https://localhost:8443/hello"

	client := &http.Client{Transport: cert.Transport()}
	resp, err := client.Get(url)
	if err != nil {
		log.Fatalf("Failed to get response: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	fmt.Println(string(body))

	// Output:
	// TLS works!
}

func ExampleSelfSignedE() {
	tmp := os.TempDir()
	certsDir := tmp + "/certs"
	defer os.RemoveAll(certsDir)

	if err := os.MkdirAll(certsDir, 0o755); err != nil {
		log.Fatal(err) // nolint: gocritic
	}

	// Generate a certificate for localhost and save it to disk.
	caCert, err := tlscert.SelfSignedFromRequestE(tlscert.Request{
		Host:      "localhost",
		Name:      "ca-cert",
		ParentDir: certsDir,
	})
	if err != nil {
		log.Fatal("Failed to generate CA certificate")
	}
	if caCert == nil {
		log.Fatal("Failed to generate CA certificate")
	}

	cert, err := tlscert.SelfSignedFromRequestE(tlscert.Request{
		Host:      "localhost",
		Name:      "client-cert",
		Parent:    caCert,
		ParentDir: certsDir,
	})
	if err != nil {
		log.Fatal("Failed to generate certificate")
	}
	if cert == nil {
		log.Fatal("Failed to generate certificate")
	}

	// create an http server that uses the generated certificate
	// and private key to serve requests over HTTPS

	server := &http.Server{
		Addr: ":8443",
	}

	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, err := w.Write([]byte("TLS works!\n"))
		if err != nil {
			log.Printf("Failed to write response: %v", err)
		}
	})

	go func() {
		_ = server.ListenAndServeTLS(cert.CertPath, cert.KeyPath)
	}()
	defer server.Close()

	// perform an HTTP request to the server, using the generated certificate

	const url = "https://localhost:8443/hello"

	client := &http.Client{Transport: cert.Transport()}
	resp, err := client.Get(url)
	if err != nil {
		log.Fatalf("Failed to get response: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	fmt.Println(string(body))

	// Output:
	// TLS works!
}
