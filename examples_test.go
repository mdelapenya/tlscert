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
		log.Println(err)
		return
	}

	// Generate a certificate for localhost and save it to disk.
	caCert := tlscert.SelfSignedFromRequest(tlscert.Request{
		Host:      "localhost",
		Name:      "ca-cert",
		ParentDir: certsDir,
	})
	if caCert == nil {
		log.Println("Failed to generate CA certificate")
		return
	}

	cert := tlscert.SelfSignedFromRequest(tlscert.Request{
		Host:      "localhost",
		Name:      "client-cert",
		Parent:    caCert,
		ParentDir: certsDir,
	})
	if cert == nil {
		log.Println("Failed to generate certificate")
		return
	}

	// create an http server that uses the generated certificate
	// and private key to serve requests over HTTPS

	server := &http.Server{
		Addr: ":8443",
	}

	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("TLS works!\n")) //nolint:errcheck
	})

	go func() {
		if err := server.ListenAndServeTLS(cert.CertPath, cert.KeyPath); err != nil {
			log.Printf("Failed to start server: %v", err)
		}
	}()
	defer server.Close()

	// perform an HTTP request to the server, using the generated certificate

	const url = "https://localhost:8443/hello"

	client := &http.Client{Transport: cert.Transport()}
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Failed to get response: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body: %v", err)
		return
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
		log.Println(err)
		return
	}

	// Generate a certificate for localhost and save it to disk.
	caCert, err := tlscert.SelfSignedFromRequestE(tlscert.Request{
		Host:      "localhost",
		Name:      "ca-cert",
		ParentDir: certsDir,
	})
	if err != nil {
		log.Println("Failed to generate CA certificate")
		return
	}
	if caCert == nil {
		log.Println("Failed to generate CA certificate")
		return
	}

	cert, err := tlscert.SelfSignedFromRequestE(tlscert.Request{
		Host:      "localhost",
		Name:      "client-cert",
		Parent:    caCert,
		ParentDir: certsDir,
	})
	if err != nil {
		log.Println("Failed to generate certificate")
		return
	}
	if cert == nil {
		log.Println("Failed to generate certificate")
		return
	}

	// create an http server that uses the generated certificate
	// and private key to serve requests over HTTPS

	server := &http.Server{
		Addr: ":8443",
	}

	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("TLS works!\n")) //nolint:errcheck
	})

	go func() {
		if err := server.ListenAndServeTLS(cert.CertPath, cert.KeyPath); err != nil {
			log.Printf("Failed to start server: %v", err)
		}
	}()
	defer server.Close()

	// perform an HTTP request to the server, using the generated certificate

	const url = "https://localhost:8443/hello"

	client := &http.Client{Transport: cert.Transport()}
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Failed to get response: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body: %v", err)
		return
	}

	fmt.Println(string(body))

	// Output:
	// TLS works!
}
