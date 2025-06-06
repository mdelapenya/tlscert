package tlscert_test

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/mdelapenya/tlscert"
)

func TestSelfSigned(t *testing.T) {
	t.Run("No host returns error", func(t *testing.T) {
		cert := tlscert.SelfSignedFromRequest(tlscert.Request{Host: ""})
		if cert != nil {
			t.Fatal("expected cert to be nil, got", cert)
		}
	})

	t.Run("With host", func(tt *testing.T) {
		cert := tlscert.SelfSigned("localhost")
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		if cert.Key == nil {
			tt.Fatal("expected key, got nil")
		}

		if cert.Bytes == nil {
			t.Fatal("expected bytes, got nil")
		}
		if cert.KeyBytes == nil {
			t.Fatal("expected key bytes, got nil")
		}

		_, err := tls.X509KeyPair(cert.Bytes, cert.KeyBytes)
		if err != nil {
			tt.Fatal(err)
		}
	})

	t.Run("With multiple hosts", func(t *testing.T) {
		ip := "1.2.3.4"
		cert := tlscert.SelfSigned("localhost, " + ip)
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		if cert.Key == nil {
			t.Fatal("expected key, got nil")
		}

		c := cert.Cert
		if len(c.IPAddresses) != 1 {
			t.Fatal("expected 1 IP address, got", len(c.IPAddresses))
		}

		if c.IPAddresses[0].String() != ip {
			t.Fatalf("expected IP address to be %s, got %s\n", ip, c.IPAddresses[0].String())
		}
	})

	t.Run("With multiple hosts and IPs", func(t *testing.T) {
		ip := "1.2.3.4"
		ips := []net.IP{net.ParseIP("4.5.6.7"), net.ParseIP("8.9.10.11")}
		cert := tlscert.SelfSignedFromRequest(tlscert.Request{
			Host:        "localhost, " + ip,
			IPAddresses: ips,
		})
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		if cert.Key == nil {
			t.Fatal("expected key, got nil")
		}

		c := cert.Cert
		if len(c.IPAddresses) != 3 {
			t.Fatal("expected 3 IP address, got", len(c.IPAddresses))
		}

		for i, ip := range ips {
			if c.IPAddresses[i].String() != ip.String() {
				t.Fatalf("expected IP address to be %s, got %s\n", ip.String(), c.IPAddresses[i].String())
			}
		}
		// the IP from the host comes after the IPs from the IPAddresses option
		if c.IPAddresses[2].String() != ip {
			t.Fatalf("expected IP address to be %s, got %s\n", ip, c.IPAddresses[2].String())
		}
	})

	t.Run("As CA", func(t *testing.T) {
		cert := tlscert.SelfSignedCA("localhost")
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		if cert.Cert == nil {
			t.Fatal("expected cert, got nil")
		}
		if cert.Key == nil {
			t.Fatal("expected key, got nil")
		}
		if cert.Bytes == nil {
			t.Fatal("expected bytes, got nil")
		}

		if !cert.Cert.IsCA {
			t.Fatal("expected cert to be CA, got false")
		}
	})

	t.Run("With Subject common name", func(t *testing.T) {
		cert := tlscert.SelfSignedFromRequest(tlscert.Request{
			Host:              "localhost",
			SubjectCommonName: "Test",
		})
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		if cert.Cert == nil {
			t.Fatal("expected cert, got nil")
		}

		c := cert.Cert
		if c.Subject.CommonName != "Test" {
			t.Fatal("expected common name to be Test, got", c.Subject.CommonName)
		}
	})

	t.Run("With Parent cert", func(t *testing.T) {
		parent := tlscert.SelfSignedFromRequest(tlscert.Request{
			Host:              "localhost",
			SubjectCommonName: "Acme Inc.",
			IsCA:              true,
		})
		if parent == nil {
			t.Fatal("expected parent to be not nil, got", parent)
		}

		cert := tlscert.SelfSignedFromRequest(tlscert.Request{
			Host:   "localhost",
			Parent: parent,
		})
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		if cert.Cert == nil {
			t.Fatal("expected cert, got nil")
		}
		if cert.Key == nil {
			t.Fatal("expected key, got nil")
		}

		c := cert.Cert
		if c.Issuer.CommonName != parent.Cert.Subject.CommonName {
			t.Fatal("expected issuer to be parent, got", c.Issuer.CommonName)
		}
	})

	t.Run("With IP addresses", func(t *testing.T) {
		ip := "1.2.3.4"

		cert := tlscert.SelfSignedFromRequest(tlscert.Request{
			Host:        "localhost",
			IPAddresses: []net.IP{net.ParseIP(ip)},
		})
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		if cert.Cert == nil {
			t.Fatal("expected cert, got nil")
		}

		c := cert.Cert
		if len(c.IPAddresses) != 1 {
			t.Fatal("expected 1 IP address, got", len(c.IPAddresses))
		}

		if c.IPAddresses[0].String() != ip {
			t.Fatalf("expected IP address to be %s, got %s\n", ip, c.IPAddresses[0].String())
		}
	})

	t.Run("Save to file", func(tt *testing.T) {
		tmp := tt.TempDir()

		cert := tlscert.SelfSignedFromRequest(tlscert.Request{
			Host:      "localhost",
			ParentDir: tmp,
		})
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		inMemoryCert, err := tls.X509KeyPair(cert.Bytes, cert.KeyBytes)
		if err != nil {
			tt.Fatal(err)
		}

		// check if file existed
		certBytes, err := os.ReadFile(cert.CertPath)
		if err != nil {
			tt.Fatal(err)
		}

		certKeyBytes, err := os.ReadFile(cert.KeyPath)
		if err != nil {
			tt.Fatal(err)
		}

		fileCert, err := tls.X509KeyPair(certBytes, certKeyBytes)
		if err != nil {
			tt.Fatal(err)
		}

		for i, cert := range inMemoryCert.Certificate {
			if string(cert) != string(fileCert.Certificate[i]) {
				tt.Fatalf("expected certificate to be %s, got %s\n", string(cert), string(fileCert.Certificate[i]))
			}
		}
	})
}

func TestSelfSignedE(t *testing.T) {
	t.Run("No host returns error", func(t *testing.T) {
		cert, err := tlscert.SelfSignedFromRequestE(tlscert.Request{Host: ""})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, tlscert.ErrHostRequired) {
			t.Fatalf("expected error to be %s, got %s\n", tlscert.ErrHostRequired, err)
		}
		if cert != nil {
			t.Fatal("expected cert to be nil, got", cert)
		}
	})

	t.Run("With host", func(tt *testing.T) {
		cert, err := tlscert.SelfSignedE("localhost")
		if err != nil {
			t.Fatal("expected error to be nil, got", err)
		}
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		if cert.Key == nil {
			tt.Fatal("expected key, got nil")
		}

		if cert.Bytes == nil {
			t.Fatal("expected bytes, got nil")
		}
		if cert.KeyBytes == nil {
			t.Fatal("expected key bytes, got nil")
		}

		_, err = tls.X509KeyPair(cert.Bytes, cert.KeyBytes)
		if err != nil {
			tt.Fatal(err)
		}
	})

	t.Run("With multiple hosts", func(t *testing.T) {
		ip := "1.2.3.4"
		cert, err := tlscert.SelfSignedE("localhost, " + ip)
		if err != nil {
			t.Fatal("expected error to be nil, got", err)
		}
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		if cert.Key == nil {
			t.Fatal("expected key, got nil")
		}

		c := cert.Cert
		if len(c.IPAddresses) != 1 {
			t.Fatal("expected 1 IP address, got", len(c.IPAddresses))
		}

		if c.IPAddresses[0].String() != ip {
			t.Fatalf("expected IP address to be %s, got %s\n", ip, c.IPAddresses[0].String())
		}
	})

	t.Run("With multiple hosts and IPs", func(t *testing.T) {
		ip := "1.2.3.4"
		ips := []net.IP{net.ParseIP("4.5.6.7"), net.ParseIP("8.9.10.11")}
		cert, err := tlscert.SelfSignedFromRequestE(tlscert.Request{
			Host:        "localhost, " + ip,
			IPAddresses: ips,
		})
		if err != nil {
			t.Fatal("expected error to be nil, got", err)
		}
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		if cert.Key == nil {
			t.Fatal("expected key, got nil")
		}

		c := cert.Cert
		if len(c.IPAddresses) != 3 {
			t.Fatal("expected 3 IP address, got", len(c.IPAddresses))
		}

		for i, ip := range ips {
			if c.IPAddresses[i].String() != ip.String() {
				t.Fatalf("expected IP address to be %s, got %s\n", ip.String(), c.IPAddresses[i].String())
			}
		}
		// the IP from the host comes after the IPs from the IPAddresses option
		if c.IPAddresses[2].String() != ip {
			t.Fatalf("expected IP address to be %s, got %s\n", ip, c.IPAddresses[2].String())
		}
	})

	t.Run("As CA", func(t *testing.T) {
		cert, err := tlscert.SelfSignedCAE("localhost")
		if err != nil {
			t.Fatal("expected error to be nil, got", err)
		}
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		if cert.Cert == nil {
			t.Fatal("expected cert, got nil")
		}
		if cert.Key == nil {
			t.Fatal("expected key, got nil")
		}
		if cert.Bytes == nil {
			t.Fatal("expected bytes, got nil")
		}

		if !cert.Cert.IsCA {
			t.Fatal("expected cert to be CA, got false")
		}
	})

	t.Run("With Subject common name", func(t *testing.T) {
		cert, err := tlscert.SelfSignedFromRequestE(tlscert.Request{
			Host:              "localhost",
			SubjectCommonName: "Test",
		})
		if err != nil {
			t.Fatal("expected error to be nil, got", err)
		}
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		if cert.Cert == nil {
			t.Fatal("expected cert, got nil")
		}

		c := cert.Cert
		if c.Subject.CommonName != "Test" {
			t.Fatal("expected common name to be Test, got", c.Subject.CommonName)
		}
	})

	t.Run("With Parent cert", func(t *testing.T) {
		parent, err := tlscert.SelfSignedFromRequestE(tlscert.Request{
			Host:              "localhost",
			SubjectCommonName: "Acme Inc.",
			IsCA:              true,
		})
		if err != nil {
			t.Fatal("expected error to be nil, got", err)
		}
		if parent == nil {
			t.Fatal("expected parent to be not nil, got", parent)
		}

		cert, err := tlscert.SelfSignedFromRequestE(tlscert.Request{
			Host:   "localhost",
			Parent: parent,
		})
		if err != nil {
			t.Fatal("expected error to be nil, got", err)
		}
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		if cert.Cert == nil {
			t.Fatal("expected cert, got nil")
		}
		if cert.Key == nil {
			t.Fatal("expected key, got nil")
		}

		c := cert.Cert
		if c.Issuer.CommonName != parent.Cert.Subject.CommonName {
			t.Fatal("expected issuer to be parent, got", c.Issuer.CommonName)
		}
	})

	t.Run("With IP addresses", func(t *testing.T) {
		ip := "1.2.3.4"

		cert, err := tlscert.SelfSignedFromRequestE(tlscert.Request{
			Host:        "localhost",
			IPAddresses: []net.IP{net.ParseIP(ip)},
		})
		if err != nil {
			t.Fatal("expected error to be nil, got", err)
		}
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		if cert.Cert == nil {
			t.Fatal("expected cert, got nil")
		}

		c := cert.Cert
		if len(c.IPAddresses) != 1 {
			t.Fatal("expected 1 IP address, got", len(c.IPAddresses))
		}

		if c.IPAddresses[0].String() != ip {
			t.Fatalf("expected IP address to be %s, got %s\n", ip, c.IPAddresses[0].String())
		}
	})

	t.Run("Save to file", func(tt *testing.T) {
		tmp := tt.TempDir()

		cert, err := tlscert.SelfSignedFromRequestE(tlscert.Request{
			Host:      "localhost",
			ParentDir: tmp,
		})
		if err != nil {
			t.Fatal("expected error to be nil, got", err)
		}
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		inMemoryCert, err := tls.X509KeyPair(cert.Bytes, cert.KeyBytes)
		if err != nil {
			tt.Fatal(err)
		}

		// check if file existed
		certBytes, err := os.ReadFile(cert.CertPath)
		if err != nil {
			tt.Fatal(err)
		}

		certKeyBytes, err := os.ReadFile(cert.KeyPath)
		if err != nil {
			tt.Fatal(err)
		}

		fileCert, err := tls.X509KeyPair(certBytes, certKeyBytes)
		if err != nil {
			tt.Fatal(err)
		}

		for i, cert := range inMemoryCert.Certificate {
			if string(cert) != string(fileCert.Certificate[i]) {
				tt.Fatalf("expected certificate to be %s, got %s\n", string(cert), string(fileCert.Certificate[i]))
			}
		}
	})

	t.Run("save-to-file/error", func(tt *testing.T) {
		tmp := filepath.Join(tt.TempDir(), "non-existing-dir")

		cert, err := tlscert.SelfSignedFromRequestE(tlscert.Request{
			Host:      "localhost",
			ParentDir: tmp,
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if cert != nil {
			t.Fatal("expected cert to be nil, got", cert)
		}
	})
}

func TestTLSConfig(t *testing.T) {
	t.Run("cached/no-error", func(t *testing.T) {
		cert := tlscert.SelfSigned("localhost")
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		config := cert.TLSConfig()
		if config == nil {
			t.Fatal("expected config to be not nil, got", config)
		}

		// force the bytes to be null, but the config should not change
		cert.Bytes = nil

		config2 := cert.TLSConfig()

		if config != config2 {
			t.Fatal("expected config to be the same, got different")
		}
	})

	t.Run("cached/error", func(t *testing.T) {
		cert, err := tlscert.SelfSignedE("")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if cert != nil {
			t.Fatal("expected cert to be nil, got", cert)
		}
	})

	t.Run("error/cached/no-error", func(t *testing.T) {
		cert, err := tlscert.SelfSignedE("localhost")
		if err != nil {
			t.Fatal("expected error to be nil, got", err)
		}
		if cert == nil {
			t.Fatal("expected cert to be not nil, got", cert)
		}

		config := cert.TLSConfig()
		if config == nil {
			t.Fatal("expected config to be not nil, got", config)
		}

		// force the bytes to be null, but the config should not change
		cert.Bytes = nil

		config2 := cert.TLSConfig()

		if config != config2 {
			t.Fatal("expected config to be the same, got different")
		}
	})

	t.Run("error/cached/error", func(t *testing.T) {
		cert, err := tlscert.SelfSignedE("")
		if err == nil {
			t.Fatal("expected error, got nil", err)
		}
		if cert != nil {
			t.Fatal("expected cert to be nil, got", cert)
		}
	})
}
