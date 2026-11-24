package ydentifi

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"
)

// GO-006: the client takes a server only when the server's certificate
// names it a Ydentifi server, with exactly one URI SAN of the form
// spiffe://<trust domain>/server/<name>. No server presents another
// certificate, so the check is made on the certificate's fields.
func TestGO006_TheServersCertificateNamesAYdentifiServer(t *testing.T) {
	uris := func(raw ...string) []*url.URL {
		out := make([]*url.URL, 0, len(raw))
		for _, r := range raw {
			u, err := url.Parse(r)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, u)
		}
		return out
	}
	cases := map[string]struct {
		uris []*url.URL
		ok   bool
	}{
		"the server's ID":            {uris("spiffe://ydentifi.local/server/main"), true},
		"a name with capitals":       {uris("spiffe://ydentifi.local/server/Main-1_a.b"), true},
		"no URI":                     {nil, false},
		"two URIs":                   {uris("spiffe://ydentifi.local/server/main", "spiffe://ydentifi.local/server/other"), false},
		"a relying party's ID":       {uris("spiffe://ydentifi.local/rp/acme"), false},
		"no name":                    {uris("spiffe://ydentifi.local/server/"), false},
		"two name segments":          {uris("spiffe://ydentifi.local/server/a/b"), false},
		"a trust domain in capitals": {uris("spiffe://Ydentifi.local/server/main"), false},
		"a port":                     {uris("spiffe://ydentifi.local:8443/server/main"), false},
		"userinfo":                   {uris("spiffe://u@ydentifi.local/server/main"), false},
		"a query":                    {uris("spiffe://ydentifi.local/server/main?x=1"), false},
		"a fragment":                 {uris("spiffe://ydentifi.local/server/main#f"), false},
		"percent-encoding":           {uris("spiffe://ydentifi.local/server/m%61in"), false},
		"the name .":                 {uris("spiffe://ydentifi.local/server/."), false},
		"the name ..":                {uris("spiffe://ydentifi.local/server/.."), false},
		"another scheme":             {uris("https://ydentifi.local/server/main"), false},
	}
	for name, c := range cases {
		cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{{URIs: c.uris}}}
		if err := verifyServerIdentity(cs); (err == nil) != c.ok {
			t.Errorf("%s: verifyServerIdentity = %v, want accepted %v", name, err, c.ok)
		}
	}
	if err := verifyServerIdentity(tls.ConnectionState{}); err == nil {
		t.Error("a server that presented no certificate was accepted")
	}
}
