// Copyright (c) 2021 Daniel Jakots

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

type Options struct {
	Domain             string
	InsecureSkipVerify bool
	IntermediatePath   string
	IP                 string
	LeafPath           string
	Port               int
}

func cli() Options {
	domain := flag.String("domain", "", "domain used in tls Handshake/SNI")
	insecureSkipVerify := flag.Bool("insecureSkipVerify", false,
		"Skip certificate validation and accept any certificate presented by the server")
	intermediatePath := flag.String("intermediate", "", "file for the intermediate certificate")
	ip := flag.String("ip", "", "(Optional) IP address of the target host")
	leafPath := flag.String("leaf", "", "path to file for the leaf certificate")
	port := flag.Int("port", 443, "(Optional) TCP port of the target host")
	flag.Parse()

	o := Options{
		Domain:             *domain,
		InsecureSkipVerify: *insecureSkipVerify,
		IntermediatePath:   *intermediatePath,
		IP:                 *ip,
		LeafPath:           *leafPath,
		Port:               *port,
	}

	if o.LeafPath == "" || o.IntermediatePath == "" || o.Domain == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	return o
}

func main() {
	options := cli()
	peerName := options.Domain
	var server string
	if options.IP != "" {
		server = options.IP
	} else {
		server = peerName
	}

	peer := fmt.Sprintf("%s:%d", server, options.Port)
	ipConn, err := net.DialTimeout("tcp", peer, 10*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer ipConn.Close()

	conf := &tls.Config{ServerName: peerName, InsecureSkipVerify: options.InsecureSkipVerify}
	conn := tls.Client(ipConn, conf)

	err = conn.Handshake()
	if err != nil {
		log.Fatal(err)
	}
	certs, err := asciiCertificates(conn.ConnectionState().PeerCertificates)
	if err != nil {
		log.Fatal(err)
	}
	err = conn.Close()
	if err != nil {
		log.Fatal(err)
	}
	err = writeCertificates(certs, options.IntermediatePath, options.LeafPath)
	if err != nil {
		log.Fatal(err)
	}
}

func asciiCertificates(certificates []*x509.Certificate) (map[bool]string, error) {
	certs := make(map[bool]string, 2)
	for _, cert := range certificates {
		buffy := new(bytes.Buffer)
		err := pem.Encode(buffy, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return nil, err
		}
		certs[cert.IsCA] += buffy.String()
	}
	return certs, nil
}

func writeCertificates(certs map[bool]string, intermediatePath, leafPath string) error {
	for k, v := range certs {
		var certFile string
		if k {
			certFile = intermediatePath
		} else {
			certFile = leafPath
		}
		err := os.WriteFile(certFile, []byte(v), 0644)
		if err != nil {
			return err
		}
	}
	return nil
}
