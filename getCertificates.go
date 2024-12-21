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

func cli() (string, string, string, string, int) {
	leafPath := flag.String("leaf", "", "path to file for the leaf certificate")
	intermediatePath := flag.String("intermediate", "", "file for the intermediate certificate")
	domain := flag.String("domain", "", "domain used in tls Handshake/SNI")
	ip := flag.String("ip", "", "(Optional) IP address of the target host")
	port := flag.Int("port", 443, "(Optional) TCP port of the target host")
	flag.Parse()

	if *leafPath == "" || *intermediatePath == "" || *domain == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	return *leafPath, *intermediatePath, *domain, *ip, *port
}

func main() {
	leafPath, intermediatePath, domain, ip, port := cli()
	peerName := domain
	var server string
	if ip != "" {
		server = ip
	} else {
		server = peerName
	}

	peer := fmt.Sprintf("%s:%d", server, port)
	ipConn, err := net.DialTimeout("tcp", peer, 10*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer ipConn.Close()

	conf := &tls.Config{ServerName: peerName}
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
	err = writeCertificates(certs, intermediatePath, leafPath)
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
