## getCertificates

This tool is used to get the certificates over TCP. The DNS resolution can be
bypassed.

~~~
$ ./getCertificates
Usage of ./getCertificates:
  -domain string
	domain used in tls Handshake/SNI
  -insecureSkipVerify
	Skip certificate validation and accept any certificate presented by the server
  -intermediate string
	file for the intermediate certificate
  -ip string
	(Optional) IP address of the target host
  -leaf string
	path to file for the leaf certificate
  -port int
	(Optional) TCP port of the target host (default 443)
~~~

For instance:

~~~
$ ./getCertificates --domain example.com --leaf example.com.pem \
	--intermediate lets-encrypt.pem --ip [2001:db8::1]
~~~
