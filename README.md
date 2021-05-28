## getCertificates

This is used to get the certificates over a TCP. The DNS resolution can be
bypassed.

~~~
$ ./getCertificates
  -domain string
	domain used in tls Handshake/SNI
  -intermediate string
	file for the intermediate certificate
  -ip string
	(Optional) IP address of the target host
  -leaf string
	path to file for the leaf certificate
~~~

For instance:

~~~
$ ./getCertificates --domain example.com --leaf example.com.pem \
	--intermediate lets-encrypt.pem --ip [2001:db8::1]
~~~
