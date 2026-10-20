# certain
certain is a command line parser and verifier written in Java for

- card verifiable (CV) certificates and certificate requests as specified in BSI TR-03110: it shows their contents and verifies the signatures, also along a chain of CVCA, DV and terminal certificates,
- signed lists of the ePassport and eID PKIs:
  - CSCA Master Lists and Deviation Lists (ICAO Doc 9303 Part 12, Part 3),
  - Signer Lists and Defect Lists (BSI TR-03129-2),
  - Block Lists (BSI TR-03129-3) and their predecessor, the Black Lists (BSI TR-03129 V1.10).

  certain shows the content of the lists, verifies the signature of the SignedData object and checks the list against its specification (SignedData profile, extended key usage of the signer, structure of the content).

certain is tolerant: a deviation from the specification is named with a reference to the specification, and certain checks whatever can still be checked instead of aborting.

<pre><code>
Usage: certain [options]
  Options:
    --cert, -c
      CVCA, DV or terminal certificate files (e.g. -c &lt;file1&gt; [&lt;file2&gt; ...])
    --details, -d
      Show more details: full public key values and signature bytes of CV
      certificates and requests, the X.509 certificates of master and signer
      lists, replacement certificates of defect lists and the IDs of block
      lists
      Default: false
    --dlist, -dl
      Deviation List, Defect List or Block List file, shows all deviations,
      defects or blocked IDs
    --dvreq, -r
      DV certificate request file
    --fingerprint, -f
      Show MD5, SHA-1, SHA-224 and SHA-256 fingerprints of certificates and
      requests
      Default: false
    --help, -h
      Show this help and exit
    --linkcert, -l
      Link certificate file (to a new CVCA)
    --masterlist, -ml
      ICAO CSCA Master List or BSI Signer List file (BSI TR-03129-2, 9)
    --version, -V
      Show the version and exit
      Default: false
  Exit codes:
    0  every check passed
    1  at least one check failed (e.g. an invalid signature)
    2  wrong usage, or an input file could not be read or parsed
    3  at least one check could not be done (e.g. missing issuer certificate)
</code></pre>

The contents and the results of the checks are written to stdout, error messages to stderr. The exit code summarizes the checks, so that certain can be used in scripts: `0` if every check passed, `1` if a check failed (e.g. an invalid signature or a violated MUST of the specification), `2` on wrong usage or if an input file could not be read or parsed, and `3` if a check could not be done (e.g. because the issuer certificate was not given). If several apply, `1` takes precedence over `2`, and `2` over `3`. Lines starting with `Note:` are informative (e.g. an expired certificate or a RECOMMENDED field that is missing) and do not affect the exit code.

`-ml` and `-dl` both accept any of the signed lists; the eContentType of the SignedData object decides how the content is parsed.

## Download
Get the latest release here: https://github.com/tsenger/certain/releases/

## Build
certain needs Java 8 or newer and Maven. The Maven project is in the subdirectory `certain/`:
<pre><code>
cd certain
mvn package
java -jar target/certain-1.0.0.jar -c &lt;cert files...&gt;
</code></pre>

## Examples
### CV certificate
input:
<pre><code>
java -jar certain.jar -c DETESTeID00004.cv
</code></pre>

output:
<pre><code>
---------------------------------------------------
Parsing DETESTeID00004
---------------------------------------------------
CAR: DETESTeID00004
CHR: DETESTeID00004

Public Key
OID : 0.4.0.127.0.7.2.2.2.2.3 (id_TA_ECDSA_SHA_256)
0x81 Prime modulus p:       a9fb57... (32 Bytes)
0x82 First coefficient a:   7d5a09... (32 Bytes)
0x83 Second coefficient b:  26dc5c... (32 Bytes)
0x84 Base point G :         048bd2... (65 Bytes)
0x85 Order of base point r: a9fb57... (32 Bytes)
0x86 Public point Y:        0474ff... (65 Bytes)
0x87 Cofactor f:            01... (1 Bytes)

Certificate Holder Authorization Template (CHAT)
Terminal Type: Authentication Terminal (AT)
Role: CVCA
Read access to DG 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 17, 18, 19, 20, 
Write access to DG 17, 18, 19, 20, 
Install Qualified Certificate
Install Certificate
PIN Management
CAN allowed
Privileged Terminal
Restricted Identification
Municipality ID Verification
Age Verification

Certificate Effective Date : 120511
Certificate Expiration Date: 150511

Certificate Extensions: 
 -&gt; no Extensions

Note: this certificate expired on 2015-05-11. Except for CVCA link certificates, expired certificates are rejected by the certificate validation (BSI TR-03110 Part 3, 2.5.1).

Signature is VALID
</code></pre>

### CSCA Master List
input:
<pre><code>
java -jar certain.jar -ml DE_ML_2026-10-01-11-50-52.ml
</code></pre>

output (shortened):
<pre><code>
eContentType: 2.23.136.1.1.2 (ICAO CSCA Master List)
Signed attributes:
	signingTime: 20261001095052GMT+00:00
	...
	contentType: 2.23.136.1.1.2
	messageDigest: 659c981fbfeace14ec4774bd8920daeeff9fcbef139f1ae2e20ba8822b4bacb4

SignedData object contains 2 Signer certificates:

Subject DN: C=DE,O=bund,OU=bsi,SERIALNUMBER=0039,CN=CSCA Master List Signer
Issuer  DN:  C=DE,O=bund,OU=bsi,CN=csca-germany
X509 SubjectKeyIdentifier: 53b0f229d3a2006dc818c1d01b9d4330bda83b6f
Signature is VALID.

Subject DN: C=DE,O=bund,OU=bsi,CN=csca-germany
Issuer  DN:  C=DE,O=bund,OU=bsi,CN=csca-germany
X509 SubjectKeyIdentifier: e8a62993eae208aa203e49d7649bbae1ba3560cb
Signature is VALID.

Signature of SignedData object is VALID


ICAO CSCA Master List version: v0
This ICAO CSCA Master List contains 609 certificates.

+++++++++++++ Certificate no. 1 ++++++++++++++
Subject DN: C=LT,O=ADIC under MoI,CN=CSCA,SERIALNUMBER=004
Issuer  DN:  C=LT,O=ADIC under MoI,CN=CSCA,SERIALNUMBER=004
X509 SubjectKeyIdentifier: 8fbdcaeed6690632782757b41c80c51d73203757
Public Key Algorithm: EC
Signing Algorithm: ECDSA
...
</code></pre>

A violated requirement of the specification is printed with its reference and makes certain exit with `1`, e.g. for a Deviation List whose signer certificate has the wrong extended key usage:
<pre><code>
The extended key usage of the Deviation List Signer certificate MUST contain 2.23.136.1.1.8 but is [2.23.136.1.1.3] (ICAO Doc 9303 Part 12, 7.1.1.3)!
</code></pre>
