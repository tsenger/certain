# certain
certain is a command line CV certificate parser written in Java. It parses card verifiable certificates as specified in BSI TR-03110 and verifies the contained signatures. 

<pre><code>
Usage: certain [options]
  Options:
    --cert, -c
      CVCA, DV or terminal certificate files (e.g. -c &lt;file1&gt; [&lt;file2&gt; ...])
    --details, -d
      Show more details (full public key values and signature bytes) on the
      certificates and requests
      Default: false
    --dlist, -dl
      Deviation List or Defect List file, shows all deviations or defects
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
      ICAO CSCA Master List file
    --version, -V
      Show the version and exit
      Default: false
  Exit codes:
    0  every check passed
    1  at least one check failed (e.g. an invalid signature)
    2  wrong usage, or an input file could not be read or parsed
    3  at least one check could not be done (e.g. missing issuer certificate)
</code></pre>

The contents and the results of the checks are written to stdout, error messages to stderr. The exit code summarizes the checks, so that certain can be used in scripts: `0` if every check passed, `1` if a check failed (e.g. an invalid signature), `2` on wrong usage or if an input file could not be read or parsed, and `3` if a check could not be done (e.g. because the issuer certificate was not given). If several apply, `1` takes precedence over `2`, and `2` over `3`.

## Download
Get latest version here
https://github.com/tsenger/certain/releases/

## Example
input:
<pre><code>
java -jar certain.jar -c DETESTeID00002.cvcert 
</code></pre>

ouput:
<pre><code>
---------------------------------------------------
Parsing DETESTeID00002
---------------------------------------------------
CAR: DETESTeID00002
CHR: DETESTeID00002

Public Key
OID : 0.4.0.127.0.7.2.2.2.2.3 (id_TA_ECDSA_SHA_256)
0x81 Prime modulus p:       a9fb57... (32 Bytes)
0x82 First coefficient a:   7d5a09... (32 Bytes)
0x83 Second coefficient b:  26dc5c... (32 Bytes)
0x84 Base point G :         048bd2... (65 Bytes)
0x85 Order of base point r: a9fb57... (32 Bytes)
0x86 Public point Y:        04096e... (65 Bytes)
0x87 Cofactor f:            01... (1 Bytes)

Certificate Holder Authorization Template (CHAT)
Terminal Type: Authentication Terminal (AT)
Role: CVCA
Read access to DG 1, 2, 3, 4, 5, 6, 7, 8, 9, 17, 18, 19, 20, 
Write access to DG 17, 18, 19, 20, 21
Install Qualified Certificate
Install Certificate
PIN Management
CAN allowed
Privileged Terminal
Restricted Identification
Community ID Verification
Age Verification

Certificate Effective Date : 100921
Certificate Expiration Date: 130921

Signature is VALID
</code></pre>
