# certain
certain is a command line CV certificate parser written in Java. It parses card verifiable certificates as specified in BSI TR-03110 and verifies the contained signatures. 

<pre><code>
Usage: certain [options]
  Options:
    --cert, -c
       CVCA or DV certificate input files. Parameter can receive multiply
       values. (e.g. --cert &lt;file1&gt; [&lt;file2&gt; [&lt;file3&gt;] ... ]
    --defectlist, -dl
       shows all defects in the given Defect List
    --details, -d
       Show more details (full publickey values and signature bytes) on the
       certificates and requests.
       Default: false
    --dvreq, -r
       DV request input file
    --fingerprint, -f
       Show MD5, SHA1, SHA224 and SHA256 printerprint for certificates and
       requests.
       Default: false
    --help, -h
       need help?
       Default: false
    --linkcert, -l
       Link certificate input file to new CVCA
</code></pre>

## Download
Get latest version here
https://github.com/tsenger/certain/blob/master/certain/dist/certain_0.92.jar

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
