package de.tsenger.certain.asn1.mrtdpki;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;

/**
 * SignerCertificateReference as specified in BSI TR-03129-2, 8.1 (defect list version 3)
 * <pre>
 *  SignerCertificateReference ::= SEQUENCE {
 *  	issuerAndSerialNumber	[0] IssuerAndSerialNumber OPTIONAL,
 *  	subjectKeyIdentifier	[1] SubjectKeyIdentifier OPTIONAL,
 *  	signerReference			[2] UTF8String OPTIONAL,
 *  	certificateHash			[3] OCTET STRING OPTIONAL
 *  }
 * </pre>
 */
public class SignerCertificateReference extends ASN1Object {

	private final ASN1Sequence seq;
	private IssuerAndSerialNumber issuerAndSerialNumber;
	private ASN1OctetString subjectKeyIdentifier;
	private String signerReference;
	private ASN1OctetString certificateHash;

	private SignerCertificateReference(ASN1Sequence seq) {
		this.seq = seq;
		for (int i = 0; i < seq.size(); i++) {
			ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
			switch (tagged.getTagNo()) {
			case 0: issuerAndSerialNumber = IssuerAndSerialNumber.getInstance(TaggedObjects.base(tagged, BERTags.SEQUENCE)); break;
			case 1: subjectKeyIdentifier = ASN1OctetString.getInstance(TaggedObjects.base(tagged, BERTags.OCTET_STRING)); break;
			case 2: signerReference = ASN1UTF8String.getInstance(TaggedObjects.base(tagged, BERTags.UTF8_STRING)).getString(); break;
			case 3: certificateHash = ASN1OctetString.getInstance(TaggedObjects.base(tagged, BERTags.OCTET_STRING)); break;
			default: throw new IllegalArgumentException("unknown tag in SignerCertificateReference: " + tagged.getTagNo());
			}
		}
	}

	/** @throws IllegalArgumentException if the object is not a SignerCertificateReference */
	public static SignerCertificateReference getInstance(Object obj) {
		if (obj instanceof SignerCertificateReference) return (SignerCertificateReference) obj;
		return new SignerCertificateReference(ASN1Sequence.getInstance(obj));
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return seq;
	}

	public IssuerAndSerialNumber getIssuerAndSerialNumber() {
		return issuerAndSerialNumber;
	}

	public ASN1OctetString getSubjectKeyIdentifier() {
		return subjectKeyIdentifier;
	}

	public String getSignerReference() {
		return signerReference;
	}

	public ASN1OctetString getCertificateHash() {
		return certificateHash;
	}
}
