package de.tsenger.certain.asn1.mrtdpki;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;

/**
 * CaCertificateReference as specified in BSI TR-03129-2, 8.1 (defect list version 3)
 * <pre>
 *  CaCertificateReference ::= SEQUENCE {
 *  	issuer					[0] Name OPTIONAL,
 *  	authorityKeyIdentifier	[1] AuthorityKeyIdentifier OPTIONAL
 *  }
 * </pre>
 */
public class CaCertificateReference extends ASN1Object {

	private final ASN1Sequence seq;
	private X500Name issuer;
	private AuthorityKeyIdentifier authorityKeyIdentifier;

	private CaCertificateReference(ASN1Sequence seq) {
		this.seq = seq;
		for (int i = 0; i < seq.size(); i++) {
			ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
			switch (tagged.getTagNo()) {
			case 0: issuer = X500Name.getInstance(TaggedObjects.base(tagged, BERTags.SEQUENCE)); break;
			case 1: authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(TaggedObjects.base(tagged, BERTags.SEQUENCE)); break;
			default: throw new IllegalArgumentException("unknown tag in CaCertificateReference: " + tagged.getTagNo());
			}
		}
	}

	/** @throws IllegalArgumentException if the object is not a CaCertificateReference */
	public static CaCertificateReference getInstance(Object obj) {
		if (obj instanceof CaCertificateReference) return (CaCertificateReference) obj;
		return new CaCertificateReference(ASN1Sequence.getInstance(obj));
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return seq;
	}

	public X500Name getIssuer() {
		return issuer;
	}

	public AuthorityKeyIdentifier getAuthorityKeyIdentifier() {
		return authorityKeyIdentifier;
	}
}
