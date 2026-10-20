package de.tsenger.certain.asn1.mrtdpki;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.cms.SignerIdentifier;

/**
 * Defect as specified in BSI TR-03129-2, 8.1 (defect list versions 1 to 3)
 * <pre>
 *  Defect ::= SEQUENCE {
 *  	signerIdentifier			SignerIdentifier OPTIONAL,	-- present in v1, MUST NOT be present in v3
 *  	certificateHash				OCTET STRING OPTIONAL,		-- MUST NOT be present in v3
 *  	signercertificateReference	SignerCertificateReference OPTIONAL,
 *  	caCertificateReference		CaCertificateReference OPTIONAL,
 *  	knownDefects				SET OF VersionedKnownDefect,
 *  	description					UTF8String OPTIONAL		-- MAY only be present in v2 or v3
 *  }
 * </pre>
 * The two references are both untagged SEQUENCEs; they are told apart by their contents.
 */
public class Defect extends ASN1Object {

	private final ASN1Sequence seq;
	private SignerIdentifier signerId;
	private ASN1OctetString certificateHash;
	private SignerCertificateReference signerCertificateReference;
	private CaCertificateReference caCertificateReference;
	private ASN1Set knownDefects;
	private String description;

	private Defect(ASN1Sequence seq) {
		this.seq = seq;
		for (int i = 0; i < seq.size(); i++) {
			ASN1Encodable element = seq.getObjectAt(i);
			if (element instanceof ASN1TaggedObject || isIssuerAndSerialNumber(element)) {
				signerId = SignerIdentifier.getInstance(element);
			} else if (element instanceof ASN1OctetString) {
				certificateHash = (ASN1OctetString) element;
			} else if (element instanceof ASN1Sequence) {
				parseReference((ASN1Sequence) element);
			} else if (element instanceof ASN1Set) {
				knownDefects = (ASN1Set) element;
			} else if (element instanceof ASN1UTF8String) {
				description = ((ASN1UTF8String) element).getString();
			} else {
				throw new IllegalArgumentException("unknown element in Defect: " + element);
			}
		}
		if (knownDefects == null) throw new IllegalArgumentException("knownDefects missing in Defect");
	}

	private void parseReference(ASN1Sequence reference) {
		if (signerCertificateReference == null && caCertificateReference == null) {
			try {
				signerCertificateReference = SignerCertificateReference.getInstance(reference);
				return;
			} catch (RuntimeException e) {
				// not a SignerCertificateReference, try the CaCertificateReference
			}
		}
		if (caCertificateReference != null) throw new IllegalArgumentException("unknown SEQUENCE in Defect: " + reference);
		caCertificateReference = CaCertificateReference.getInstance(reference);
	}

	private static boolean isIssuerAndSerialNumber(ASN1Encodable element) {
		if (!(element instanceof ASN1Sequence)) return false;
		ASN1Sequence s = (ASN1Sequence) element;
		return s.size() == 2 && s.getObjectAt(0) instanceof ASN1Sequence && s.getObjectAt(1) instanceof ASN1Integer;
	}

	public static Defect getInstance(Object obj) {
		if (obj instanceof Defect) return (Defect) obj;
		if (obj != null) return new Defect(ASN1Sequence.getInstance(obj));
		return null;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return seq;
	}

	public SignerIdentifier getSignerId() {
		return signerId;
	}

	public ASN1OctetString getCertificateHash() {
		return certificateHash;
	}

	public SignerCertificateReference getSignerCertificateReference() {
		return signerCertificateReference;
	}

	public CaCertificateReference getCaCertificateReference() {
		return caCertificateReference;
	}

	public ASN1Set getKnownDefects() {
		return knownDefects;
	}

	public String getDescription() {
		return description;
	}
}
