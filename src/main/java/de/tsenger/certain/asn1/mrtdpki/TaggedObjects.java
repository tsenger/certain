package de.tsenger.certain.asn1.mrtdpki;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.BERTags;

/**
 * Reads context-specific tagged fields of the defect list. BSI TR-03129-2 refers to BSI TR-03129-3 for the module
 * and its tagging environment, so a field is accepted with EXPLICIT and with IMPLICIT tagging.
 */
final class TaggedObjects {

	private TaggedObjects() {
	}

	/**
	 * @param universalTag the universal tag of the field type, e.g. {@link BERTags#SEQUENCE}
	 * @return the contents of the field
	 * @throws IllegalArgumentException or IllegalStateException if the contents are not of that type
	 */
	static ASN1Primitive base(ASN1TaggedObject tagged, int universalTag) {
		if (tagged.isExplicit()) {
			ASN1Primitive base = tagged.getExplicitBaseObject().toASN1Primitive();
			if (hasType(base, universalTag)) return base;
		}
		ASN1Primitive base = tagged.getBaseUniversal(false, universalTag);
		if (universalTag == BERTags.OCTET_STRING) {
			// a constructed field would be read as an OCTET STRING made of its elements, which needs them to be OCTET STRINGs
			ASN1OctetString.getInstance(base).getOctets();
		}
		return base;
	}

	private static boolean hasType(ASN1Primitive base, int universalTag) {
		switch (universalTag) {
		case BERTags.SEQUENCE: return base instanceof ASN1Sequence;
		case BERTags.OCTET_STRING: return base instanceof ASN1OctetString;
		case BERTags.UTF8_STRING: return base instanceof ASN1UTF8String;
		default: return false;
		}
	}
}
