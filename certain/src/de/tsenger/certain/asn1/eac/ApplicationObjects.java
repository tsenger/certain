package de.tsenger.certain.asn1.eac;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * Reads and creates the APPLICATION tagged data objects used in CV certificates (ISO 7816, TR-03110).
 * <p>
 * Bouncy Castle represents them as {@link ASN1TaggedObject}. A data object either holds raw
 * contents (e.g. a date or a signature) or other data objects (e.g. the certificate body).
 */
final class ApplicationObjects {

	private ApplicationObjects() {
	}

	/** @return true if {@code obj} is a tagged object of the class APPLICATION */
	static boolean isApplication(ASN1Encodable obj) {
		return obj instanceof ASN1TaggedObject && ((ASN1TaggedObject) obj).hasTagClass(BERTags.APPLICATION);
	}

	/**
	 * @param obj an {@link ASN1TaggedObject} or its encoding
	 * @throws IllegalArgumentException if {@code obj} is not APPLICATION tagged
	 */
	static ASN1TaggedObject getInstance(Object obj) {
		ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(obj);
		if (!isApplication(tagged)) {
			throw new IllegalArgumentException("not an APPLICATION tagged object, tag class: " + tagged.getTagClass());
		}
		return tagged;
	}

	/** @return the contents of a data object that holds raw bytes */
	static byte[] octets(ASN1TaggedObject tagged) {
		return ((ASN1OctetString) tagged.getBaseUniversal(false, BERTags.OCTET_STRING)).getOctets();
	}

	/** @return the contents of a data object that holds other data objects */
	static ASN1Sequence children(ASN1TaggedObject tagged) {
		return (ASN1Sequence) tagged.getBaseUniversal(false, BERTags.SEQUENCE);
	}

	/** Creates a data object that holds raw bytes. */
	static ASN1TaggedObject create(int tag, byte[] contents) {
		return new DERTaggedObject(false, BERTags.APPLICATION, tag, new DEROctetString(contents));
	}

	/** Creates a data object that holds the given data objects. */
	static ASN1TaggedObject create(int tag, ASN1EncodableVector children) {
		return new DERTaggedObject(false, BERTags.APPLICATION, tag, new DERSequence(children));
	}

	/** Creates a data object that replaces the tag of {@code contents} (implicit tagging). */
	static ASN1TaggedObject create(int tag, ASN1Encodable contents) {
		return new DERTaggedObject(false, BERTags.APPLICATION, tag, contents);
	}
}
