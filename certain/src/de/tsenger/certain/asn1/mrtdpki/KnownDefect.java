package de.tsenger.certain.asn1.mrtdpki;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.BERTags;

/**
 * VersionedKnownDefect as specified in BSI TR-03129-2, 8.1: a KnownDefect (version 1) or a KnownDefectV2
 * (versions 2 and 3).
 * <pre>
 *  VersionedKnownDefect ::= CHOICE {
 *  	knownDefect		KnownDefect,
 *  	knownDefectV2	[0] KnownDefectV2
 *  }
 *  KnownDefect ::= SEQUENCE {
 *  	defectType	OBJECT IDENTIFIER,
 *  	parameters	ANY DEFINED BY defectType OPTIONAL
 *  }
 *  KnownDefectV2 ::= SEQUENCE {
 *  	defectType	OBJECT IDENTIFIER,
 *  	parameters	[0] ANY DEFINED BY defectType OPTIONAL,
 *  	description	[1] UTF8String OPTIONAL
 *  }
 * </pre>
 */
public class KnownDefect extends ASN1Object {

	private final ASN1Encodable encoded;
	private final boolean v2;
	private ASN1ObjectIdentifier defectType;
	private ASN1Encodable parameters;
	private String description;

	private KnownDefect(ASN1Encodable obj) {
		this.encoded = obj;
		this.v2 = obj instanceof ASN1TaggedObject;
		ASN1Sequence seq;
		if (v2) {
			ASN1TaggedObject tagged = (ASN1TaggedObject) obj;
			if (tagged.getTagNo() != 0) throw new IllegalArgumentException("unknown tag of VersionedKnownDefect: " + tagged.getTagNo());
			seq = ASN1Sequence.getInstance(TaggedObjects.base(tagged, BERTags.SEQUENCE));
		} else {
			seq = ASN1Sequence.getInstance(obj);
		}
		if (seq.size() < 1 || seq.size() > 3) {
			throw new IllegalArgumentException("Bad sequence size: " + seq.size());
		}
		defectType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
		for (int i = 1; i < seq.size(); i++) {
			if (!v2) {
				if (i > 1) throw new IllegalArgumentException("Bad sequence size: " + seq.size());
				parameters = seq.getObjectAt(i);
				continue;
			}
			ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
			if (tagged.getTagNo() == 0) {
				// ANY is always tagged explicitly; if not, the parameters are kept as tagged object
				parameters = tagged.isExplicit() ? tagged.getExplicitBaseObject() : tagged;
			} else if (tagged.getTagNo() == 1) {
				description = ASN1UTF8String.getInstance(TaggedObjects.base(tagged, BERTags.UTF8_STRING)).getString();
			} else {
				throw new IllegalArgumentException("unknown tag in KnownDefectV2: " + tagged.getTagNo());
			}
		}
	}

	/** @throws IllegalArgumentException if the object is neither a KnownDefect nor a KnownDefectV2 */
	public static KnownDefect getInstance(Object obj) {
		if (obj instanceof KnownDefect) return (KnownDefect) obj;
		if (obj instanceof ASN1TaggedObject) return new KnownDefect((ASN1TaggedObject) obj);
		return new KnownDefect(ASN1Sequence.getInstance(obj));
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return encoded.toASN1Primitive();
	}

	/** @return true for a KnownDefectV2, false for a KnownDefect */
	public boolean isV2() {
		return v2;
	}

	public ASN1ObjectIdentifier getDefectType() {
		return defectType;
	}

	public ASN1Encodable getParameters() {
		return parameters;
	}

	public String getDescription() {
		return description;
	}
}
