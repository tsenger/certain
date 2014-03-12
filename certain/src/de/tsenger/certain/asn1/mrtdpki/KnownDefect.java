package de.tsenger.certain.asn1.mrtdpki;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERSequence;

/**
 * KnowDefect as specified in BSI TR-03129
 * <p/>
 * <pre>
 *  KnowDefect ::= SEQUENCE {
 *  	defectType	OBJECT IDENTIFIER,
 *  	parameters	ANY defined by defectType OPTIONAL
 *  }
 * </pre>
 */

public class KnownDefect extends ASN1Object {
	
	private ASN1ObjectIdentifier defectType;
	private ASN1Encodable parameters;
	
	private KnownDefect(ASN1Sequence seq) {
		
		if (seq.size() < 1 || seq.size() > 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

		defectType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
		
		if (seq.size() > 1) {
			parameters = seq.getObjectAt(1);
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(defectType);

        if (parameters != null)
        {
            v.add(parameters);
        }

        return BERSequence.getInstance(v);
	}
	
	public ASN1ObjectIdentifier getDefectType() {
		return defectType;
	}
	
	public ASN1Encodable getParameters() {
		return parameters;
	}

}
