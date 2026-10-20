package de.tsenger.certain.asn1.icao;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;


/**
 * Deviation as specified in DOC9303 Part 3
 * <p/>
 * <pre>
 *  Deviation ::= SEQUENCE {
 *  	documents		DeviationDocuments,
 *  	descriptions	SET OF DeviationDescription
 *  }
 * </pre>
 */

public class Deviation extends ASN1Object {
	
	private DeviationDocuments documents;
	private ASN1Set descriptions;
	
	private Deviation(ASN1Sequence seq) {
				
		if (seq.size() < 1 || seq.size() > 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
		
		documents = DeviationDocuments.getInstance(seq.getObjectAt(0));
		descriptions = ASN1Set.getInstance(seq.getObjectAt(1));
		
	}
	
	public static Deviation getInstance(Object obj)
    {
        if (obj instanceof Deviation)
        {
            return (Deviation) obj;
        }
        else if (obj != null)
        {
            return new Deviation(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

	@Override
	public ASN1Primitive toASN1Primitive() {
		
		ASN1EncodableVector v = new ASN1EncodableVector();
		
		v.add(documents);
		v.add(descriptions);
			
		return DERSequence.getInstance(v);
	}
	
	public DeviationDocuments getDocuments() {
		return documents;
	}
		
	public ASN1Set getDescriptions() {
		return descriptions;
	}

}
