package de.tsenger.certain.asn1.icao;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;


/**
 * IssuancePeriod as specified in DOC9303 Part 3
 * <p/>
 * <pre>
 *  IssuancePeriod ::= SEQUENCE {
 *  	firstIssued		GeneralizedTime,
 *  	lastIssued		GeneralizedTime
 *  }
 * </pre>
 */

public class IssuancePeriod extends ASN1Object {
	
	private ASN1GeneralizedTime firstIssued, lastIssued;
	
	private IssuancePeriod(ASN1Sequence seq) {
				
		if (seq.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
		
		firstIssued = ASN1GeneralizedTime.getInstance(seq.getObjectAt(0));
		lastIssued  = ASN1GeneralizedTime.getInstance(seq.getObjectAt(1));
		
	}
	
	public static IssuancePeriod getInstance(Object obj)
    {
        if (obj instanceof IssuancePeriod)
        {
            return (IssuancePeriod) obj;
        }
        else if (obj != null)
        {
            return new IssuancePeriod(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

	@Override
	public ASN1Primitive toASN1Primitive() {
		
		ASN1EncodableVector v = new ASN1EncodableVector();
		
		v.add(firstIssued);
		v.add(lastIssued);
			
		return DERSequence.getInstance(v);
	}
	
	public ASN1GeneralizedTime getFirstIssued() {
		return firstIssued;
	}
		
	public ASN1GeneralizedTime getLastIssued() {
		return lastIssued;
	}

}
