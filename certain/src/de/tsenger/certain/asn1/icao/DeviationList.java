package de.tsenger.certain.asn1.icao;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;



/**
 * DeviationList as specified in BSI TR-03129
 * <p/>
 * <pre>
 *  DeviationList ::= SEQUENCE {
 *  	version			INTEGER {v0 (0) },
 *  	digestAlg		Algorithm Identifier OPTIONAL,
 *  	deviations		SET OF Deviation
 *  }
 * </pre>
 */

public class DeviationList extends ASN1Object 
{
	private ASN1Integer version;
	private AlgorithmIdentifier digestAlg;
	private ASN1Set deviations;
	
	private DeviationList(ASN1Sequence seq) {
		
		int index = 0;
		
		if (seq.size() < 2 || seq.size() > 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
		
		version = ASN1Integer.getInstance(seq.getObjectAt(index++));
		
		if (seq.getObjectAt(index) instanceof AlgorithmIdentifier) {
			digestAlg = AlgorithmIdentifier.getInstance(seq.getObjectAt(index++));
		}
		if (seq.getObjectAt(index) instanceof AlgorithmIdentifier) {
			deviations = ASN1Set.getInstance(seq.getObjectAt(index++));
		}		
		
		
	}
	
	public static DeviationList getInstance(Object obj)
    {
        if (obj instanceof DeviationList)
        {
            return (DeviationList)obj;
        }
        else if (obj != null)
        {
            return new DeviationList(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

	@Override
	public ASN1Primitive toASN1Primitive() {
		
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(version);
		
		if (digestAlg != null) {
			v.add(digestAlg);
		}
		
		v.add(deviations);		
		
		return DERSequence.getInstance(v);
	}
	
	public int getVersion() {
		return version.getValue().intValue();
	}
	
	public AlgorithmIdentifier getDigestAlg() {
		return digestAlg;
	}
	
	public ASN1Set getDeviations() {
		return deviations;
	}

	

}
