package de.tsenger.certain.asn1.mrtdpki;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DLSet;



/**
 * DefectList as specified in BSI TR-03129
 * <p/>
 * <pre>
 *  DefectList ::= SEQUENCE {
 *  	version		INTEGER {v1 (0) },
 *  	hashAlg		OBJECT IDENTIFIER,
 *  	defects		SET OF Defect
 *  }
 * </pre>
 */

public class DefectList extends ASN1Object 
{
	private ASN1Integer version;
	private ASN1ObjectIdentifier hashAlg;
	private DLSet defects;
	
	private DefectList(ASN1Sequence seq) {
		
		if (seq.size() < 1 || seq.size() > 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
		
		version = ASN1Integer.getInstance(seq.getObjectAt(0));
		hashAlg = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
		defects = (DLSet) DLSet.getInstance(seq.getObjectAt(2));
		
	}
	
	public static DefectList getInstance(Object obj)
    {
        if (obj instanceof DefectList)
        {
            return (DefectList)obj;
        }
        else if (obj != null)
        {
            return new DefectList(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(version);
		v.add(hashAlg);
		v.add(defects);		
		return BERSequence.getInstance(v);
	}
	
	public int getVersion() {
		return version.getValue().intValue();
	}
	
	public ASN1ObjectIdentifier getHashAlg() {
		return hashAlg;
	}
	
	public DLSet getDefects() {
		return defects;
	}

	

}
