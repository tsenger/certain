package de.tsenger.certain.asn1.icao;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;



/**
 * DeviationDescription as specified in DOC9303 Part 3
 * <p/>
 * <pre>
 *  DeviationDescription ::= SEQUENCE {
 *  	description		PrintableString OPTIONAL,
 *  	deviationType	OBJECT IDENTIFIER,
 *  	parameters		[0] ANY DEFINED BY deviationType OPTIONAL,
 *  	nationalUse		[1] ANY OPTIONAL
 *  }
 * </pre>
 */

public class DeviationDescription extends ASN1Object 
{
	private DERPrintableString description;
	private ASN1ObjectIdentifier deviationType ;
	private ASN1TaggedObject parameters;
	private ASN1TaggedObject nationalUse;
	
	private DeviationDescription(ASN1Sequence seq) {
		
		int index = 0;
		
		if (seq.size() < 1 || seq.size() > 4) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
		

		if (seq.getObjectAt(index) instanceof DERPrintableString) {
			description = DERPrintableString.getInstance(seq.getObjectAt(index++));
		}
		
		if (seq.getObjectAt(index) instanceof ASN1ObjectIdentifier) {
			deviationType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(index++));
		}
		if (seq.getObjectAt(index) instanceof ASN1TaggedObject) {
			parameters = ASN1TaggedObject.getInstance((ASN1TaggedObject) seq.getObjectAt(index++),false);
		}	
		if (seq.getObjectAt(index) instanceof ASN1TaggedObject) {
			nationalUse = ASN1TaggedObject.getInstance((ASN1TaggedObject) seq.getObjectAt(index++),false);
		}
		
		
	}
	
	public static DeviationDescription getInstance(Object obj)
    {
        if (obj instanceof DeviationDescription)
        {
            return (DeviationDescription)obj;
        }
        else if (obj != null)
        {
            return new DeviationDescription(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

	@Override
	public ASN1Primitive toASN1Primitive() {
		
		ASN1EncodableVector v = new ASN1EncodableVector();
		
		if (description != null) {
			v.add(description);
		}
		
		if (deviationType != null) {
			v.add(deviationType);
		}
		
		if (parameters != null) {
			v.add(parameters);
		}
		
		if (nationalUse != null) {
			v.add(nationalUse);
		}
		
		return DERSequence.getInstance(v);
	}
	
	public String getDescription() {
		return description.getString();
	}
	
	public ASN1ObjectIdentifier getDeviationType() {
		return deviationType;
	}
	
	public ASN1TaggedObject getParameters() {
		return parameters;
	}

	public ASN1TaggedObject getNationalUse() {
		return nationalUse;
	}
	

}
