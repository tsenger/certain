package de.tsenger.certain.asn1.mrtdpki;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.SignerIdentifier;


/**
 * Defect as specified in BSI TR-03129
 * <p/>
 * <pre>
 *  Defect ::= SEQUENCE {
 *  	signerIdentifier	SignerIdentifier,
 *  	certificateHash		OCTET STRING OPTIONAL,
 *  	knowDefects			SET OF KnownDefect
 *  }
 * </pre>
 */

public class Defect extends ASN1Object {
	
	private SignerIdentifier signerId;
	private DEROctetString certificateHash;
	private DLSet knownDefects;
	
	private Defect(ASN1Sequence seq) {
		
		int index = 0;
		
		if (seq.size() < 1 || seq.size() > 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
		
		signerId = SignerIdentifier.getInstance(seq.getObjectAt(index++));
		
		if (seq.getObjectAt(index) instanceof ASN1OctetString) {
			certificateHash = (DEROctetString) DEROctetString.getInstance(seq.getObjectAt(index++));
		}
		
		if (seq.getObjectAt(index) instanceof ASN1Set) {
			knownDefects = (DLSet) DLSet.getInstance(seq.getObjectAt(index++));
		} 
	}
	
	public static Defect getInstance(Object obj)
    {
        if (obj instanceof Defect)
        {
            return (Defect) obj;
        }
        else if (obj != null)
        {
            return new Defect(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

	@Override
	public ASN1Primitive toASN1Primitive() {
		
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(signerId);
		
		if (certificateHash!= null) {
			v.add(certificateHash);
		}
		
		v.add(knownDefects);		
		return BERSequence.getInstance(v);
	}
	
	public SignerIdentifier getSignerId() {
		return signerId;
	}
	
	public DEROctetString getCertificateHash() {
		return certificateHash;
	}
	
	public DLSet getKnownDefects() {
		return knownDefects;
	}

}
