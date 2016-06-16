package de.tsenger.certain.asn1.icao;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;


/**
 * CertField as specified in DOC9303 Part 3
 * <p/>
 * <pre>
 *  DocumentSignerIdentifier ::= CHOICE {
 *  	body		CertificateBodyField,
 *  	extension	OBJECT IDENTIFIER
 *  }
 *  
 *  CertificateBodyField ::= INTEGER {
 *  	generic(0), version(1), serialNumber(2), signature(3),
 *      issuer(4), validity(5), subject(6), subjectPublicKeyInfo (7),
 *      issuerUniqueID(8), subjectUniqueID(9)
 *  }
 * </pre>
 */

public class CertField extends ASN1Object implements ASN1Choice {
	
	public static final int GENERIC				= 0;
	public static final int VERSION				= 1;
	public static final int SERIALNUMBER		= 2;
	public static final int SIGNATURE			= 3;
	public static final int ISSUER				= 4;
	public static final int VALIDITY			= 5;
	public static final int SUBJECT				= 6;
	public static final int SUBJECTPUBKEYINFO	= 7;
	public static final int ISSUERUNIQUEID		= 8;
	public static final int SUBJECTUNIQUEID		= 9;
	
	private ASN1Encodable obj;
	
	
	public CertField(int certBodyField) {
		 if (certBodyField <=9 && certBodyField >= 0)
	        {
	                obj = new ASN1Integer(certBodyField);
	        }
	        else
	        {
	            throw new IllegalArgumentException("unknow CertificateBodyField : " + certBodyField);
	        } 
	}
	
	public CertField(ASN1ObjectIdentifier oid) {
		this.obj = oid;
	}

	
	public static CertField getInstance(Object obj)
    {
        if (obj == null || obj instanceof CertField)
        {
            return (CertField) obj;
        }
        
        if (obj instanceof ASN1TaggedObject) {
        	ASN1Object embeddedObj = ASN1TaggedObject.getInstance(obj).getObject();
        	
        	if (embeddedObj instanceof ASN1Integer)
            {
                ASN1Integer certBodyFieldObj = ASN1Integer.getInstance(embeddedObj);
                int  certBodyField = certBodyFieldObj.getValue().intValue();

                return new CertField(certBodyField);
            }
            else if (embeddedObj instanceof ASN1ObjectIdentifier)
            {
                ASN1ObjectIdentifier extensionOID = ASN1ObjectIdentifier.getInstance(embeddedObj);
                return new CertField(extensionOID);
            }
        }
        

        throw new IllegalArgumentException("unknown object in getInstance");
    }

	@Override
	public ASN1Primitive toASN1Primitive() {
		
		return obj.toASN1Primitive();
		 
	}
		
	public int getCertificateBodyField() {
		if (obj instanceof ASN1Integer) {
			return ((ASN1Integer)obj).getValue().intValue();
		}
		else return -1;
	}
	
	public ASN1ObjectIdentifier getExtensionOID()  {
		if (obj instanceof ASN1ObjectIdentifier) {
			return (ASN1ObjectIdentifier)obj;
		}
		else return null;
    }

}
