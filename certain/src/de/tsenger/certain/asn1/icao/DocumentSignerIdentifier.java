package de.tsenger.certain.asn1.icao;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;


/**
 * DocumentSignerIdentifier as specified in DOC9303 Part 3
 * <p/>
 * <pre>
 *  DocumentSignerIdentifier ::= CHOICE {
 *  	issuerAndSerialNumber	[1] IssuerAndSerialNumber,
 *  	subjectKeyIdentifier	[2] SubjectKeyIdentifier,
 *  	certificateDigest		[3] Digest
 *  }
 * </pre>
 */

public class DocumentSignerIdentifier extends ASN1Object implements ASN1Choice {
	
	
	private ASN1Encodable obj;
	private int tag;
	
	public static final int TYPE_issuerAndSerialNumber = 1;
	public static final int TYPE_subjectKeyIdentifier = 2;
	public static final int TYPE_certificateDigest = 3;
	
	
	public DocumentSignerIdentifier(IssuerAndSerialNumber iasn) {
		this.obj = iasn;
		this.tag = TYPE_issuerAndSerialNumber;
	}
	
	public DocumentSignerIdentifier(SubjectKeyIdentifier ski) {
		this.obj = ski;
		this.tag = TYPE_subjectKeyIdentifier;
	}
	
	public DocumentSignerIdentifier(ASN1OctetString ocString) {
		this.obj = ocString;
		this.tag = TYPE_certificateDigest;
	}
	
	public static DocumentSignerIdentifier getInstance(Object obj)
    {
        if (obj == null || obj instanceof DocumentSignerIdentifier)
        {
            return (DocumentSignerIdentifier) obj;
        }
        else if (obj instanceof ASN1TaggedObject)
        {
        	ASN1TaggedObject    tagObj = (ASN1TaggedObject)obj;
        	int tag = tagObj.getTagNo();
        	
        	ASN1Encodable asn1enc = null;
			try {
				asn1enc = tagObj.getObjectParser(TYPE_issuerAndSerialNumber, false);
			} catch (IOException e) {
				return null;
			}
			
    		switch (tag) {
            	case TYPE_issuerAndSerialNumber:    
            		return new DocumentSignerIdentifier(IssuerAndSerialNumber.getInstance(asn1enc));
            	case TYPE_subjectKeyIdentifier:
            		return new DocumentSignerIdentifier(SubjectKeyIdentifier.getInstance(tagObj, false));
            	case TYPE_certificateDigest:
            		return new DocumentSignerIdentifier(ASN1OctetString.getInstance(tagObj, false));
            	default:
            		throw new IllegalArgumentException("unknown tag: " + tagObj.getTagNo());
            }
        }

        return null;
    }

	@Override
	public ASN1Primitive toASN1Primitive() {
		
		return new DERTaggedObject(true, tag, obj);
		 
	}
	
	public ASN1Encodable getDSIdentifier() {
		return obj;
	}
		
	public int getTag() {
		return tag;
	}

}
