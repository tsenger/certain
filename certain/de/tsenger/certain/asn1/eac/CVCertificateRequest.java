//package org.bouncycastle.asn1.eac;
package de.tsenger.certain.asn1.eac;

import java.io.IOException;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DEROctetString;


public class CVCertificateRequest extends ASN1Object
{
    private CertificateBody certificateBody;
    
    private CertificationAuthorityReference outerCAR;

    private byte[] innerSignature = null;
    private byte[] outerSignature = null;

    private CVCertificateRequest(DERApplicationSpecific request)  throws IOException
    {
//        if (request.getApplicationTag() == EACTags.AUTHENTIFICATION_DATA)
    	if (request.getApplicationTag() == 7)
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(request.getObject(BERTags.SEQUENCE));

            initCertBody(DERApplicationSpecific.getInstance(seq.getObjectAt(0)));
            
            outerCAR = new CertificationAuthorityReference(DERApplicationSpecific.getInstance(seq.getObjectAt(1)).getContents());

            outerSignature = DERApplicationSpecific.getInstance(seq.getObjectAt(seq.size() - 1)).getContents();
        }
        else
        {
            initCertBody(request);
        }
    }

    private void initCertBody(DERApplicationSpecific request)
        throws IOException
    {
        if (request.getApplicationTag() == EACTags.CARDHOLDER_CERTIFICATE)
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(request.getObject(BERTags.SEQUENCE));
            for (Enumeration<?> en = seq.getObjects(); en.hasMoreElements();)
            {
                DERApplicationSpecific obj = DERApplicationSpecific.getInstance(en.nextElement());
                switch (obj.getApplicationTag())
                {
                case EACTags.CERTIFICATE_CONTENT_TEMPLATE:
                    certificateBody = CertificateBody.getInstance(obj);
                    break;
                case EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP:
                    innerSignature = obj.getContents();
                    break;
                default:
                    throw new IOException("Invalid tag, not an CV Certificate Request element:" + obj.getApplicationTag());
                }
            }
        }
        else
        {
            throw new IOException("not a CARDHOLDER_CERTIFICATE in request:" + request.getApplicationTag());
        }
    }

    public static CVCertificateRequest getInstance(Object obj)
    {
        if (obj instanceof CVCertificateRequest)
        {
            return (CVCertificateRequest)obj;
        }
        else if (obj != null)
        {
            try
            {
                return new CVCertificateRequest(DERApplicationSpecific.getInstance(obj));
            }
            catch (IOException e)
            {
                throw new ASN1ParsingException("unable to parse data: " + e.getMessage(), e);
            }
        }

        return null;
    }

    ASN1ObjectIdentifier signOid = null;
    ASN1ObjectIdentifier keyOid = null;

    public static byte[] ZeroArray = new byte[]{0};


    String strCertificateHolderReference;

    byte[] encodedAuthorityReference;

    int ProfileId;

    /**
     * Returns the body of the certificate template
     *
     * @return the body.
     */
    public CertificateBody getCertificateBody()
    {
        return certificateBody;
    }
    
    /**
     * Returns the Certification Authority Reference for the outer Signature
     *
     * @return the CAR
     */
    public CertificationAuthorityReference getOuterCAR() {
    	return outerCAR;
    }
    
    public String getOuterCarStr() {
    	CertificationAuthorityReference car = getOuterCAR();
    	return car.getCountryCode()+car.getHolderMnemonic()+car.getSequenceNumber();
    }

    /**
     * Return the public key data object carried in the request
     * @return  the public key
     */
    public PublicKeyDataObject getPublicKey()
    {
        return certificateBody.getPublicKey();
    }

    public byte[] getInnerSignature()
    {
        return innerSignature;
    }

    public byte[] getOuterSignature()
    {
        return outerSignature;
    }

    byte[] certificate = null;
    protected String overSignerReference = null;

    public boolean hasOuterSignature()
    {
        return outerSignature != null;
    }

    byte[] encoded;

    PublicKeyDataObject iso7816PubKey = null;

    @Override
	public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(certificateBody);

        try
        {
            v.add(new DERApplicationSpecific(false, EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP, new DEROctetString(innerSignature)));
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to convert signature!");
        }

        return new DERApplicationSpecific(EACTags.CARDHOLDER_CERTIFICATE, v);
    }
}
