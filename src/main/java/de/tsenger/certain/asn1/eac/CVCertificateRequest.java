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
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.eac.CertificationAuthorityReference;
import org.bouncycastle.asn1.eac.PublicKeyDataObject;


public class CVCertificateRequest extends ASN1Object
{
    private CertificateBody certificateBody;
    
    private CertificationAuthorityReference outerCAR;

    private byte[] innerSignature = null;
    private byte[] outerSignature = null;

	private CVCertificateRequest(ASN1TaggedObject request) throws IOException {

		if (request.hasTag(BERTags.APPLICATION, 7)) {
			ASN1Sequence seq = ApplicationObjects.children(request);

			try {
				outerCAR = References.authorityReference("!!! MISSING CAR DATA OBJECT !!!".getBytes());
				for (int i = 0; i < seq.size(); i++) {
					ASN1TaggedObject element = ApplicationObjects.getInstance(seq.getObjectAt(i));
					int tag = element.getTagNo();
					if (tag == 0x21)
						initCertBody(element);
					else if (tag == 0x2)
						outerCAR = References.authorityReference(ApplicationObjects.octets(element));
					else if (tag == 0x37)
						outerSignature = ApplicationObjects.octets(element);

				}
			} catch (IllegalArgumentException e) {
				throw new IOException("Didn't found a valid CVCertificate request!");
			}

		} else initCertBody(request);
	}

    private void initCertBody(ASN1TaggedObject request)
        throws IOException
    {
        if (request.hasTag(BERTags.APPLICATION, EACTags.CARDHOLDER_CERTIFICATE))
        {
            ASN1Sequence seq = ApplicationObjects.children(request);
            for (Enumeration<?> en = seq.getObjects(); en.hasMoreElements();)
            {
                ASN1TaggedObject obj = ApplicationObjects.getInstance(en.nextElement());
                switch (obj.getTagNo())
                {
                case EACTags.CERTIFICATE_CONTENT_TEMPLATE:
                    certificateBody = CertificateBody.getInstance(obj);
                    break;
                case EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP:
                    innerSignature = ApplicationObjects.octets(obj);
                    break;
                default:
                    throw new IOException("Invalid tag, not an CV Certificate Request element:" + obj.getTagNo());
                }
            }
        }
        else
        {
            throw new IOException("not a CARDHOLDER_CERTIFICATE in request:" + request.getTagNo());
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
                return new CVCertificateRequest(ApplicationObjects.getInstance(obj));
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

        v.add(ApplicationObjects.create(EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP, innerSignature));

        return ApplicationObjects.create(EACTags.CARDHOLDER_CERTIFICATE, v);
    }
}
