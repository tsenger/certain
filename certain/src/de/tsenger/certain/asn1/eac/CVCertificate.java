//package org.bouncycastle.asn1.eac;
package de.tsenger.certain.asn1.eac;


import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.DEROctetString;

import de.tsenger.tools.Converter;


/**
 * an iso7816Certificate structure.
 * <p/>
 * <pre>
 *  Certificate ::= SEQUENCE {
 *      CertificateBody 		Iso7816CertificateBody,
 *      signature               DER Application specific
 *  }
 * </pre>
 */
public class CVCertificate  extends ASN1Object
{
    private CertificateBody certificateBody;
    private byte[] signature;
    private int valid;
    private static int bodyValid = 0x01;
    private static int signValid = 0x02;
    public static final byte version_1 = 0x0;

    public static String ReferenceEncoding = "ISO-8859-1";

    /**
     * Sets the values of the certificate (body and signature).
     *
     * @param appSpe is a ASN1ApplicationSpecific object containing body and signature.
     * @throws IOException if tags or value are incorrect.
     */
    private void setPrivateData(ASN1ApplicationSpecific appSpe)
        throws IOException
    {
        valid = 0;
        if (appSpe.getApplicationTag() == EACTags.CARDHOLDER_CERTIFICATE)
        {
            ASN1InputStream content = new ASN1InputStream(appSpe.getContents());
            ASN1Primitive tmpObj;
            while ((tmpObj = content.readObject()) != null)
            {
                ASN1ApplicationSpecific aSpe;
                if (tmpObj instanceof ASN1ApplicationSpecific)
                {
                    aSpe = (ASN1ApplicationSpecific)tmpObj;
                    switch (aSpe.getApplicationTag())
                    {
                    case EACTags.CERTIFICATE_CONTENT_TEMPLATE:
                        certificateBody = CertificateBody.getInstance(aSpe);
                        valid |= bodyValid;
                        break;
                    case EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP:
                        signature = aSpe.getContents();
                        valid |= signValid;
                        break;
                    default:
                        throw new IOException("Invalid tag, not an Iso7816CertificateStructure :" + aSpe.getApplicationTag());
                    }
                }
                else
                {
                	content.close();
                    throw new IOException("Invalid Object, not an Iso7816CertificateStructure");
                }
            }
            content.close();
        }
        else
        {
            throw new IOException("not a CARDHOLDER_CERTIFICATE :" + appSpe.getApplicationTag());
        }
    }

    /**
     * Create an iso7816Certificate structure from an ASN1InputStream.
     *
     * @param aIS the byte stream to parse.
     * @return the Iso7816CertificateStructure represented by the byte stream.
     * @throws IOException if there is a problem parsing the data.
     */
    public CVCertificate(ASN1InputStream aIS)
        throws IOException
    {
        initFrom(aIS);
    }

    private void initFrom(ASN1InputStream aIS)
        throws IOException
    {
        ASN1Primitive obj;
        while ((obj = aIS.readObject()) != null)
        {
            if (obj instanceof ASN1ApplicationSpecific)
            {
                setPrivateData((ASN1ApplicationSpecific)obj);
            }
            else
            {
                throw new IOException("Invalid Input Stream for creating an Iso7816CertificateStructure");
            }
        }
    }

    /**
     * Create an iso7816Certificate structure from a ASN1ApplicationSpecific.
     *
     * @param appSpe the ASN1ApplicationSpecific object.
     * @return the Iso7816CertificateStructure represented by the ASN1ApplicationSpecific object.
     * @throws IOException if there is a problem parsing the data.
     */
    private CVCertificate(ASN1ApplicationSpecific appSpe)
        throws IOException
    {
        setPrivateData(appSpe);
    }

    /**
     * Create an iso7816Certificate structure from a body and its signature.
     *
     * @param body the Iso7816CertificateBody object containing the body.
     * @param signature   the byte array containing the signature
     * @return the Iso7816CertificateStructure
     * @throws IOException if there is a problem parsing the data.
     */
    public CVCertificate(CertificateBody body, byte[] signature)
        throws IOException
    {
        certificateBody = body;
        this.signature = signature;
        // patch remi
        valid |= bodyValid;
        valid |= signValid;
    }

    /**
     * Create an iso7816Certificate structure from an object.
     *
     * @param obj the Object to extract the certificate from.
     * @return the Iso7816CertificateStructure represented by the byte stream.
     * @throws IOException if there is a problem parsing the data.
     */
    public static CVCertificate getInstance(Object obj)
    {
        if (obj instanceof CVCertificate)
        {
            return (CVCertificate)obj;
        }
        else if (obj != null)
        {
            try
            {
                return new CVCertificate(ASN1ApplicationSpecific.getInstance(obj));
            }
            catch (IOException e)
            {
                throw new ASN1ParsingException("unable to parse data: " + e.getMessage(), e);
            }
        }

        return null;
    }

    /**
     * Gives the signature of the whole body. Type of signature is given in
     * the Iso7816CertificateBody.Iso7816PublicKey.ASN1ObjectIdentifier
     *
     * @return the signature of the body.
     */
    public byte[] getSignature()
    {
        return signature;
    }

    /**
     * Gives the body of the certificate.
     *
     * @return the body.
     */
    public CertificateBody getBody()
    {
        return certificateBody;
    }

    /**
     * @see org.bouncycastle.asn1.ASN1Object#toASN1Primitive()
     */
    @Override
	public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (valid != (signValid | bodyValid))
        {
            return null;
        }
        v.add(certificateBody);

        try
        {
            v.add(new DERApplicationSpecific(false, EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP, new DEROctetString(signature)));
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to convert signature!");
        }

        return new DERApplicationSpecific(EACTags.CARDHOLDER_CERTIFICATE, v);
    }

    /**
     * @return the Holder authorization and role (CVCA, DV, IS).
     */
    public ASN1ObjectIdentifier getHolderAuthorization()
        throws IOException
    {
        CertificateHolderAuthorization cha = certificateBody.getCertificateHolderAuthorization();
        return cha.getOid();
    }

    /**
     * @return the date of the certificate generation
     */
    public PackedDate getEffectiveDate()
        throws IOException
    {
        return certificateBody.getCertificateEffectiveDate();
    }


    /**
     * @return the type of certificate (request or profile)
     *         value is either Iso7816CertificateBody.profileType
     *         or Iso7816CertificateBody.requestType. Any other value
     *         is not valid.
     */
    public int getCertificateType()
    {
        return this.certificateBody.getCertificateType();
    }

    /**
     * @return the date of the certificate generation
     */
    public PackedDate getExpirationDate()
        throws IOException
    {
        return certificateBody.getCertificateExpirationDate();
    }


    /**
     * @return role description string
     * @see CertificateHolderAuthorization
     */
    
    public String getRoleDescription() 
    {
        CertificateHolderAuthorization cha = certificateBody.getCertificateHolderAuthorization();
        if (cha==null) return null;
        return cha.getRoleDescription();
    }

    /**
     * @return the Authority Reference field of the certificate
     * @throws IOException
     */
    public CertificationAuthorityReference getAuthorityReference()
    {
        return certificateBody.getCertificationAuthorityReference();
    }
    
    public String getCarString() {
    	return certificateBody.getCarString();
    }

    /**
     * @return the Holder Reference Field of the certificate
     * @throws IOException
     */
    public CertificateHolderReference getHolderReference()
    {
        return certificateBody.getCertificateHolderReference();
    }
    
    public String getChrString() {
    	return certificateBody.getChrString();
    }

    /**
     * @return the bits corresponding to the role intented for the certificate
     *         See Iso7816CertificateHolderAuthorization static int for values
     * @throws IOException
     */
    public int getHolderAuthorizationRole()
    {
        int rights = certificateBody.getCertificateHolderAuthorization().getAccessRights()[0];
        return rights;
    }

    /**
     * @return the bits corresponding the authorizations contained in the certificate
     *         See Iso7816CertificateHolderAuthorization static int for values
     * @throws IOException
     */
    public Flags getHolderAuthorizationRights()
        throws IOException
    {
    	byte[] accessRights = certificateBody.getCertificateHolderAuthorization().getAccessRights();
    	accessRights[0]  &= 0x3F;
        return new Flags(Converter.ByteArrayToLong(accessRights));
    }
    
    @Override
	public String toString() {
    	return getChrString();
    }
}