//package org.bouncycastle.asn1.eac;
package de.tsenger.certain.asn1.eac;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DEROctetString;


/**
 * an Iso7816CertificateBody structure.
 * <p/>
 * <pre>
 *  CertificateBody ::= SEQUENCE {
 *  	// version of the certificate format. Must be 0 (version 1)
 *      CertificateProfileIdentifer 		ASN1TaggedObject,
 *      //uniquely identifies the issuinng CA's signature key pair
 *      // contains the iso3166-1 alpha2 encoded country code, the
 *      // name of issuer and the sequence number of the key pair.
 *      CertificationAuthorityReference		ASN1TaggedObject,
 *      // stores the encoded public key
 *      PublicKey							Iso7816PublicKey,
 *      //associates the public key contained in the certificate with a unique name
 *      // contains the iso3166-1 alpha2 encoded country code, the
 *      // name of the holder and the sequence number of the key pair.
 *      certificateHolderReference			ASN1TaggedObject,
 *      // Encodes the role of the holder (i.e. CVCA, DV, IS) and assigns read/write
 *      // access rights to data groups storing sensitive data
 *      certificateHolderAuthorization		Iso7816CertificateHolderAuthorization,
 *      // the date of the certificate generation
 *      CertificateEffectiveDate			ASN1TaggedObject,
 *      // the date after which the certificate expires
 *      certificateExpirationDate			ASN1TaggedObject
 *      // certificates may contain extension
 *      certificateExtensions				CertificateExtensions
 *  }
 * </pre>
 */
public class CertificateBody  extends ASN1Object
{
    ASN1InputStream seq;
    private ASN1TaggedObject certificateProfileIdentifier;// version of the certificate format. Must be 0 (version 1)
    private ASN1TaggedObject certificationAuthorityReference;//uniquely identifies the issuing CA's signature key pair
    private PublicKeyDataObject publicKey;// stores the encoded public key
    private ASN1TaggedObject certificateHolderReference;//associates the public key contained in the certificate with a unique name
    private CertificateHolderAuthorization certificateHolderAuthorization;// Encodes the role of the holder (i.e. CVCA, DV, IS) and assigns read/write access rights to data groups storing sensitive data
    private ASN1TaggedObject certificateEffectiveDate;// the date of the certificate generation
    private ASN1TaggedObject certificateExpirationDate;// the date after which the certificate expires
    private CertificateExtensions certificateExtensions;
    private int certificateType = 0;// bit field of initialized data. This will tell us if the data are valid.
    private static final int CPI = 0x01;//certificate Profile Identifier
    private static final int CAR = 0x02;//certification Authority Reference
    private static final int PK = 0x04;//public Key
    private static final int CHR = 0x08;//certificate Holder Reference
    private static final int CHA = 0x10;//certificate Holder Authorization
    private static final int CEfD = 0x20;//certificate Effective Date
    private static final int CExD = 0x40;//certificate Expiration Date
    private static final int CeEx = 0x80;//certificate Extensions

    public static final int certWoExt = 0x7f;//Profile type Certificate without Extension
    public static final int certWExt = 0xff;//Profile type Certificate with Extension
    public static final int requestTypeWithoutCAR = 0x0D;// Request type Certificate without CAR
    public static final int requestTypeWithCAR = 0x0F;// Request type Certificate with CAR
    public static final int requestTypeWithoutCARAndWithExt = 0x8D;//Profile type Certificate without CAR and with Extensions
    public static final int requestTypeWithCARAndWithExt = 0x8F;//Profile type Certificate with CAR and with Extensions
    

    private void setIso7816CertificateBody(ASN1TaggedObject appSpe) throws IOException {
        byte[] content;
        if (appSpe.getTagClass() == BERTags.CONTEXT_SPECIFIC && appSpe.getTagNo() == EACTags.CERTIFICATE_CONTENT_TEMPLATE)
        {
            content = ((ASN1OctetString)appSpe.getLoadedObject()).getOctets();
        }
        else
        {
            throw new IOException("Bad tag : not an iso7816 CERTIFICATE_CONTENT_TEMPLATE");
        }
        ASN1InputStream aIS = new ASN1InputStream(content);
        ASN1Primitive obj;
        while ((obj = aIS.readObject()) != null) {
        	ASN1TaggedObject aSpe;

            if (obj instanceof ASN1TaggedObject)
            {
                aSpe = (ASN1TaggedObject)obj;
            }
            else
            {
            	aIS.close();
                throw new IOException("Not a valid iso7816 content : not a ASN1TaggedObject Object :" + EACTags.encodeTag(appSpe) + obj.getClass());           
            }
            switch (aSpe.getApplicationTag())
            {
            case EACTags.CERTIFICATE_PROFILE_IDENTIFIER:
                setCertificateProfileIdentifier(aSpe);
                break;
            case EACTags.CERTIFICATION_AUTHORITY_REFERENCE:
                setCertificationAuthorityReference(aSpe);
                break;
            case EACTags.PUBLIC_KEY:
                setPublicKey(PublicKeyDataObject.getInstance(aSpe.getObject(BERTags.SEQUENCE)));
                break;
            case EACTags.CERTIFICATE_HOLDER_REFERENCE:
                setCertificateHolderReference(aSpe);
                break;
            case EACTags.CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE:
                setCertificateHolderAuthorization(new CertificateHolderAuthorization(aSpe));
                break;
            case EACTags.CERTIFICATE_EFFECTIVE_DATE:
                setCertificateEffectiveDate(aSpe);
                break;
            case EACTags.CERTIFICATE_EXPIRATION_DATE:
                setCertificateExpirationDate(aSpe);
                break;
            case EACTags.CERTIFICATE_EXTENSIONS:
            	setCertificateExtensions(aSpe);
            	break;
            default:
                certificateType = 0;
                throw new IOException("Not a valid iso7816 ASN1TaggedObject tag " + aSpe.getApplicationTag());
            }
        }
        aIS.close();
    }

	/**
     * builds an Iso7816CertificateBody by settings each parameters.
     *
     * @param certificateProfileIdentifier
     * @param certificationAuthorityReference
     *
     * @param publicKey
     * @param certificateHolderReference
     * @param certificateHolderAuthorization
     * @param certificateEffectiveDate
     * @param certificateExpirationDate
     * @param certificateExtensions
     * @throws IOException
     */
    public CertificateBody(ASN1TaggedObject certificateProfileIdentifier,
    		CertificationAuthorityReference certificationAuthorityReference,
    		PublicKeyDataObject publicKey,
    		CertificateHolderReference certificateHolderReference,
    		CertificateHolderAuthorization certificateHolderAuthorization,
    		PackedDate certificateEffectiveDate,
    		PackedDate certificateExpirationDate,
    		CertificateExtensions certificateExtensions) {
    	
        setCertificateProfileIdentifier(certificateProfileIdentifier);
        setCertificationAuthorityReference(new DERApplicationSpecific(EACTags.CERTIFICATION_AUTHORITY_REFERENCE, certificationAuthorityReference.getEncoded()));
        setPublicKey(publicKey);
        setCertificateHolderReference(new DERApplicationSpecific(EACTags.CERTIFICATE_HOLDER_REFERENCE, certificateHolderReference.getEncoded()));
        setCertificateHolderAuthorization(certificateHolderAuthorization);
        try {
            setCertificateEffectiveDate(new DERApplicationSpecific(false, EACTags.CERTIFICATE_EFFECTIVE_DATE, new DEROctetString(certificateEffectiveDate.getEncoding())));
            setCertificateExpirationDate(new DERApplicationSpecific(false, EACTags.CERTIFICATE_EXPIRATION_DATE, new DEROctetString(certificateExpirationDate.getEncoding())));
        }
        catch (IOException e) {
            throw new IllegalArgumentException("unable to encode dates: " + e.getMessage());
        }
        this.certificateExtensions = certificateExtensions;
    }

    /**
     * builds an Iso7816CertificateBody with an ASN1InputStream.
     *
     * @param ASN1TaggedObject ASN1TaggedObject containing the whole body.
     * @throws IOException if the body is not valid.
     */
    private CertificateBody(ASN1TaggedObject ASN1TaggedObject)
        throws IOException
    {
        setIso7816CertificateBody(ASN1TaggedObject);
    }

    /**
     * create a profile type Iso7816CertificateBody.
     *
     * @return return the "profile" type certificate body.
     * @throws IOException if the ASN1TaggedObject cannot be created.
     */
	private ASN1Primitive profileToASN1Object()
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(certificateProfileIdentifier);
        v.add(certificationAuthorityReference);
        v.add(publicKey);
        v.add(certificateHolderReference);
        v.add(certificateHolderAuthorization);
        v.add(certificateEffectiveDate);
        v.add(certificateExpirationDate);
        if (certificateExtensions!=null) v.add(certificateExtensions);
        return new DERApplicationSpecific(EACTags.CERTIFICATE_CONTENT_TEMPLATE, v);
    }

    private void setCertificateProfileIdentifier(ASN1TaggedObject certificateProfileIdentifier)
	throws IllegalArgumentException {
		if (certificateProfileIdentifier.getApplicationTag() == EACTags.CERTIFICATE_PROFILE_IDENTIFIER) {
			this.certificateProfileIdentifier = certificateProfileIdentifier;
			certificateType |= CPI;
		}
		else
			throw new IllegalArgumentException("Not an Iso7816Tags.INTERCHANGE_PROFILE tag :"+ EACTags.encodeTag(certificateProfileIdentifier));
	}

    private void setCertificateHolderReference(ASN1TaggedObject certificateHolderReference)
	throws IllegalArgumentException {
		if (certificateHolderReference.getApplicationTag() == EACTags.CERTIFICATE_HOLDER_REFERENCE) {
			this.certificateHolderReference = certificateHolderReference;
			certificateType |= CHR;
		}
		else
			throw new IllegalArgumentException("Not an Iso7816Tags.CARDHOLDER_NAME tag");
	}

    	/**
	 * set the CertificationAuthorityReference.
	 * @param certificationAuthorityReference the ASN1TaggedObject containing the CertificationAuthorityReference.
	 * @throws IllegalArgumentException if the ASN1TaggedObject is not valid.
	 */
	private void setCertificationAuthorityReference(ASN1TaggedObject certificationAuthorityReference) throws IllegalArgumentException {
		if (certificationAuthorityReference.getApplicationTag() == EACTags.CERTIFICATION_AUTHORITY_REFERENCE) {
			this.certificationAuthorityReference = certificationAuthorityReference;
			certificateType |= CAR;
		}
		else
			throw new IllegalArgumentException("Not an Iso7816Tags.ISSUER_IDENTIFICATION_NUMBER tag");
	}

    	/**
	 * set the public Key
	 * @param publicKey : the ASN1TaggedObject containing the public key
	 * @throws java.io.IOException
	 */
	private void setPublicKey(PublicKeyDataObject publicKey)
    {
		this.publicKey = PublicKeyDataObject.getInstance(publicKey);
        this.certificateType |= PK;
	}

    /**
     * create a request type Iso7816CertificateBody.
     *
     * @return return the "request" type certificate body.
     * @throws IOException if the ASN1TaggedObject cannot be created.
     */
    private ASN1Primitive requestToASN1Object()
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(certificateProfileIdentifier);
        if (certificationAuthorityReference!=null) v.add(certificationAuthorityReference);
        v.add(publicKey);
        v.add(certificateHolderReference);
        if (certificateExtensions!=null) v.add(certificateExtensions);
        return new DERApplicationSpecific(EACTags.CERTIFICATE_CONTENT_TEMPLATE, v);
    }

    /**
     * create a "request" or "profile" type Iso7816CertificateBody according to the variables sets.
     *
     * @return return the ASN1Primitive representing the "request" or "profile" type certificate body.
     * @throws IOException if the ASN1TaggedObject cannot be created or if data are missings to create a valid certificate.
     */
    @Override
	public ASN1Primitive toASN1Primitive()
    {
        try
        {
            if (certificateType == certWoExt || certificateType == certWExt)
            {
                return profileToASN1Object();
            }
            if (certificateType == requestTypeWithoutCAR || certificateType == requestTypeWithCAR || certificateType == requestTypeWithoutCARAndWithExt || certificateType == requestTypeWithCARAndWithExt)
            {
                return requestToASN1Object();
            }
        }
        catch (IOException e)
        {
            return null;
        }
        return null;
    }

    /**
     * gives the type of the certificate (value should be certWoExt or requestType if all data are set).
     *
     * @return the int representing the data already set.
     */
    public int getCertificateType()
    {
        return certificateType;
    }

    /**
     * Gives an instance of Iso7816CertificateBody taken from Object obj
     *
     * @param obj is the Object to extract the certificate body from.
     * @return the Iso7816CertificateBody taken from Object obj.
     * @throws IOException if object is not valid.
     */
    public static CertificateBody getInstance(Object obj)
        throws IOException
    {
        if (obj instanceof CertificateBody)
        {
            return (CertificateBody)obj;
        }
        else if (obj != null)
        {
            return new CertificateBody(ASN1TaggedObject.getInstance(obj));
        }

        return null;
    }
    
    /**
     * @return the certificate extensions
     */
    public CertificateExtensions getCertificateExtensions() {
    	if ((this.certificateType & CertificateBody.CeEx) == CertificateBody.CeEx)
            {
                return certificateExtensions;
            }
            return null;
    }

    /**
     * set the certificate extensions
     * @param cext CertificateExtensions object
     * @throws IOException
     */
    private void setCertificateExtensions(ASN1TaggedObject cext) throws IOException {
    	if (cext.getApplicationTag() == EACTags.CERTIFICATE_EXTENSIONS) {
    		this.certificateExtensions = CertificateExtensions.getInstance(cext);
    		certificateType |= CeEx;
    	}
    	else {
    		throw new IllegalArgumentException("Not an CERTIFICATE_EXTENSIONS tag :" + EACTags.encodeTag(cext));
    	}
		
	}

    /**
     * @return the date of the certificate generation
     */
    public PackedDate getCertificateEffectiveDate()
    {
        if ((this.certificateType & CertificateBody.CEfD) ==
            CertificateBody.CEfD)
        {
            return new PackedDate(certificateEffectiveDate.getContents());
        }
        return null;
    }

    /**
     * set the date of the certificate generation
     *
     * @param ced ASN1TaggedObject containing the date of the certificate generation
     * @throws IllegalArgumentException if the tag is not Iso7816Tags.APPLICATION_EFFECTIVE_DATE
     */
    private void setCertificateEffectiveDate(ASN1TaggedObject ced)
        throws IllegalArgumentException
    {
        if (ced.getApplicationTag() == EACTags.CERTIFICATE_EFFECTIVE_DATE)
        {
            this.certificateEffectiveDate = ced;
            certificateType |= CEfD;
        }
        else
        {
            throw new IllegalArgumentException("Not an Iso7816Tags.APPLICATION_EFFECTIVE_DATE tag :" + EACTags.encodeTag(ced));
        }
    }

    /**
     * @return the date after wich the certificate expires
     */
    public PackedDate getCertificateExpirationDate()
    {
        if ((this.certificateType & CertificateBody.CExD) ==  CertificateBody.CExD)
        {
            return new PackedDate(certificateExpirationDate.getContents());
        }
        return null;
    }

    /**
     * set the date after wich the certificate expires
     *
     * @param ced ASN1TaggedObject containing the date after wich the certificate expires
     * @throws IllegalArgumentException if the tag is not Iso7816Tags.APPLICATION_EXPIRATION_DATE
     */
    private void setCertificateExpirationDate(ASN1TaggedObject ced)
        throws IllegalArgumentException
    {
        if (ced.getApplicationTag() == EACTags.CERTIFICATE_EXPIRATION_DATE)
        {
            this.certificateExpirationDate = ced;
            certificateType |= CExD;
        }
        else
        {
            throw new IllegalArgumentException("Not an Iso7816Tags.APPLICATION_EXPIRATION_DATE tag");
        }
    }

    /**
     * the Iso7816CertificateHolderAuthorization encodes the role of the holder
     * (i.e. CVCA, DV, IS) and assigns read/write access rights to data groups
     * storing sensitive data. This functions returns the Certificate Holder
     * Authorization
     *
     * @return the Iso7816CertificateHolderAuthorization
     */
    public CertificateHolderAuthorization getCertificateHolderAuthorization() {
        if ((this.certificateType & CertificateBody.CHA) == CertificateBody.CHA) {
            return certificateHolderAuthorization;
        } else return null;
    }

    /**
     * set the CertificateHolderAuthorization
     *
     * @param cha the Certificate Holder Authorization
     */
    private void setCertificateHolderAuthorization(CertificateHolderAuthorization cha)
    {
        this.certificateHolderAuthorization = cha;
        certificateType |= CHA;
    }

    /**
     * certificateHolderReference : associates the public key contained in the certificate with a unique name
     *
     * @return the certificateHolderReference.
     */
    public CertificateHolderReference getCertificateHolderReference()
    {
        return new CertificateHolderReference(certificateHolderReference.getContents());
    }
    
    public String getChrString() {
    	CertificateHolderReference chr = getCertificateHolderReference();
    	if (chr==null) return null;
    	return chr.getCountryCode()+chr.getHolderMnemonic()+chr.getSequenceNumber();
    }
    

    /**
     * CertificateProfileIdentifier : version of the certificate format. Must be 0 (version 1)
     *
     * @return the CertificateProfileIdentifier
     */
    public ASN1TaggedObject getCertificateProfileIdentifier()
    {
        return certificateProfileIdentifier;
    }

    /**
     * get the certificationAuthorityReference
     * certificationAuthorityReference : uniquely identifies the issuinng CA's signature key pair
     *
     * @return the certificationAuthorityReference
     */
    public CertificationAuthorityReference getCertificationAuthorityReference() 
    {
        if ((this.certificateType & CertificateBody.CAR) == CertificateBody.CAR)
        {
            return new CertificationAuthorityReference(certificationAuthorityReference.getContents());
        }
        return null;
    }
    
    public String getCarString() {
    	CertificationAuthorityReference car = getCertificationAuthorityReference();
    	if (car==null) return null;
    	return car.getCountryCode()+car.getHolderMnemonic()+car.getSequenceNumber();
    }

    /**
     * @return the PublicKey
     */
    public PublicKeyDataObject getPublicKey()
    {
        return publicKey;
    }
}