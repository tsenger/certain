//package org.bouncycastle.asn1.eac;
package de.tsenger.certain.asn1.eac;


import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.eac.CertificateHolderReference;
import org.bouncycastle.asn1.eac.CertificationAuthorityReference;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.eac.PackedDate;
import org.bouncycastle.asn1.eac.PublicKeyDataObject;


/**
 * an Iso7816CertificateBody structure.
 * <p/>
 * <pre>
 *  CertificateBody ::= SEQUENCE {
 *  	// version of the certificate format. Must be 0 (version 1)
 *      CertificateProfileIdentifer 		APPLICATION tagged,
 *      //uniquely identifies the issuinng CA's signature key pair
 *      // contains the iso3166-1 alpha2 encoded country code, the
 *      // name of issuer and the sequence number of the key pair.
 *      CertificationAuthorityReference		APPLICATION tagged,
 *      // stores the encoded public key
 *      PublicKey							Iso7816PublicKey,
 *      //associates the public key contained in the certificate with a unique name
 *      // contains the iso3166-1 alpha2 encoded country code, the
 *      // name of the holder and the sequence number of the key pair.
 *      certificateHolderReference			APPLICATION tagged,
 *      // Encodes the role of the holder (i.e. CVCA, DV, IS) and assigns read/write
 *      // access rights to data groups storing sensitive data
 *      certificateHolderAuthorization		Iso7816CertificateHolderAuthorization,
 *      // the date of the certificate generation
 *      CertificateEffectiveDate			APPLICATION tagged,
 *      // the date after wich the certificate expires
 *      certificateExpirationDate			APPLICATION tagged
 *      // certificates may contain extension
 *      certificateExtensions				CertificateExtensions
 *  }
 * </pre>
 */
public class CertificateBody  extends ASN1Object
{
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
        if (!appSpe.hasTag(BERTags.APPLICATION, EACTags.CERTIFICATE_CONTENT_TEMPLATE))
        {
            throw new IOException("Bad tag : not an iso7816 CERTIFICATE_CONTENT_TEMPLATE");
        }
        for (ASN1Encodable obj : ApplicationObjects.children(appSpe)) {
            ASN1TaggedObject aSpe;

            if (ApplicationObjects.isApplication(obj))
            {
                aSpe = (ASN1TaggedObject)obj;
            }
            else
            {
                throw new IOException("Not a valid iso7816 content : not an APPLICATION tagged object :" + obj.getClass());
            }
            switch (aSpe.getTagNo())
            {
            case EACTags.CERTIFICATE_PROFILE_IDENTIFIER:
                setCertificateProfileIdentifier(aSpe);
                break;
            case EACTags.CERTIFICATION_AUTHORITY_REFERENCE:
                setCertificationAuthorityReference(aSpe);
                break;
            case EACTags.PUBLIC_KEY:
                setPublicKey(parsePublicKey(ApplicationObjects.children(aSpe)));
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
                throw new IOException("Not a valid iso7816 APPLICATION tag " + aSpe.getTagNo());
            }
        }
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
        setCertificationAuthorityReference(ApplicationObjects.create(EACTags.CERTIFICATION_AUTHORITY_REFERENCE, certificationAuthorityReference.getEncoded()));
        setPublicKey(publicKey);
        setCertificateHolderReference(ApplicationObjects.create(EACTags.CERTIFICATE_HOLDER_REFERENCE, certificateHolderReference.getEncoded()));
        setCertificateHolderAuthorization(certificateHolderAuthorization);
        setCertificateEffectiveDate(ApplicationObjects.create(EACTags.CERTIFICATE_EFFECTIVE_DATE, certificateEffectiveDate.getEncoding()));
        setCertificateExpirationDate(ApplicationObjects.create(EACTags.CERTIFICATE_EXPIRATION_DATE, certificateExpirationDate.getEncoding()));
        this.certificateExtensions = certificateExtensions;
    }

    /**
     * builds an Iso7816CertificateBody with an ASN1InputStream.
     *
     * @param tagged the APPLICATION tagged object containing the whole body.
     * @throws IOException if the body is not valid.
     */
    private CertificateBody(ASN1TaggedObject tagged)
        throws IOException
    {
        setIso7816CertificateBody(tagged);
    }

    /**
     * Bouncy Castle reads every key that is not an ECDSA key as an RSA key and fails with an
     * unspecific message, so the algorithm is checked first.
     *
     * @throws IOException if the algorithm is neither ECDSA nor RSA Terminal Authentication
     */
    private static PublicKeyDataObject parsePublicKey(ASN1Sequence key)
        throws IOException
    {
        ASN1ObjectIdentifier usage = ASN1ObjectIdentifier.getInstance(key.getObjectAt(0));
        if (!usage.on(EACObjectIdentifiers.id_TA_ECDSA) && !usage.on(EACObjectIdentifiers.id_TA_RSA))
        {
            throw new IOException("unsupported public key algorithm " + usage);
        }
        return PublicKeyDataObject.getInstance(key);
    }

    /**
     * Bouncy Castle encodes a public key as a plain sequence, the body adds the public key tag.
     */
    private ASN1Encodable encodedPublicKey()
    {
        return ApplicationObjects.create(EACTags.PUBLIC_KEY, publicKey);
    }

    /**
     * create a profile type Iso7816CertificateBody.
     *
     * @return return the "profile" type certificate body.
     * @throws IOException if the APPLICATION tagged object cannot be created.
     */
	private ASN1Primitive profileToASN1Object()
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(certificateProfileIdentifier);
        v.add(certificationAuthorityReference);
        v.add(encodedPublicKey());
        v.add(certificateHolderReference);
        v.add(certificateHolderAuthorization);
        v.add(certificateEffectiveDate);
        v.add(certificateExpirationDate);
        if (certificateExtensions!=null) v.add(certificateExtensions);
        return ApplicationObjects.create(EACTags.CERTIFICATE_CONTENT_TEMPLATE, v);
    }

    private void setCertificateProfileIdentifier(ASN1TaggedObject certificateProfileIdentifier)
	throws IllegalArgumentException {
		if (certificateProfileIdentifier.hasTag(BERTags.APPLICATION, EACTags.CERTIFICATE_PROFILE_IDENTIFIER)) {
			this.certificateProfileIdentifier = certificateProfileIdentifier;
			certificateType |= CPI;
		}
		else
			throw new IllegalArgumentException("Not an Iso7816Tags.INTERCHANGE_PROFILE tag :"+ certificateProfileIdentifier.getTagNo());
	}

    private void setCertificateHolderReference(ASN1TaggedObject certificateHolderReference)
	throws IllegalArgumentException {
		if (certificateHolderReference.hasTag(BERTags.APPLICATION, EACTags.CERTIFICATE_HOLDER_REFERENCE)) {
			this.certificateHolderReference = certificateHolderReference;
			certificateType |= CHR;
		}
		else
			throw new IllegalArgumentException("Not an Iso7816Tags.CARDHOLDER_NAME tag");
	}

    	/**
	 * set the CertificationAuthorityReference.
	 * @param certificationAuthorityReference the APPLICATION tagged object containing the CertificationAuthorityReference.
	 * @throws IllegalArgumentException if the tag is not valid.
	 */
	private void setCertificationAuthorityReference(ASN1TaggedObject certificationAuthorityReference) throws IllegalArgumentException {
		if (certificationAuthorityReference.hasTag(BERTags.APPLICATION, EACTags.CERTIFICATION_AUTHORITY_REFERENCE)) {
			this.certificationAuthorityReference = certificationAuthorityReference;
			certificateType |= CAR;
		}
		else
			throw new IllegalArgumentException("Not an Iso7816Tags.ISSUER_IDENTIFICATION_NUMBER tag");
	}

    	/**
	 * set the public Key
	 * @param publicKey : the ASN1ApplicationSpecific containing the public key
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
     * @throws IOException if the APPLICATION tagged object cannot be created.
     */
    private ASN1Primitive requestToASN1Object()
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(certificateProfileIdentifier);
        if (certificationAuthorityReference!=null) v.add(certificationAuthorityReference);
        v.add(encodedPublicKey());
        v.add(certificateHolderReference);
        if (certificateExtensions!=null) v.add(certificateExtensions);
        return ApplicationObjects.create(EACTags.CERTIFICATE_CONTENT_TEMPLATE, v);
    }

    /**
     * create a "request" or "profile" type Iso7816CertificateBody according to the variables sets.
     *
     * @return return the ASN1Primitive representing the "request" or "profile" type certificate body.
     * @throws IOException if the ASN1ApplicationSpecific cannot be created or if data are missings to create a valid certificate.
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
            return new CertificateBody(ApplicationObjects.getInstance(obj));
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
    	if (cext.hasTag(BERTags.APPLICATION, EACTags.CERTIFICATE_EXTENSIONS)) {
    		this.certificateExtensions = CertificateExtensions.getInstance(cext);
    		certificateType |= CeEx;
    	}
    	else {
    		throw new IllegalArgumentException("Not an CERTIFICATE_EXTENSIONS tag :" + cext.getTagNo());
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
            return References.packedDate(ApplicationObjects.octets(certificateEffectiveDate));
        }
        return null;
    }

    /**
     * set the date of the certificate generation
     *
     * @param ced APPLICATION tagged object containing the date of the certificate generation
     * @throws IllegalArgumentException if the tag is not Iso7816Tags.APPLICATION_EFFECTIVE_DATE
     */
    private void setCertificateEffectiveDate(ASN1TaggedObject ced)
        throws IllegalArgumentException
    {
        if (ced.hasTag(BERTags.APPLICATION, EACTags.CERTIFICATE_EFFECTIVE_DATE))
        {
            this.certificateEffectiveDate = ced;
            certificateType |= CEfD;
        }
        else
        {
            throw new IllegalArgumentException("Not an Iso7816Tags.APPLICATION_EFFECTIVE_DATE tag :" + ced.getTagNo());
        }
    }

    /**
     * @return the date after wich the certificate expires
     */
    public PackedDate getCertificateExpirationDate()
    {
        if ((this.certificateType & CertificateBody.CExD) ==  CertificateBody.CExD)
        {
            return References.packedDate(ApplicationObjects.octets(certificateExpirationDate));
        }
        return null;
    }

    /**
     * set the date after wich the certificate expires
     *
     * @param ced APPLICATION tagged object containing the date after wich the certificate expires
     * @throws IllegalArgumentException if the tag is not Iso7816Tags.APPLICATION_EXPIRATION_DATE
     */
    private void setCertificateExpirationDate(ASN1TaggedObject ced)
        throws IllegalArgumentException
    {
        if (ced.hasTag(BERTags.APPLICATION, EACTags.CERTIFICATE_EXPIRATION_DATE))
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
        return References.holderReference(ApplicationObjects.octets(certificateHolderReference));
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
            return References.authorityReference(ApplicationObjects.octets(certificationAuthorityReference));
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