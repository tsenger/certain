//package org.bouncycastle.asn1.eac;
package de.tsenger.certain.asn1.eac;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERApplicationSpecific;

import de.tsenger.tools.Converter;

/**
 * an Iso7816CertificateHolderAuthorization structure.
 * <p/>
 * <pre>
 *  Certificate Holder Authorization ::= SEQUENCE {
 *  	// specifies the format and the rules for the evaluation of the authorization
 *  	// level
 *  	ASN1ObjectIdentifier		oid,
 *  	// access rights
 *  	ASN1ApplicationSpecific	accessRights,
 *  }
 * </pre>
 */
public class CertificateHolderAuthorization
    extends ASN1Object
{
    ASN1ObjectIdentifier oid;
    ASN1ApplicationSpecific accessRights;
    long authorization;
    public static final ASN1ObjectIdentifier id_IS = EACObjectIdentifiers.bsi_de.branch("3.1.2.1");
    public static final ASN1ObjectIdentifier id_AT = EACObjectIdentifiers.bsi_de.branch("3.1.2.2");
    public static final ASN1ObjectIdentifier id_ST = EACObjectIdentifiers.bsi_de.branch("3.1.2.3");
    public static final int CVCA = 0xC0;
    public static final int DV_OFFICIAL_DOMESTIC = 0x80;
    public static final int DV_NON_OFFICIAL_FOREIGN = 0x40;
    public static final int TERMINAL = 0;
    
    public static final byte IS_RADG4 = 0x02;//Read Access to DG4 (Iris)
	public static final byte IS_RADG3 = 0x01;//Read Access to DG3 (fingerprint)
	    
	public static final byte ST_GENQES = 0x02;//Generate qualified electronic signature
	public static final byte ST_GENES = 0x01;//Generate electronic signature
	    
	public static final long AT_WADG17 = 0x0000002000000000L;//Write Access to DG17
    public static final long AT_WADG18 = 0x0000001000000000L;
    public static final long AT_WADG19 = 0x0000000800000000L;
    public static final long AT_WADG20 = 0x0000000400000000L;
    public static final long AT_WADG21 = 0x0000000200000000L;
    
    public static final long AT_RADG21 = 0x0000000010000000L;//Read Access to DG21
    public static final long AT_RADG20 = 0x0000000008000000L;//Read Access to DG21
    public static final long AT_RADG19 = 0x0000000004000000L;
    public static final long AT_RADG18 = 0x0000000002000000L;
    public static final long AT_RADG17 = 0x0000000001000000L;
    
    public static final long AT_RADG16 = 0x0000000000800000L;
    public static final long AT_RADG15 = 0x0000000000400000L;
    public static final long AT_RADG14 = 0x0000000000200000L;
    public static final long AT_RADG13 = 0x0000000000100000L;
    public static final long AT_RADG12 = 0x0000000000080000L;
    public static final long AT_RADG11 = 0x0000000000040000L;
    public static final long AT_RADG10 = 0x0000000000020000L;
    public static final long AT_RADG9 =  0x0000000000010000L;
    
    public static final long AT_RADG8 = 	0x0000000000008000L;
    public static final long AT_RADG7 =  0x0000000000004000L;
    public static final long AT_RADG6 =  0x0000000000002000L;
    public static final long AT_RADG5 =  0x0000000000001000L;
    public static final long AT_RADG4 =  0x0000000000000800L;
    public static final long AT_RADG3 =  0x0000000000000400L;
    public static final long AT_RADG2 =  0x0000000000000200L;
    public static final long AT_RADG1 =  0x0000000000000100L;
    
    public static final long AT_IQCERT = 0x0000000000000080L;//Install Qualified Certificte
    public static final long AT_ICERT =  0x0000000000000040L;//Install Certificate
    public static final long AT_PINMGNT =0x0000000000000020L;//PIN Management
    public static final long AT_CAN =    0x0000000000000010L;//CAN allowed
    public static final long AT_PRIVTERM = 0x0000000000000008L;//Privileged Terminal
    public static final long AT_RI =     0x0000000000000004L;//Restricted Identification
    public static final long AT_COMIDVRF = 0x0000000000000002L;//Community ID Verification
    public static final long AT_AGEVRF = 0x0000000000000001L;//Age Verification
       

    static BidirectionalMap AuthorizationRole = new BidirectionalMap();
    static
    {
        AuthorizationRole.put(Integer.valueOf(CVCA), "CVCA");
        AuthorizationRole.put(Integer.valueOf(DV_OFFICIAL_DOMESTIC), "DV_OFFICIAL_DOMESTIC");
        AuthorizationRole.put(Integer.valueOf(DV_NON_OFFICIAL_FOREIGN), "DV_NON-OFFICIAL_FOREIGN");
        AuthorizationRole.put(Integer.valueOf(TERMINAL), "TERMINAL");

    }
    
    static BidirectionalMap TerminalType = new BidirectionalMap();
    static
    {
    	TerminalType.put(id_IS, "Inspection System (IS)");
    	TerminalType.put(id_AT, "Authentication Terminal (AT)");
    	TerminalType.put(id_ST, "Signature Terminal (ST)");

    }

    public static String GetRoleDescription(int i)
    {
        return (String)AuthorizationRole.get(Integer.valueOf(i));
    }

    public static int GetFlag(String description)
    {
        Integer i = (Integer)AuthorizationRole.getReverse(description);
        if (i == null)
        {
            throw new IllegalArgumentException("Unknown value " + description);
        }

        return i.intValue();
    }
    
    public String getRoleDescription() {
    	byte[] accessRights = this.accessRights.getContents();
    	if (accessRights==null) return null;
    	return (String)AuthorizationRole.get(accessRights[0]&0xC0);
    }
    
    public String getTerminalTypeDescription() {
    	return (String)TerminalType.get(this.oid);
    }
    

    private void setPrivateData(ASN1InputStream cha)
        throws IOException
    {
        ASN1Primitive obj;
        obj = cha.readObject();
        if (obj instanceof ASN1ObjectIdentifier)
        {
            this.oid = (ASN1ObjectIdentifier)obj;
        }
        else
        {
            throw new IllegalArgumentException("no Oid in CerticateHolderAuthorization");
        }
        obj = cha.readObject();
        if (obj instanceof ASN1ApplicationSpecific)
        {
            this.accessRights = (ASN1ApplicationSpecific)obj;
        	authorization = Converter.ByteArrayToLong(accessRights.getContents());
        }
        else
        {
            throw new IllegalArgumentException("No access rights in CerticateHolderAuthorization");
        }
    }


    /**
     * create an Iso7816CertificateHolderAuthorization according to the parameters
     *
     * @param oid    Object Identifier : specifies the format and the rules for the
     *               evaluatioin of the authorization level.
     * @param rights specifies the access rights
     * @throws IOException
     */
    public CertificateHolderAuthorization(ASN1ObjectIdentifier oid, byte[] rights)
        throws IOException
    {
        setOid(oid);
        setAccessRights(rights);
    }

    /**
     * create an Iso7816CertificateHolderAuthorization according to the {@link ASN1ApplicationSpecific}
     *
     * @param aSpe the ASN1ApplicationSpecific containing the data
     * @throws IOException
     */
    public CertificateHolderAuthorization(ASN1ApplicationSpecific aSpe)
        throws IOException
    {
        if (aSpe.getApplicationTag() == EACTags.CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE)
        {
            setPrivateData(new ASN1InputStream(aSpe.getContents()));
        }
    }
    
    public boolean hasAuth(long auth) {
    	return (authorization & auth) == auth;
    }

    /**
     * @return containing the access rights
     */
    public byte[] getAccessRights()
    {	
    	if (oid.equals(id_IS)||oid.equals(id_ST)) { 
    		accessRights.getContents()[0] &= (byte) 0xff;
    		return accessRights.getContents();
    	} else {
    		byte[] by = accessRights.getContents();
    		for (int i = 0; i < by.length; i++)
    		{
    		   by[i] &= 0xff;
    		}
    		return by;
    	}
    }

    /**
     * create a ASN1ApplicationSpecific and set the access rights to "rights"
     *
     * @param rights byte containing the rights.
     */
    private void setAccessRights(byte[] rights)
    {
       	this.accessRights = new DERApplicationSpecific(EACTags.getTag(EACTags.DISCRETIONARY_DATA), rights);
    }

    /**
     * @return the Object identifier
     */
    public ASN1ObjectIdentifier getOid()
    {
        return oid;
    }

    /**
     * set the Object Identifier
     *
     * @param oid {@link ASN1ObjectIdentifier} containing the Object Identifier
     */
    private void setOid(ASN1ObjectIdentifier oid)
    {
        this.oid = oid;
    }

    /**
     * return the Certificate Holder Authorization as a ASN1ApplicationSpecific Object
     */
    @Override
	public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(oid);
        v.add(accessRights);

        return new DERApplicationSpecific(EACTags.CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE, v);
    }
}
