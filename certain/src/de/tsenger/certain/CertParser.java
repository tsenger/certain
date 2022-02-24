package de.tsenger.certain;

import java.io.StringWriter;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.util.encoders.Hex;

import de.tsenger.certain.asn1.eac.CertificateBody;
import de.tsenger.certain.asn1.eac.CertificateExtensions;
import de.tsenger.certain.asn1.eac.CertificateHolderAuthorization;
import de.tsenger.certain.asn1.eac.CertificateHolderReference;
import de.tsenger.certain.asn1.eac.CertificationAuthorityReference;
import de.tsenger.certain.asn1.eac.DiscretionaryDataTemplate;
import de.tsenger.certain.asn1.eac.EACObjectIdentifiers;
import de.tsenger.certain.asn1.eac.ECDSAPublicKey;
import de.tsenger.certain.asn1.eac.PackedDate;
import de.tsenger.certain.asn1.eac.PublicKeyDataObject;
import de.tsenger.certain.asn1.eac.RSAPublicKey;
import de.tsenger.tools.Converter;
import de.tsenger.tools.HexString;

public class CertParser {
	

	private CertificateBody body;
	private byte[] profileId;
	private CertificationAuthorityReference car;
	private PublicKeyDataObject pubKey;	
	private ASN1ObjectIdentifier pubKeyOid;
	private CertificateHolderReference chr;
	private CertificateHolderAuthorization chat;
	private PackedDate effdate;
	private PackedDate expdate;
	private CertificateExtensions extensions;
	
	boolean isCertificate;
	boolean showDetails=false;
	
	private String profileIdStr;
	private String carStr;
	private String pubKeyStr;		
	private String chrStr;
	private String terminalType;
	private String certRole;
	private String authorizationBitStr;
	private String authorizationStr;
	private String effdateStr;
	private String expdateStr;
	private String extentensionsStr;

	
	public void setBody(CertificateBody body, boolean isCertificate){
		clearAll();
		this.body = body;
		this.isCertificate = isCertificate;
		//parse();
	}

	
	private void clearAll() {
		profileId = null;
		car = null;
		pubKey = null;
		pubKeyOid = null;
		chr = null;
		chat = null;
		effdate = null;
		expdate = null;
		profileIdStr = null;
		carStr = null;
		pubKeyStr = null;		
		chrStr = null;
		terminalType = null;
		certRole = null;
		authorizationBitStr = null;
		authorizationStr = null;
		effdateStr = null;
		expdateStr = null;	
		extensions = null;
	}
	
	private void parse()  {

		if (isCertificate) {
			chat = body.getCertificateHolderAuthorization();
			certRole = chat.getRoleDescription();
		}
		
		profileId = body.getCertificateProfileIdentifier().getContents();

		if (showDetails) profileIdStr = HexString.bufferToHex(profileId);
		if (profileId.length>1) profileIdStr += " -> Length of Profile Identifier is bigger den 1!";
		if (profileId[0]!=0)  profileIdStr += " ->  Profile Identifier value is not 0!";
		
		car = body.getCertificationAuthorityReference();
		if (isCertificate&&car==null) carStr = " -> Certification authority reference is not set";
		else if (isCertificate||car!=null) {
			carStr = checkCHR(car);
		}
		
		pubKey = body.getPublicKey();
		pubKeyOid = pubKey.getUsage();
		StringWriter sw = new StringWriter();
		sw.write("OID : "+pubKeyOid + " ("+pubKey.getAlgorithmName()+")\n");
		if (pubKeyOid.on(EACObjectIdentifiers.id_TA_ECDSA)) {
			ECDSAPublicKey pk = (ECDSAPublicKey) pubKey;
			if ((certRole!=null&&certRole.equals("CVCA"))||!isCertificate) {
				if (pk.hasDomainParameters()) { 
					byte[] p = Converter.cutLeadingZero(pk.getPrimeModulusP().toByteArray());
					byte[] a = Converter.cutLeadingZero(pk.getFirstCoefA().toByteArray());
					byte[] b = Converter.cutLeadingZero(pk.getSecondCoefB().toByteArray());
					byte[] g = pk.getBasePointG();
					byte[] r = Converter.cutLeadingZero(pk.getOrderOfBasePointR().toByteArray());
					byte[] y = pk.getPublicPointY();
					byte[] f = Converter.cutLeadingZero(pk.getCofactorF().toByteArray());
					sw.write("0x81 Prime modulus p:       " + (showDetails?"\n"+HexString.bufferToHex(p, true):HexString.bufferToHex(p, 0, 3)+"... ("+p.length+" Bytes)")+"\n");
					sw.write("0x82 First coefficient a:   " + (showDetails?"\n"+HexString.bufferToHex(a, true):HexString.bufferToHex(a, 0, 3)+"... ("+a.length+" Bytes)")+"\n");
					sw.write("0x83 Second coefficient b:  " + (showDetails?"\n"+HexString.bufferToHex(b, true):HexString.bufferToHex(b, 0 ,3)+"... ("+b.length+" Bytes)")+"\n");
					sw.write("0x84 Base point G :         " + (showDetails?"\n"+HexString.bufferToHex(g, true):HexString.bufferToHex(g, 0 ,3)+"... ("+g.length+" Bytes)")+"\n");
					sw.write("0x85 Order of base point r: " + (showDetails?"\n"+HexString.bufferToHex(r, true):HexString.bufferToHex(r, 0 ,3)+"... ("+r.length+" Bytes)")+"\n");
					sw.write("0x86 Public point Y:        " + (showDetails?"\n"+HexString.bufferToHex(y, true):HexString.bufferToHex(y, 0 ,3)+"... ("+y.length+" Bytes)")+"\n");
					sw.write("0x87 Cofactor f:            " + (showDetails?"\n"+HexString.bufferToHex(f, true):HexString.bufferToHex(f, 0, 1)+"... ("+f.length+" Bytes)"));
				} else {
					byte[] y = pk.getPublicPointY();
					sw.write("0x86 Public point Y : " + (showDetails?HexString.bufferToHex(y):HexString.bufferToHex(y, 0 ,3)+"... ("+y.length+" Bytes)")+"\n");
					sw.write(" -> no Domain Parameters");
				}
			} else {
				byte[] y = pk.getPublicPointY();
				sw.write("0x86 Public point Y : " + (showDetails?HexString.bufferToHex(y):HexString.bufferToHex(y, 0 ,3)+"... ("+y.length+" Bytes)"));
			}

		} else if (pubKeyOid.on(EACObjectIdentifiers.id_TA_RSA)) {
			RSAPublicKey pk = (RSAPublicKey) pubKey;
			byte[] m = Converter.cutLeadingZero(pk.getModulus().toByteArray());
			byte[] e = Converter.cutLeadingZero(pk.getPublicExponent().toByteArray());
			sw.write("Composite modulus: " + (showDetails?"\n"+HexString.bufferToHex(m, true):HexString.bufferToHex(m, 0, 3)+"... ("+m.length+" Bytes)")+"\n");
			sw.write("Public exponent:   " + (showDetails?"\n"+HexString.bufferToHex(e, true):HexString.bufferToHex(e, 0, 3)+"... ("+e.length+" Bytes)"));
		} else {
			sw.write(" -> Neither RSA nor ECDSA public key was found.");
		}
		pubKeyStr = sw.toString();

		chr = body.getCertificateHolderReference();
		chrStr = checkCHR(chr);

		if (chat==null&&isCertificate) {
			authorizationBitStr = authorizationStr = terminalType = " -> CHAT not set!";
		}
		else if(isCertificate) {
			terminalType = chat.getTerminalTypeDescription();
			authorizationBitStr = Long.toBinaryString(Converter.ByteArrayToLong(chat.getAccessRights()));
			authorizationStr = authorizationToString(chat);
		}
		
		effdate = body.getCertificateEffectiveDate();
		if (effdate==null&&isCertificate) effdateStr = " -> Effective Date not set";
		else if(isCertificate) effdateStr = effdate.toString();
		
		this.expdate = body.getCertificateExpirationDate();
		if (expdate==null&&isCertificate) effdateStr = " -> Expiration Date not set";
		else if(isCertificate) expdateStr = expdate.toString();
		
		this.extensions = body.getCertificateExtensions();
		if (extensions==null) extentensionsStr = " -> no Extensions\n";
		else  {
			sw = new StringWriter();
			for (DiscretionaryDataTemplate ddt : extensions.getDiscretionaryDataTemplateList()) {
				byte[] ddtValue = ddt.getDataContent();
				if (ddtValue!=null)
					sw.write(ddt.getExtensionDescription()+ " (OID: " + ddt.getOid().toString() +"): " +(ddtValue.length>16?"\n":"")+HexString.bufferToHex(ddtValue, true)+"\n");
				else
					sw.write(ddt.getExtensionDescription() + " (OID: " + ddt.getOid().toString() + ")\n");
			}
			extentensionsStr = sw.toString();
		}
		
	}

	private String checkCHR(CertificateHolderReference chr) {
		String errorText ="";
		try {
			CountryCode.getByCode(chr.getCountryCode()).getAlpha2();
        } catch (NullPointerException e) {
        	errorText=" -> unknown or missing country code";
        }
		chrStr = chr.getCountryCode()+chr.getHolderMnemonic()+chr.getSequenceNumber()+errorText;
		return chrStr;
	}
	
	private String authorizationToString(CertificateHolderAuthorization chat) {
		StringWriter sw = new StringWriter();
				
		if (chat.getOid().equals(CertificateHolderAuthorization.id_AT)) {		
			sw.write("Read access to DG "+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG1)?"1, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG2)?"2, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG3)?"3, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG4)?"4, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG4)?"5, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG5)?"6, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG7)?"7, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG8)?"8, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG9)?"9, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG10)?"10, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG11)?"11, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG12)?"12, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG13)?"13, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG14)?"14, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG15)?"15, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG16)?"16, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG17)?"17, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG18)?"18, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG19)?"19, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG20)?"20, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_RADG21)?"21":"")+
					"\n"
			);
			sw.write("Write access to DG "+
					(chat.hasAuth(CertificateHolderAuthorization.AT_WADG17)?"17, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_WADG18)?"18, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_WADG19)?"19, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_WADG20)?"20, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.AT_WADG21)?"21":"")+
					"\n"
			);
			sw.write(chat.hasAuth(CertificateHolderAuthorization.AT_IQCERT)?"Install Qualified Certificate\n":"");
			sw.write(chat.hasAuth(CertificateHolderAuthorization.AT_ICERT)?"Install Certificate\n":"");
			sw.write(chat.hasAuth(CertificateHolderAuthorization.AT_PINMGNT)?"PIN Management\n":"");
			sw.write(chat.hasAuth(CertificateHolderAuthorization.AT_CAN)?"CAN allowed\n":"");
			sw.write(chat.hasAuth(CertificateHolderAuthorization.AT_PRIVTERM)?"Privileged Terminal\n":"");
			sw.write(chat.hasAuth(CertificateHolderAuthorization.AT_RI)?"Restricted Identification\n":"");
			sw.write(chat.hasAuth(CertificateHolderAuthorization.AT_COMIDVRF)?"Community ID Verification\n":"");
			sw.write(chat.hasAuth(CertificateHolderAuthorization.AT_AGEVRF)?"Age Verification\n":"");
		} 
		else if (chat.getOid().equals(CertificateHolderAuthorization.id_IS)) {
			sw.write("Read access to DG " + (chat.hasAuth(CertificateHolderAuthorization.IS_RADG3)?"3, ":"")+
					(chat.hasAuth(CertificateHolderAuthorization.IS_RADG4)?"4":""));
		} 
		else if (chat.getOid().equals(CertificateHolderAuthorization.id_ST)) {
			sw.write(chat.hasAuth(CertificateHolderAuthorization.ST_GENQES)?"Generate qualified electronic signature\n":"");
			sw.write(chat.hasAuth(CertificateHolderAuthorization.ST_GENES)?"Generate electronic signature":"");
		}
		return sw.toString();
	}
	
	public String getContentString(boolean showDetails) {	
		this.showDetails = showDetails;
		
		parse();
		
		StringWriter sw = new StringWriter();
		if (profileIdStr!=null) sw.write("Profile ID: "+profileIdStr+"\n\n");
		
		sw.write("CAR: ");
		sw.write(getCarString()+"\n");
		sw.write("CHR: ");
		sw.write(getChrString()+"\n\n");
				
		sw.write("Public Key\n");
		sw.write(getPublicKeyString()+"\n");


		if (isCertificate) {
			sw.write("\nCertificate Holder Authorization Template (CHAT)\n");
			sw.write("Terminal Type: ");
			sw.write(getTerminalType()+"\n");
			sw.write("Role: ");
			sw.write(getCertificateRole());
			if (showDetails) {
				sw.write("\nAuthorization bits: ");
				sw.write(getAuthorizationBitString());	
			}
			sw.write("\n"+getAuthorizationString()+"\n");
		
			sw.write("Certificate Effective Date : ");
			sw.write(getEffectiveDateString()+"\n");
			sw.write("Certificate Expiration Date: ");
			sw.write(getExpirationDateString()+"\n");
			
		}
		
		sw.write("\nCertificate Extensions: \n");
		sw.write(getExtensionsString());
		
		return sw.toString();
	}
	
	public boolean isCertificate() {
		return isCertificate;
	}
	
	public String getProfileIdentifier() {
		return profileIdStr;
	}
	
	public String getCarString() {
		return carStr;
	}
	
	public String getPublicKeyString() {
		return pubKeyStr;
	}
	
	public String getChrString() {
		return chrStr;
	}
	
	public String getTerminalType() {
		return terminalType;
	}
	
	public String getCertificateRole(){
		return certRole;
	}
	
	public String getAuthorizationBitString() {
		return authorizationBitStr;
	}
	
	public String getAuthorizationString() {
		return authorizationStr;
	}
	
	public String getEffectiveDateString() {
		return effdateStr;
	}
	
	public String getExpirationDateString() {
		return expdateStr;
	}
	
	public String getExtensionsString() {
		return extentensionsStr;
	}

}
