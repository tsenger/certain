package de.tsenger.certain;

import java.io.StringWriter;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import de.tsenger.certain.asn1.eac.CertificateBody;
import de.tsenger.certain.asn1.eac.CertificateHolderAuthorization;
import de.tsenger.certain.asn1.eac.CertificateHolderReference;
import de.tsenger.certain.asn1.eac.CertificationAuthorityReference;
import de.tsenger.certain.asn1.eac.EACObjectIdentifiers;
import de.tsenger.certain.asn1.eac.ECDSAPublicKey;
import de.tsenger.certain.asn1.eac.PackedDate;
import de.tsenger.certain.asn1.eac.PublicKeyDataObject;
import de.tsenger.certain.asn1.eac.RSAPublicKey;
import de.tsenger.tools.Converter;
import de.tsenger.tools.HexString;

public class CertainParser {
	

	private CertificateBody body;
	private byte[] profileId;
	private CertificationAuthorityReference car;
	private PublicKeyDataObject pubKey;	
	private ASN1ObjectIdentifier pubKeyOid;
	private CertificateHolderReference chr;
	private CertificateHolderAuthorization chat;
	private PackedDate effdate;
	private PackedDate expdate;
	
	boolean isCertificate;
	
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
	
	private CertStorage certStorage;
	
	public CertainParser(CertStorage certStore) {
		this.certStorage = certStore;
	}
	
	public CertainParser(CertificateBody body, boolean isCertificate){
		this.body = body;
		this.isCertificate = isCertificate;
		parse();
	}
	
	public String parse(String chr) {
		this.body = certStorage.getCertByCHR(chr).getBody();
		this.isCertificate = true;
		parse();
		return getContentString();
		
	}
	
	private void parse()  {

		if (isCertificate) {
			chat = body.getCertificateHolderAuthorization();
			certRole = chat.getRoleDescription();
		}
		
		profileId = body.getCertificateProfileIdentifier().getContents();
		String errorText = "";
		if (profileId.length>1) errorText = " -> Profile Identifier length is bigger den 1!";
		if (profileId[0]!=0)  errorText = " ->  Profile Identifier value is not 0!";
		profileIdStr = "0"+errorText;
		
		car = body.getCertificationAuthorityReference();
		errorText = "";
		if (isCertificate&&car==null) errorText = " -> Certification authority reference is not set";
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
				sw.write("0x81 Prime modulus p: " + pk.getPrimeModulusP().toString(16)+"\n");
				sw.write("0x82 First coefficient a: " + pk.getFirstCoefA().toString(16)+"\n");
				sw.write("0x83 Second coefficient b (): " + pk.getSecondCoefB().toString(16)+"\n");
				sw.write("0x84 Base point G : " + HexString.bufferToHex(pk.getBasePointG())+"\n");
				sw.write("0x85 Order of base point r : " + pk.getOrderOfBasePointR().toString(16)+"\n");
				sw.write("0x86 Public point Y : " + HexString.bufferToHex(pk.getPublicPointY())+"\n");
				sw.write("0x87 Cofactor f  : " + pk.getCofactorF().toString(16));
			} else {
				sw.write("0x86 Public point Y : " + HexString.bufferToHex(pk.getPublicPointY()));
			}

		} else if (pubKeyOid.on(EACObjectIdentifiers.id_TA_RSA)) {
			RSAPublicKey pk = (RSAPublicKey) pubKey;
			sw.write("Composite modulus: " + pk.getModulus().toString(16)+"\n");
			sw.write("Public exponent: " + pk.getPublicExponent().toString(16));
		} else {
			sw.write(" -> Neither RSA nor ECDSA public key was found.");
		}
		pubKeyStr = sw.toString();

		chr = body.getCertificateHolderReference();
		chrStr = checkCHR(chr);
		
		errorText = "";
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
		
	}
	
	
	private String checkCHR(CertificateHolderReference chr) {
		String errorText ="";
		try {
			CountryCode.getByCode(chr.getCountryCode()).getAlpha2();
        } catch (NullPointerException e) {
        	errorText=" -> unknown or missing country code";
        }
		try {
			Integer.parseInt(chr.getSequenceNumber());
		} catch (NumberFormatException e) {
			errorText=" -> incorrect or missing sequence number";
        }
		chrStr = chr.getCountryCode()+chr.getHolderMnemonic()+chr.getSequenceNumber()+errorText;
		return chrStr;
	}
	
	private String authorizationToString(CertificateHolderAuthorization chat) {
		StringWriter sw = new StringWriter();
		if (chat.getOid().equals(CertificateHolderAuthorization.id_AT)) {
			sw.write("WA to DG17: " + chat.hasAuth(CertificateHolderAuthorization.AT_WADG17) + "\n");
			sw.write("WA to DG18: " + chat.hasAuth(CertificateHolderAuthorization.AT_WADG18) + "\n");
			sw.write("WA to DG19: " + chat.hasAuth(CertificateHolderAuthorization.AT_WADG19) + "\n");
			sw.write("WA to DG20: " + chat.hasAuth(CertificateHolderAuthorization.AT_WADG20) + "\n");
			sw.write("WA to DG21: " + chat.hasAuth(CertificateHolderAuthorization.AT_WADG21) + "\n");
			sw.write("RA to DG21: " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG21) + "\n");
			sw.write("RA to DG20: " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG20) + "\n");
			sw.write("RA to DG19: " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG19) + "\n");
			sw.write("RA to DG18: " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG18) + "\n");
			sw.write("RA to DG17: " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG17) + "\n");
			sw.write("RA to DG16: " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG16) + "\n");
			sw.write("RA to DG15: " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG15) + "\n");
			sw.write("RA to DG14: " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG14) + "\n");
			sw.write("RA to DG13: " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG13) + "\n");
			sw.write("RA to DG12: " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG12) + "\n");
			sw.write("RA to DG11: " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG11) + "\n");
			sw.write("RA to DG10: " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG10) + "\n");
			sw.write("RA to DG9 : " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG9) + "\n");
			sw.write("RA to DG8 : " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG8) + "\n");
			sw.write("RA to DG7 : " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG7) + "\n");
			sw.write("RA to DG6 : " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG6) + "\n");
			sw.write("RA to DG5 : " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG5) + "\n");
			sw.write("RA to DG4 : " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG4) + "\n");
			sw.write("RA to DG3 : " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG3) + "\n");
			sw.write("RA to DG2 : " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG2) + "\n");
			sw.write("RA to DG1 : " + chat.hasAuth(CertificateHolderAuthorization.AT_RADG1) + "\n");
			sw.write("Install Qualified Certificate: " + chat.hasAuth(CertificateHolderAuthorization.AT_IQCERT) + "\n");
			sw.write("Install Certificate: " + chat.hasAuth(CertificateHolderAuthorization.AT_ICERT) + "\n");
			sw.write("PIN Management: " + chat.hasAuth(CertificateHolderAuthorization.AT_PINMGNT) + "\n");
			sw.write("CAN allowed: " + chat.hasAuth(CertificateHolderAuthorization.AT_CAN) + "\n");
			sw.write("Privileged Terminal: " + chat.hasAuth(CertificateHolderAuthorization.AT_PRIVTERM) + "\n");
			sw.write("Restricted Identification: " + chat.hasAuth(CertificateHolderAuthorization.AT_RI) + "\n");
			sw.write("Community ID Verification: " + chat.hasAuth(CertificateHolderAuthorization.AT_COMIDVRF) + "\n");
			sw.write("Age Verification: " + chat.hasAuth(CertificateHolderAuthorization.AT_AGEVRF));
		} 
		else if (chat.getOid().equals(CertificateHolderAuthorization.id_IS)) {
			sw.write("RA to DG4: " + chat.hasAuth(CertificateHolderAuthorization.IS_RADG4) + "\n");
			sw.write("RA to DG3: " + chat.hasAuth(CertificateHolderAuthorization.IS_RADG3));
		} 
		else if (chat.getOid().equals(CertificateHolderAuthorization.id_ST)) {
			sw.write("Generate qualified electronic signature: " + chat.hasAuth(CertificateHolderAuthorization.ST_GENQES) + "\n");
			sw.write("Generate electronic signature: " + chat.hasAuth(CertificateHolderAuthorization.ST_GENES));
		}
		return sw.toString();
	}
	
	private String getContentString() {		
		StringWriter sw = new StringWriter();
		sw.write("Certificate Authority Reference (CAR): ");
		sw.write(getCarString()+"\n\n");
		
		sw.write("Public Key\n");
		sw.write(getPublicKeyString()+"\n\n");

		sw.write("Certificate Holder Reference (CHR): ");
		sw.write(getChrString()+"\n\n");

		if (isCertificate) {
			sw.write("Certificate Holder Authorization Template (CHAT)\n");
			sw.write("Terminal Type: ");
			sw.write(getTerminalType()+"\n");
			sw.write("Role: ");
			sw.write(getCertificateRole()+"\n");
			sw.write("Authorizations: ");
			sw.write(getAuthorizationBitString()+"\n");
			sw.write(getAuthorizationString()+"\n\n");
		
			sw.write("Certificate Effective Date: ");
			sw.write(getEffectiveDateString()+"\n");
			sw.write("Certificate Expiration Date: ");
			sw.write(getExpirationDateString()+"\n\n");
		}
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

}
