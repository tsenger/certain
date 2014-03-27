package de.tsenger.certain;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.jce.provider.X509CertificateObject;

import de.tsenger.certain.asn1.eac.BSIObjectIdentifiers;
import de.tsenger.certain.asn1.mrtdpki.Defect;
import de.tsenger.certain.asn1.mrtdpki.DefectList;
import de.tsenger.certain.asn1.mrtdpki.KnownDefect;
import de.tsenger.tools.HexString;

public class DefectListParser {
	
	private List<Certificate> defectListSignerCertificates;
	private DefectList defectList;

	/** Use this to get all defectListSignerCertificates, including link defectListSignerCertificates. */
	private static final CertSelector IDENTITY_SELECTOR = new X509CertSelector() {
		@Override
		public boolean match(Certificate cert) {
			if (!(cert instanceof X509Certificate)) { return false; }
			return true;
		}

		@Override
		public Object clone() { return this; }	
	};

	/** Use this to get self-signed defectListSignerCertificates only. (Excludes link defectListSignerCertificates.) */
	private static final CertSelector SELF_SIGNED_SELECTOR = new X509CertSelector() {
		@Override
		public boolean match(Certificate cert) {
			if (!(cert instanceof X509Certificate)) { return false; }
			X509Certificate x509Cert = (X509Certificate)cert;
			X500Principal issuer = x509Cert.getIssuerX500Principal();
			X500Principal subject = x509Cert.getSubjectX500Principal();
			return (issuer == null && subject == null) || subject.equals(issuer);
		}

		@Override
		public Object clone() { return this; }
	};
	

	/** Private constructor, only used locally. */
	private DefectListParser() {
		this.defectListSignerCertificates = new ArrayList<Certificate>(16);	
	}
	
	/**
	 * Constructs a defect list from a collection of defectListSignerCertificates.
	 * 
	 * @param defectListSignerCertificates a collection of defectListSignerCertificates
	 */
	public DefectListParser(Collection<Certificate> certificates) {
		this();
		this.defectListSignerCertificates.addAll(certificates);
	}
	
	public DefectListParser(byte[] binary, CertSelector selector) {
		this();
		SignedData signedData = getSignedDataFromBinary(binary);
		this.defectList = getDefectList(signedData);
		this.defectListSignerCertificates.addAll(getDefectListSignerCertificatesFromSignedData(signedData, selector));
	}
	
	public DefectListParser(byte[] binary) {
		this(binary, IDENTITY_SELECTOR);
	}
	
	public List<Certificate> getDefectListSignerCertificates() {
		return defectListSignerCertificates;
	}
	
	public DefectList getDefectList() {
		return defectList;
	}
	
	public String getDefectListInfoString(boolean showDetails) {
		
		Defect defect;
		
		StringWriter sw = new StringWriter();
		
		sw.write("\nThis Defect List contains defects from "+defectList.getDefects().size()+" different DS certificates\n");
		sw.write("and contains "+defectListSignerCertificates.size()+" Defects List Signer certificates:\n\n");
		
		PublicKey pubKey = null;	
		
		for (Certificate cert : defectListSignerCertificates) {			
			X509Certificate x509Cert = (X509Certificate) cert;
			
			if (x509Cert.getSubjectDN().toString().equals(x509Cert.getIssuerDN().toString())) {
				pubKey = x509Cert.getPublicKey();
			}			
		}
		
		if (pubKey != null) {

			for (Certificate cert : defectListSignerCertificates) {
				
				X509Certificate x509Cert = (X509Certificate) cert;
				String subjectDN = x509Cert.getSubjectDN().toString();
				String issuerDN = x509Cert.getIssuerDN().toString();
				
				sw.write("Subject DN: "+subjectDN+"\n");
				sw.write("Issuer DN:  "+issuerDN+"\n");
				
				try {
					((X509Certificate) cert).verify(pubKey);
					sw.write("Signature is valid.\n");
				} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
					System.out.print("Verifying signature of "+((X509Certificate) cert).getSubjectDN()+" failed: ");
					sw.write(e.getLocalizedMessage()+"\n");
				}
			}
		} else {
			sw.write("Could verify signatures: no public key available\n");
		}
		
		for (int i=0;i<defectList.getDefects().size();i++) {
			sw.write("\n++++++++++++++++++++++++++++++++++ DEFECT No. "+(i+1)+" ++++++++++++++++++++++++++++++++++\n");
			defect = Defect.getInstance(defectList.getDefects().getObjectAt(i));
			
			if (defect.getSignerId().getId() instanceof ASN1Encodable) { //SignerIdentifier CHOICE is IssuerAndSerialNumber 
				IssuerAndSerialNumber iasn = IssuerAndSerialNumber.getInstance(defect.getSignerId().getId());
				sw.write(iasn.getName().toString()+", SerialNumber: "+iasn.getSerialNumber()+"\n");
				
				
			} else if (defect.getSignerId().getId() instanceof ASN1OctetString) {	//SignerIdentifier CHOICE is SubjectKeyIdentifier 
				byte[] encoded = ((ASN1OctetString)defect.getSignerId().getId()).getOctets();
				sw.write(HexString.bufferToHex(encoded)+"\n");
				
			}
			
			if (defect.getCertificateHash()!=null) { //optional Hash available?
				byte[] encoded = defect.getCertificateHash().getOctets();
				sw.write("Certificate Hash: "+ HexString.bufferToHex(encoded)+"\n");
			}
			sw.write("This DS certificate has "+defect.getKnownDefects().size()+" known defects:\n");
			
			KnownDefect knownDefect;
			for (int j=0;j<defect.getKnownDefects().size();j++) {
				knownDefect = KnownDefect.getInstance(defect.getKnownDefects().getObjectAt(j));
				ASN1ObjectIdentifier id_defectType = knownDefect.getDefectType();
				
				if (id_defectType.equals(BSIObjectIdentifiers.certRevoked)) {
					sw.write("+ Authentication Defect: DS certificate revoked (OID: "+id_defectType+")");
					DEREnumerated statusCode = (DEREnumerated)knownDefect.getParameters();
					
					switch (statusCode.getValue().intValue()) {
					case 0: sw.write("\tno details given (status code 0: noIndication)\n");
					case 1: sw.write("\trevocation under investigation (status code 1: onHold)\n");
					case 2: sw.write("\tthe certificate has been used for testing purpose (status code 2: testing)\n");
					case 3: sw.write("\tthe issuer has revoked the certificate by CRL (status code 3: revoked by Issuer)\n");
					case 4: sw.write("\tthe Defect List Signer has revoked the certificate (status code 4: revoked DLS)\n");
					default: sw.write("\tstatus codes >=32 can be used for internal purpose (status code "+statusCode.getValue().intValue()+": proprietary)\n");
					}
					
				} else if (id_defectType.equals(BSIObjectIdentifiers.certReplaced)) {
					sw.write("+ Authentication Defect: DS certificate malformed (OID: "+id_defectType+")\n");
					Certificate replacementCert= (Certificate)knownDefect.getParameters();
					sw.write("\tReplacement Certificate:\n\t"+replacementCert.toString()+"\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.certChipAuthKeyRevoked)) {
					sw.write("+ Authentication Defect: Chip Authentication private keys compromised (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.certActiveAuthKeyRevoked)) {
					sw.write("+ Authentication Defect: Active Authentication private keys compromised (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.ePassportDGMalformed)) {
					sw.write("+ Personalisation Defect ePassport: data group malformed (OID: "+id_defectType+")\n");
					DLSet malformedDgs = (DLSet)knownDefect.getParameters();
					sw.write("\tDatagroups:");
					for (int k=0;k<malformedDgs.size();k++){
						int dgno = ASN1Integer.getInstance(malformedDgs.getObjectAt(k)).getValue().intValue();
						sw.write(dgno+" ");
					}
					sw.write("\n");
					
				} else if (id_defectType.equals(BSIObjectIdentifiers.SODInvalid)) {
					sw.write("+ Personalisation Defect ePassport: SOD malformed (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.COMSODDiscrepancy)) {
					sw.write("+ Personalisation Defect ePassport: COM SOD discrepancy (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.eIDDGMalformed)) {
					sw.write("+ Personalisation Defect eID: data group malformed (OID: "+id_defectType+")\n");
					DLSet malformedDgs = (DLSet)knownDefect.getParameters();
					sw.write("\tDatagroups: ");
					for (int l=0;l<malformedDgs.size();l++){
						int dgno = ASN1Integer.getInstance(malformedDgs.getObjectAt(l)).getValue().intValue();
						sw.write(dgno+" ");
					}
					sw.write("\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.eIDIntegrity)) {
					sw.write("+ Personalisation Defect eID: application integrity uncertain (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.eIDSecurityInfoMissing)) {
					sw.write("+ Personalisation Defect eID: SecurityInfo missing (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.eIDDGMissing)) {
					sw.write("+ Personalisation Defect eID: data group missing (OID: "+id_defectType+")\n");
					DLSet malformedDgs = (DLSet)knownDefect.getParameters();
					sw.write("\tDatagroups: ");
					for (int m=0;m<malformedDgs.size();m++){
						int dgno = ASN1Integer.getInstance(malformedDgs.getObjectAt(m)).getValue().intValue();
						sw.write(dgno+" ");
					}
					sw.write("\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.CardSecurityMalformed)) {
					sw.write("+ General Document Defects: Card Security Object malformed (OID: "+id_defectType+")\n");
					DERSequence cardSecurity = (DERSequence)knownDefect.getParameters();
					sw.write("\tSize of new CardSecurity: "+cardSecurity.size()+"\n");
					//TODO Print whole new DS cert is showDetails is set
				} else if (id_defectType.equals(BSIObjectIdentifiers.ChipSecurityMalformed)) {
					sw.write("+ General Document Defects: Chip Security Object malformed (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.PowerDownReq)) {
					sw.write("+ General Document Defects: Power Down is required (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.DSMalformed)) {
					sw.write("+ General Document Defects: Document Signer is malformed (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.EAC2PrivilegedTerminalInfoMissing)) {
					sw.write("+ General Document Defects: EAC2 PrivilegedTerminalInfo missing (OID: "+id_defectType+")\n");
				} else {
					sw.write("! Unknown Defect OID: "+id_defectType+")\n");
				}
				
			}
						
		}
		
		
		
		return sw.toString();
	}
	
	/* PRIVATE METHODS BELOW */
	
	private DefectList getDefectList(SignedData signedData) {
		
		DefectList defectList = null;
		
		ContentInfo contentInfo = signedData.getContentInfo();
		ASN1ObjectIdentifier id_DefectList =  contentInfo.getContentType();
		Object content = contentInfo.getContent();
		
		if (id_DefectList.equals(BSIObjectIdentifiers.DefectList)) {

			if (content instanceof DEROctetString) {
				DEROctetString derOctetString = (DEROctetString)content;
				byte[] octets = derOctetString.getOctets();
				defectList = DefectList.getInstance(octets);
			}
		}
		return defectList;
	}

	private List<Certificate> getDefectListSignerCertificatesFromSignedData(SignedData signedData, CertSelector selector) {
		
		List<Certificate> result = new ArrayList<Certificate>();

		// The signer certifcate(s)
		Object certs = signedData.getCertificates(); // signer Certs
		Collection<Certificate> signerCertificates = getCertificatesFromDERObject(certs, null);
		
		for (Certificate certificate: signerCertificates) {
			if (selector.match(certificate)) {
				result.add(certificate);
			}
		}
		return result;
	}
	
	private SignedData getSignedDataFromBinary(byte[] binary) {

		List<SignedData> list =  getSignedDataFromDERObject(ASN1Sequence.getInstance(binary),null);
		if (list.size()>1) System.out.println("More than one SignedData Object available.");
		if (list.size()>=1) return list.get(0);
		else return null;
	}
	
	private List<SignedData> getSignedDataFromDERObject(Object o, List<SignedData> result) {
		if (result == null) { result = new ArrayList<SignedData>(); }

		try {
			SignedData signedData = SignedData.getInstance(o);
			if (signedData != null) {
				result.add(signedData);
			}
			return result;
		} catch (Exception e) {
		}

		if (o instanceof DERTaggedObject) {
			ASN1Primitive childObject = ((DERTaggedObject)o).getObject();
			return getSignedDataFromDERObject(childObject, result);
		} else if (o instanceof ASN1Sequence) {
			Enumeration<?> derObjects = ((ASN1Sequence)o).getObjects();
			while (derObjects.hasMoreElements()) {
				Object nextObject = derObjects.nextElement();
				result = getSignedDataFromDERObject(nextObject, result);
			}
			return result;
		} else if (o instanceof ASN1Set) {
			Enumeration<?> derObjects = ((ASN1Set)o).getObjects();
			while (derObjects.hasMoreElements()) {
				Object nextObject = derObjects.nextElement();
				result = getSignedDataFromDERObject(nextObject, result);
			}
			return result;
		} else if (o instanceof DEROctetString) {
			DEROctetString derOctetString = (DEROctetString)o;
			byte[] octets = derOctetString.getOctets();
			ASN1InputStream derInputStream = new ASN1InputStream(new ByteArrayInputStream(octets));
			try {
				while (true) {
					ASN1Primitive derObject = derInputStream.readObject();
					if (derObject == null) { break; }
					result = getSignedDataFromDERObject(derObject, result);
				}
				derInputStream.close();
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
			return result;
		}
		return result;
	}

	
	private Collection<Certificate> getCertificatesFromDERObject(Object o, Collection<Certificate> certificates) {
		if (certificates == null) { certificates = new ArrayList<Certificate>(); }

		try {
			org.bouncycastle.asn1.x509.Certificate certAsASN1Object = org.bouncycastle.asn1.x509.Certificate.getInstance(o);
			certificates.add(new X509CertificateObject(certAsASN1Object)); // NOTE: BC 1.48
			return certificates;
		} catch (Exception e) {
		}

		if (o instanceof DERTaggedObject) {
			ASN1Primitive childObject = ((DERTaggedObject)o).getObject();
			return getCertificatesFromDERObject(childObject, certificates);
		} else if (o instanceof ASN1Sequence) {
			Enumeration<?> derObjects = ((ASN1Sequence)o).getObjects();
			while (derObjects.hasMoreElements()) {
				Object nextObject = derObjects.nextElement();
				certificates = getCertificatesFromDERObject(nextObject, certificates);
			}
			return certificates;
		} else if (o instanceof ASN1Set) {
			Enumeration<?> derObjects = ((ASN1Set)o).getObjects();
			while (derObjects.hasMoreElements()) {
				Object nextObject = derObjects.nextElement();
				certificates = getCertificatesFromDERObject(nextObject, certificates);
			}
			return certificates;
		} else if (o instanceof DEROctetString) {
			DEROctetString derOctetString = (DEROctetString)o;
			byte[] octets = derOctetString.getOctets();
			ASN1InputStream derInputStream = new ASN1InputStream(new ByteArrayInputStream(octets));
			try {
				while (true) {
					ASN1Primitive derObject = derInputStream.readObject();
					if (derObject == null) { break; }
					certificates = getCertificatesFromDERObject(derObject, certificates);
					derInputStream.close();
				}
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
			return certificates;
		} else if (o instanceof SignedData) {
			SignedData signedData = (SignedData)o;
			//			ASN1Set certificatesASN1Set = signedData.getCertificates();
			//			Enumeration certificatesEnum = certificatesASN1Set.getObjects();
			//			while (certificatesEnum.hasMoreElements()) {
			//				Object certificateObject = certificatesEnum.nextElement();
			//				// TODO: interpret certificateObject, and check signature
			//			}

			ContentInfo contentInfo = signedData.getContentInfo();
			Object content = contentInfo.getContent();
			return getCertificatesFromDERObject(content, certificates);
		}
		return certificates;
	}
}
