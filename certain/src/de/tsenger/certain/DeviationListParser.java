package de.tsenger.certain;

import java.io.ByteArrayOutputStream;
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
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

import de.tsenger.certain.asn1.eac.BSIObjectIdentifiers;
import de.tsenger.certain.asn1.icao.ICAOObjectIdentifiers;
import de.tsenger.certain.asn1.mrtdpki.Defect;
import de.tsenger.certain.asn1.mrtdpki.DefectList;
import de.tsenger.certain.asn1.mrtdpki.KnownDefect;
import de.tsenger.tools.HexString;

public class DeviationListParser {
	
	private List<Certificate> deviationListSignerCertificates;
	private DefectList deviationList;
	private CMSSignedData cmsSignedData;
	private SignerInformation signerInfo;

	/** Use this to get all deviationListSignerCertificates, including link deviationListSignerCertificates. */
	private static final CertSelector IDENTITY_SELECTOR = new X509CertSelector() {
		@Override
		public boolean match(Certificate cert) {
			if (!(cert instanceof X509Certificate)) { return false; }
			return true;
		}

		@Override
		public Object clone() { return this; }	
	};

	/** Use this to get self-signed deviationListSignerCertificates only. (Excludes link deviationListSignerCertificates.) */
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
	private DeviationListParser() {
		this.deviationListSignerCertificates = new ArrayList<Certificate>(4);	
	}
	
	
	public DeviationListParser(byte[] binary, CertSelector selector) {
		this();
		
		this.cmsSignedData = buildCMSSignedDataFromBinary(binary);		
		this.signerInfo = parseSignerInfo();
		this.deviationList = parseDeviationList();
		this.deviationListSignerCertificates = getDeviationListSignerCertificates(cmsSignedData);		
	}
	

	public DeviationListParser(byte[] binary) {
		this(binary, IDENTITY_SELECTOR);
	}
	
	public List<Certificate> getDefectListSignerCertificates() {
		return deviationListSignerCertificates;
	}
	
	public DefectList getDefectList() {
		return deviationList;
	}
	
	public String getDefectListInfoString(boolean showDetails) {
		
		Defect defect;
		
		StringWriter sw = new StringWriter();
		
		if 	(cmsSignedData.getVersion()!=3)	System.out.println("SignedData Version SHOULD be 3 but is "+ cmsSignedData.getVersion()+"!");
		
		sw.write("\nThis Deviation List contains defects from "+deviationList.getDefects().size()+" different DS certificates\n");
		sw.write("and contains "+deviationListSignerCertificates.size()+" Defects List Signer certificates:\n\n");
		
		PublicKey pubKey = null;	
		
		for (Certificate cert : deviationListSignerCertificates) {			
			X509Certificate x509Cert = (X509Certificate) cert;
			
			if (x509Cert.getSubjectDN().toString().equals(x509Cert.getIssuerDN().toString())) {
				pubKey = x509Cert.getPublicKey();
			}			
		}
		
		if (pubKey != null) {

			for (Certificate cert : deviationListSignerCertificates) {
				
				X509Certificate x509Cert = (X509Certificate) cert;

				String subjectDN = x509Cert.getSubjectDN().toString();
				String issuerDN = x509Cert.getIssuerDN().toString();
				
				sw.write("Subject DN: "+subjectDN+"\n");
				sw.write("Issuer  DN:  "+issuerDN+"\n");
				DEROctetString oct = (DEROctetString) DEROctetString.getInstance(x509Cert.getExtensionValue("2.5.29.14"));
				SubjectKeyIdentifier skid = SubjectKeyIdentifier.getInstance(oct.getOctets());
				sw.write("X509 SubjectKeyIdentifier: "+HexString.bufferToHex(skid.getKeyIdentifier())+"\n");
				
				try {
					((X509Certificate) cert).verify(pubKey);
					sw.write("Signature is VALID.\n\n");
				} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
					sw.write("Verifying signature of "+((X509Certificate) cert).getSubjectDN()+" failed: ");
					sw.write(e.getLocalizedMessage()+"\n\n");
				}
			}
		} else {
			sw.write("Could verify signatures. Didn't found a valid issuer\n");
		}
		
		sw.write("Signature of SignedData object is "+(verifySignedData()?"VALID":"!!! INVALID !!!")+"\n");
		
		
				
		for (int i=0;i<deviationList.getDefects().size();i++) {
			sw.write("\n++++++++++++++++++++++++++++++++++ DEFECT No. "+(i+1)+" ++++++++++++++++++++++++++++++++++\n");
			defect = Defect.getInstance(deviationList.getDefects().getObjectAt(i));
			
			if (defect.getSignerId().getId() instanceof ASN1Encodable) { //SignerIdentifier CHOICE is IssuerAndSerialNumber 
				IssuerAndSerialNumber iasn = IssuerAndSerialNumber.getInstance(defect.getSignerId().getId());
				
				sw.write("DS Issuer: "+iasn.getName().toString()+"; DS Serial No.: "+iasn.getSerialNumber()+"\n");
				
				
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
					sw.write("+ Authentication Deviation: DS certificate revoked (OID: "+id_defectType+")");
					DEREnumerated statusCode = (DEREnumerated)knownDefect.getParameters();
					
					switch (statusCode.getValue().intValue()) {
					case 0: sw.write("\tno details given (status code 0: noIndication)\n");
					case 1: sw.write("\trevocation under investigation (status code 1: onHold)\n");
					case 2: sw.write("\tthe certificate has been used for testing purpose (status code 2: testing)\n");
					case 3: sw.write("\tthe issuer has revoked the certificate by CRL (status code 3: revoked by Issuer)\n");
					case 4: sw.write("\tthe Deviation List Signer has revoked the certificate (status code 4: revoked DLS)\n");
					default: sw.write("\tstatus codes >=32 can be used for internal purpose (status code "+statusCode.getValue().intValue()+": proprietary)\n");
					}
					
				} else if (id_defectType.equals(BSIObjectIdentifiers.certReplaced)) {
					sw.write("+ Authentication Deviation: DS certificate malformed (OID: "+id_defectType+")\n");
					Certificate replacementCert= (Certificate)knownDefect.getParameters();
					sw.write("\tReplacement Certificate:\n\t"+replacementCert.toString()+"\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.certChipAuthKeyRevoked)) {
					sw.write("+ Authentication Deviation: Chip Authentication private keys compromised (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.certActiveAuthKeyRevoked)) {
					sw.write("+ Authentication Deviation: Active Authentication private keys compromised (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.ePassportDGMalformed)) {
					sw.write("+ Personalisation Deviation ePassport: data group malformed (OID: "+id_defectType+")\n");
					DLSet malformedDgs = (DLSet)knownDefect.getParameters();
					sw.write("\tDatagroups:");
					for (int k=0;k<malformedDgs.size();k++){
						int dgno = ASN1Integer.getInstance(malformedDgs.getObjectAt(k)).getValue().intValue();
						sw.write(dgno+" ");
					}
					sw.write("\n");
					
				} else if (id_defectType.equals(BSIObjectIdentifiers.SODInvalid)) {
					sw.write("+ Personalisation Deviation ePassport: SOD malformed (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.COMSODDiscrepancy)) {
					sw.write("+ Personalisation Deviation ePassport: COM SOD discrepancy (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.eIDDGMalformed)) {
					sw.write("+ Personalisation Deviation eID: data group malformed (OID: "+id_defectType+")\n");
					DLSet malformedDgs = (DLSet)knownDefect.getParameters();
					sw.write("\tDatagroups: ");
					for (int l=0;l<malformedDgs.size();l++){
						int dgno = ASN1Integer.getInstance(malformedDgs.getObjectAt(l)).getValue().intValue();
						sw.write(dgno+" ");
					}
					sw.write("\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.eIDIntegrity)) {
					sw.write("+ Personalisation Deviation eID: application integrity uncertain (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.eIDSecurityInfoMissing)) {
					sw.write("+ Personalisation Deviation eID: SecurityInfo missing (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.eIDDGMissing)) {
					sw.write("+ Personalisation Deviation eID: data group missing (OID: "+id_defectType+")\n");
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
					sw.write("! Unknown Deviation OID: "+id_defectType+")\n");
				}
				
			}
						
		}

		return sw.toString();
	}
	
	public boolean verifySignedData() {
		boolean result = false;
		for (Certificate cert : deviationListSignerCertificates) {			
			X509Certificate x509Cert = (X509Certificate) cert;
			
			if (x509Cert.getSubjectDN().toString().equals(x509Cert.getIssuerDN().toString())) {
				SignedDataVerifier verifier = new SignedDataVerifier(x509Cert);
				try {
					result = verifier.signatureVerified(cmsSignedData);
				} catch (CertificateException | OperatorCreationException | CMSException e) {
					System.out.println("Couldn't verify signature of SignedData objekt: "+e.getMessage());
				}				
			}				
		}
		return result;
	}
	
	/* PRIVATE METHODS BELOW */
	
	private SignerInformation parseSignerInfo() {
		
		Iterator<SignerInformation> iterator = cmsSignedData.getSignerInfos().getSigners().iterator();

		this.signerInfo = iterator.next();
		return signerInfo;
	}
	
	private DefectList parseDeviationList() {
		
		DefectList deviationList = null;

		String id_DeviationList = cmsSignedData.getSignedContentTypeOID(); 
		CMSProcessableByteArray content = (CMSProcessableByteArray) cmsSignedData.getSignedContent();
		
		if (id_DeviationList.equals(ICAOObjectIdentifiers.id_icao_DeviationList.toString())) {
			ByteArrayOutputStream bout = new ByteArrayOutputStream();
			
			try {
				content.write(bout);
			} catch (IOException | CMSException e) {
				System.out.println(e.getLocalizedMessage());
			}
			
			byte[] octets = bout.toByteArray();
			deviationList = DefectList.getInstance(octets);
		}
		return deviationList;
	}

	
	private List<Certificate> getDeviationListSignerCertificates(CMSSignedData signedData) {
		
		List<Certificate> result = new ArrayList<Certificate>();

		// The signer certifcate(s)
		Store certStore = signedData.getCertificates();
		
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
		converter.setProvider("BC");
		
		ArrayList<X509CertificateHolder> certificateHolders = (ArrayList<X509CertificateHolder>)certStore.getMatches(null); 

		 for(X509CertificateHolder holder: certificateHolders){
			try {
				X509Certificate cert = converter.getCertificate(holder);
				result.add(cert);
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 
		 }
		return result;
	}
	
	private CMSSignedData buildCMSSignedDataFromBinary(byte[] binary) {
		CMSSignedData signedData =null;
		try {
			signedData = new CMSSignedData(binary);
		} catch (CMSException e) {
			System.out.println("Could find a SignedData object: "+e.getLocalizedMessage());
		}
		return signedData;
	}
	
}
