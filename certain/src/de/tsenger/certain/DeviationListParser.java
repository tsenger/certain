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

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
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

import de.tsenger.certain.asn1.icao.CertField;
import de.tsenger.certain.asn1.icao.Deviation;
import de.tsenger.certain.asn1.icao.DeviationDescription;
import de.tsenger.certain.asn1.icao.DeviationList;
import de.tsenger.certain.asn1.icao.DocumentSignerIdentifier;
import de.tsenger.certain.asn1.icao.ICAOObjectIdentifiers;
import de.tsenger.certain.asn1.icao.IssuancePeriod;
import de.tsenger.tools.HexString;

public class DeviationListParser {
	
	private List<Certificate> deviationListSignerCertificates;
	private DeviationList deviationList;
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
	
	public List<Certificate> getDeviationListSignerCertificates() {
		return deviationListSignerCertificates;
	}
	
	public DeviationList getDeviationList() {
		return deviationList;
	}
	
	public String getDeviationListInfoString(boolean showDetails) {
		
		Deviation deviation;
		
		StringWriter sw = new StringWriter();
		
		if 	(cmsSignedData.getVersion()!=3)	System.out.println("SignedData Version SHOULD be 3 but is "+ cmsSignedData.getVersion()+"!");
		
		sw.write("\nThis Deviation List contains deviations from "+deviationList.getDeviations().size()+" different DS certificates\n");
		sw.write("and contains "+deviationListSignerCertificates.size()+" Deviation List Signer certificates:\n\n");
		
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
		
				
		for (int i=0;i<deviationList.getDeviations().size();i++) {
			sw.write("\n++++++++++++++++++++++++++++++++++ DEVIATION No. "+(i+1)+" ++++++++++++++++++++++++++++++++++\n");
			deviation = Deviation.getInstance(deviationList.getDeviations().getObjectAt(i));
			
			sw.write("Documents:\n");
			
			if (deviation.getDocuments().getDocumentType() != null) { 		
				sw.write("\tDocument Type: "+deviation.getDocuments().getDocumentType()+"\n");		
			}
			
			if (deviation.getDocuments().getDscIdentifier() != null) {	

				DocumentSignerIdentifier dscIdentifier  = deviation.getDocuments().getDscIdentifier();
				
				switch (dscIdentifier.getTag()) {
					case 1: 
						IssuerAndSerialNumber iasn = IssuerAndSerialNumber.getInstance(dscIdentifier.getDSIdentifier());	
						sw.write("\tDS Issuer: "+iasn.getName().toString()+"; DS Serial No.: "+iasn.getSerialNumber()+"\n");
						break;
					case 2:
						SubjectKeyIdentifier skid = SubjectKeyIdentifier.getInstance(dscIdentifier.getDSIdentifier());
						sw.write("\tSubject Key Identifier: "+HexString.bufferToHex(skid.getKeyIdentifier())+"\n");
						break;
					case 3:
						ASN1OctetString octStr = ASN1OctetString.getInstance(dscIdentifier.getDSIdentifier());
						sw.write("\tDigest ("+deviationList.getDigestAlg().getAlgorithm().getId()+"): "+HexString.bufferToHex(octStr.getOctets())+"\n");
				}							
			}
			
			if (deviation.getDocuments().getIssuingDate() != null) {
				IssuancePeriod issuancePeriod = deviation.getDocuments().getIssuingDate();
				sw.write("\tfirst issued: "+issuancePeriod.getFirstIssued().getTime()+"\n");
				sw.write("\tlast  issued: "+issuancePeriod.getLastIssued().getTime()+"\n");
			}
			
			
			if (deviation.getDocuments().getDocumentNumbers() != null) { 
				ASN1Set docNumberSet = deviation.getDocuments().getDocumentNumbers();
				sw.write("\tDocument numbers:\n");
				for (int j=0; j<docNumberSet.size(); j++) {
					sw.write("\t\t"+(DERPrintableString.getInstance(docNumberSet.getObjectAt(j)).getString()+"\n"));
				}
				
			}
			sw.write("This documents have "+deviation.getDescriptions().size()+" known deviations:\n");
			
			DeviationDescription deviationDescription;
			for (int k=0;k<deviation.getDescriptions().size();k++) {
				deviationDescription = DeviationDescription.getInstance(deviation.getDescriptions().getObjectAt(k));
				
				if (deviationDescription.getDescription() != null) {
					sw.write("\tDescription: "+(DERPrintableString.getInstance(deviationDescription.getDescription()).getString()+"\n"));
				}
				
				ASN1ObjectIdentifier id_deviationType = deviationDescription.getDeviationType();
				
				if (id_deviationType.equals(ICAOObjectIdentifiers.id_Deviation_CertOrKey)) {
					sw.write("\t+ Generic certificate or key related deviation without more details. (OID: "+id_deviationType+")\n");
				} 
				else if (id_deviationType.equals(ICAOObjectIdentifiers.id_Deviation_CertOrKey_DSSignature)) {
					sw.write("\t+ DS Signature is wrong (OID: "+id_deviationType+")\n");
				}
				else if (id_deviationType.equals(ICAOObjectIdentifiers.id_Deviation_CertOrKey_DSEncoding) || id_deviationType.equals(ICAOObjectIdentifiers.id_Deviation_CertOrKey_CSCAEncoding)) {
					if (id_deviationType.equals(ICAOObjectIdentifiers.id_Deviation_CertOrKey_DSEncoding)) sw.write("\t+ DS certificate contains a coding error (OID: "+id_deviationType+"): ");
					else sw.write("\t+ CSCA certificate contains a coding error (OID: "+id_deviationType+"): ");
					
					CertField certField = CertField.getInstance(deviationDescription.getParameters().getLoadedObject());
					
					switch (certField.getCertificateBodyField()) {
					case 0: sw.write("generic deviation in certificate body\n"); break;
					case 1: sw.write("deviation in certificate body field: version\n"); break;
					case 2: sw.write("deviation in certificate body field: serialNumber\n"); break;
					case 3: sw.write("deviation in certificate body field: signature\n"); break;
					case 4: sw.write("deviation in certificate body field: issuer\n"); break;
					case 5: sw.write("deviation in certificate body field: validity\n"); break;
					case 6: sw.write("deviation in certificate body field: subject\n"); break;
					case 7: sw.write("deviation in certificate body field: subjectPublicKeyInfo\n"); break;
					case 8: sw.write("deviation in certificate body field: issuerUniqueID\n"); break;
					case 9: sw.write("deviation in certificate body field: subjectUniqueID\n"); break;
					default: break;	
					}
					
					if (certField.getExtensionOID() != null) {
						sw.write("deviation in certificate extension with OID: "+certField.getExtensionOID()+"\n");
					}
					
				} else if (id_deviationType.equals(ICAOObjectIdentifiers.id_Deviation_CertOrKey_AAKeyCompromised)) {
					sw.write("\t+ Key for AA may be compromised ans should not be relied upon (OID: "+id_deviationType+")\n");
				} else if (id_deviationType.equals(ICAOObjectIdentifiers.id_Deviation_LDS)) {
					sw.write("\t+ Generic LDS related deviation without more details. (OID: "+id_deviationType+")\n");
				} else if (id_deviationType.equals(ICAOObjectIdentifiers.id_Deviation_LDS_DGMalformed) || id_deviationType.equals(ICAOObjectIdentifiers.id_Deviation_LDS_DGHashWrong)) {
					if (id_deviationType.equals(ICAOObjectIdentifiers.id_Deviation_LDS_DGMalformed) ) sw.write("\t+ TLV encoding of the following datagroup is corrupted (OID: "+id_deviationType+"): ");
					else sw.write("\t+ Hash value of the following datagroup in the EF.SOD is wrong (OID: "+id_deviationType+"): ");
					
					int dg = ASN1Integer.getInstance(deviationDescription.getParameters().getLoadedObject()).getPositiveValue().intValue();
					
					if (dg>0 && dg <=16) sw.write("DG"+dg+"\n"); 
					else if (dg==20) sw.write("SOD"+dg+"\n"); 
					else if (dg==21) sw.write("COM"+dg+"\n"); 
					
				} else if (id_deviationType.equals(ICAOObjectIdentifiers.id_Deviation_LDS_SODSignatureWrong)) {
					sw.write("\t+ Signature contained in EF.SOD is wrong (OID: "+id_deviationType+")\n");
				} else if (id_deviationType.equals(ICAOObjectIdentifiers.id_Deviation_LDS_COMInconsistent)) {
					sw.write("\t+ EF.COM and EF.SOD are inconsistent (OID: "+id_deviationType+")\n");
				} else if (id_deviationType.equals(ICAOObjectIdentifiers.id_Deviation_MRZ)) {
					sw.write("\t+ Generic MRZ related deviation without more details. (OID: "+id_deviationType+")\n");
				} else if (id_deviationType.equals(ICAOObjectIdentifiers.id_Deviation_MRZ_WrongCheckDigit) || id_deviationType.equals(ICAOObjectIdentifiers.id_Deviation_MRZ_WrongData)) {
					if (id_deviationType.equals(ICAOObjectIdentifiers.id_Deviation_MRZ_WrongData)) sw.write("\t+ The following field of MRZ contains wrong data (OID: "+id_deviationType+"): ");
					else sw.write("\t+ Check digit to the following field of the MRZ is calculated wrong (OID: "+id_deviationType+"): ");
					
					int mrzField = ASN1Integer.getInstance(deviationDescription.getParameters().getLoadedObject()).getPositiveValue().intValue();
					
					switch (mrzField) {
					case 0: sw.write("generic\n"); break;
					case 1: sw.write("documentCode\n"); break;
					case 2: sw.write("issuingState\n"); break;
					case 3: sw.write("personName\n"); break;
					case 4: sw.write("documentNumber\n"); break;
					case 5: sw.write("nationality\n"); break;
					case 6: sw.write("dateOfBirth\n"); break;
					case 7: sw.write("sex\n"); break;
					case 8: sw.write("dateOfExpiry\n"); break;
					case 9: sw.write("optionalData\n"); break;
					default: break;	
					}
					
				} else if (id_deviationType.equals(ICAOObjectIdentifiers.id_Deviation_Chip)) {
					sw.write("\t+ Chip is not usable (OID: "+id_deviationType+")\n");
				}
				
				if (deviationDescription.getNationalUse() != null) {
					try {
						sw.write("\tnationalUse field contains data (RAW DATA following): \n"+HexString.bufferToHex(deviationDescription.getNationalUse().getEncoded(),true)+"\n");
					} catch (IOException e) {
						sw.write("\tError while decode nationalUse field.\n");
					}
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
	
	private DeviationList parseDeviationList() {
		
		DeviationList deviationList = null;

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
			deviationList = DeviationList.getInstance(octets);
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
