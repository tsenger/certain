package de.tsenger.certain;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.Store;

import de.tsenger.tools.HexString;

public class MasterListParser {
	

	
	private List<Certificate> masterListSignerCertificates;
	private List<Certificate> cscaCerts;
	private CMSSignedData cmsSignedData;
	private SignerInformation signerInfo;

	/** Use this to get all certificates, including link certificates. */
	private static final CertSelector IDENTITY_SELECTOR = new X509CertSelector() {
		@Override
		public boolean match(Certificate cert) {
			if (!(cert instanceof X509Certificate)) { return false; }
			return true;
		}

		@Override
		public Object clone() { return this; }	
	};

	/** Use this to get self-signed certificates only. (Excludes link certificates.) */
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
	private MasterListParser() {
		cscaCerts = new ArrayList<Certificate>(256);
		masterListSignerCertificates  = new ArrayList<Certificate>(4);
	}
	
	public MasterListParser(byte[] binary, CertSelector selector) {
		this();
		
		this.cmsSignedData = buildCMSSignedDataFromBinary(binary);		
		this.signerInfo = parseSignerInfo();
		this.cscaCerts = parseMasterList();
		this.masterListSignerCertificates = parseMasterListSignerCertificates();		

	}
	
	public MasterListParser(byte[] binary) {
		this(binary, IDENTITY_SELECTOR);
	}
	
	
	public List<Certificate> getMasterListSignerCertificates() {
		return masterListSignerCertificates;
	}
	
	public List<Certificate> getCSCACertificates() {
		return cscaCerts;
	}
	
	public String getMasterListInfoString(boolean showDetails) {
			
		StringWriter sw = new StringWriter();
		
		int i=0;
		
		
		sw.append("\nThis Master List contains "+cscaCerts.size()+" CSCA certificates and "+masterListSignerCertificates.size()+" Master List Signer Certificates.\n\n");
		
		for (Certificate mlSigner : masterListSignerCertificates) {
			sw.append("+++++++++++++ Masterlist Signer Cert no. "+(++i)+" ++++++++++++++\n");
			
			X509Certificate x509Cert = (X509Certificate) mlSigner;

			String subjectDN = x509Cert.getSubjectDN().toString();
			String issuerDN = x509Cert.getIssuerDN().toString();
			
			sw.write("Subject DN: "+subjectDN+"\n");
			sw.write("Issuer  DN:  "+issuerDN+"\n");
			DEROctetString oct = (DEROctetString) DEROctetString.getInstance(x509Cert.getExtensionValue("2.5.29.14"));
			SubjectKeyIdentifier skid = SubjectKeyIdentifier.getInstance(oct.getOctets());
			sw.write("X509 SubjectKeyIdentifier: "+HexString.bufferToHex(skid.getKeyIdentifier())+"\n");
		}
		
		sw.append("\n");		
		i = 0;
		
		for (Certificate cert : cscaCerts) {
			sw.append("+++++++++++++ CSCA Cert no. "+(++i)+" ++++++++++++++\n");
			
			X509Certificate x509Cert = (X509Certificate) cert;

			String subjectDN = x509Cert.getSubjectDN().toString();
			String issuerDN = x509Cert.getIssuerDN().toString();
			
			sw.write("Subject DN: "+subjectDN+"\n");
			sw.write("Issuer  DN:  "+issuerDN+"\n");
			DEROctetString oct = (DEROctetString) DEROctetString.getInstance(x509Cert.getExtensionValue("2.5.29.14"));
			SubjectKeyIdentifier skid = SubjectKeyIdentifier.getInstance(oct.getOctets());
			sw.write("X509 SubjectKeyIdentifier: "+HexString.bufferToHex(skid.getKeyIdentifier()) + "\n");
			sw.append("Public Key Algorithm: " + x509Cert.getPublicKey().getAlgorithm() + "\n");
			sw.append("Signing Algorithm: " + x509Cert.getSigAlgName() + "\n");
			if (showDetails) sw.append(x509Cert.toString());
			
//			try {
//				cert.verify(x509Cert.getPublicKey());
//				sw.append("Signature is valid.");
//
//			} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
//				// TODO Auto-generated catch block
//				sw.append(e.getMessage());
//			} 
			
			sw.append("\n\n");
		}
		return sw.toString();
		
	}
	
	/* PRIVATE METHODS BELOW */
	

	private CMSSignedData buildCMSSignedDataFromBinary(byte[] binary) {
		CMSSignedData signedData =null;
		try {
			signedData = new CMSSignedData(binary);
		} catch (CMSException e) {
			System.out.println("Could find a SignedData object: "+e.getLocalizedMessage());
		}
		return signedData;
	}
	
	private SignerInformation parseSignerInfo() {
		
		Iterator<SignerInformation> iterator = cmsSignedData.getSignerInfos().getSigners().iterator();

		this.signerInfo = iterator.next(); //TODO This only returns the first Signer. Are there more?
		return signerInfo;
	}
	
	private List<Certificate> parseMasterList() {
		
		if (cscaCerts == null) { cscaCerts = new ArrayList<Certificate>(); }
		
		String id_MasterList = cmsSignedData.getSignedContentTypeOID(); 
		CMSProcessableByteArray content = (CMSProcessableByteArray) cmsSignedData.getSignedContent();
		
		byte[] octets = null;
		if (id_MasterList.equals("2.23.136.1.1.2")) {
			
			ByteArrayOutputStream bout = new ByteArrayOutputStream();
			
			try {
				content.write(bout);
			} catch (IOException | CMSException e) {
				System.out.println("parseMasterList() Exception: "+e.getLocalizedMessage());
			}
			octets = bout.toByteArray();
		}

		try {
			Enumeration<?> derObjects = ASN1Sequence.getInstance(octets).getObjects();
			CertificateFactory cf = CertificateFactory.getInstance("X.509","BC");
			
			while (derObjects.hasMoreElements()) {
				ASN1Integer version = (ASN1Integer)derObjects.nextElement(); //Should be 0
//				if (version!=0) throw Exception; //TODO Exception model
				ASN1Set certSet = ASN1Set.getInstance(derObjects.nextElement());
				
				Enumeration<Certificate> certs = certSet.getObjects();				
				while (certs.hasMoreElements()) {
					org.bouncycastle.asn1.x509.Certificate certAsASN1Object = org.bouncycastle.asn1.x509.Certificate.getInstance(certs.nextElement());
					cscaCerts.add(cf.generateCertificate(new ByteArrayInputStream(certAsASN1Object.getEncoded())));
				}
				
			}

		} catch (Exception e) {
			System.out.println("parseMasterList() Exception: "+e.getLocalizedMessage());
		}

		return cscaCerts;
	}
	
	private List<Certificate> parseMasterListSignerCertificates() {
		
		List<Certificate> result = new ArrayList<Certificate>();

		// The signer certifcate(s)
		Store<X509CertificateHolder> certStore = cmsSignedData.getCertificates();
		
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
		converter.setProvider("BC");
		
		ArrayList<X509CertificateHolder> certificateHolders = (ArrayList<X509CertificateHolder>)certStore.getMatches(null); 

		 for(X509CertificateHolder holder: certificateHolders){
			try {
				X509Certificate cert = converter.getCertificate(holder);
				result.add(cert);
			} catch (CertificateException e) {
				System.out.println("parseMasterListSignerCertificates() Exception: "+e.getLocalizedMessage());
			} 
		 }
		return result;
	}
}
