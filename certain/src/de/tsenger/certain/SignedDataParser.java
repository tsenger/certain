/**
 * 
 */
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

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DEROctetString;
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
import de.tsenger.certain.asn1.icao.DeviationList;
import de.tsenger.certain.asn1.icao.ICAOObjectIdentifiers;
import de.tsenger.certain.asn1.mrtdpki.DefectList;
import de.tsenger.tools.HexString;

/**
 * @author Tobias Senger
 *
 */
public class SignedDataParser {
	
	private String signedContentTypeOID;
	private ASN1Object signedDataContent;
	private DListParser dListParser;
	
	protected List<Certificate> dListSignerCertificates;
	
	protected CMSSignedData cmsSignedData;
	protected SignerInformation signerInfo;

	
	
	private SignedDataParser() {
		this.dListSignerCertificates = new ArrayList<Certificate>(4);	
	}
	
	
	public SignedDataParser(byte[] binary, CertSelector selector) {
		this();		
		this.cmsSignedData = buildCMSSignedDataFromBinary(binary);		
		this.signerInfo = parseSignerInfo();
		this.signedDataContent = parseDList();
		this.dListSignerCertificates = getDListSignerCertificates(cmsSignedData);		
	}
	
	public SignedDataParser(byte[] binary) {
		this(binary, IDENTITY_SELECTOR);
	}
	
	public String getContentTypeOID() {
		return signedContentTypeOID;
	}
	
	public List<Certificate> getDListSignerCertificates() {
		return dListSignerCertificates;
	}
	
	public boolean verifySignedData() {
		boolean result = false;
		for (Certificate cert : dListSignerCertificates) {			
			X509Certificate x509Cert = (X509Certificate) cert;
			
			if (x509Cert.getSubjectDN().toString().equals(x509Cert.getIssuerDN().toString())) {
				SignedDataVerifier verifier = new SignedDataVerifier(x509Cert);
				try {
					result = verifier.signatureVerified(cmsSignedData);
				} catch (CertificateException | OperatorCreationException | CMSException e) {
					System.out.println("Verify failed: "+e.getMessage());
				}				
			}				
		}
		return result;
	}	


	public ASN1Object getContent() {
		return signedDataContent;
	}
	
	public DListParser getDListParser() {
		return dListParser;
	}
	
	
	public String getSignedDataInfoString() {

		StringWriter sw = new StringWriter();

		if (cmsSignedData.getVersion() != 3)
			System.out.println("SignedData Version SHOULD be 3 but is " + cmsSignedData.getVersion() + "!");

		sw.write("SignedData object contains " + dListSignerCertificates.size() + " Signer certificates:\n\n");

		PublicKey pubKey = getRootCertPubKey();

		for (Certificate cert : dListSignerCertificates) {

			X509Certificate x509Cert = (X509Certificate) cert;

			String subjectDN = x509Cert.getSubjectDN().toString();
			String issuerDN = x509Cert.getIssuerDN().toString();

			sw.write("Subject DN: " + subjectDN + "\n");
			sw.write("Issuer  DN:  " + issuerDN + "\n");
			DEROctetString oct = (DEROctetString) DEROctetString.getInstance(x509Cert.getExtensionValue("2.5.29.14"));
			SubjectKeyIdentifier skid = SubjectKeyIdentifier.getInstance(oct.getOctets());
			sw.write("X509 SubjectKeyIdentifier: " + HexString.bufferToHex(skid.getKeyIdentifier()) + "\n");

			if (pubKey != null) {
				try {
					((X509Certificate) cert).verify(pubKey);
					sw.write("Signature is VALID.\n\n");
				} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
					sw.write("Verifying signature of \"" + ((X509Certificate) cert).getSubjectDN() + "\" failed: ");
					sw.write(e.getLocalizedMessage() + "\n\n");
				}
			} else {
				sw.write("Couldn't verify signature because of missing issuer certificate!\n\n");
			}			
		}
		if (pubKey != null) {
			sw.write("Signature of SignedData object is "+(verifySignedData()?"VALID":"!!! INVALID !!!")+"\n");
		} else {
			sw.write("SignedData signature couldn't be verified because of missing issuer certificate!\n");
		}

		return sw.toString();
	}


	/**
	 * @return
	 */
	private PublicKey getRootCertPubKey() {
		PublicKey pubKey = null;	
		
		//Search for selfsigned Certificate because we think thats the root certificate 
		for (Certificate cert : dListSignerCertificates) {			
			X509Certificate x509Cert = (X509Certificate) cert;
			
			if (x509Cert.getSubjectDN().toString().equals(x509Cert.getIssuerDN().toString())) {
				pubKey = x509Cert.getPublicKey();
			}			
		}
		return pubKey;
	}
	
	private ASN1Object parseDList() {
		
		ASN1Object dList = null;

		signedContentTypeOID = cmsSignedData.getSignedContentTypeOID(); 
		CMSProcessableByteArray content = (CMSProcessableByteArray) cmsSignedData.getSignedContent();
		
		if (signedContentTypeOID.equals(BSIObjectIdentifiers.DefectList.toString()) || signedContentTypeOID.equals(ICAOObjectIdentifiers.id_icao_DeviationList.toString())) {
			ByteArrayOutputStream bout = new ByteArrayOutputStream();
			
			try {
				content.write(bout);
			} catch (IOException | CMSException e) {
				System.out.println(e.getLocalizedMessage());
			}
			
			byte[] octets = bout.toByteArray();
			if (signedContentTypeOID.equals(BSIObjectIdentifiers.DefectList.toString())) {
				dList = DefectList.getInstance(octets);
				dListParser = new DefectListParser(dList);
			}
			else if (signedContentTypeOID.equals(ICAOObjectIdentifiers.id_icao_DeviationList.toString())) {
				dList = DeviationList.getInstance(octets);
				dListParser = new DeviationListParser(dList);
			}
		}
		return dList;
	}
	
	/** Use this to get all dListSignerCertificates, including link dListSignerCertificates. */
	private static final CertSelector IDENTITY_SELECTOR = new X509CertSelector() {
		@Override
		public boolean match(Certificate cert) {
			if (!(cert instanceof X509Certificate)) { return false; }
			return true;
		}

		@Override
		public Object clone() { return this; }	
	};
	
	/** Use this to get self-signed dListSignerCertificates only. (Excludes link dListSignerCertificates.) */
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
	
	private List<Certificate> getDListSignerCertificates(CMSSignedData signedData) {
		
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
			System.out.println("Couldn't find a SignedData object: "+e.getLocalizedMessage());
		}
		return signedData;
	}
	
	
	private SignerInformation parseSignerInfo() {
		
		Iterator<SignerInformation> iterator = cmsSignedData.getSignerInfos().getSigners().iterator();

		this.signerInfo = iterator.next();
		return signerInfo;
	}

}
