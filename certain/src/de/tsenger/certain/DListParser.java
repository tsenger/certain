/**
 * 
 */
package de.tsenger.certain;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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

/**
 * @author Tobias Senger
 *
 */
public class DListParser {
	
	private String signedContentTypeOID;
	
	protected List<Certificate> dListSignerCertificates;
	
	protected CMSSignedData cmsSignedData;
	protected SignerInformation signerInfo;

	private ASN1Object dList;
	
	private DListParser() {
		this.dListSignerCertificates = new ArrayList<Certificate>(4);	
	}
	
	
	public DListParser(byte[] binary, CertSelector selector) {
		this();		
		this.cmsSignedData = buildCMSSignedDataFromBinary(binary);		
		this.signerInfo = parseSignerInfo();
		this.setdList(parseDList());
		this.dListSignerCertificates = getDListSignerCertificates(cmsSignedData);		
	}
	
	public DListParser(byte[] binary) {
		this(binary, IDENTITY_SELECTOR);
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
					System.out.println("Couldn't verify signature of SignedData objekt: "+e.getMessage());
				}				
			}				
		}
		return result;
	}	

	public ASN1Object getdList() {
		return dList;
	}

	public void setdList(ASN1Object dList) {
		this.dList = dList;
	}
	
	public String getDListInfoString(boolean showDetails) {
		return(null);
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
			if (signedContentTypeOID.equals(BSIObjectIdentifiers.DefectList.toString())) dList = DefectList.getInstance(octets);
			else if (signedContentTypeOID.equals(ICAOObjectIdentifiers.id_icao_DeviationList.toString())) dList = DeviationList.getInstance(octets);
		}
		return dList;
	}
	
	/** Use this to get all dListSignerCertificates, including link dListSignerCertificates. */
	protected static final CertSelector IDENTITY_SELECTOR = new X509CertSelector() {
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
	
	protected List<Certificate> getDListSignerCertificates(CMSSignedData signedData) {
		
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
	
	protected CMSSignedData buildCMSSignedDataFromBinary(byte[] binary) {
		CMSSignedData signedData =null;
		try {
			signedData = new CMSSignedData(binary);
		} catch (CMSException e) {
			System.out.println("Could find a SignedData object: "+e.getLocalizedMessage());
		}
		return signedData;
	}
	
	
	protected SignerInformation parseSignerInfo() {
		
		Iterator<SignerInformation> iterator = cmsSignedData.getSignerInfos().getSigners().iterator();

		this.signerInfo = iterator.next();
		return signerInfo;
	}

}
