/**
 * 
 */
package de.tsenger.certain;

import java.io.IOException;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
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
import java.util.Collection;
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
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
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
	
	/** Object identifier of the Deviation List Signer key purpose (ICAO Doc 9303 Part 12, 7.1.1.3). */
	private static final KeyPurposeId DEVIATION_LIST_SIGNING_KEY = KeyPurposeId.getInstance(ICAOObjectIdentifiers.id_icao_DeviationListSigningKey);

	private final byte[] binary;
	private String signedContentTypeOID;
	private ASN1Object signedDataContent;
	private DListParser dListParser;
	
	protected List<Certificate> dListSignerCertificates;
	
	protected CMSSignedData cmsSignedData;
	protected SignerInformation signerInfo;

	
	
	public SignedDataParser(byte[] binary, CertSelector selector) {
		this.binary = binary;
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
	
	/**
	 * Verifies the signature of the SignedData object with the signer certificate its SignerInfo refers to, by
	 * issuerAndSerialNumber or subjectKeyIdentifier. This needs only the signer certificate, not its issuer.
	 */
	public CheckResult verifySignedData() {
		Collection<X509CertificateHolder> signerCerts = cmsSignedData.getCertificates().getMatches(signerInfo.getSID());
		if (signerCerts.isEmpty()) {
			return new CheckResult(CheckResult.Status.NOT_CHECKED, "SignedData signature couldn't be verified because the "
					+ "SignedData object doesn't contain the signer certificate its SignerInfo refers to!\n");
		}
		try {
			if (signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signerCerts.iterator().next()))) {
				return new CheckResult(CheckResult.Status.VALID, "Signature of SignedData object is VALID\n");
			}
			return new CheckResult(CheckResult.Status.INVALID, "Signature of SignedData object is !!! INVALID !!!\n");
		} catch (CMSSignerDigestMismatchException e) {
			return new CheckResult(CheckResult.Status.INVALID, "Signature of SignedData object is !!! INVALID !!!: "
					+ e.getLocalizedMessage() + "\n");
		} catch (CertificateException | OperatorCreationException | CMSException e) {
			// e.g. an unsupported algorithm
			return new CheckResult(CheckResult.Status.NOT_CHECKED, "SignedData signature couldn't be verified: "
					+ e.getLocalizedMessage() + "\n");
		}
	}


	public ASN1Object getContent() {
		return signedDataContent;
	}
	
	public DListParser getDListParser() {
		return dListParser;
	}
	
	
	/**
	 * Describes the signer certificates and verifies their signatures and the signature of the SignedData object
	 * with the self-signed signer certificate.
	 */
	public CheckResult checkSignedData() {

		StringWriter sw = new StringWriter();
		CheckResult.Status status = CheckResult.Status.VALID;

		sw.write("eContentType: " + signedContentTypeOID + " (" + contentTypeName() + ")\n");
		boolean deviationList = signedContentTypeOID.equals(ICAOObjectIdentifiers.id_icao_DeviationList.getId());
		if (deviationList) {
			status = checkDeviationListProfile(sw);
		} else if (cmsSignedData.getVersion() != 3) {
			sw.write("SignedData Version SHOULD be 3 but is " + cmsSignedData.getVersion() + "!\n");
		}
		writeSignedAttributes(sw);
		sw.write("\n");

		sw.write("SignedData object contains " + dListSignerCertificates.size() + " Signer certificates:\n\n");

		PublicKey pubKey = getRootCertPubKey();

		for (Certificate cert : dListSignerCertificates) {

			X509Certificate x509Cert = (X509Certificate) cert;

			String subjectDN = x509Cert.getSubjectDN().toString();
			String issuerDN = x509Cert.getIssuerDN().toString();

			sw.write("Subject DN: " + subjectDN + "\n");
			sw.write("Issuer  DN:  " + issuerDN + "\n");
			if (x509Cert.getExtensionValue("2.5.29.14") != null) {
				DEROctetString oct = (DEROctetString) DEROctetString.getInstance(x509Cert.getExtensionValue("2.5.29.14"));
				SubjectKeyIdentifier skid = SubjectKeyIdentifier.getInstance(oct.getOctets());
				sw.write("X509 SubjectKeyIdentifier: " + HexString.bufferToHex(skid.getKeyIdentifier()) + "\n");
			}

			if (pubKey != null) {
				try {
					((X509Certificate) cert).verify(pubKey);
					sw.write("Signature is VALID.\n\n");
				} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
					sw.write("Verifying signature of \"" + ((X509Certificate) cert).getSubjectDN() + "\" failed: ");
					sw.write(e.getLocalizedMessage() + "\n\n");
					status = CheckResult.Status.INVALID;
				}
			} else {
				sw.write("Couldn't verify signature because of missing issuer certificate!\n\n");
				if (status == CheckResult.Status.VALID) status = CheckResult.Status.NOT_CHECKED;
			}
		}
		CheckResult signature = verifySignedData();
		sw.write(signature.getText());
		if (signature.getStatus().compareTo(status) > 0) status = signature.getStatus();

		return new CheckResult(status, sw.toString());
	}

	private String contentTypeName() {
		if (signedContentTypeOID.equals(ICAOObjectIdentifiers.id_icao_DeviationList.getId())) return "ICAO Deviation List";
		if (signedContentTypeOID.equals(BSIObjectIdentifiers.DefectList.getId())) return "BSI Defect List";
		return "unknown, the content is not parsed";
	}

	/** Lists the signed attributes of the SignerInfo. */
	private void writeSignedAttributes(StringWriter sw) {
		AttributeTable signedAttributes = signerInfo.getSignedAttributes();
		if (signedAttributes == null) return;
		sw.write("Signed attributes:\n");
		ASN1EncodableVector attributes = signedAttributes.toASN1EncodableVector();
		for (int i = 0; i < attributes.size(); i++) {
			Attribute attribute = Attribute.getInstance(attributes.get(i));
			ASN1ObjectIdentifier type = attribute.getAttrType();
			ASN1Encodable value = attribute.getAttrValues().getObjectAt(0);
			if (type.equals(CMSAttributes.contentType)) {
				sw.write("\tcontentType: " + value + "\n");
			} else if (type.equals(CMSAttributes.signingTime)) {
				sw.write("\tsigningTime: " + Time.getInstance(value).getTime() + "\n");
			} else if (type.equals(CMSAttributes.messageDigest)) {
				sw.write("\tmessageDigest: " + HexString.bufferToHex(ASN1OctetString.getInstance(value).getOctets()) + "\n");
			} else {
				sw.write("\t" + type + ":\n" + ASN1Dump.dumpAsString(attribute.getAttrValues(), true).replaceAll("(?m)^", "\t\t"));
			}
		}
	}

	/**
	 * Checks the SignedData profile for Deviation Lists (ICAO Doc 9303 Part 12, 10.1, Table 19) and the extended key
	 * usage of the Deviation List Signer certificate (7.1.1.3). Violated MUSTs make the check fail, RECOMMENDED
	 * fields are only noted.
	 */
	private CheckResult.Status checkDeviationListProfile(StringWriter sw) {
		CheckResult.Status status = CheckResult.Status.VALID;
		try {
			if (!Arrays.equals(binary, ASN1Primitive.fromByteArray(binary).getEncoded(ASN1Encoding.DER))) {
				sw.write("The Deviation List MUST be DER encoded but is not (ICAO Doc 9303 Part 12, 10)!\n");
				status = CheckResult.Status.INVALID;
			}
		} catch (IOException e) {
			sw.write("Couldn't check the DER encoding: " + e.getLocalizedMessage() + "\n");
		}
		if (cmsSignedData.getVersion() != 3) {
			sw.write("SignedData version MUST be v3 but is v" + cmsSignedData.getVersion() + " (ICAO Doc 9303 Part 12, Table 19)!\n");
			status = CheckResult.Status.INVALID;
		}
		if (!cmsSignedData.getCRLs().getMatches(null).isEmpty()) {
			sw.write("crls MUST NOT be present (ICAO Doc 9303 Part 12, Table 19)!\n");
			status = CheckResult.Status.INVALID;
		}
		int signerInfos = cmsSignedData.getSignerInfos().size();
		if (signerInfos != 1) {
			sw.write("Note: it is RECOMMENDED to provide only one signerInfo, but there are " + signerInfos
					+ ", only the first one is checked (ICAO Doc 9303 Part 12, Table 19).\n");
		}
		if (signerInfo.getSID().getSubjectKeyIdentifier() == null) {
			sw.write("Note: the sid of the SignerInfo is issuerAndSerialNumber, subjectKeyIdentifier is RECOMMENDED "
					+ "(ICAO Doc 9303 Part 12, Table 19).\n");
		}
		AttributeTable signedAttributes = signerInfo.getSignedAttributes();
		if (signedAttributes == null) {
			sw.write("signedAttrs MUST be present (ICAO Doc 9303 Part 12, Table 19)!\n");
			status = CheckResult.Status.INVALID;
		} else {
			if (signedAttributes.get(CMSAttributes.signingTime) == null) {
				sw.write("signedAttrs MUST include the signing time (ICAO Doc 9303 Part 12, Table 19)!\n");
				status = CheckResult.Status.INVALID;
			}
			Attribute contentType = signedAttributes.get(CMSAttributes.contentType);
			if (contentType == null || !contentType.getAttrValues().getObjectAt(0).equals(new ASN1ObjectIdentifier(signedContentTypeOID))) {
				sw.write("The content-type attribute MUST be present and match the eContentType (RFC 5652, 11.1)!\n");
				status = CheckResult.Status.INVALID;
			}
		}
		if (signerInfo.getUnsignedAttributes() != null) {
			sw.write("unsignedAttrs MUST NOT be present (ICAO Doc 9303 Part 12, Table 19)!\n");
			status = CheckResult.Status.INVALID;
		}
		Collection<X509CertificateHolder> signerCerts = cmsSignedData.getCertificates().getMatches(signerInfo.getSID());
		if (!signerCerts.isEmpty()) {
			X509CertificateHolder signerCert = signerCerts.iterator().next();
			BasicConstraints basicConstraints = BasicConstraints.fromExtensions(signerCert.getExtensions());
			if (basicConstraints != null && basicConstraints.isCA()) {
				sw.write("The Deviation List is signed by a CA certificate, but Deviation Lists MUST NOT be issued directly "
						+ "by a CSCA (ICAO Doc 9303 Part 3, 7.3.2)!\n");
				status = CheckResult.Status.INVALID;
			}
			ExtendedKeyUsage eku = ExtendedKeyUsage.fromExtensions(signerCert.getExtensions());
			if (eku == null || !eku.hasKeyPurposeId(DEVIATION_LIST_SIGNING_KEY)) {
				sw.write("The extended key usage of the Deviation List Signer certificate MUST contain "
						+ DEVIATION_LIST_SIGNING_KEY.getId() + " but is " + (eku == null ? "missing" : Arrays.toString(eku.getUsages()))
						+ " (ICAO Doc 9303 Part 12, 7.1.1.3)!\n");
				status = CheckResult.Status.INVALID;
			}
		}
		return status;
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
				System.err.println(e.getLocalizedMessage());
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
		Store<X509CertificateHolder> certStore = signedData.getCertificates();
		
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
		try {
			return new CMSSignedData(binary);
		} catch (CMSException e) {
			throw new IllegalArgumentException("Couldn't find a SignedData object: "+e.getLocalizedMessage(), e);
		}
	}
	
	
	private SignerInformation parseSignerInfo() {
		
		Iterator<SignerInformation> iterator = cmsSignedData.getSignerInfos().getSigners().iterator();

		this.signerInfo = iterator.next();
		return signerInfo;
	}

}
