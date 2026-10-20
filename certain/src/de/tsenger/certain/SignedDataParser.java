/**
 * 
 */
package de.tsenger.certain;

import java.text.ParseException;
import java.util.Date;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import java.io.IOException;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
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
	
	/** Object identifiers of the RSA PKCS #1 v1.5 signature algorithms, whose parameters MUST be NULL (RFC 3447). */
	private static final List<String> RSA_PKCS1_SIGNATURES = Arrays.asList("1.2.840.113549.1.1.4", "1.2.840.113549.1.1.5",
			"1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13", "1.2.840.113549.1.1.14");

	private final byte[] binary;
	private String signedContentTypeOID;
	private ListType listType;
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

		sw.write("eContentType: " + signedContentTypeOID + " (" + (listType != null ? listType.name : "unknown, the content is not parsed") + ")\n");
		if (listType == null) {
			if (cmsSignedData.getVersion() != 3) {
				sw.write("SignedData Version SHOULD be 3 but is " + cmsSignedData.getVersion() + "!\n");
			}
		} else {
			status = checkProfile(sw);
			if (listType.isSignerList()) {
				CheckResult.Status signer = checkSignerListSigner(sw);
				if (signer.compareTo(status) > 0) status = signer;
			}
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
			} else if (type.equals(BSIObjectIdentifiers.ListContentDescription) && value instanceof ASN1UTF8String) {
				sw.write("\tlistContentDescription: " + ((ASN1UTF8String) value).getString() + "\n");
			} else {
				sw.write("\t" + type + ":\n" + ASN1Dump.dumpAsString(attribute.getAttrValues(), true).replaceAll("(?m)^", "\t\t"));
			}
		}
	}

	/**
	 * Checks the SignedData profile and the signer certificate: of Deviation Lists (ICAO Doc 9303 Part 12, 10.1,
	 * Table 19), Master Lists (9.1, Table 18), and of Defect Lists and signer lists (BSI TR-03129-3, Appendix C, Table 3,
	 * referred to by BSI TR-03129-2, 8 and 9). Violated MUSTs make the check fail, RECOMMENDED fields are only noted.
	 */
	private CheckResult.Status checkProfile(StringWriter sw) {
		boolean masterList = listType == ListType.MASTER_LIST;
		boolean icao = masterList || listType == ListType.DEVIATION_LIST;
		String table = icao ? "ICAO Doc 9303 Part 12, " + (masterList ? "Table 18" : "Table 19") : "BSI TR-03129-3, Table 3";
		String signer = masterList ? "Master List Signer" : icao ? "Deviation List Signer" : listType == ListType.DEFECT_LIST ? "DFL Signer"
				: listType == ListType.BLOCK_LIST ? "Block List Signer" : "Signer List Signer";
		CheckResult.Status status = CheckResult.Status.VALID;
		// BSI lists are BER encoded (BSI TR-03129-2, 8.1 and 9), block lists SHOULD be DER encoded (BSI TR-03129-3, B.1)
		if (listType == ListType.BLOCK_LIST && !isDer()) {
			sw.write("Note: the Block List SHOULD be DER encoded but is not (BSI TR-03129-3, B.1).\n");
		}
		if (icao) {
			if (!isDer()) {
				sw.write("The " + listType.name + " MUST be DER encoded but is not (ICAO Doc 9303 Part 12, " + (masterList ? "9" : "10") + ")!\n");
				status = CheckResult.Status.INVALID;
			}
		}
		if (cmsSignedData.getVersion() != 3) {
			sw.write("SignedData version MUST be v3 but is v" + cmsSignedData.getVersion() + " (" + table + ")!\n");
			status = CheckResult.Status.INVALID;
		}
		if (!cmsSignedData.getCRLs().getMatches(null).isEmpty()) {
			sw.write("crls MUST NOT be present (" + table + ")!\n");
			status = CheckResult.Status.INVALID;
		}
		int signerInfos = cmsSignedData.getSignerInfos().size();
		if (signerInfos != 1) {
			sw.write("Note: it is RECOMMENDED to provide only one signerInfo, but there are " + signerInfos
					+ ", only the first one is checked (" + table + ").\n");
		}
		if (signerInfo.getSID().getSubjectKeyIdentifier() == null) {
			sw.write("Note: the sid of the SignerInfo is issuerAndSerialNumber, subjectKeyIdentifier is RECOMMENDED (" + table + ").\n");
		}
		AttributeTable signedAttributes = signerInfo.getSignedAttributes();
		if (signedAttributes == null) {
			sw.write("signedAttrs MUST be present (" + table + ")!\n");
			status = CheckResult.Status.INVALID;
		} else {
			if (signedAttributes.get(CMSAttributes.signingTime) == null) {
				sw.write("signedAttrs MUST include the signing time (" + table + ")!\n");
				status = CheckResult.Status.INVALID;
			}
			Attribute contentType = signedAttributes.get(CMSAttributes.contentType);
			if (contentType == null || !contentType.getAttrValues().getObjectAt(0).equals(new ASN1ObjectIdentifier(signedContentTypeOID))) {
				sw.write("The content-type attribute MUST be present and match the eContentType (RFC 5652, 11.1)!\n");
				status = CheckResult.Status.INVALID;
			}
			if (!icao && signedAttributes.get(BSIObjectIdentifiers.ListContentDescription) == null) {
				sw.write("signedAttrs MUST include the ListContentDescription attribute " + BSIObjectIdentifiers.ListContentDescription
						+ " (BSI TR-03129-3, Table 3 and C.1)!\n");
				status = CheckResult.Status.INVALID;
			}
		}
		if (listType == ListType.DEVIATION_LIST && signerInfo.getUnsignedAttributes() != null) {
			sw.write("unsignedAttrs MUST NOT be present (" + table + ")!\n");
			status = CheckResult.Status.INVALID;
		}
		if (masterList) {
			// Note of Table 18: DigestAlgorithmIdentifiers MUST omit NULL, RSA SignatureAlgorithmIdentifiers MUST include it
			for (AlgorithmIdentifier digestAlgorithm : cmsSignedData.getDigestAlgorithmIDs()) {
				if (DERNull.INSTANCE.equals(digestAlgorithm.getParameters())) {
					sw.write("The digest algorithm " + digestAlgorithm.getAlgorithm() + " MUST omit NULL parameters (" + table + ")!\n");
					status = CheckResult.Status.INVALID;
				}
			}
			AlgorithmIdentifier signatureAlgorithm = signerInfo.toASN1Structure().getDigestEncryptionAlgorithm();
			if (RSA_PKCS1_SIGNATURES.contains(signatureAlgorithm.getAlgorithm().getId()) && signatureAlgorithm.getParameters() == null) {
				sw.write("The signature algorithm " + signatureAlgorithm.getAlgorithm() + " MUST include NULL as parameters (" + table + ")!\n");
				status = CheckResult.Status.INVALID;
			}
		}
		X509CertificateHolder signerCert = signerCertificate();
		if (signerCert == null) {
			sw.write("certificates MUST include the " + signer + " certificate (" + table + ")!\n");
			return CheckResult.Status.INVALID;
		}
		if (listType != ListType.DEVIATION_LIST && !containsIssuer(signerCert)) {
			sw.write("Note: the CSCA certificate that issued the " + signer + " certificate SHOULD be included (" + table
					+ (masterList ? "; 5.3 says MUST" : "") + ").\n");
		}
		if (listType == ListType.DEFECT_LIST && !hasSigningKeyUsage(signerCert)) {
			sw.write("Note: the extended key usage of the DFL Signer certificate SHOULD contain " + listType.signingKey.getId()
					+ " but is " + extendedKeyUsage(signerCert) + "; this will become mandatory (BSI TR-03129-2, 8.2).\n");
		}
		if (!icao) return status;
		BasicConstraints basicConstraints = BasicConstraints.fromExtensions(signerCert.getExtensions());
		if (basicConstraints != null && basicConstraints.isCA()) {
			sw.write("The " + listType.name + " is signed by a CA certificate, but it MUST NOT be signed directly by a CSCA ("
					+ (masterList ? "ICAO Doc 9303 Part 12, 5.3" : "ICAO Doc 9303 Part 3, 7.3.2") + ")!\n");
			status = CheckResult.Status.INVALID;
		}
		if (!hasSigningKeyUsage(signerCert)) {
			sw.write("The extended key usage of the " + signer + " certificate MUST contain " + listType.signingKey.getId() + " but is "
					+ extendedKeyUsage(signerCert) + " (ICAO Doc 9303 Part 12, 7.1.1.3)!\n");
			status = CheckResult.Status.INVALID;
		}
		return status;
	}

	/**
	 * Checks the Signer List Signer certificate (BSI TR-03129-2, 9.8) and that the signing time is within its private key
	 * usage period (9.10).
	 */
	private CheckResult.Status checkSignerListSigner(StringWriter sw) {
		X509CertificateHolder signerCert = signerCertificate();
		if (signerCert == null) return CheckResult.Status.NOT_CHECKED;
		CheckResult.Status status = CheckResult.Status.VALID;
		if (!hasSigningKeyUsage(signerCert)) {
			sw.write("The extended key usage of the Signer List Signer certificate SHALL contain " + listType.signingKey.getId()
					+ " but is " + extendedKeyUsage(signerCert) + " (BSI TR-03129-2, 9.8)!\n");
			status = CheckResult.Status.INVALID;
		}
		Extension extension = signerCert.getExtension(Extension.privateKeyUsagePeriod);
		PrivateKeyUsagePeriod period = extension != null ? PrivateKeyUsagePeriod.getInstance(extension.getParsedValue()) : null;
		if (period == null || period.getNotBefore() == null || period.getNotAfter() == null) {
			sw.write("The Signer List Signer certificate SHALL include the private key usage period extension with notBefore and "
					+ "notAfter (BSI TR-03129-2, 9.8)!\n");
			return CheckResult.Status.INVALID;
		}
		try {
			Date notBefore = period.getNotBefore().getDate();
			Date notAfter = period.getNotAfter().getDate();
			sw.write("Private key usage period of the Signer List Signer: " + period.getNotBefore().getTime() + " to "
					+ period.getNotAfter().getTime() + "\n");
			if (notBefore.before(signerCert.getNotBefore()) || notAfter.after(signerCert.getNotAfter())) {
				sw.write("The private key usage period SHALL be within the validity period of the Signer List Signer certificate "
						+ "(BSI TR-03129-2, 9.8)!\n");
				status = CheckResult.Status.INVALID;
			}
			Attribute signingTime = signerInfo.getSignedAttributes() != null ? signerInfo.getSignedAttributes().get(CMSAttributes.signingTime) : null;
			if (signingTime == null) {
				sw.write("The signing time can't be checked against the private key usage period, signedAttrs contain no signing time "
						+ "(BSI TR-03129-2, 9.10)!\n");
				if (status == CheckResult.Status.VALID) status = CheckResult.Status.NOT_CHECKED;
			} else {
				Date signed = Time.getInstance(signingTime.getAttrValues().getObjectAt(0)).getDate();
				if (signed.before(notBefore) || signed.after(notAfter)) {
					sw.write("The signing time SHALL be within the private key usage period of the Signer List Signer certificate "
							+ "(BSI TR-03129-2, 9.10)!\n");
					status = CheckResult.Status.INVALID;
				}
			}
		} catch (ParseException e) {
			sw.write("The private key usage period can't be decoded: " + e.getLocalizedMessage() + "!\n");
			status = CheckResult.Status.INVALID;
		}
		return status;
	}

	/** @return true if the input is DER encoded; an input that can't be re-encoded is taken as DER, CMS parsed it already */
	private boolean isDer() {
		try {
			return Arrays.equals(binary, ASN1Primitive.fromByteArray(binary).getEncoded(ASN1Encoding.DER));
		} catch (IOException e) {
			return true;
		}
	}

	/** @return the certificate the SignerInfo refers to or null if the SignedData object doesn't contain it */
	private X509CertificateHolder signerCertificate() {
		Collection<X509CertificateHolder> signerCerts = cmsSignedData.getCertificates().getMatches(signerInfo.getSID());
		return signerCerts.isEmpty() ? null : signerCerts.iterator().next();
	}

	private boolean containsIssuer(X509CertificateHolder cert) {
		for (X509CertificateHolder candidate : cmsSignedData.getCertificates().getMatches(null)) {
			if (candidate.getSubject().equals(cert.getIssuer())) return true;
		}
		return false;
	}

	private boolean hasSigningKeyUsage(X509CertificateHolder cert) {
		ExtendedKeyUsage eku = ExtendedKeyUsage.fromExtensions(cert.getExtensions());
		return eku != null && eku.hasKeyPurposeId(listType.signingKey);
	}

	private static String extendedKeyUsage(X509CertificateHolder cert) {
		ExtendedKeyUsage eku = ExtendedKeyUsage.fromExtensions(cert.getExtensions());
		return eku == null ? "missing" : Arrays.toString(eku.getUsages());
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
		listType = ListType.of(signedContentTypeOID);
		if (listType == null) return null;

		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		try {
			((CMSProcessableByteArray) cmsSignedData.getSignedContent()).write(bout);
		} catch (IOException | CMSException e) {
			System.err.println(e.getLocalizedMessage());
		}
		byte[] octets = bout.toByteArray();

		if (listType == ListType.DEFECT_LIST) {
			dList = DefectList.getInstance(octets);
			dListParser = new DefectListParser(dList);
		} else if (listType == ListType.DEVIATION_LIST) {
			dList = DeviationList.getInstance(octets);
			dListParser = new DeviationListParser(dList);
		} else {
			try {
				dListParser = listType == ListType.BLOCK_LIST ? new BlockListParser(octets) : new CertificateListParser(listType, octets);
			} catch (Exception e) {
				throw new IllegalArgumentException("can't parse the content of the " + listType.name + ": " + e.getLocalizedMessage(), e);
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
