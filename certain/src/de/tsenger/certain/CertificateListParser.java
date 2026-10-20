package de.tsenger.certain;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

import de.tsenger.tools.HexString;

/**
 * Shows and checks the content of a CSCA Master List (ICAO Doc 9303 Part 12, 9.2) or of a signer list (BSI
 * TR-03129-2, 9). All of them have the same structure:
 * <pre>
 *  CscaMasterList ::= SEQUENCE {
 *  	version		INTEGER {v0(0)},
 *  	certList	SET OF Certificate
 *  }
 * </pre>
 */
public class CertificateListParser extends DListParser {

	private final ListType type;
	private final int version;
	private final List<X509Certificate> certificates = new ArrayList<X509Certificate>();
	/** Certificates that can't be parsed, with the reason. */
	private final List<String> errors = new ArrayList<String>();

	CertificateListParser(ListType type, byte[] content) throws Exception {
		this.type = type;
		ASN1Sequence seq = ASN1Sequence.getInstance(content);
		version = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().intValue();
		ASN1Set certList = ASN1Set.getInstance(seq.getObjectAt(1));
		CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
		for (int i = 0; i < certList.size(); i++) {
			try {
				certificates.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certList.getObjectAt(i).toASN1Primitive().getEncoded())));
			} catch (Exception e) {
				errors.add("certificate No. " + (i + 1) + " can't be parsed: " + e.getLocalizedMessage());
			}
		}
	}

	/** @return the certificates of the list that could be parsed */
	public List<X509Certificate> getCertificates() {
		return certificates;
	}

	@Override
	public String getDListInfoString(boolean showDetails) {
		StringWriter sw = new StringWriter();
		sw.write("\n" + type.name + " version: v" + version + "\n");
		sw.write("This " + type.name + " contains " + certificates.size() + " certificates.\n");
		for (String error : errors) sw.write("! " + error + "\n");
		sw.write("\n");

		int i = 0;
		for (X509Certificate cert : certificates) {
			sw.write("+++++++++++++ Certificate no. " + (++i) + " ++++++++++++++\n");
			sw.write("Subject DN: " + cert.getSubjectDN() + "\n");
			sw.write("Issuer  DN:  " + cert.getIssuerDN() + "\n");
			byte[] ski = cert.getExtensionValue("2.5.29.14");
			if (ski != null) {
				SubjectKeyIdentifier skid = SubjectKeyIdentifier.getInstance(DEROctetString.getInstance(ski).getOctets());
				sw.write("X509 SubjectKeyIdentifier: " + HexString.bufferToHex(skid.getKeyIdentifier()) + "\n");
			}
			sw.write("Public Key Algorithm: " + cert.getPublicKey().getAlgorithm() + "\n");
			sw.write("Signing Algorithm: " + cert.getSigAlgName() + "\n");
			if (showDetails) sw.write(cert.toString());
			sw.write("\n\n");
		}
		return sw.toString();
	}

	/** Checks the version and that all certificates can be parsed. */
	@Override
	public CheckResult check() {
		StringWriter sw = new StringWriter();
		if (version != 0) {
			String reference = type == ListType.MASTER_LIST ? "ICAO Doc 9303 Part 12, 9.2" : "BSI TR-03129-2, 9";
			sw.write(type.name + " version MUST be v0 but is v" + version + " (" + reference + ")!\n");
		}
		for (String error : errors) sw.write(type.name + ": " + error + "!\n");
		return new CheckResult(sw.getBuffer().length() == 0 ? CheckResult.Status.VALID : CheckResult.Status.INVALID, sw.toString());
	}
}
