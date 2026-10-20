package de.tsenger.certain;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.style.BCStyle;

import de.tsenger.certain.asn1.eac.BSIObjectIdentifiers;
import de.tsenger.certain.asn1.mrtdpki.CaCertificateReference;
import de.tsenger.certain.asn1.mrtdpki.Defect;
import de.tsenger.certain.asn1.mrtdpki.DefectList;
import de.tsenger.certain.asn1.mrtdpki.KnownDefect;
import de.tsenger.certain.asn1.mrtdpki.SignerCertificateReference;
import de.tsenger.tools.HexString;

/**
 * Shows and checks defect lists as specified in BSI TR-03129-2, chapter 8 (versions 1 to 3). The defects of the eID
 * application are specified in BSI TR-03129-3; the known ones are shown, but not checked.
 */
public class DefectListParser extends DListParser {

	private static final String[] REVOCATION_STATUS = { "noIndication (no details given)", "onHold (revocation under investigation)",
			"testing (the certificate has been used for testing)", "revokedByIssuer (the issuer has revoked the certificate by CRL)",
			"revokedDLS (the Defect List Signer has revoked the certificate)", "certInadequate (the certificate is inadequate)" };
	private static final String[] PROTOCOL_FAILURE = { "CA_failure", "AA_failure", "CA_AA_failure", "PACE_CAM_failure",
			"CA_PACE_CAM_failure", "AA_PACE_CAM_failure", "CA_AA_PACE_CAM_failure" };
	private static final String[] VALIDITY_PERIOD = { "CSCA_validity (CSCA certificate validity is incorrect)",
			"DS_validity (signer certificate validity is incorrect)", "CSCA_DS_validity (both validities are incorrect)" };
	private static final String[] SOD_FAULT = { "noIndication (no details given)", "sodSignatureFailure", "sodHashInvalid",
			"sodEncodingFailure", "sodDGHashesInvalid" };
	private static final String[] MALFORMED_STATUS = { "noIndication (no details given)", "unknownCryptoAlg", "encodingFailure" };
	private static final String[] MALFORMED_CERTIFICATE_TYPE = { "CountrySigning (root or link certificate of a CSCA)",
			"Signer (Document Signer, Barcode Signer or LDS2 Signer)" };
	private static final String[] DN_DEFECT_TYPE = { "Issuer", "Subject" };

	private DefectList defectList;

	public DefectListParser(ASN1Object dListObject) {
		defectList = DefectList.getInstance(dListObject);
	}

	@Override
	public String getDListInfoString(boolean showDetails) {
		return render(showDetails, new ArrayList<String>());
	}

	/** Checks the MUSTs of TR-03129-2, 8.1 and 8.3 that the parser can see: the version rules and the parameters. */
	@Override
	public CheckResult check() {
		List<String> violations = new ArrayList<String>();
		render(false, violations);
		StringWriter sw = new StringWriter();
		for (String violation : violations) sw.write(violation + "\n");
		return new CheckResult(violations.isEmpty() ? CheckResult.Status.VALID : CheckResult.Status.INVALID, sw.toString());
	}

	/** Describes the defect list and collects the violations of the specification. */
	private String render(boolean showDetails, List<String> violations) {
		StringWriter sw = new StringWriter();
		int version = defectList.getVersion();
		sw.write("\nDefect List version: v" + (version + 1) + "\n");
		if (version < 0 || version > 2) {
			fail(sw, violations, "Defect List", "version MUST be v1, v2 or v3 (BSI TR-03129-2, 8.1)");
		}
		sw.write("Hash algorithm: " + defectList.getHashAlg() + "\n");
		sw.write("This Defect List contains " + defectList.getDefects().size() + " defects\n");

		for (int i = 0; i < defectList.getDefects().size(); i++) {
			String where = "Defect No. " + (i + 1);
			sw.write("\n++++++++++++++++++++++++++++++++++ DEFECT No. " + (i + 1) + " ++++++++++++++++++++++++++++++++++\n");
			try {
				writeDefect(sw, Defect.getInstance(defectList.getDefects().getObjectAt(i)), version, showDetails, violations, where);
			} catch (RuntimeException e) {
				fail(sw, violations, where, "can't be parsed: " + e.getLocalizedMessage());
			}
		}
		return sw.toString();
	}

	private void writeDefect(StringWriter sw, Defect defect, int version, boolean showDetails, List<String> violations, String where) {
		if (defect.getSignerId() != null) sw.write("Signer identifier: " + signerIdentifier(defect.getSignerId()) + "\n");
		if (defect.getCertificateHash() != null) sw.write("Certificate hash: " + hex(defect.getCertificateHash()) + "\n");
		SignerCertificateReference signerReference = defect.getSignerCertificateReference();
		if (signerReference != null) {
			sw.write("Signer certificate reference:\n");
			if (signerReference.getIssuerAndSerialNumber() != null) sw.write("\t" + issuerAndSerialNumber(signerReference.getIssuerAndSerialNumber()) + "\n");
			if (signerReference.getSubjectKeyIdentifier() != null) sw.write("\tSubject Key Identifier: " + hex(signerReference.getSubjectKeyIdentifier()) + "\n");
			if (signerReference.getSignerReference() != null) sw.write("\tSigner reference: " + signerReference.getSignerReference() + "\n");
			if (signerReference.getCertificateHash() != null) sw.write("\tCertificate hash: " + hex(signerReference.getCertificateHash()) + "\n");
		}
		CaCertificateReference caReference = defect.getCaCertificateReference();
		if (caReference != null) {
			sw.write("CA certificate reference:\n");
			if (caReference.getIssuer() != null) sw.write("\tIssuer: " + caReference.getIssuer() + "\n");
			if (caReference.getAuthorityKeyIdentifier() != null) {
				byte[] keyIdentifier = caReference.getAuthorityKeyIdentifier().getKeyIdentifierOctets();
				sw.write("\tAuthority Key Identifier: " + (keyIdentifier != null ? HexString.bufferToHex(keyIdentifier) : "without key identifier") + "\n");
			}
		}
		if (defect.getDescription() != null) sw.write("Description: " + defect.getDescription() + "\n");

		if (version == 0 && defect.getSignerId() == null) {
			fail(sw, violations, where, "signerIdentifier MUST be present in version 1 (BSI TR-03129-2, 8.1)");
		}
		if (version == 0 && defect.getDescription() != null) {
			fail(sw, violations, where, "description MAY only be present in version 2 or 3 (BSI TR-03129-2, 8.1)");
		}
		if (version == 2) {
			if (defect.getSignerId() != null) fail(sw, violations, where, "signerIdentifier MUST NOT be present in version 3 (BSI TR-03129-2, 8.1)");
			if (defect.getCertificateHash() != null) fail(sw, violations, where, "certificateHash MUST NOT be present in version 3 (BSI TR-03129-2, 8.1)");
			if (signerReference == null && caReference == null) {
				fail(sw, violations, where, "signercertificateReference or caCertificateReference MUST be present in version 3 (BSI TR-03129-2, 8.1)");
			}
		}

		sw.write("Known defects: " + defect.getKnownDefects().size() + "\n");
		for (int j = 0; j < defect.getKnownDefects().size(); j++) {
			KnownDefect knownDefect;
			try {
				knownDefect = KnownDefect.getInstance(defect.getKnownDefects().getObjectAt(j));
			} catch (RuntimeException e) {
				fail(sw, violations, where, "known defect No. " + (j + 1) + " can't be parsed: " + e.getLocalizedMessage());
				continue;
			}
			if (version == 0 && knownDefect.isV2()) {
				fail(sw, violations, where, "knownDefect (not knownDefectV2) is used in version 1 (BSI TR-03129-2, 8.1)");
			} else if (version > 0 && !knownDefect.isV2()) {
				fail(sw, violations, where, "knownDefectV2 (not knownDefect) is used in version 2 and 3 (BSI TR-03129-2, 8.1)");
			}
			try {
				writeKnownDefect(sw, knownDefect, showDetails, violations, where);
			} catch (RuntimeException e) {
				fail(sw, violations, where, "the parameters of " + knownDefect.getDefectType() + " can't be decoded: " + e.getLocalizedMessage());
				writeParameters(sw, knownDefect.getParameters());
			}
			if (knownDefect.getDescription() != null) sw.write("\tDescription: " + knownDefect.getDescription() + "\n");
		}
	}

	private void writeKnownDefect(StringWriter sw, KnownDefect knownDefect, boolean showDetails, List<String> violations, String where) {
		ASN1ObjectIdentifier type = knownDefect.getDefectType();
		ASN1Encodable parameters = knownDefect.getParameters();
		String oid = " (OID: " + type + ")";

		// Authentication defects (8.3.1)
		if (type.equals(BSIObjectIdentifiers.certRevoked)) {
			sw.write("+ Authentication defect: signer certificate revoked" + oid + "\n");
			if (required(sw, violations, where, type, parameters)) sw.write("\t" + enumerated(parameters, REVOCATION_STATUS, true) + "\n");
		} else if (type.equals(BSIObjectIdentifiers.certReplaced)) {
			sw.write("+ Authentication defect: signer certificate malformed, replacement certificate provided" + oid + "\n");
			if (required(sw, violations, where, type, parameters)) writeReplacementCertificate(sw, ASN1OctetString.getInstance(parameters).getOctets(), showDetails);
		} else if (type.equals(BSIObjectIdentifiers.certChipAuthKeyRevoked)) {
			sw.write("+ Authentication defect: Chip Authentication private keys compromised" + oid + "\n");
			writeParameters(sw, parameters);
		} else if (type.equals(BSIObjectIdentifiers.certActiveAuthKeyRevoked)) {
			sw.write("+ Authentication defect: Active Authentication private keys compromised" + oid + "\n");
			writeParameters(sw, parameters);
		} else if (type.equals(BSIObjectIdentifiers.AuthenticationProtocolFailure)) {
			sw.write("+ Authentication defect: authentication protocol failure" + oid + "\n");
			if (required(sw, violations, where, type, parameters)) sw.write("\t" + enumerated(parameters, PROTOCOL_FAILURE, false) + "\n");
		} else if (type.equals(BSIObjectIdentifiers.ValidityPeriodIncorrect)) {
			sw.write("+ Authentication defect: validity period incorrect" + oid + "\n");
			if (required(sw, violations, where, type, parameters)) sw.write("\t" + enumerated(parameters, VALIDITY_PERIOD, false) + "\n");

		// Application defects of the ePassport application (8.3.2)
		} else if (type.equals(BSIObjectIdentifiers.ePassportDGMalformed)) {
			sw.write("+ ePassport defect: data group malformed" + oid + "\n");
			if (required(sw, violations, where, type, parameters)) sw.write("\tData groups: " + integers(parameters) + "\n");
		} else if (type.equals(BSIObjectIdentifiers.SODInvalid)) {
			sw.write("+ ePassport defect: Document Security Object malformed" + oid + "\n");
			if (parameters != null) sw.write("\t" + enumerated(parameters, SOD_FAULT, true) + "\n");
		} else if (type.equals(BSIObjectIdentifiers.COMSODDiscrepancy)) {
			sw.write("+ ePassport defect: COM and SOD discrepancy" + oid + "\n");
			if (parameters != null) {
				ASN1Sequence discrepancy = ASN1Sequence.getInstance(parameters);
				sw.write("\tData groups listed in EF.COM: " + integers(discrepancy.getObjectAt(0)) + "\n");
				sw.write("\tData groups listed in EF.SOD: " + integers(discrepancy.getObjectAt(1)) + "\n");
			} else {
				sw.write("\tgeneric discrepancy\n");
			}
		} else if (type.equals(BSIObjectIdentifiers.sodWrongSignerIdentifier)) {
			sw.write("+ ePassport defect: wrong signer identifier" + oid + "\n");
			if (required(sw, violations, where, type, parameters)) sw.write("\tCorrected signer identifier: " + signerIdentifier(SignerIdentifier.getInstance(parameters)) + "\n");
		} else if (type.equals(BSIObjectIdentifiers.IssuingCountryDefect)) {
			sw.write("+ ePassport defect: issuing country defect (DEPRECATED, use Distinguished Name Defect)" + oid + "\n");
			if (required(sw, violations, where, type, parameters)) sw.write("\tCorrected issuing country: " + ASN1PrintableString.getInstance(parameters).getString() + "\n");
		} else if (type.equals(BSIObjectIdentifiers.DistinguishedNameDefect)) {
			sw.write("+ ePassport defect: distinguished name defect" + oid + "\n");
			if (required(sw, violations, where, type, parameters)) writeDistinguishedNameDefect(sw, ASN1Set.getInstance(parameters));

		// Application defects of the eID application (BSI TR-03129-3)
		} else if (type.equals(BSIObjectIdentifiers.eIDDGMalformed)) {
			sw.write("+ eID defect: data group malformed" + oid + "\n");
			if (parameters != null) sw.write("\tData groups: " + integers(parameters) + "\n");
		} else if (type.equals(BSIObjectIdentifiers.eIDIntegrity)) {
			sw.write("+ eID defect: application integrity uncertain" + oid + "\n");
			writeParameters(sw, parameters);
		} else if (type.equals(BSIObjectIdentifiers.eIDSecurityInfoMissing)) {
			sw.write("+ eID defect: SecurityInfo missing" + oid + "\n");
			writeParameters(sw, parameters);
		} else if (type.equals(BSIObjectIdentifiers.eIDDGMissing)) {
			sw.write("+ eID defect: data group missing" + oid + "\n");
			if (parameters != null) sw.write("\tData groups: " + integers(parameters) + "\n");

		// General document defects (8.3.3)
		} else if (type.equals(BSIObjectIdentifiers.CardSecurityMalformed)) {
			sw.write("+ Document defect: Card Security Object malformed, corrected one provided" + oid + "\n");
			if (required(sw, violations, where, type, parameters)) {
				sw.write("\tCorrected Card Security Object: " + encodedLength(parameters) + " bytes\n");
				if (showDetails) sw.write(dump(parameters));
			}
		} else if (type.equals(BSIObjectIdentifiers.ChipSecurityMalformed)) {
			sw.write("+ Document defect: Chip Security Object malformed, use the Card Security Object" + oid + "\n");
			writeParameters(sw, parameters);
		} else if (type.equals(BSIObjectIdentifiers.PowerDownReq)) {
			sw.write("+ Document defect: power down required between two authentications" + oid + "\n");
			writeParameters(sw, parameters);
		} else if (type.equals(BSIObjectIdentifiers.DSMalformed)) {
			sw.write("+ Document defect: Document Signer certificate malformed (DEPRECATED, use Certificate malformed)" + oid + "\n");
			if (required(sw, violations, where, type, parameters)) sw.write("\t" + enumerated(parameters, MALFORMED_STATUS, true) + "\n");
		} else if (type.equals(BSIObjectIdentifiers.EAC2PrivilegedTerminalInfoMissing)) {
			sw.write("+ Document defect: EAC2 PrivilegedTerminalInfo missing" + oid + "\n");
			writeParameters(sw, parameters);
		} else if (type.equals(BSIObjectIdentifiers.CertificateMalformed)) {
			sw.write("+ Document defect: certificate incorrectly encoded or malformed" + oid + "\n");
			if (required(sw, violations, where, type, parameters)) {
				ASN1Sequence information = ASN1Sequence.getInstance(parameters);
				sw.write("\t" + enumerated(information.getObjectAt(0), MALFORMED_STATUS, true) + "\n");
				sw.write("\tCertificate type: " + enumerated(information.getObjectAt(1), MALFORMED_CERTIFICATE_TYPE, false) + "\n");
			}
		} else {
			sw.write("! Unknown defect type, not defined in BSI TR-03129-2, 8.3" + oid + "\n");
			if (type.on(BSIObjectIdentifiers.DocumentDefect)) {
				sw.write("\tNote: for a general document defect with unknown interpretation the electronic part of the document "
						+ "SHOULD NOT be used for document checks (BSI TR-03129-2, 8.3.3).\n");
			}
			writeParameters(sw, parameters);
		}
	}

	/** Reports missing parameters that MUST be present (BSI TR-03129-2, 8.3). */
	private static boolean required(StringWriter sw, List<String> violations, String where, ASN1ObjectIdentifier type, ASN1Encodable parameters) {
		if (parameters != null) return true;
		fail(sw, violations, where, "the parameter of " + type + " MUST be present (BSI TR-03129-2, 8.3)");
		return false;
	}

	private static void fail(StringWriter sw, List<String> violations, String where, String text) {
		sw.write("\t! " + text + "\n");
		violations.add(where + ": " + text + "!");
	}

	private static void writeReplacementCertificate(StringWriter sw, byte[] encoded, boolean showDetails) {
		try {
			X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(encoded));
			sw.write("\tReplacement certificate: Subject DN: " + cert.getSubjectDN() + "; Issuer DN: "
					+ cert.getIssuerDN() + "; Serial No.: " + cert.getSerialNumber() + "\n");
			if (showDetails) sw.write(cert.toString() + "\n");
		} catch (Exception e) {
			sw.write("\tReplacement certificate can't be parsed: " + e.getLocalizedMessage() + "\n\t" + HexString.bufferToHex(encoded, true) + "\n");
		}
	}

	private static void writeDistinguishedNameDefect(StringWriter sw, ASN1Set erroneousParts) {
		for (int i = 0; i < erroneousParts.size(); i++) {
			ASN1Sequence part = ASN1Sequence.getInstance(erroneousParts.getObjectAt(i));
			ASN1ObjectIdentifier attributeType = ASN1ObjectIdentifier.getInstance(part.getObjectAt(1));
			String name = BCStyle.INSTANCE.oidToDisplayName(attributeType);
			sw.write("\t" + enumerated(part.getObjectAt(0), DN_DEFECT_TYPE, false) + ", attribute " + attributeType
					+ (name != null ? " (" + name + ")" : "") + "\n");
			boolean incorrectValue = false;
			for (int j = 2; j < part.size(); j++) {
				ASN1TaggedObject value = ASN1TaggedObject.getInstance(part.getObjectAt(j));
				if (value.getTagNo() == 0) incorrectValue = true;
				sw.write("\t\t" + (value.getTagNo() == 0 ? "incorrect value: " : "corrected value: ") + attributeValue(value.getExplicitBaseObject()) + "\n");
			}
			if (!incorrectValue) sw.write("\t\tthe value is missing\n");
		}
	}

	private static String attributeValue(ASN1Encodable value) {
		if (value instanceof ASN1String) return ((ASN1String) value).getString();
		return value.toString();
	}

	/** @return the value of an ENUMERATED with its name; codes >= 32 are proprietary if the type allows them */
	private static String enumerated(ASN1Encodable parameter, String[] names, boolean proprietary) {
		int value = ASN1Enumerated.getInstance(parameter).getValue().intValue();
		String name;
		if (value >= 0 && value < names.length) name = names[value];
		else if (proprietary && value >= 32) name = "proprietary";
		else name = "unknown (RFU)";
		return "status code " + value + ": " + name;
	}

	/** @return the elements of a SET OF INTEGER, separated by blanks */
	private static String integers(ASN1Encodable parameter) {
		ASN1Set set = ASN1Set.getInstance(parameter);
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < set.size(); i++) {
			sb.append(i > 0 ? " " : "").append(ASN1Integer.getInstance(set.getObjectAt(i)).getValue());
		}
		return sb.toString();
	}

	private static String signerIdentifier(SignerIdentifier signerIdentifier) {
		if (signerIdentifier.isTagged()) return "Subject Key Identifier: " + hex(ASN1OctetString.getInstance(signerIdentifier.getId()));
		return issuerAndSerialNumber(IssuerAndSerialNumber.getInstance(signerIdentifier.getId()));
	}

	private static String issuerAndSerialNumber(IssuerAndSerialNumber iasn) {
		return "Issuer: " + iasn.getName() + "; Serial No.: " + iasn.getSerialNumber();
	}

	private static String hex(ASN1OctetString octets) {
		return HexString.bufferToHex(octets.getOctets());
	}

	private static int encodedLength(ASN1Encodable obj) {
		try {
			return obj.toASN1Primitive().getEncoded().length;
		} catch (IOException e) {
			return -1;
		}
	}

	/** Shows the ASN.1 structure of parameters that are not decoded. */
	private static void writeParameters(StringWriter sw, ASN1Encodable parameters) {
		if (parameters != null) sw.write("\tparameters:\n" + dump(parameters));
	}

	private static String dump(ASN1Encodable obj) {
		return ASN1Dump.dumpAsString(obj, true).replaceAll("(?m)^", "\t\t");
	}
}
