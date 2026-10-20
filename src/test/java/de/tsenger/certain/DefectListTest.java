package de.tsenger.certain;

import static de.tsenger.certain.TestSignedData.SERIAL;
import static de.tsenger.certain.TestSignedData.SIGNER;
import static de.tsenger.certain.TestSignedData.certificate;
import static de.tsenger.certain.TestSignedData.keyPair;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Test;

import de.tsenger.certain.asn1.eac.BSIObjectIdentifiers;

/**
 * Shows and checks defect lists of the versions 1 to 3 (BSI TR-03129-2, chapter 8), created by the test.
 */
public class DefectListTest {

	private static final int V1 = 0, V2 = 1, V3 = 2;

	@Test
	public void revokedDefectShowsOnlyItsStatusCode() throws Exception {
		DListParser parser = parser(V1, v1Defect(knownDefect(BSIObjectIdentifiers.certRevoked, new ASN1Enumerated(1))));
		String output = parser.getDListInfoString(false);

		assertTrue(output, output.contains("status code 1: onHold"));
		assertFalse(output, output.contains("status code 2"));
		assertEquals(CheckResult.Status.VALID, parser.check().getStatus());
	}

	@Test
	public void replacementCertificateIsShown() throws Exception {
		X509CertificateHolder replacement = certificate(keyPair());
		String output = output(V1, v1Defect(knownDefect(BSIObjectIdentifiers.certReplaced, new DEROctetString(replacement.getEncoded()))));

		assertTrue(output, output.contains("Replacement certificate: Subject DN: C=DE,O=Test,OU=Lists,CN=List Signer"));
	}

	@Test
	public void signerIdentifierWithSubjectKeyIdentifierIsShown() throws Exception {
		ASN1Encodable defect = new DERSequence(new ASN1Encodable[] {
				new DERTaggedObject(false, 0, new DEROctetString(new byte[] { 0x01, 0x02, 0x03 })),
				new DERSet(knownDefect(BSIObjectIdentifiers.PowerDownReq, null)) });

		String output = output(V1, defect);

		assertTrue(output, output.contains("Signer identifier: Subject Key Identifier: 010203"));
	}

	@Test
	public void missingRequiredParameterFails() throws Exception {
		DListParser parser = parser(V1, v1Defect(knownDefect(BSIObjectIdentifiers.ValidityPeriodIncorrect, null)));

		CheckResult result = parser.check();

		assertEquals(CheckResult.Status.INVALID, result.getStatus());
		assertTrue(result.getText(), result.getText().contains("MUST be present"));
	}

	@Test
	public void version3WithSignerCertificateReferenceIsShown() throws Exception {
		for (boolean explicit : new boolean[] { true, false }) {
			ASN1Encodable reference = new DERSequence(new ASN1Encodable[] {
					new DERTaggedObject(explicit, 0, new IssuerAndSerialNumber(SIGNER, SERIAL)),
					new DERTaggedObject(explicit, 1, new DEROctetString(new byte[] { 0x0a })),
					new DERTaggedObject(explicit, 2, new DERUTF8String("DS-4711")),
					new DERTaggedObject(explicit, 3, new DEROctetString(new byte[] { 0x0b })) });
			ASN1Encodable knownDefect = knownDefectV2(BSIObjectIdentifiers.ValidityPeriodIncorrect, new ASN1Enumerated(1), "too long", explicit);
			DListParser parser = parser(V3, new DERSequence(new ASN1Encodable[] { reference, new DERSet(knownDefect), new DERUTF8String("test defect") }));
			String output = parser.getDListInfoString(false);

			assertTrue(output, output.contains("Defect List version: v3"));
			assertTrue(output, output.contains("Signer certificate reference:"));
			assertTrue(output, output.contains("Issuer: C=DE,O=Test,OU=Lists,CN=List Signer; Serial No.: 4711"));
			assertTrue(output, output.contains("Subject Key Identifier: 0a"));
			assertTrue(output, output.contains("Signer reference: DS-4711"));
			assertTrue(output, output.contains("Certificate hash: 0b"));
			assertTrue(output, output.contains("status code 1: DS_validity"));
			assertTrue(output, output.contains("Description: too long"));
			assertTrue(output, output.contains("Description: test defect"));
			assertEquals(parser.check().getText(), CheckResult.Status.VALID, parser.check().getStatus());
		}
	}

	@Test
	public void version3WithCaCertificateReferenceIsShown() throws Exception {
		for (boolean explicit : new boolean[] { true, false }) {
			ASN1Encodable reference = new DERSequence(new ASN1Encodable[] { new DERTaggedObject(explicit, 0, SIGNER),
					new DERTaggedObject(explicit, 1, new AuthorityKeyIdentifier(new byte[] { 0x0c })) });
			ASN1Encodable knownDefect = knownDefectV2(BSIObjectIdentifiers.PowerDownReq, null, null, explicit);
			DListParser parser = parser(V3, new DERSequence(new ASN1Encodable[] { reference, new DERSet(knownDefect) }));
			String output = parser.getDListInfoString(false);

			assertTrue(output, output.contains("CA certificate reference:"));
			assertTrue(output, output.contains("Issuer: C=DE,O=Test,OU=Lists,CN=List Signer"));
			assertTrue(output, output.contains("Authority Key Identifier: 0c"));
			assertEquals(parser.check().getText(), CheckResult.Status.VALID, parser.check().getStatus());
		}
	}

	@Test
	public void version3WithSignerIdentifierFails() throws Exception {
		ASN1Encodable defect = new DERSequence(new ASN1Encodable[] { new IssuerAndSerialNumber(SIGNER, SERIAL),
				new DERSet(knownDefectV2(BSIObjectIdentifiers.PowerDownReq, null, null, false)) });

		CheckResult result = parser(V3, defect).check();

		assertEquals(CheckResult.Status.INVALID, result.getStatus());
		assertTrue(result.getText(), result.getText().contains("signerIdentifier MUST NOT be present in version 3"));
		assertTrue(result.getText(), result.getText().contains("signercertificateReference or caCertificateReference MUST be present"));
	}

	@Test
	public void version1KnownDefectInVersion2Fails() throws Exception {
		CheckResult result = parser(V2, v1Defect(knownDefect(BSIObjectIdentifiers.PowerDownReq, null))).check();

		assertEquals(CheckResult.Status.INVALID, result.getStatus());
		assertTrue(result.getText(), result.getText().contains("knownDefectV2 (not knownDefect) is used in version 2 and 3"));
	}

	@Test
	public void distinguishedNameDefectIsShown() throws Exception {
		ASN1Encodable part = new DERSequence(new ASN1Encodable[] { new ASN1Enumerated(0), BCStyle.C,
				new DERTaggedObject(true, 0, new DERPrintableString("DEU")), new DERTaggedObject(true, 1, new DERPrintableString("DE")) });
		String output = output(V2, v1Defect(knownDefectV2(BSIObjectIdentifiers.DistinguishedNameDefect, new DERSet(part), null, false)));

		assertTrue(output, output.contains("status code 0: Issuer, attribute 2.5.4.6 (C)"));
		assertTrue(output, output.contains("incorrect value: DEU"));
		assertTrue(output, output.contains("corrected value: DE"));
	}

	@Test
	public void unknownDocumentDefectIsNamed() throws Exception {
		ASN1ObjectIdentifier unknown = BSIObjectIdentifiers.DocumentDefect.branch("99");
		String output = output(V1, v1Defect(knownDefect(unknown, new ASN1Integer(7))));

		assertTrue(output, output.contains("Unknown defect type"));
		assertTrue(output, output.contains("SHOULD NOT be used for document checks"));
		assertTrue(output, output.contains("Integer(7)"));
	}

	@Test
	public void unknownAuthenticationDefectIsNamed() throws Exception {
		String output = output(V1, v1Defect(knownDefect(BSIObjectIdentifiers.AuthDefect.branch("99"), null)));

		assertTrue(output, output.contains("electronic part of the document MUST NOT be used (BSI TR-03129-3, A.2.1)"));
	}

	/** Version 1 defect that refers to the signer certificate by issuerAndSerialNumber. */
	private static ASN1Encodable v1Defect(ASN1Encodable knownDefect) {
		return new DERSequence(new ASN1Encodable[] { new IssuerAndSerialNumber(SIGNER, SERIAL), new DERSet(knownDefect) });
	}

	private static ASN1Encodable knownDefect(ASN1ObjectIdentifier type, ASN1Encodable parameters) {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(type);
		if (parameters != null) v.add(parameters);
		return new DERSequence(v);
	}

	/** KnownDefectV2 tagged with [0]; the tagging of [0] and the description [1] is explicit or implicit. */
	private static ASN1Encodable knownDefectV2(ASN1ObjectIdentifier type, ASN1Encodable parameters, String description, boolean explicit) {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(type);
		if (parameters != null) v.add(new DERTaggedObject(true, 0, parameters));
		if (description != null) v.add(new DERTaggedObject(explicit, 1, new DERUTF8String(description)));
		return new DERTaggedObject(explicit, 0, new DERSequence(v));
	}

	private static String output(int version, ASN1Encodable defect) throws Exception {
		return parser(version, defect).getDListInfoString(false);
	}

	private static DListParser parser(int version, ASN1Encodable defect) throws Exception {
		byte[] list = new DERSequence(new ASN1Encodable[] { new ASN1Integer(version), new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
				new DERSet(defect) }).getEncoded();
		KeyPair keyPair = keyPair();
		return new SignedDataParser(TestSignedData.sign(BSIObjectIdentifiers.DefectList, list, keyPair, certificate(keyPair), false)).getDListParser();
	}
}
