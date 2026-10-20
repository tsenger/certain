package de.tsenger.certain;

import static de.tsenger.certain.TestSignedData.certificate;
import static de.tsenger.certain.TestSignedData.keyPair;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Test;

import de.tsenger.certain.asn1.icao.ICAOObjectIdentifiers;

/**
 * Parses and checks ICAO deviation lists (ICAO Doc 9303 Part 3, 7 and Part 12, 10) wrapped in CMS SignedData.
 */
public class DeviationListTest {

	private static final AlgorithmIdentifier SHA256 = new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"));
	private static final ExtendedKeyUsage DEVIATION_LIST_SIGNER = new ExtendedKeyUsage(
			KeyPurposeId.getInstance(ICAOObjectIdentifiers.id_icao_DeviationListSigningKey));

	@Test
	public void signedDeviationListCanBeParsed() throws Exception {
		SignedDataParser parser = new SignedDataParser(TestData.read("deviation-lists/cms/all_deviations.bin"));

		DListParser deviationList = parser.getDListParser();

		assertNotNull(deviationList);
		assertFalse(deviationList.getDListInfoString(false).isEmpty());
	}

	@Test
	public void allDocumentFieldsAreShown() throws Exception {
		ASN1Encodable documents = new DERSequence(new ASN1Encodable[] {
				new DERTaggedObject(false, 0, new DERPrintableString("P")),
				new DERTaggedObject(false, 3, new DEROctetString(new byte[] { 0x0a, 0x0b })),
				new DERTaggedObject(false, 4, new DERSequence(new ASN1Encodable[] {
						new DERGeneralizedTime("20110121050000Z"), new DERGeneralizedTime("20110910040000Z") })),
				new DERTaggedObject(false, 5, new DERSet(new DERPrintableString("C01X00T47"))) });

		String output = output(deviationList(SHA256, documents, description(ICAOObjectIdentifiers.id_Deviation_Chip, null)));

		assertTrue(output, output.contains("Document Type: P"));
		assertTrue(output, output.contains("Certificate digest (2.16.840.1.101.3.4.2.1): 0a0b"));
		assertTrue(output, output.contains("first issued: 20110121050000"));
		assertTrue(output, output.contains("C01X00T47"));
	}

	@Test
	public void chipDeviationIsNamed() throws Exception {
		String output = output(deviationList(SHA256, new DERSequence(), description(ICAOObjectIdentifiers.id_Deviation_Chip, null)));

		assertTrue(output, output.contains("Chip is not usable (OID: 2.23.136.1.1.7.4)"));
	}

	@Test
	public void unknownDeviationTypeIsShownWithItsParameters() throws Exception {
		ASN1Encodable description = description(new ASN1ObjectIdentifier("2.23.136.1.1.7.2.6"), new ASN1Integer(5));

		String output = output(deviationList(SHA256, new DERSequence(), description));

		assertTrue(output, output.contains("Unknown deviation type"));
		assertTrue(output, output.contains("2.23.136.1.1.7.2.6"));
		assertTrue(output, output.contains("Integer(5)"));
	}

	@Test
	public void certificateDigestWithoutDigestAlgorithmFails() throws Exception {
		ASN1Encodable documents = new DERSequence(new DERTaggedObject(false, 3, new DEROctetString(new byte[] { 0x0a })));
		DListParser parser = parser(deviationList(null, documents, description(ICAOObjectIdentifiers.id_Deviation_Chip, null)));

		assertTrue(parser.getDListInfoString(false), parser.getDListInfoString(false).contains("digestAlgorithm missing"));
		assertEquals(CheckResult.Status.INVALID, parser.check().getStatus());
	}

	@Test
	public void deviationListSignerWithoutExtendedKeyUsageFails() throws Exception {
		KeyPair keyPair = keyPair();
		byte[] signedData = sign(validDeviationList(), keyPair, certificate(keyPair));

		CheckResult result = new SignedDataParser(signedData).checkSignedData();

		assertEquals(CheckResult.Status.INVALID, result.getStatus());
		assertTrue(result.getText(), result.getText().contains("MUST contain 2.23.136.1.1.8 but is missing"));
	}

	@Test
	public void deviationListSignedByCaFails() throws Exception {
		KeyPair keyPair = keyPair();
		X509CertificateHolder ca = certificate(keyPair, Extension.extendedKeyUsage, DEVIATION_LIST_SIGNER,
				Extension.basicConstraints, new BasicConstraints(true));

		CheckResult result = new SignedDataParser(sign(validDeviationList(), keyPair, ca)).checkSignedData();

		assertEquals(CheckResult.Status.INVALID, result.getStatus());
		assertTrue(result.getText(), result.getText().contains("MUST NOT be signed directly by a CSCA (ICAO Doc 9303 Part 3, 7.3.2)"));
	}

	@Test
	public void profileOfValidDeviationListIsAccepted() throws Exception {
		KeyPair keyPair = keyPair();
		X509CertificateHolder signer = certificate(keyPair, Extension.extendedKeyUsage, DEVIATION_LIST_SIGNER);

		CheckResult result = new SignedDataParser(sign(validDeviationList(), keyPair, signer)).checkSignedData();

		assertFalse(result.getText(), result.getText().contains("MUST"));
		assertTrue(result.getText(), result.getText().contains("eContentType: 2.23.136.1.1.7 (ICAO Deviation List)"));
		assertTrue(result.getText(), result.getText().contains("signingTime:"));
		assertTrue(result.getText(), result.getText().contains("Signature of SignedData object is VALID"));
	}

	private static byte[] validDeviationList() throws Exception {
		return deviationList(SHA256, new DERSequence(), description(ICAOObjectIdentifiers.id_Deviation_Chip, null));
	}

	/** DeviationDescription without description text, with the parameters if they are not null. */
	private static ASN1Encodable description(ASN1ObjectIdentifier type, ASN1Encodable parameters) {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(type);
		if (parameters != null) v.add(new DERTaggedObject(true, 0, parameters));
		return new DERSequence(v);
	}

	/** DeviationList with one deviation; the digest algorithm is left out if it is null. */
	private static byte[] deviationList(AlgorithmIdentifier digestAlgorithm, ASN1Encodable documents, ASN1Encodable description) throws Exception {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(new ASN1Integer(0));
		if (digestAlgorithm != null) v.add(digestAlgorithm);
		v.add(new DERSet(new DERSequence(new ASN1Encodable[] { documents, new DERSet(description) })));
		return new DERSequence(v).getEncoded();
	}

	private static DListParser parser(byte[] deviationList) throws Exception {
		KeyPair keyPair = keyPair();
		return new SignedDataParser(sign(deviationList, keyPair, certificate(keyPair))).getDListParser();
	}

	private static String output(byte[] deviationList) throws Exception {
		return parser(deviationList).getDListInfoString(false);
	}

	private static byte[] sign(byte[] deviationList, KeyPair keyPair, X509CertificateHolder cert) throws Exception {
		return TestSignedData.sign(ICAOObjectIdentifiers.id_icao_DeviationList, deviationList, keyPair, cert, true);
	}
}
