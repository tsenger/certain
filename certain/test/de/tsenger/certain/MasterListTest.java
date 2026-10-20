package de.tsenger.certain;

import static de.tsenger.certain.TestSignedData.certificate;
import static de.tsenger.certain.TestSignedData.keyPair;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Test;

import de.tsenger.certain.asn1.icao.ICAOObjectIdentifiers;

/**
 * Parses and checks CSCA Master Lists (ICAO Doc 9303 Part 12, 9): the German master list {@code master-lists/de.ml}
 * (2026-10-01) and master lists created by the test.
 */
public class MasterListTest {

	private static SignedDataParser parseGermanMasterList() throws Exception {
		return new SignedDataParser(TestData.read("master-lists/de.ml"));
	}

	@Test
	public void containsExpectedNumberOfCertificates() throws Exception {
		SignedDataParser parser = parseGermanMasterList();

		assertEquals(609, ((CertificateListParser) parser.getDListParser()).getCertificates().size());
		assertEquals(2, parser.getDListSignerCertificates().size());
	}

	@Test
	public void signerCertificateIsIssuedByGermanCsca() throws Exception {
		X509Certificate signer = (X509Certificate) parseGermanMasterList().getDListSignerCertificates().get(0);

		assertEquals("C=DE,O=bund,OU=bsi,SERIALNUMBER=0039,CN=CSCA Master List Signer", signer.getSubjectDN().toString());
		assertEquals("C=DE,O=bund,OU=bsi,CN=csca-germany", signer.getIssuerDN().toString());
	}

	@Test
	public void germanMasterListIsValid() throws Exception {
		SignedDataParser parser = parseGermanMasterList();

		CheckResult result = parser.checkSignedData();

		assertEquals(result.getText(), CheckResult.Status.VALID, result.getStatus());
		assertEquals(CheckResult.Status.VALID, parser.getDListParser().check().getStatus());
	}

	@Test
	public void infoStringListsAllCertificates() throws Exception {
		String info = parseGermanMasterList().getDListParser().getDListInfoString(false);

		assertTrue(info.contains("This ICAO CSCA Master List contains 609 certificates."));
		assertTrue(info.contains("Certificate no. 609"));
	}

	@Test
	public void masterListSignerWithoutExtendedKeyUsageFails() throws Exception {
		KeyPair keyPair = keyPair();
		CheckResult result = new SignedDataParser(masterList(0, keyPair, certificate(keyPair))).checkSignedData();

		assertEquals(CheckResult.Status.INVALID, result.getStatus());
		assertTrue(result.getText(), result.getText().contains("MUST contain 2.23.136.1.1.3 but is missing"));
	}

	@Test
	public void masterListWithSignerExtendedKeyUsageIsAccepted() throws Exception {
		KeyPair keyPair = keyPair();
		X509CertificateHolder signer = certificate(keyPair, Extension.extendedKeyUsage,
				new ExtendedKeyUsage(KeyPurposeId.getInstance(ICAOObjectIdentifiers.id_icao_cscaMasterListSigningKey)));
		SignedDataParser parser = new SignedDataParser(masterList(0, keyPair, signer));

		CheckResult result = parser.checkSignedData();

		assertFalse(result.getText(), result.getText().contains("MUST"));
		assertEquals(result.getText(), CheckResult.Status.VALID, result.getStatus());
		assertEquals(1, ((CertificateListParser) parser.getDListParser()).getCertificates().size());
	}

	@Test
	public void wrongMasterListVersionFails() throws Exception {
		KeyPair keyPair = keyPair();
		CheckResult result = new SignedDataParser(masterList(1, keyPair, certificate(keyPair))).getDListParser().check();

		assertEquals(CheckResult.Status.INVALID, result.getStatus());
		assertTrue(result.getText(), result.getText().contains("version MUST be v0 but is v1"));
	}

	/** Master list with the signer certificate as only CSCA certificate. */
	private static byte[] masterList(int version, KeyPair keyPair, X509CertificateHolder signer) throws Exception {
		byte[] list = new DERSequence(new ASN1Encodable[] { new ASN1Integer(version), new DERSet(signer.toASN1Structure()) }).getEncoded();
		return TestSignedData.sign(ICAOObjectIdentifiers.id_icao_cscaMasterList, list, keyPair, signer, true);
	}
}
