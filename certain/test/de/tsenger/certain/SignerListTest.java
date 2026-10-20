package de.tsenger.certain;

import static de.tsenger.certain.TestSignedData.HOUR;
import static de.tsenger.certain.TestSignedData.certificate;
import static de.tsenger.certain.TestSignedData.keyPair;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Test;

import de.tsenger.certain.asn1.eac.BSIObjectIdentifiers;

/**
 * Checks signer lists (BSI TR-03129-2, 9) and the defect list signer (8.2) with lists created by the test.
 */
public class SignerListTest {

	private static final ExtendedKeyUsage DOCUMENT_SIGNER_LIST_SIGNER = new ExtendedKeyUsage(
			KeyPurposeId.getInstance(BSIObjectIdentifiers.documentSignerListSigningKey));

	@Test
	public void documentSignerListIsAccepted() throws Exception {
		CheckResult result = check(DOCUMENT_SIGNER_LIST_SIGNER, privateKeyUsagePeriod(-HOUR / 2, 12 * HOUR));

		assertEquals(result.getText(), CheckResult.Status.VALID, result.getStatus());
		assertTrue(result.getText(), result.getText().contains("BSI Document Signer List"));
		assertTrue(result.getText(), result.getText().contains("Private key usage period of the Signer List Signer"));
	}

	@Test
	public void wrongExtendedKeyUsageFails() throws Exception {
		ExtendedKeyUsage healthSealSigner = new ExtendedKeyUsage(KeyPurposeId.getInstance(BSIObjectIdentifiers.euHealthSealSignerListSigningKey));
		CheckResult result = check(healthSealSigner, privateKeyUsagePeriod(-HOUR / 2, 12 * HOUR));

		assertEquals(CheckResult.Status.INVALID, result.getStatus());
		assertTrue(result.getText(), result.getText().contains("SHALL contain 0.4.0.127.0.7.3.11.1.4.2"));
	}

	@Test
	public void missingPrivateKeyUsagePeriodFails() throws Exception {
		CheckResult result = check(DOCUMENT_SIGNER_LIST_SIGNER, null);

		assertEquals(CheckResult.Status.INVALID, result.getStatus());
		assertTrue(result.getText(), result.getText().contains("SHALL include the private key usage period extension"));
	}

	@Test
	public void signingTimeOutsidePrivateKeyUsagePeriodFails() throws Exception {
		CheckResult result = check(DOCUMENT_SIGNER_LIST_SIGNER, privateKeyUsagePeriod(2 * HOUR, 12 * HOUR));

		assertEquals(CheckResult.Status.INVALID, result.getStatus());
		assertTrue(result.getText(), result.getText().contains("signing time SHALL be within the private key usage period"));
	}

	@Test
	public void privateKeyUsagePeriodOutsideValidityFails() throws Exception {
		CheckResult result = check(DOCUMENT_SIGNER_LIST_SIGNER, privateKeyUsagePeriod(-HOUR / 2, 48 * HOUR));

		assertEquals(CheckResult.Status.INVALID, result.getStatus());
		assertTrue(result.getText(), result.getText().contains("SHALL be within the validity period"));
	}

	@Test
	public void defectListSignerWithoutExtendedKeyUsageIsNoted() throws Exception {
		KeyPair keyPair = keyPair();
		byte[] list = new DERSequence(new ASN1Encodable[] { new ASN1Integer(0), BSIObjectIdentifiers.DefectList, new DERSet() }).getEncoded();

		CheckResult result = new SignedDataParser(TestSignedData.sign(BSIObjectIdentifiers.DefectList, list, keyPair, certificate(keyPair), true))
				.checkSignedData();

		assertEquals(CheckResult.Status.VALID, result.getStatus());
		assertTrue(result.getText(), result.getText().contains("Note: the extended key usage of the DFL Signer certificate SHOULD contain 0.4.0.127.0.7.3.11.2.1.2"));
	}

	/** Checks a document signer list signed by a certificate with these extensions. */
	private static CheckResult check(ExtendedKeyUsage eku, ASN1Encodable privateKeyUsagePeriod) throws Exception {
		KeyPair keyPair = keyPair();
		X509CertificateHolder signer = privateKeyUsagePeriod == null ? certificate(keyPair, Extension.extendedKeyUsage, eku)
				: certificate(keyPair, Extension.extendedKeyUsage, eku, Extension.privateKeyUsagePeriod, privateKeyUsagePeriod);
		byte[] list = new DERSequence(new ASN1Encodable[] { new ASN1Integer(0), new DERSet(signer.toASN1Structure()) }).getEncoded();
		return new SignedDataParser(TestSignedData.sign(BSIObjectIdentifiers.DocumentSignerList, list, keyPair, signer, true)).checkSignedData();
	}

	/** PrivateKeyUsagePeriod relative to now, in milliseconds. */
	private static ASN1Encodable privateKeyUsagePeriod(long notBefore, long notAfter) {
		long now = System.currentTimeMillis();
		return new DERSequence(new ASN1Encodable[] { new DERTaggedObject(false, 0, new DERGeneralizedTime(new Date(now + notBefore))),
				new DERTaggedObject(false, 1, new DERGeneralizedTime(new Date(now + notAfter))) });
	}
}
