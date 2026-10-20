package de.tsenger.certain;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.eac.CertificateHolderAuthorization;
import org.bouncycastle.asn1.eac.ECDSAPublicKey;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.junit.Ignore;
import org.junit.Test;

import de.tsenger.certain.CheckResult.Status;
import de.tsenger.certain.asn1.eac.CVCertificate;
import de.tsenger.certain.asn1.eac.CVCertificateRequest;

/**
 * Checks of {@link CvChecker} with certificates and requests created by {@link TestCertificates}.
 */
public class CvCheckerTest {

	private static Status innerSignatureWithGuessedCurve(String curve, ASN1ObjectIdentifier algorithm) throws Exception {
		return new CvChecker(new CertStorage())
				.checkInnerSignature(TestCertificates.ecRequestWithoutDomainParameters(algorithm, curve)).getStatus();
	}

	@Test
	public void guessesBrainpoolCurve() throws Exception {
		assertEquals(Status.VALID, innerSignatureWithGuessedCurve("brainpoolP256r1", EACObjectIdentifiers.id_TA_ECDSA_SHA_256));
		assertEquals(Status.VALID, innerSignatureWithGuessedCurve("brainpoolP384r1", EACObjectIdentifiers.id_TA_ECDSA_SHA_384));
		assertEquals(Status.VALID, innerSignatureWithGuessedCurve("brainpoolP512r1", EACObjectIdentifiers.id_TA_ECDSA_SHA_512));
	}

	@Test
	public void guessesNistCurveAfterBrainpool() throws Exception {
		assertEquals(Status.VALID, innerSignatureWithGuessedCurve("secp224r1", EACObjectIdentifiers.id_TA_ECDSA_SHA_224));
		assertEquals(Status.VALID, innerSignatureWithGuessedCurve("secp256r1", EACObjectIdentifiers.id_TA_ECDSA_SHA_256));
		assertEquals(Status.VALID, innerSignatureWithGuessedCurve("secp384r1", EACObjectIdentifiers.id_TA_ECDSA_SHA_384));
	}

	@Test
	public void unknownCurveIsNotChecked() throws Exception {
		assertEquals(Status.NOT_CHECKED, innerSignatureWithGuessedCurve("secp521r1", EACObjectIdentifiers.id_TA_ECDSA_SHA_512));
	}

	@Test
	public void terminalCertificateIsVerifiedWithKeyOfDv() throws Exception {
		KeyPair cvcaKeys = TestCertificates.rsaKeyPair();
		KeyPair dvKeys = TestCertificates.rsaKeyPair();
		CertStorage store = new CertStorage();
		store.putCert(TestCertificates.rsaCertificate(cvcaKeys, "00001", cvcaKeys, "00001", CertificateHolderAuthorization.CVCA));
		store.putCert(TestCertificates.rsaCertificate(cvcaKeys, "00001", dvKeys, "00002", CertificateHolderAuthorization.DV_DOMESTIC));
		CVCertificate terminal = TestCertificates.rsaCertificate(dvKeys, "00002", TestCertificates.rsaKeyPair(), "00003",
				CertificateHolderAuthorization.IS);

		assertEquals(Status.VALID, new CvChecker(store).checkSignature(terminal).getStatus());
	}

	@Test
	public void missingIssuerIsNotChecked() throws Exception {
		KeyPair cvcaKeys = TestCertificates.rsaKeyPair();
		CVCertificate dv = TestCertificates.rsaCertificate(cvcaKeys, "00001", TestCertificates.rsaKeyPair(), "00002",
				CertificateHolderAuthorization.DV_DOMESTIC);

		assertEquals(Status.NOT_CHECKED, new CvChecker(new CertStorage()).checkSignature(dv).getStatus());
	}

	@Test
	public void changedSignatureIsInvalid() throws Exception {
		KeyPair cvcaKeys = TestCertificates.rsaKeyPair();
		CVCertificate cvca = TestCertificates.rsaCertificate(cvcaKeys, "00001", cvcaKeys, "00001", CertificateHolderAuthorization.CVCA);
		cvca.getSignature()[0] ^= 0x01;
		CertStorage store = new CertStorage();
		store.putCert(cvca);

		assertEquals(Status.INVALID, new CvChecker(store).checkSignature(cvca).getStatus());
	}

	@Test
	public void requestWithoutDomainParametersIsDeviationButStillVerified() throws Exception {
		CVCertificateRequest req = TestCertificates.ecRequestWithoutDomainParameters(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, "brainpoolP256r1");
		CvChecker checker = new CvChecker(new CertStorage());

		CheckResult domainParameters = checker.checkDomainParameters(req);
		assertEquals(Status.INVALID, domainParameters.getStatus());
		assertTrue(domainParameters.getText(), domainParameters.getText().contains("D.3.3"));
		assertEquals(Status.VALID, checker.checkInnerSignature(req).getStatus());
	}

	@Test
	public void domainParametersOfRequestAreComparedWithCvca() throws Exception {
		CertStorage store = new CertStorage();
		store.putCert(TestCertificates.ecCvca(TestCertificates.ecKeyPair("brainpoolP256r1")));
		CvChecker checker = new CvChecker(store);

		assertEquals(Status.VALID, checker.checkDomainParameters(
				TestCertificates.ecRequest(TestCertificates.ecKeyPair("brainpoolP256r1"))).getStatus());
		assertEquals(Status.INVALID, checker.checkDomainParameters(
				TestCertificates.ecRequest(TestCertificates.ecKeyPair("secp256r1"))).getStatus());
	}

	@Test
	public void cvcaWithoutCofactorIsReportedAsUnsupported() throws Exception {
		byte[] encoded = TestCertificates.ecCvcaWithoutCofactor(TestCertificates.ecKeyPair("brainpoolP256r1"));
		try {
			CVCertificate.getInstance(encoded);
			fail("certificate without cofactor was parsed");
		} catch (RuntimeException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("without the cofactor") && e.getMessage().contains("D.3.3"));
		}
	}

	@Ignore("The cofactor is optional (BSI TR-03110 Part 3, D.3.3), but Bouncy Castle's ECDSAPublicKey only accepts "
			+ "all domain parameters or none. Not supported on purpose: no known certificate lacks the cofactor.")
	@Test
	public void cvcaWithoutCofactor() throws Exception {
		KeyPair cvcaKeys = TestCertificates.ecKeyPair("brainpoolP256r1");
		CVCertificate cvca = CVCertificate.getInstance(TestCertificates.ecCvcaWithoutCofactor(cvcaKeys));
		assertNull(((ECDSAPublicKey) cvca.getBody().getPublicKey()).getCofactorF());
		CertStorage store = new CertStorage();
		store.putCert(cvca);
		CvChecker checker = new CvChecker(store);

		assertEquals(Status.VALID, checker.checkSignature(cvca).getStatus());
		assertEquals(Status.VALID, checker.checkDomainParameters(
				TestCertificates.ecRequest(TestCertificates.ecKeyPair("brainpoolP256r1"))).getStatus());
	}
}
