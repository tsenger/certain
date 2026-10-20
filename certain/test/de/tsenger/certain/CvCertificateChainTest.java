package de.tsenger.certain;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Ignore;
import org.junit.Test;

import de.tsenger.certain.asn1.eac.CVCertificate;

/**
 * Parses CV certificates and verifies their signatures along the chain CVCA -> DV -> terminal.
 */
public class CvCertificateChainTest {

	/**
	 * Verifies {@code cert} the same way {@link CertainMain} does: a CVCA is checked against its own key,
	 * all other certificates against the signer's key using the EC domain parameters of the CVCA.
	 */
	private static boolean isSignatureValid(CVCertificate cert, CVCertificate signer, CVCertificate cvca) throws Exception {
		CertVerifier verifier = signer == cvca
				? new CertVerifier(cvca.getBody().getPublicKey())
				: new CertVerifier(cvca.getBody().getPublicKey(), signer.getBody().getPublicKey());
		return verifier.hasValidSignature(cert);
	}

	private static void assertChain(String dir) throws Exception {
		CVCertificate cvca = TestData.certificate(dir + "/cvca.cvcert");
		CVCertificate dv = TestData.certificate(dir + "/dv.cvcert");
		CVCertificate ta = TestData.certificate(dir + "/ta.cvcert");

		assertEquals("CVCA", cvca.getRoleDescription());
		assertEquals(cvca.getChrString(), cvca.getCarString());
		assertEquals(cvca.getChrString(), dv.getCarString());
		assertEquals(dv.getChrString(), ta.getCarString());

		assertTrue("CVCA", isSignatureValid(cvca, cvca, cvca));
		assertTrue("DV", isSignatureValid(dv, cvca, cvca));
	}

	private static void assertTerminalSignature(String dir) throws Exception {
		CVCertificate cvca = TestData.certificate(dir + "/cvca.cvcert");
		CVCertificate dv = TestData.certificate(dir + "/dv.cvcert");
		CVCertificate ta = TestData.certificate(dir + "/ta.cvcert");

		assertTrue(isSignatureValid(ta, dv, cvca));
	}

	@Test
	public void chainAuthenticationTerminal() throws Exception {
		assertChain("dev/AT");
	}

	@Test
	public void chainInspectionSystem() throws Exception {
		assertChain("dev/IS");
	}

	@Test
	public void chainSignatureTerminal() throws Exception {
		assertChain("dev/ST");
	}

	@Test
	public void terminalSignatureAuthenticationTerminal() throws Exception {
		assertTerminalSignature("dev/AT");
	}

	@Test
	public void terminalSignatureInspectionSystem() throws Exception {
		assertTerminalSignature("dev/IS");
	}

	@Test
	public void terminalSignatureSignatureTerminal() throws Exception {
		assertTerminalSignature("dev/ST");
	}

	@Test
	public void dvSignedByOtherCvcaIsInvalid() throws Exception {
		CVCertificate otherCvca = TestData.certificate("dev/IS/cvca.cvcert");
		CVCertificate dv = TestData.certificate("dev/AT/dv.cvcert");

		assertFalse(isSignatureValid(dv, otherCvca, otherCvca));
	}

	@Test
	public void germanTestCvcas() throws Exception {
		for (String dir : new String[] { "eid", "epass", "esign" }) {
			CVCertificate cvca = TestData.certificate("de-test/" + dir + "/cvca.cv");
			assertTrue(dir, isSignatureValid(cvca, cvca, cvca));
		}
	}

	@Test
	public void italianCvcas() throws Exception {
		for (String file : new String[] { "cvca_00001.cvcert", "cvca_rp_it001.cvcert" }) {
			CVCertificate cvca = TestData.certificate("it/" + file);
			assertTrue(file, isSignatureValid(cvca, cvca, cvca));
		}
	}

	@Ignore("Known bug: RSA public keys in rsa/ fail with 'not an Iso7816RSAPublicKeyStructure'")
	@Test
	public void rsaCertificatesCanBeParsed() throws Exception {
		TestData.certificate("rsa/root_idl.cvcert");
		TestData.certificate("rsa/ta_idl.cvcert");
	}
}
