package de.tsenger.certain;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import org.junit.Test;

import de.tsenger.certain.asn1.eac.CVCertificateRequest;

/**
 * Parses DV certificate requests.
 */
public class CvCertificateRequestTest {

	@Test
	public void requestWithoutOuterSignature() throws Exception {
		CVCertificateRequest req = CVCertificateRequest.getInstance(
				TestCertificates.rsaRequest(TestCertificates.rsaKeyPair(), null, null));

		assertEquals("DETEST00001", req.getCertificateBody().getCarString());
		assertEquals("DETEST00002", req.getCertificateBody().getChrString());
		assertFalse(req.hasOuterSignature());
	}

	@Test
	public void requestWithExtension() throws Exception {
		CVCertificateRequest req = TestData.request("requests/dv_is_ext_null_sign_fail.cvreq");

		assertEquals("DECVCATQSIS00006", req.getCertificateBody().getCarString());
		assertEquals("DEDVCATQSIS00001", req.getCertificateBody().getChrString());
	}
}
