package de.tsenger.certain;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.junit.Test;

/**
 * Parses the German master list {@code master-lists/de.ml} (2026-10-01).
 */
public class MasterListTest {

	private static MasterListParser parseGermanMasterList() throws Exception {
		return new MasterListParser(TestData.read("master-lists/de.ml"));
	}

	@Test
	public void containsExpectedNumberOfCertificates() throws Exception {
		MasterListParser parser = parseGermanMasterList();

		assertEquals(609, parser.getCSCACertificates().size());
		assertEquals(2, parser.getMasterListSignerCertificates().size());
	}

	@Test
	public void signerCertificateIsIssuedByGermanCsca() throws Exception {
		MasterListParser parser = parseGermanMasterList();

		X509Certificate signer = (X509Certificate) parser.getMasterListSignerCertificates().get(0);

		assertEquals("C=DE,O=bund,OU=bsi,SERIALNUMBER=0039,CN=CSCA Master List Signer", signer.getSubjectDN().toString());
		assertEquals("C=DE,O=bund,OU=bsi,CN=csca-germany", signer.getIssuerDN().toString());
	}

	@Test
	public void cscaCertificatesAreX509() throws Exception {
		for (Certificate cert : parseGermanMasterList().getCSCACertificates()) {
			assertTrue(cert instanceof X509Certificate);
		}
	}

	@Test
	public void infoStringListsAllCertificates() throws Exception {
		String info = parseGermanMasterList().getMasterListInfoString(false);

		assertTrue(info.contains("This Master List contains 609 CSCA certificates and 2 Master List Signer Certificates."));
		assertTrue(info.contains("CSCA Cert no. 609"));
	}
}
