package de.tsenger.certain;

import static org.junit.Assert.assertEquals;

import static de.tsenger.certain.TestSignedData.SERIAL;
import static de.tsenger.certain.TestSignedData.SIGNER;
import static de.tsenger.certain.TestSignedData.certificate;
import static de.tsenger.certain.TestSignedData.keyPair;

import java.security.KeyPair;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Test;

import de.tsenger.certain.asn1.eac.BSIObjectIdentifiers;

/**
 * Checks the signature verification of {@link SignedDataParser} with SignedData objects created by the test.
 */
public class SignedDataParserTest {

	@Test
	public void signatureWithIssuerAndSerialNumberIsValid() throws Exception {
		KeyPair keyPair = keyPair();
		SignedDataParser parser = new SignedDataParser(sign(defectList(revoked(1)), keyPair, certificate(keyPair), false));

		assertEquals(CheckResult.Status.VALID, parser.verifySignedData().getStatus());
	}

	@Test
	public void signatureWithSubjectKeyIdentifierIsValid() throws Exception {
		KeyPair keyPair = keyPair();
		SignedDataParser parser = new SignedDataParser(sign(defectList(revoked(1)), keyPair, certificate(keyPair), true));

		assertEquals(CheckResult.Status.VALID, parser.verifySignedData().getStatus());
	}

	@Test
	public void signatureWithOtherKeyIsInvalid() throws Exception {
		KeyPair keyPair = keyPair();
		// The SignerInfo refers to a certificate with the same issuer and serial number but another public key
		byte[] signedData = sign(defectList(revoked(1)), keyPair(), certificate(keyPair), false);

		assertEquals(CheckResult.Status.INVALID, new SignedDataParser(signedData).verifySignedData().getStatus());
	}

	/** KnownDefect id-CertRevoked with the given status code. */
	private static ASN1Encodable revoked(int statusCode) {
		return new DERSequence(new ASN1Encodable[] { BSIObjectIdentifiers.certRevoked, new ASN1Enumerated(statusCode) });
	}

	/** Version 1 defect list with one defect that refers to the signer certificate by issuerAndSerialNumber. */
	private static byte[] defectList(ASN1Encodable knownDefect) throws Exception {
		ASN1Encodable defect = new DERSequence(new ASN1Encodable[] { new IssuerAndSerialNumber(SIGNER, SERIAL), new DERSet(knownDefect) });
		return new DERSequence(new ASN1Encodable[] { new ASN1Integer(0), new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
				new DERSet(defect) }).getEncoded();
	}

	private static byte[] sign(byte[] defectList, KeyPair keyPair, X509CertificateHolder cert, boolean subjectKeyIdentifier) throws Exception {
		return TestSignedData.sign(BSIObjectIdentifiers.DefectList, defectList, keyPair, cert, subjectKeyIdentifier);
	}
}
