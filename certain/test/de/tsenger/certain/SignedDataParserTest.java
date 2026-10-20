package de.tsenger.certain;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.Test;

import de.tsenger.certain.asn1.eac.BSIObjectIdentifiers;

/**
 * Checks the signature verification of {@link SignedDataParser} and the output of defect lists (BSI TR-03129-2,
 * chapter 8) with SignedData objects created by the test.
 */
public class SignedDataParserTest {

	/** Several RDNs, so that a different order of the RDNs makes a difference. */
	private static final X500Name SIGNER = new X500Name("C=DE,O=Test,OU=Lists,CN=DFL Signer");
	/** Larger than 127, so that boxed Integers are not cached. */
	private static final BigInteger SERIAL = BigInteger.valueOf(4711);

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

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

	@Test
	public void revokedDefectShowsOnlyItsStatusCode() throws Exception {
		String output = defectListOutput(defectList(revoked(1)));

		assertTrue(output, output.contains("status code 1: onHold"));
		assertFalse(output, output.contains("status code 2"));
		assertFalse(output, output.contains("proprietary"));
	}

	@Test
	public void replacementCertificateIsShown() throws Exception {
		X509CertificateHolder replacement = certificate(keyPair());
		ASN1Encodable knownDefect = new DERSequence(new ASN1Encodable[] { BSIObjectIdentifiers.certReplaced,
				new DEROctetString(replacement.getEncoded()) });

		String output = defectListOutput(defectList(knownDefect));

		assertTrue(output, output.contains("Replacement Certificate:"));
		assertTrue(output, output.contains("CN=DFL Signer"));
	}

	@Test
	public void signerIdentifierWithSubjectKeyIdentifierIsShown() throws Exception {
		ASN1Encodable defect = new DERSequence(new ASN1Encodable[] {
				new DERTaggedObject(false, 0, new DEROctetString(new byte[] { 0x01, 0x02, 0x03 })), new DERSet(revoked(0)) });

		String output = defectListOutput(list(0, defect));

		assertTrue(output, output.contains("DS Subject Key Identifier: 010203"));
	}

	@Test
	public void unsupportedVersion3DefectIsNamed() throws Exception {
		// SignerCertificateReference and KnownDefectV2 of version 3 (TR-03129-2, 8.1)
		ASN1Encodable reference = new DERSequence(new DERTaggedObject(true, 0, new IssuerAndSerialNumber(SIGNER, SERIAL)));
		ASN1Encodable knownDefectV2 = new DERTaggedObject(false, 0, new DERSequence(new ASN1Encodable[] {
				new ASN1ObjectIdentifier("0.4.0.127.0.7.3.1.5.1.6"), new DERTaggedObject(true, 0, new ASN1Enumerated(1)),
				new DERTaggedObject(false, 1, new DERUTF8String("DS validity too long")) }));
		ASN1Encodable defect = new DERSequence(new ASN1Encodable[] { reference, new DERSet(knownDefectV2) });

		String output = defectListOutput(list(2, defect));

		assertTrue(output, output.contains("This defect can't be parsed (Defect List version 3)"));
	}

	private static String defectListOutput(byte[] defectList) throws Exception {
		KeyPair keyPair = keyPair();
		return new SignedDataParser(sign(defectList, keyPair, certificate(keyPair), false)).getDListParser().getDListInfoString(false);
	}

	/** KnownDefect id-CertRevoked with the given status code. */
	private static ASN1Encodable revoked(int statusCode) {
		return new DERSequence(new ASN1Encodable[] { BSIObjectIdentifiers.certRevoked, new ASN1Enumerated(statusCode) });
	}

	/** Version 1 defect list with one defect that refers to the signer certificate by issuerAndSerialNumber. */
	private static byte[] defectList(ASN1Encodable knownDefect) throws Exception {
		return list(0, new DERSequence(new ASN1Encodable[] { new IssuerAndSerialNumber(SIGNER, SERIAL), new DERSet(knownDefect) }));
	}

	private static byte[] list(int version, ASN1Encodable defect) throws Exception {
		return new DERSequence(new ASN1Encodable[] { new ASN1Integer(version), new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
				new DERSet(defect) }).getEncoded();
	}

	private static byte[] sign(byte[] defectList, KeyPair keyPair, X509CertificateHolder cert, boolean subjectKeyIdentifier) throws Exception {
		JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(
				new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());
		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		if (subjectKeyIdentifier) {
			byte[] ski = SubjectKeyIdentifier.fromExtensions(cert.getExtensions()).getKeyIdentifier();
			generator.addSignerInfoGenerator(builder.build(signer(keyPair), ski));
		} else {
			generator.addSignerInfoGenerator(builder.build(signer(keyPair), cert));
		}
		generator.addCertificate(cert);
		return generator.generate(new CMSProcessableByteArray(BSIObjectIdentifiers.DefectList, defectList), true).getEncoded();
	}

	private static org.bouncycastle.operator.ContentSigner signer(KeyPair keyPair) throws Exception {
		return new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(keyPair.getPrivate());
	}

	/** Self-signed certificate with the subject {@link #SIGNER} and the serial number {@link #SERIAL}. */
	private static X509CertificateHolder certificate(KeyPair keyPair) throws Exception {
		JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(SIGNER, SERIAL, new Date(),
				new Date(System.currentTimeMillis() + 86400000L), SIGNER, keyPair.getPublic());
		builder.addExtension(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic()));
		return builder.build(signer(keyPair));
	}

	private static KeyPair keyPair() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
		generator.initialize(256);
		return generator.generateKeyPair();
	}
}
