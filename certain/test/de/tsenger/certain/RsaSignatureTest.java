package de.tsenger.certain;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.eac.CertificateHolderAuthorization;
import org.bouncycastle.asn1.eac.CertificateHolderReference;
import org.bouncycastle.asn1.eac.CertificationAuthorityReference;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.eac.PackedDate;
import org.bouncycastle.eac.EACCertificateBuilder;
import org.bouncycastle.eac.operator.EACSigner;
import org.bouncycastle.eac.operator.jcajce.JcaEACSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import de.tsenger.certain.asn1.eac.CVCertificate;

/**
 * Checks Terminal Authentication with RSA (BSI TR-03110 Part 3, Appendix A.7.3, Table 17) for all six
 * object identifiers. The certificates are created with the signer of Bouncy Castle, so that the
 * signature formats (e.g. the RSA-PSS parameters) are checked against an independent implementation.
 */
public class RsaSignatureTest {

	private static final ASN1ObjectIdentifier[] RSA_OIDS = {
			EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_1,
			EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_256,
			EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_512,
			EACObjectIdentifiers.id_TA_RSA_PSS_SHA_1,
			EACObjectIdentifiers.id_TA_RSA_PSS_SHA_256,
			EACObjectIdentifiers.id_TA_RSA_PSS_SHA_512 };

	@BeforeClass
	public static void registerProvider() {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static KeyPair newKeyPair(int modulusBits) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(modulusBits);
		return generator.generateKeyPair();
	}

	/**
	 * Creates a certificate for {@code subject}, signed with the private key of the issuer.
	 *
	 * @param role CVCA or DV_DOMESTIC of Bouncy Castle
	 */
	private static CVCertificate certificate(ASN1ObjectIdentifier algorithm, KeyPair issuer, String issuerSequence,
			KeyPair subject, String subjectSequence, int role) throws Exception {
		RSAPublicKey publicKey = (RSAPublicKey) subject.getPublic();
		EACSigner signer = new JcaEACSignerBuilder().setProvider("BC").build(algorithm, issuer.getPrivate());
		org.bouncycastle.asn1.eac.RSAPublicKey publicKeyObject = new org.bouncycastle.asn1.eac.RSAPublicKey(algorithm,
				publicKey.getModulus(), publicKey.getPublicExponent());
		EACCertificateBuilder builder = new EACCertificateBuilder(
				new CertificationAuthorityReference("DE", "RSATEST", issuerSequence), publicKeyObject,
				new CertificateHolderReference("DE", "RSATEST", subjectSequence),
				new CertificateHolderAuthorization(EACObjectIdentifiers.id_EAC_ePassport,
						role | CertificateHolderAuthorization.RADG3),
				new PackedDate("200101"), new PackedDate("300101"));

		return CVCertificate.getInstance(builder.build(signer).toASN1Structure().getEncoded());
	}

	/** Creates a self-signed CVCA certificate with a new RSA key of the given modulus length. */
	private static CVCertificate selfSignedCvca(ASN1ObjectIdentifier algorithm, int modulusBits) throws Exception {
		KeyPair keyPair = newKeyPair(modulusBits);
		return certificate(algorithm, keyPair, "00001", keyPair, "00001", CertificateHolderAuthorization.CVCA);
	}

	@Test
	public void allSixAlgorithmsVerify() throws Exception {
		for (ASN1ObjectIdentifier algorithm : RSA_OIDS) {
			CVCertificate cert = selfSignedCvca(algorithm, 2048);

			assertEquals(algorithm, cert.getBody().getPublicKey().getUsage());
			assertTrue(algorithm.getId(), new CertVerifier(cert.getBody().getPublicKey()).hasValidSignature(cert));
		}
	}

	@Test
	public void modulusLengthsOfTheSpecification() throws Exception {
		for (int bits : new int[] { 1024, 1280, 1536, 3072 }) {
			CVCertificate cert = selfSignedCvca(EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_256, bits);

			assertTrue(bits + " bit", new CertVerifier(cert.getBody().getPublicKey()).hasValidSignature(cert));
		}
	}

	@Test
	public void keyAndExponentArePreserved() throws Exception {
		CVCertificate cert = selfSignedCvca(EACObjectIdentifiers.id_TA_RSA_PSS_SHA_256, 2048);
		org.bouncycastle.asn1.eac.RSAPublicKey key = (org.bouncycastle.asn1.eac.RSAPublicKey) cert.getBody().getPublicKey();

		assertEquals(2048, key.getModulus().bitLength());
		assertEquals(BigInteger.valueOf(65537), key.getPublicExponent());
	}

	@Test
	public void changedSignatureIsRejected() throws Exception {
		CVCertificate cert = selfSignedCvca(EACObjectIdentifiers.id_TA_RSA_PSS_SHA_256, 2048);
		cert.getSignature()[0] ^= 0x01;

		assertFalse(new CertVerifier(cert.getBody().getPublicKey()).hasValidSignature(cert));
	}

	@Test
	public void documentVerifierCertificateSignedByCvca() throws Exception {
		for (ASN1ObjectIdentifier algorithm : RSA_OIDS) {
			KeyPair cvcaKeys = newKeyPair(2048);
			CVCertificate cvca = certificate(algorithm, cvcaKeys, "00001", cvcaKeys, "00001", CertificateHolderAuthorization.CVCA);
			CVCertificate dv = certificate(algorithm, cvcaKeys, "00001", newKeyPair(2048), "00002",
					CertificateHolderAuthorization.DV_DOMESTIC);

			assertEquals(cvca.getChrString(), dv.getCarString());
			assertTrue(algorithm.getId(), new CertVerifier(cvca.getBody().getPublicKey()).hasValidSignature(dv));
		}
	}
}
