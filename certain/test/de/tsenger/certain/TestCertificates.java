package de.tsenger.certain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.eac.CertificateHolderAuthorization;
import org.bouncycastle.asn1.eac.CertificateHolderReference;
import org.bouncycastle.asn1.eac.CertificationAuthorityReference;
import org.bouncycastle.asn1.eac.ECDSAPublicKey;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.eac.PackedDate;
import org.bouncycastle.asn1.eac.PublicKeyDataObject;
import org.bouncycastle.eac.EACCertificateBuilder;
import org.bouncycastle.eac.operator.jcajce.JcaEACSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.tsenger.certain.asn1.eac.CVCertificate;
import de.tsenger.certain.asn1.eac.CVCertificateRequest;

/**
 * Creates CV certificates and requests for tests, signed with the signer of Bouncy Castle.
 * All references use the country code DE and the mnemonic TEST, they differ in the sequence number.
 */
final class TestCertificates {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private TestCertificates() {
	}

	static KeyPair rsaKeyPair() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		return generator.generateKeyPair();
	}

	static KeyPair ecKeyPair(String curve) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDSA", "BC");
		generator.initialize(new ECGenParameterSpec(curve));
		return generator.generateKeyPair();
	}

	/**
	 * Creates an RSA certificate (id_TA_RSA_v1_5_SHA_256) for {@code subject}, signed with the private key of the issuer.
	 *
	 * @param role CVCA, DV_DOMESTIC or IS of Bouncy Castle
	 */
	static CVCertificate rsaCertificate(KeyPair issuer, String issuerSequence, KeyPair subject, String subjectSequence,
			int role) throws Exception {
		ASN1ObjectIdentifier algorithm = EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_256;
		RSAPublicKey publicKey = (RSAPublicKey) subject.getPublic();
		return build(algorithm, issuer, issuerSequence,
				new org.bouncycastle.asn1.eac.RSAPublicKey(algorithm, publicKey.getModulus(), publicKey.getPublicExponent()),
				subjectSequence, role);
	}

	/**
	 * Creates a request without outer signature whose ECDSA key contains no domain parameters, so that
	 * they have to be guessed to verify the inner signature.
	 */
	static CVCertificateRequest ecRequestWithoutDomainParameters(ASN1ObjectIdentifier algorithm, String curve) throws Exception {
		KeyPair keyPair = ecKeyPair(curve);
		byte[] point = ((org.bouncycastle.jce.interfaces.ECPublicKey) keyPair.getPublic()).getQ().getEncoded(false);
		// A request without outer signature has the structure of a certificate.
		CVCertificate cert = build(algorithm, keyPair, "00001", new ECDSAPublicKey(algorithm, point), "00002",
				CertificateHolderAuthorization.DV_DOMESTIC);
		return CVCertificateRequest.getInstance(cert.getEncoded());
	}

	private static CVCertificate build(ASN1ObjectIdentifier algorithm, KeyPair issuer, String issuerSequence,
			PublicKeyDataObject publicKey, String subjectSequence, int role) throws Exception {
		EACCertificateBuilder builder = new EACCertificateBuilder(
				new CertificationAuthorityReference("DE", "TEST", issuerSequence), publicKey,
				new CertificateHolderReference("DE", "TEST", subjectSequence),
				new CertificateHolderAuthorization(EACObjectIdentifiers.id_EAC_ePassport,
						role | CertificateHolderAuthorization.RADG3),
				new PackedDate("200101"), new PackedDate("300101"));
		return CVCertificate.getInstance(builder.build(
				new JcaEACSignerBuilder().setProvider("BC").build(algorithm, issuer.getPrivate())).toASN1Structure().getEncoded());
	}
}
