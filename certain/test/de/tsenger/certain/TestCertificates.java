package de.tsenger.certain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.eac.CertificateHolderAuthorization;
import org.bouncycastle.asn1.eac.CertificateHolderReference;
import org.bouncycastle.asn1.eac.CertificationAuthorityReference;
import org.bouncycastle.asn1.eac.ECDSAPublicKey;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.eac.PackedDate;
import org.bouncycastle.asn1.eac.PublicKeyDataObject;
import org.bouncycastle.eac.EACCertificateBuilder;
import org.bouncycastle.eac.operator.jcajce.JcaEACSignerBuilder;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

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
		byte[] point = ((ECPublicKey) keyPair.getPublic()).getQ().getEncoded(false);
		// A request without outer signature has the structure of a certificate.
		CVCertificate cert = build(algorithm, keyPair, "00001", new ECDSAPublicKey(algorithm, point), "00002",
				CertificateHolderAuthorization.DV_DOMESTIC);
		return CVCertificateRequest.getInstance(cert.getEncoded());
	}

	/** Creates a request without outer signature (id_TA_ECDSA_SHA_256) whose key contains the domain parameters. */
	static CVCertificateRequest ecRequest(KeyPair keyPair) throws Exception {
		ASN1ObjectIdentifier algorithm = EACObjectIdentifiers.id_TA_ECDSA_SHA_256;
		CVCertificate cert = build(algorithm, keyPair, "00001", ecPublicKeyWithDomainParameters(algorithm, keyPair), "00002",
				CertificateHolderAuthorization.DV_DOMESTIC);
		return CVCertificateRequest.getInstance(cert.getEncoded());
	}

	/** Creates a self-signed ECDSA CVCA certificate (id_TA_ECDSA_SHA_256, sequence number 00001). */
	static CVCertificate ecCvca(KeyPair keyPair) throws Exception {
		ASN1ObjectIdentifier algorithm = EACObjectIdentifiers.id_TA_ECDSA_SHA_256;
		return build(algorithm, keyPair, "00001", ecPublicKeyWithDomainParameters(algorithm, keyPair), "00001",
				CertificateHolderAuthorization.CVCA);
	}

	/**
	 * Creates the encoding of a self-signed ECDSA CVCA certificate whose domain parameters lack the cofactor,
	 * which is allowed by BSI TR-03110 Part 3, D.3.3, but not supported by certain.
	 */
	static byte[] ecCvcaWithoutCofactor(KeyPair keyPair) throws Exception {
		return withoutCofactor(ecCvca(keyPair), keyPair);
	}

	private static ECDSAPublicKey ecPublicKeyWithDomainParameters(ASN1ObjectIdentifier algorithm, KeyPair keyPair) {
		ECPublicKey key = (ECPublicKey) keyPair.getPublic();
		ECParameterSpec params = key.getParameters();
		return new ECDSAPublicKey(algorithm, params.getCurve().getField().getCharacteristic(),
				params.getCurve().getA().toBigInteger(), params.getCurve().getB().toBigInteger(),
				params.getG().getEncoded(false), params.getN(), key.getQ().getEncoded(false), params.getH().intValue());
	}

	/** Removes the cofactor (0x87) from the public key of a certificate and signs the changed body again. */
	private static byte[] withoutCofactor(CVCertificate cert, KeyPair keyPair) throws Exception {
		ASN1EncodableVector body = new ASN1EncodableVector();
		for (ASN1Encodable element : children(cert.getBody().getEncoded())) {
			ASN1TaggedObject tagged = (ASN1TaggedObject) element;
			if (tagged.getTagNo() != 0x49) {
				body.add(tagged);
				continue;
			}
			ASN1EncodableVector publicKey = new ASN1EncodableVector();
			for (ASN1Encodable keyElement : children(tagged.getEncoded())) {
				if (!(keyElement instanceof ASN1TaggedObject && ((ASN1TaggedObject) keyElement).getTagNo() == 7)) {
					publicKey.add(keyElement);
				}
			}
			body.add(new DERTaggedObject(false, BERTags.APPLICATION, 0x49, new DERSequence(publicKey)));
		}
		DERTaggedObject newBody = new DERTaggedObject(false, BERTags.APPLICATION, 0x4E, new DERSequence(body));

		Signature signer = Signature.getInstance("SHA256withCVC-ECDSA", "BC");
		signer.initSign(keyPair.getPrivate());
		signer.update(newBody.getEncoded());
		ASN1EncodableVector certificate = new ASN1EncodableVector();
		certificate.add(newBody);
		certificate.add(new DERTaggedObject(false, BERTags.APPLICATION, 0x37, new DEROctetString(signer.sign())));
		return new DERTaggedObject(false, BERTags.APPLICATION, 0x21, new DERSequence(certificate)).getEncoded();
	}

	/** @return the data objects contained in the encoded APPLICATION tagged data object */
	private static ASN1Sequence children(byte[] encoded) {
		return (ASN1Sequence) ASN1TaggedObject.getInstance(encoded).getBaseUniversal(false, BERTags.SEQUENCE);
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
