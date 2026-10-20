package de.tsenger.certain;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import de.tsenger.certain.asn1.eac.BSIObjectIdentifiers;

/**
 * Creates CMS SignedData objects (deviation and defect lists) and their signer certificates for tests.
 */
final class TestSignedData {

	/** Several RDNs, so that a different order of the RDNs makes a difference. */
	static final X500Name SIGNER = new X500Name("C=DE,O=Test,OU=Lists,CN=List Signer");
	/** Larger than 127, so that boxed Integers are not cached. */
	static final BigInteger SERIAL = BigInteger.valueOf(4711);
	static final long HOUR = 3600000L;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private TestSignedData() {
	}

	static KeyPair keyPair() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
		generator.initialize(256);
		return generator.generateKeyPair();
	}

	/**
	 * Self-signed certificate with the subject {@link #SIGNER}, the serial number {@link #SERIAL}, a subject key
	 * identifier and the given extensions (pairs of object identifier and value). It is valid from an hour ago to tomorrow.
	 */
	static X509CertificateHolder certificate(KeyPair keyPair, Object... extensions) throws Exception {
		// valid from an hour ago to tomorrow, so that the signing time (now) is within the validity
		JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(SIGNER, SERIAL, new Date(System.currentTimeMillis() - HOUR),
				new Date(System.currentTimeMillis() + 24 * HOUR), SIGNER, keyPair.getPublic());
		builder.addExtension(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic()));
		for (int i = 0; i < extensions.length; i += 2) {
			builder.addExtension((ASN1ObjectIdentifier) extensions[i], false, (ASN1Encodable) extensions[i + 1]);
		}
		return builder.build(signer(keyPair));
	}

	/**
	 * Signs the content with the key pair; the SignerInfo refers to the certificate by subjectKeyIdentifier or by
	 * issuerAndSerialNumber. The certificate is included in the SignedData object.
	 */
	static byte[] sign(ASN1ObjectIdentifier contentType, byte[] content, KeyPair keyPair, X509CertificateHolder cert,
			boolean subjectKeyIdentifier) throws Exception {
		return sign(contentType, content, keyPair, cert, subjectKeyIdentifier, null);
	}

	/**
	 * Like {@link #sign(ASN1ObjectIdentifier, byte[], KeyPair, X509CertificateHolder, boolean)}, with the signed attribute
	 * ListContentDescription (BSI TR-03129-3, C.1) if the description is not null.
	 */
	static byte[] sign(ASN1ObjectIdentifier contentType, byte[] content, KeyPair keyPair, X509CertificateHolder cert,
			boolean subjectKeyIdentifier, String listContentDescription) throws Exception {
		JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(
				new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());
		if (listContentDescription != null) {
			Attribute description = new Attribute(BSIObjectIdentifiers.ListContentDescription, new DERSet(new DERUTF8String(listContentDescription)));
			builder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(description)));
		}
		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		if (subjectKeyIdentifier) {
			byte[] ski = SubjectKeyIdentifier.fromExtensions(cert.getExtensions()).getKeyIdentifier();
			generator.addSignerInfoGenerator(builder.build(signer(keyPair), ski));
		} else {
			generator.addSignerInfoGenerator(builder.build(signer(keyPair), cert));
		}
		generator.addCertificate(cert);
		return generator.generate(new CMSProcessableByteArray(contentType, content), true).getEncoded(ASN1Encoding.DER);
	}

	private static ContentSigner signer(KeyPair keyPair) throws Exception {
		return new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(keyPair.getPrivate());
	}
}
