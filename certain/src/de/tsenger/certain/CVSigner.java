package de.tsenger.certain;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import de.tsenger.certain.asn1.eac.CertificateBody;
import de.tsenger.certain.asn1.eac.EACObjectIdentifiers;

public class CVSigner {

	
	private Signature sig;
	private byte[] signatureBytes;
	private static final Hashtable<ASN1ObjectIdentifier, String> sigNames = new Hashtable<ASN1ObjectIdentifier, String>();

	static {
		sigNames.put(EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_1, "SHA1withRSA");
		sigNames.put(EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_256, "SHA256withRSA");
		sigNames.put(EACObjectIdentifiers.id_TA_RSA_PSS_SHA_1, "SHA1withRSAandMGF1");
		sigNames.put(EACObjectIdentifiers.id_TA_RSA_PSS_SHA_256, "SHA256withRSAandMGF1");
		sigNames.put(EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_512, "SHA512withRSA");
		sigNames.put(EACObjectIdentifiers.id_TA_RSA_PSS_SHA_512, "SHA512withRSAandMGF1");

		sigNames.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1withCVC-ECDSA");
		sigNames.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224withCVC-ECDSA");
		sigNames.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256withCVC-ECDSA");
		sigNames.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384withCVC-ECDSA");
		sigNames.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512withCVC-ECDSA");
	}

	public CVSigner(CertificateBody body, PrivateKey privKey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
		this.sig = getSignature(body.getPublicKey().getUsage());
		signatureBytes = generateSignature(body.getEncoded(), privKey);
	}
	
	public byte[] getSignatureBytes() {
		return signatureBytes;
	}

	private Signature getSignature(ASN1ObjectIdentifier oid) throws NoSuchProviderException, NoSuchAlgorithmException {
		return Signature.getInstance(sigNames.get(oid));
	}

	private byte[] generateSignature(byte[] dataToSign, PrivateKey privateKey) throws InvalidKeyException, SignatureException {
		sig.initSign(privateKey);
		sig.update(dataToSign);
		return sig.sign();
	}


}
