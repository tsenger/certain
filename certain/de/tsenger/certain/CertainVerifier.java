package de.tsenger.certain;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.eac.EACException;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.OperatorCreationException;

import de.tsenger.certain.asn1.eac.CVCertificate;
import de.tsenger.certain.asn1.eac.CVCertificateRequest;
import de.tsenger.certain.asn1.eac.EACObjectIdentifiers;
import de.tsenger.certain.asn1.eac.ECDSAPublicKey;
import de.tsenger.certain.asn1.eac.PublicKeyDataObject;
import de.tsenger.certain.asn1.eac.RSAPublicKey;

public class CertainVerifier {

	private final PublicKey publicKey;
	private final Signature sig;
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
	


	public CertainVerifier(PublicKeyDataObject pubKeyObj) throws InvalidKeySpecException, EACException, NoSuchProviderException, NoSuchAlgorithmException {
		this.publicKey = convertPublicKey(pubKeyObj);
		this.sig = getSignature(pubKeyObj.getUsage());
	}
	
	public CertainVerifier(PublicKeyDataObject pubKeyObj, PublicKeyDataObject pubKeyObjWithoutDomainParameter) throws InvalidKeySpecException, EACException, NoSuchProviderException, NoSuchAlgorithmException {
		this.publicKey = getECPublicKeyPublicKey((ECDSAPublicKey)pubKeyObj, (ECDSAPublicKey)pubKeyObjWithoutDomainParameter);
		this.sig = getSignature(pubKeyObj.getUsage());
	}
	
	public boolean hasValidOuterSignature(CVCertificateRequest req) throws OperatorCreationException, EACException {
		try {
			byte[] reqData = req.getEncoded();	
			byte[] outerCAR = req.getOuterCAR().getEncoded();
			byte[] data = new byte[reqData.length+2+outerCAR.length];
			
			//HACK we need the tag and the length of outer car
			data[reqData.length]=0x42;
			data[reqData.length+1]=(byte) outerCAR.length;
						
			System.arraycopy(reqData, 0, data, 0, reqData.length);			
			System.arraycopy(outerCAR, 0, data, reqData.length+2, outerCAR.length);
			
			byte[] signature = req.getOuterSignature();
			
			return verify(data, signature);
		} catch (IOException e) {
			throw new EACException("unable to process signature: " + e.getMessage(), e);
		}
	}
	
	public boolean hasValidSignature(CVCertificateRequest req) throws OperatorCreationException, EACException {
		try {
			byte[] data = req.getCertificateBody().getEncoded();
			byte[] signature = req.getInnerSignature();
			
			return verify(data, signature);
		} catch (IOException e) {
			throw new EACException("unable to process signature: " + e.getMessage(), e);
		}
	}
	
	public boolean hasValidSignature(CVCertificate cert) throws OperatorCreationException, EACException {
		try {
			return verify(cert.getBody().getEncoded(), cert.getSignature());
		} catch (IOException e) {
			throw new EACException("unable to process signature: " + e.getMessage(), e);
		}
	}

	private boolean verify(byte[] data, byte[] signatureBytes) throws OperatorCreationException, EACException {
		try {
			sig.initVerify(publicKey);
		} catch (InvalidKeyException e) {
			throw new OperatorCreationException("invalid key: " + e.getMessage(), e);
		}
		try {			
			sig.update(data);
			return sig.verify(signatureBytes);
		} catch (Exception e) {
			throw new EACException("unable to process signature: " + e.getMessage(), e);
		}
	}

	private Signature getSignature(ASN1ObjectIdentifier oid) throws NoSuchProviderException, NoSuchAlgorithmException {
		return createSignature(sigNames.get(oid));
	}

	private Signature createSignature(String type) throws NoSuchAlgorithmException {
		return Signature.getInstance(type);
	}

	private PublicKey convertPublicKey(PublicKeyDataObject pubKeyObj) throws InvalidKeySpecException, EACException {
		if (pubKeyObj.getUsage().on(EACObjectIdentifiers.id_TA_ECDSA)) {
			return getECPublicKeyPublicKey((ECDSAPublicKey) pubKeyObj);
		} else {
			RSAPublicKey pubKey = (RSAPublicKey) pubKeyObj;
			RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(pubKey.getModulus(), pubKey.getPublicExponent());

			try {
				KeyFactory factk = createKeyFactory("RSA");

				return factk.generatePublic(pubKeySpec);
			} catch (NoSuchAlgorithmException e) {
				throw new EACException("cannot find algorithm ECDSA: " + e.getMessage(), e);
			}
		}
	}
	
	private PublicKey getECPublicKeyPublicKey(ECDSAPublicKey key) throws EACException, InvalidKeySpecException {
		return getECPublicKeyPublicKey(key, null);
	}

	private PublicKey getECPublicKeyPublicKey(ECDSAPublicKey keyWithDP, ECDSAPublicKey keyWithOutDP) throws EACException, InvalidKeySpecException {
		ECParameterSpec spec = getParams(keyWithDP);
		ECCurve curve = spec.getCurve();

		ECPoint point;
		if(keyWithOutDP!=null) {
			point = curve.decodePoint(keyWithOutDP.getPublicPointY());
		} else {
			point = curve.decodePoint(keyWithDP.getPublicPointY());
		}
		ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, spec);

		KeyFactory factk;
		try {
			factk = createKeyFactory("ECDSA");
		} catch (NoSuchAlgorithmException e) {
			throw new EACException("cannot find algorithm ECDSA: " + e.getMessage(), e);
		}

		return factk.generatePublic(pubKeySpec);
	}

	private ECParameterSpec getParams(ECDSAPublicKey key) throws EACException {
		if (!key.hasParameters()) {
			throw new EACException("Public key does not contains EC Params");
		}

		BigInteger p = key.getPrimeModulusP();
		ECCurve.Fp curve = new ECCurve.Fp(p, key.getFirstCoefA(), key.getSecondCoefB());

		ECPoint G = curve.decodePoint(key.getBasePointG());

		BigInteger order = key.getOrderOfBasePointR();
		BigInteger coFactor = key.getCofactorF();
		// TODO: update to use JDK 1.5 EC API
		ECParameterSpec ecspec = new ECParameterSpec(curve, G, order, coFactor);

		return ecspec;
	}

	private KeyFactory createKeyFactory(String type) throws NoSuchAlgorithmException {
		return KeyFactory.getInstance(type);
	}
}
