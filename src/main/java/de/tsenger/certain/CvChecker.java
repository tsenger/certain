package de.tsenger.certain;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.eac.ECDSAPublicKey;
import org.bouncycastle.asn1.eac.PublicKeyDataObject;
import org.bouncycastle.asn1.eac.RSAPublicKey;

import de.tsenger.certain.CheckResult.Status;
import de.tsenger.certain.asn1.eac.CVCertificate;
import de.tsenger.certain.asn1.eac.CVCertificateRequest;

/**
 * Checks CV certificates, link certificates and certificate requests against the certificates of a
 * {@link CertStorage}: signatures, the public key of link certificates and the domain parameters of requests.
 * <p>
 * The ECDSA keys of DV and terminal certificates usually contain no domain parameters; they are taken from the
 * CVCA of the chain.
 */
public class CvChecker {

	private static final String NO_CHAIN = "Can't check signature. No matching certificate (chain) available.";

	/** Named curves tried for an ECDSA key without domain parameters if no CVCA is available, by signature algorithm. */
	private static final Map<ASN1ObjectIdentifier, String[]> GUESSED_CURVES = new HashMap<ASN1ObjectIdentifier, String[]>();

	static {
		GUESSED_CURVES.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_224, new String[] { "brainpoolP224r1", "secp224r1" });
		GUESSED_CURVES.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, new String[] { "brainpoolP256r1", "secp256r1" });
		GUESSED_CURVES.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_384, new String[] { "brainpoolP384r1", "secp384r1" });
		GUESSED_CURVES.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_512, new String[] { "brainpoolP512r1" });
	}

	/** A signature that is verified with a given {@link CertVerifier}. */
	private interface SignatureCheck {
		boolean verify(CertVerifier verifier) throws Exception;
	}

	private final CertStorage certStore;

	public CvChecker(CertStorage certStore) {
		this.certStore = certStore;
	}

	/**
	 * Verifies the signature of a certificate with the key of its issuer (the certificate referenced by its CAR).
	 */
	public CheckResult checkSignature(CVCertificate cert) {
		CVCertificate issuer = certStore.getCertByCHR(cert.getCarString());
		if (issuer == null) {
			return new CheckResult(Status.NOT_CHECKED, NO_CHAIN);
		}
		return verify("Signature", issuer.getBody().getPublicKey(), getCvcaChr(issuer.getChrString(), 3), false,
				verifier -> verifier.hasValidSignature(cert));
	}

	/** Verifies the inner signature of a request, made with the key contained in the request. */
	public CheckResult checkInnerSignature(CVCertificateRequest req) {
		return verify("Inner Signature", req.getCertificateBody().getPublicKey(),
				getCvcaChr(req.getCertificateBody().getCarString(), 3), true, verifier -> verifier.hasValidSignature(req));
	}

	/** Verifies the outer signature of a request with the key of the certificate referenced by the outer CAR. */
	public CheckResult checkOuterSignature(CVCertificateRequest req) {
		CVCertificate issuer = certStore.getCertByCHR(req.getOuterCarStr());
		if (issuer == null) {
			return new CheckResult(Status.NOT_CHECKED,
					"Can't check outer signature without matching parent DV and/or CVCA certificate.");
		}
		return verify("Outer Signature", issuer.getBody().getPublicKey(), getCvcaChr(issuer.getChrString(), 3), true,
				verifier -> verifier.hasValidOuterSignature(req));
	}

	/**
	 * Checks the domain parameters of a request: an ECDSA key MUST contain them (BSI TR-03110 Part 3, D.3.3), and
	 * they have to be those of the CVCA referenced by the request. Without certificates there is nothing to compare,
	 * and RSA keys have no domain parameters; the result has no text then.
	 */
	public CheckResult checkDomainParameters(CVCertificateRequest req) {
		PublicKeyDataObject reqKey = req.getCertificateBody().getPublicKey();
		if (!hasDomainParameters(reqKey)) {
			return new CheckResult(Status.INVALID, "Deviation from BSI TR-03110 Part 3, D.3.3: the public key of this request "
					+ "contains no domain parameters, but certificate requests MUST always contain them.");
		}
		String cvcaChr = getCvcaChr(req.getCertificateBody().getCarString(), 3);
		if (!(reqKey instanceof ECDSAPublicKey) || (cvcaChr == null && certStore.isEmpty())) {
			return new CheckResult(Status.VALID, "");
		}
		if (cvcaChr == null) {
			return new CheckResult(Status.NOT_CHECKED, "Can't find a matching parent CVCA certificate to this request. "
					+ "Therefore can't check if CVCA DP are equal to Request DP.");
		}
		if (!equalDomainParameters(certStore.getCertByCHR(cvcaChr).getBody().getPublicKey(), reqKey)) {
			return new CheckResult(Status.INVALID, "Domain parameters of this request don't match domain parameters of CVCA " + cvcaChr + ".");
		}
		return new CheckResult(Status.VALID, "Domain parameters of this request match domain parameters of CVCA " + cvcaChr + ".");
	}

	/** Checks that a link certificate contains the public key of the new CVCA certificate (referenced by its CHR). */
	public CheckResult checkLinkPublicKey(CVCertificate linkCert) {
		CVCertificate newCvca = certStore.getCertByCHR(linkCert.getChrString());
		if (newCvca == null) {
			return new CheckResult(Status.NOT_CHECKED, "No CVCA was given. Can't check matching public point to any CVCA.\n");
		}
		if (equalPublicKeys(linkCert.getBody().getPublicKey(), newCvca.getBody().getPublicKey())) {
			return new CheckResult(Status.VALID, "The public key in this linkcert is equal to the public key in\n" + newCvca.getChrString() + "\n");
		}
		return new CheckResult(Status.INVALID, "The public key in this linkcert IS NOT EQUAL to the public key in\n" + newCvca.getChrString() + "\n");
	}

	/**
	 * Verifies a signature made with {@code key}. If it is an ECDSA key without domain parameters, those of the CVCA
	 * {@code cvcaChr} are used; without CVCA well-known curves are tried if {@code guess} is set.
	 */
	private CheckResult verify(String name, PublicKeyDataObject key, String cvcaChr, boolean guess, SignatureCheck check) {
		CertVerifier verifier;
		try {
			if (hasDomainParameters(key)) {
				verifier = new CertVerifier(key);
			} else if (cvcaChr != null) {
				verifier = new CertVerifier(certStore.getCertByCHR(cvcaChr).getBody().getPublicKey(), key);
			} else if (guess) {
				return guessDomainParameters(name, key, check);
			} else {
				return new CheckResult(Status.NOT_CHECKED, NO_CHAIN);
			}
			return validity(name, check.verify(verifier));
		} catch (Exception e) {
			return new CheckResult(Status.INVALID, "Couldn't verify " + name.toLowerCase() + ": " + e.getLocalizedMessage());
		}
	}

	/** Tries the well-known curves for the algorithm of {@code key} until one verifies the signature. */
	private CheckResult guessDomainParameters(String name, PublicKeyDataObject key, SignatureCheck check) {
		StringBuilder text = new StringBuilder("No domain parameters provided via CVCA certificate but we will try some educated guesses...\n");
		String[] curves = GUESSED_CURVES.get(key.getUsage());
		for (String curve : curves != null ? curves : new String[0]) {
			text.append("Trying DP ").append(curve).append(": ");
			try {
				CheckResult result = validity(name, check.verify(new CertVerifier(curve, key)));
				text.append(result.getText());
				if (result.getStatus() == Status.VALID) {
					return new CheckResult(Status.VALID, text.toString());
				}
			} catch (Exception e) {
				text.append("failed! Reason: ").append(e.getLocalizedMessage());
			}
			text.append('\n');
		}
		// No match does not prove the signature invalid, the domain parameters may just be unknown.
		return new CheckResult(Status.NOT_CHECKED, text.append("Out of guesses").toString());
	}

	private static CheckResult validity(String name, boolean valid) {
		return valid ? new CheckResult(Status.VALID, name + " is VALID")
				: new CheckResult(Status.INVALID, name + " is !!! INVALID !!!");
	}

	/**
	 * Recursive search for the CHR of the CVCA certificate.
	 *
	 * @param chrStr CHR of the certificate to start with
	 * @param maxDepth limits the recursion to avoid endless loops
	 * @return CHR of the CVCA certificate or null if the chain is incomplete
	 */
	private String getCvcaChr(String chrStr, int maxDepth) {
		if (maxDepth == 0) return null;

		CVCertificate cert = certStore.getCertByCHR(chrStr);
		if (cert == null) return null;

		if ("CVCA".equals(cert.getRoleDescription())) return cert.getChrString();
		if (cert.getCarString() == null) return null;
		return getCvcaChr(cert.getCarString(), maxDepth - 1);
	}

	private static boolean hasDomainParameters(PublicKeyDataObject key) {
		return !(key instanceof ECDSAPublicKey) || ((ECDSAPublicKey) key).hasParameters();
	}

	private static boolean equalPublicKeys(PublicKeyDataObject pk1, PublicKeyDataObject pk2) {
		ASN1ObjectIdentifier pk1Oid = pk1.getUsage();
		ASN1ObjectIdentifier pk2Oid = pk2.getUsage();
		if (!pk1Oid.equals(pk2Oid)) return false;

		if (pk1Oid.on(EACObjectIdentifiers.id_TA_ECDSA)) {
			ECDSAPublicKey ecdsapk1 = (ECDSAPublicKey) pk1;
			ECDSAPublicKey ecdsapk2 = (ECDSAPublicKey) pk2;
			return Arrays.equals(ecdsapk1.getPublicPointY(), ecdsapk2.getPublicPointY());
		} else if (pk1Oid.on(EACObjectIdentifiers.id_TA_RSA)) {
			RSAPublicKey rsapk1 = (RSAPublicKey) pk1;
			RSAPublicKey rsapk2 = (RSAPublicKey) pk2;
			return rsapk1.getModulus().equals(rsapk2.getModulus())
					&& rsapk1.getPublicExponent().equals(rsapk2.getPublicExponent());
		}
		return false;
	}

	private static boolean equalDomainParameters(PublicKeyDataObject pk1, PublicKeyDataObject pk2) {
		ASN1ObjectIdentifier pk1Oid = pk1.getUsage();
		ASN1ObjectIdentifier pk2Oid = pk2.getUsage();
		if (!pk1Oid.equals(pk2Oid)) return false;

		if (pk1Oid.on(EACObjectIdentifiers.id_TA_ECDSA)) {
			ECDSAPublicKey ecdsapk1 = (ECDSAPublicKey) pk1;
			ECDSAPublicKey ecdsapk2 = (ECDSAPublicKey) pk2;
			return ecdsapk1.getPrimeModulusP().equals(ecdsapk2.getPrimeModulusP())
					&& ecdsapk1.getFirstCoefA().equals(ecdsapk2.getFirstCoefA())
					&& ecdsapk1.getSecondCoefB().equals(ecdsapk2.getSecondCoefB())
					&& Arrays.equals(ecdsapk1.getBasePointG(), ecdsapk2.getBasePointG())
					&& ecdsapk1.getOrderOfBasePointR().equals(ecdsapk2.getOrderOfBasePointR())
					&& ecdsapk1.getCofactorF().equals(ecdsapk2.getCofactorF());
		}
		return pk1Oid.on(EACObjectIdentifiers.id_TA_RSA);
	}
}
