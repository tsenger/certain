package de.tsenger.certain;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

/**
 * Validator for CMS SignedData objects which verifies the signature and that
 * the certificate path is valid as well.
 */
public class SignedDataVerifier {
	private final X509Certificate trustAnchor;

	/**
	 * Base constructor.
	 * 
	 * @param trustAnchor
	 *            the root certificate that certificate paths must extend from.
	 */
	public SignedDataVerifier(X509Certificate trustAnchor) {
		this.trustAnchor = trustAnchor;
	}

	/**
	 * Verify the passed in CMS signed data, return false on failure.
	 * 
	 * @param cmsData
	 *            a CMSSignedData object.
	 * @return true if signature checks out, false if there is a problem with
	 *         the signature or the path to its verifying certificate.
	 * @throws CertificateException
	 * @throws CMSException
	 * @throws OperatorCreationException
	 */
	public boolean signatureVerified(CMSSignedData cmsData) throws CertificateException, OperatorCreationException, CMSException {

		Store<X509CertificateHolder> certs = cmsData.getCertificates();
		SignerInformationStore signers = cmsData.getSignerInfos();

		Collection<?> c = signers.getSigners();
		Iterator<?> it = c.iterator();

		SignerInformation signer = (SignerInformation) it.next();
		
		

		JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
		converter.setProvider("BC");

		ArrayList<X509CertificateHolder> certificateHolders = (ArrayList<X509CertificateHolder>) certs.getMatches(null);

		for (X509CertificateHolder holder : certificateHolders) {
			
			X509Certificate cert = converter.getCertificate(holder);
			
			

			if (signer.getVersion()==1) {		
				String signerIssuer = signer.getSID().getIssuer().toString();
				Integer signerSerialNo = signer.getSID().getSerialNumber().intValue();
				
				String certIssuer = cert.getIssuerX500Principal().getName();
				Integer certSerialNo = cert.getSerialNumber().intValue();
				
				if (signerIssuer.equals(certIssuer)&&signerSerialNo==certSerialNo) {
					return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
				}
			}
			
			if (signer.getVersion()==3) {
				DEROctetString oct = (DEROctetString) DEROctetString.getInstance(cert.getExtensionValue("2.5.29.14"));
				SubjectKeyIdentifier certSubjectKeyId = SubjectKeyIdentifier.getInstance(oct.getOctets());
				byte[] signerSubjectKeyId = signer.getSID().getSubjectKeyIdentifier();
				
				if (Arrays.equals(certSubjectKeyId.getKeyIdentifier(), signerSubjectKeyId)) {
					return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
				}
			}

		}
		return false;
	}
}