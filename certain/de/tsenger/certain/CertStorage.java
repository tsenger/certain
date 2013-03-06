package de.tsenger.certain;

import java.util.HashMap;

import de.tsenger.certain.asn1.eac.CVCertificate;
import de.tsenger.certain.asn1.eac.CertificateHolderReference;
import de.tsenger.certain.asn1.eac.CertificationAuthorityReference;

public class CertStorage {
	
	//We use the CHR string as key
	private final HashMap<String, CVCertificate> certs = new HashMap<String, CVCertificate> (6);


	public String storeCert(CVCertificate cvCert) {
		CertificateHolderReference chr = cvCert.getHolderReference();
		String chrStr = chr.getCountryCode()+chr.getHolderMnemonic()+chr.getSequenceNumber();
		certs.put(chrStr, cvCert);
		return chrStr;
	}	
	
	public String getCarString(String chrStr) {
		CertificationAuthorityReference car = certs.get(chrStr).getAuthorityReference();
		return car.getCountryCode()+car.getHolderMnemonic()+car.getSequenceNumber();
	}
	
	public CVCertificate getCertByCHR(CertificateHolderReference chr) {
		String chrStr = chr.getCountryCode()+chr.getHolderMnemonic()+chr.getSequenceNumber();
		return certs.get(chrStr);
	}
	
	public CVCertificate getCertByCHR(String chrStr) {
		return certs.get(chrStr);
	}

}
