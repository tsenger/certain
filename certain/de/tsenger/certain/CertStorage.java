package de.tsenger.certain;

import java.util.HashMap;
import java.util.Set;

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
		CVCertificate cert = certs.get(chrStr);
		if (cert==null) return null;
		CertificationAuthorityReference car = cert.getAuthorityReference();
		return car.getCountryCode()+car.getHolderMnemonic()+car.getSequenceNumber();
	}
	
	public String getCarString(CertificateHolderReference chr) {
		String chrStr = chr.getCountryCode()+chr.getHolderMnemonic()+chr.getSequenceNumber();
		return getCarString(chrStr);
	}
	
	public CVCertificate getCertByCHR(CertificateHolderReference chr) {
		String chrStr = chr.getCountryCode()+chr.getHolderMnemonic()+chr.getSequenceNumber();
		return certs.get(chrStr);
	}
	
	public int getSize() {
		return certs.size();
	}
	
	public boolean isEmpty() {
		return certs.isEmpty();
	}
	
	public Set<String> getKeys() {
		return certs.keySet();
	}
	
	public boolean containsKey(String chrStr) {
		return certs.keySet().contains(chrStr);
	}
	
	public CVCertificate getCertByCHR(String chrStr) {
		return certs.get(chrStr);
	}

}
