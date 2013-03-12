package de.tsenger.certain;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Security;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;

import de.tsenger.certain.asn1.eac.CVCertificate;
import de.tsenger.certain.asn1.eac.CVCertificateRequest;
import de.tsenger.certain.asn1.eac.CertificateHolderAuthorization;
import de.tsenger.certain.asn1.eac.EACObjectIdentifiers;
import de.tsenger.certain.asn1.eac.ECDSAPublicKey;
import de.tsenger.certain.asn1.eac.PublicKeyDataObject;

/**
 * @author Tobias Senger
 * @version 0.3
 *
 */
public class CertainMain {
	
	private static final String version = "0.3";

	@Parameter(names = {"-cert","-c"}, variableArity = true, description = "CVCA or DV certificate input files. Parameter can receive multiply values. (e.g. -cert <file1> [<file2> [<file3>] ... ]")
	public List<String> certFileNames;
	
	@Parameter(names = {"-dvreq","-r"}, description = "DV request input file")
	private String dvReqFileName;
	
	@Parameter(names = {"-linkcert","-l"}, description = "link certificate to new CVCA")
	private String linkCertFileName;
	
	@Parameter(names = { "--help", "-h" }, description = "need more help?", help = true)
	private boolean help;

	
	private CertStorage certStore = null;
	private CVCertificateRequest dvReq = null;
	private CVCertificate linkCert = null;	
		
	private CertainParser cvParser = null;
	private CertainVerifier verifier;
	

	public static void main(String[] args) throws IOException {
		System.out.println("certain (v"+ version + ") - a cv certificate parser");
		Security.addProvider(new BouncyCastleProvider());
		CertainMain cm = new CertainMain();
		
		final JCommander jcmdr = new JCommander(cm);
		try {
			jcmdr.parse(args);
			if (args.length==0) throw new ParameterException("No arguments given");
			cm.run();
		} catch (ParameterException e) {
			// handling of wrong arguments
			System.out.println(e.getMessage());
			jcmdr.setProgramName("certain");
			jcmdr.usage();
		}
	}

	/**
	 * 
	 */
	public void run() {
		if (help) System.out.println(new String(data));
		
		readFilesAndGetCVInstances();
		cvParser = new CertainParser();
		
		/** CV-Certifikates from certStore **/
		if (!certStore.isEmpty()) {
			checkCerts();
		}
		
		
		/** CV-Request **/
		if (dvReq!=null) {
			checkDvRequest();
		}
		
		
		/** Link Certificate **/
		if (linkCert!=null) {	
			checkLinkCert();
		}

	}
	
	/**
	 * Read the files which are set via the command line arguments and set the CVCerticate / CVCertificateRequest instances.
	 */
	private void readFilesAndGetCVInstances() {
		byte[] tempCvcBytes;
		certStore = new CertStorage();
		
		if ((certFileNames!=null)&&(!certFileNames.isEmpty())) {		
			for (Iterator<String> i = certFileNames.iterator(); i.hasNext();) {	
				File cvcaCertFile = new File(i.next());
				tempCvcBytes = readFile(cvcaCertFile);	
				certStore.putCert(CVCertificate.getInstance(tempCvcBytes));
			}
		}
		
		if (dvReqFileName!=null) {
			tempCvcBytes = readFile(new File(dvReqFileName));
			dvReq = CVCertificateRequest.getInstance(tempCvcBytes);
		}
		
		if (linkCertFileName!=null) {
			tempCvcBytes = readFile(new File(linkCertFileName));
			linkCert = CVCertificate.getInstance(tempCvcBytes);
		}
		
	}
	
	/**
	 * Check all CVCA and DV certificates which are stored in the certStore
	 */
	private void checkCerts() {
		for (Iterator<String> i = certStore.getKeys().iterator(); i.hasNext();) {	
			
			String chrStr = i.next();				
			CVCertificate cert = certStore.getCertByCHR(chrStr);
			
			printBanner(chrStr);
			
			int role = cert.getHolderAuthorizationRole()&0xC0;
			if (role==CertificateHolderAuthorization.CVCA) {
				//TODO this is a CVCA, is there anything to do?
			}
			if (role==CertificateHolderAuthorization.DV_OFFICIAL_DOMESTIC||role==CertificateHolderAuthorization.DV_NON_OFFICIAL_FOREIGN) {
				//TODO this is a DV, is there anything to do?
			}
			
			cvParser.setBody(cert.getBody(), true);
			System.out.println(cvParser.getContentString());
			verifySignatureAndPrintResult(cert);
		}
	}

	/**
	 * Check the DV request
	 */
	private void checkDvRequest() {
		cvParser.setBody(dvReq.getCertificateBody(), false);
		
		printBanner("Request for "+dvReq.getCertificateBody().getChrString());
		System.out.println(cvParser.getContentString());
		
		// Check if Domain Parameters are the same as in the CVCA
		if (certFileNames!=null&&!certFileNames.isEmpty()) {
			String cvcaChrStr = getCvcaChr(dvReq.getCertificateBody().getCarString(), 3);
			if (cvcaChrStr==null) {
				System.out.println("Can't find a matching parent CVCA certifcate to this request.");
			}
			if (!equalDomainParameters(certStore.getCertByCHR(cvcaChrStr).getBody().getPublicKey(), dvReq.getCertificateBody().getPublicKey())) {
				System.out.println("Domain parameters of this request don't match domain parameters of any provided CVCA certificate.");
			}
		}
		
		//verify inner signature
		try {
			verifier = new CertainVerifier(dvReq.getCertificateBody().getPublicKey());
			System.out.println("Inner Signature is " + (verifier.hasValidSignature(dvReq) ? "VALID" : "!!! INVALID !!!"));
		} catch (Exception e) {
			System.out.println("Verfifier throws exception: " + e.getLocalizedMessage());
		}	
		
		if (dvReq.hasOuterSignature()) {
			String outerCarString = dvReq.getOuterCarStr();
			System.out.println("\nOuter CAR:"+outerCarString);
			
			CVCertificate outerCarCert = certStore.getCertByCHR(outerCarString);
							
			if (outerCarCert!=null) {
				// If outer CAR is a DV cert get the matching CVCA cert
				int parentCertRole = outerCarCert.getHolderAuthorizationRole()&0xC0;
				if (parentCertRole==CertificateHolderAuthorization.DV_OFFICIAL_DOMESTIC||parentCertRole==CertificateHolderAuthorization.DV_NON_OFFICIAL_FOREIGN) {
					String cvcaChrString = getCvcaChr(outerCarString,3);
					CVCertificate cvcaCert = certStore.getCertByCHR(cvcaChrString);
					
					if (cvcaCert!=null) {
						try {
							verifier = new CertainVerifier(cvcaCert.getBody().getPublicKey(),outerCarCert.getBody().getPublicKey());
							System.out.println("Outer Signature is " + (verifier.hasValidOuterSignature(dvReq) ? "VALID" : "!!! INVALID !!!"));
						} catch (Exception e) {
							System.out.println("Verfifier throws exception: " + e.getLocalizedMessage());
						}
					} else {
						System.out.println("Can't check outer signature without matching DV and CVCA certifcate.");
					}
					
				} else if (parentCertRole==CertificateHolderAuthorization.CVCA) { // Outer Car is CVCA cert  
					try {
						verifier = new CertainVerifier(outerCarCert.getBody().getPublicKey());
						System.out.println("Outer Signature is " + (verifier.hasValidOuterSignature(dvReq) ? "VALID" : "!!! INVALID !!!"));
					} catch (Exception e) {
						System.out.println("Verfifier throws exception: " + e.getLocalizedMessage());
					}
				}
				
			} else {
				System.out.println("Can't check outer signature without matching parent DV and/or CVCA certifcate.");
			}
		}
	}
	
	/**
	 * Check the Link certificate
	 */
	private void checkLinkCert() {
		printBanner("Link "+linkCert.getCarString()+" -> "+linkCert.getChrString());
		
		cvParser.setBody(linkCert.getBody(), true);				
		System.out.println(cvParser.getContentString());
		
		//verify signature
		CVCertificate cvca = certStore.getCertByCHR(linkCert.getCarString());
		try {
			verifier = new CertainVerifier(cvca.getBody().getPublicKey());
			System.out.println("Signature is " + (verifier.hasValidSignature(linkCert) ? "VALID" : "!!! INVALID !!!"));
		} catch (Exception e) {
			System.out.println("Verfifier throws exception: " + e.getLocalizedMessage());
		}	
	}

	
	private void verifySignatureAndPrintResult(CVCertificate cert) {
		
		String cvcaChrStr = getCvcaChr(cert.getCarString(),3);
		CVCertificate cvcaCert = certStore.getCertByCHR(cvcaChrStr);
		if (cvcaCert!=null) {
			try {		
				verifier = new CertainVerifier(cvcaCert.getBody().getPublicKey());
				System.out.println("Signature is " + (verifier.hasValidSignature(cert) ? "VALID" : "!!! INVALID !!!"));
			} catch (Exception e) {
				System.out.println("Couldn't verifiy signature: " + e.getLocalizedMessage());
			}
		} else {
			System.out.println("Can't check signature. No matching CVCA certificate available.");
		}
	}
	

	/**
	 * Rekursive Suche nach dem CVCA CHR
	 * @param chrStr Start CHR
	 * @param maxDepth begrenzt die Rekursionstiefe um Endlosschleifen zu vermeiden
	 * @return CHR des CVCA Zertifikats
	 */
	private String getCvcaChr(String chrStr, int maxDepth) {
		if (maxDepth==0) return null;
		String carStr = certStore.getCarString(chrStr);
		if (carStr == null) return null;
		if (carStr.equals(chrStr)) return chrStr;
		else getCvcaChr(carStr, maxDepth--);
		return carStr;
	}

	
	private void printBanner(String name) {
		System.out.println("\n\n---------------------------------------------------");
		System.out.println("Parsing " + name);
		System.out.println("---------------------------------------------------");
	}
	
	private boolean equalDomainParameters(PublicKeyDataObject pk1, PublicKeyDataObject pk2) {
		ASN1ObjectIdentifier pk1Oid = pk1.getUsage();
		ASN1ObjectIdentifier pk2Oid = pk2.getUsage();
		if (!pk1Oid.equals(pk2Oid)) return false;

		if (pk1Oid.on(EACObjectIdentifiers.id_TA_ECDSA)) {
			ECDSAPublicKey ecdsapk1 = (ECDSAPublicKey) pk1;
			ECDSAPublicKey ecdsapk2 = (ECDSAPublicKey) pk2;
			if (!ecdsapk1.getPrimeModulusP().equals(ecdsapk2.getPrimeModulusP())) return false;
			if (!ecdsapk1.getFirstCoefA().equals(ecdsapk2.getFirstCoefA())) return false;
			if (!ecdsapk1.getSecondCoefB().equals(ecdsapk2.getSecondCoefB())) return false;
			if (!Arrays.equals(ecdsapk1.getBasePointG(), ecdsapk2.getBasePointG())) return false;
			if (!ecdsapk1.getOrderOfBasePointR().equals(ecdsapk2.getOrderOfBasePointR())) return false;
			if (!ecdsapk1.getCofactorF().equals(ecdsapk2.getCofactorF())) return false;
			return true;
		} else if (pk1Oid.on(EACObjectIdentifiers.id_TA_RSA)) {
			return true;
		}
		return false;
	}	
	
	private final byte[] data = new byte[] {0x54,0x68,0x65,0x72,0x65,0x20,0x69,0x73,0x20,0x6E,0x6F,0x20,0x68,0x65,0x6C,0x70,0x21,0x20,0x41,0x73,0x6B,0x20,0x54,0x6F,0x62,0x69,0x61,0x73,0x20,0x3A,0x2D,0x29};
	

	/**
	 * Get the content of the given file as byte-Array
	 * 
	 * @param filename path and filename
	 * @return binary content of the selected file
	 */
	private byte[] readFile(File binFile){
		FileInputStream in = null;
		byte buffer[] = new byte[(int) binFile.length()];

		try {
			in = new FileInputStream(binFile);
			in.read(buffer, 0, buffer.length);
			in.close();
		} catch (IOException e) {
			System.err.println("Erro while open file "+binFile.getName()+": "+e.getMessage());
			return null;
		}

		return buffer;
	}

}
