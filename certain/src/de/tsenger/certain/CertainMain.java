package de.tsenger.certain;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1ParsingException;
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
import de.tsenger.certain.asn1.eac.RSAPublicKey;
import de.tsenger.tools.FileSystem;
import de.tsenger.tools.HexString;

/**
 * @author Tobias Senger
 * @version 0.5
 *
 */
public class CertainMain {
	
	private static final String version = "0.6 build 140210";

	@Parameter(names = {"--cert","-c"}, variableArity = true, description = "CVCA or DV certificate input files. Parameter can receive multiply values. (e.g. -cert <file1> [<file2> [<file3>] ... ]")
	public List<String> certFileNames;
	
	@Parameter(names = {"--dvreq","-r"}, description = "DV request input file")
	private String dvReqFileName;
	
	@Parameter(names = {"--linkcert","-l"}, description = "Link certificate input file to new CVCA")
	private String linkCertFileName;
	
	@Parameter(names = {"--masterlist","-ml"}, description = "CVCA Master List")
	private String masterListFileName;
	
	@Parameter(names = {"--help", "-h"}, description = "need help?", help = true)
	private boolean help;
	
	@Parameter(names = {"--details", "-d"}, description = "Show more details (full publickey values and signature bytes) on the certificates and requests.")
	private boolean showDetails = false;
	
	@Parameter(names = {"--fingerprint", "-f"}, description = "Show MD5, SHA1, SHA224 and SHA256 printerprint for certificates and requests.")
	private boolean showFingerprints = false;
	
	private CertStorage certStore = null;
	private CVCertificateRequest dvReq = null;
	private CVCertificate linkCert = null;	
	
	private MasterListParser mlParser = null;
		
	private CertParser cvParser = null;
	private CertVerifier verifier;
	

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
		cvParser = new CertParser();
		
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
		
		/** Master List **/
		if (mlParser!=null) {
			printMasterListInfo();
		}

	}

	/**
	 * Read the files which are set via the command line arguments and set the CVCerticate / CVCertificateRequest instances.
	 */
	private void readFilesAndGetCVInstances() {
		byte[] tempBytes;
		CVCertificate tmpCvCert;
		certStore = new CertStorage();
		
		if ((certFileNames!=null)&&(!certFileNames.isEmpty())) {		
			for (Iterator<String> i = certFileNames.iterator(); i.hasNext();) {	
				try {
					tempBytes = FileSystem.readFile(i.next());
					tmpCvCert = CVCertificate.getInstance(tempBytes);
					certStore.putCert(tmpCvCert);
				} catch (ASN1ParsingException e) {
					System.out.println(e.getLocalizedMessage());				
				} catch (IOException e) {
					System.err.println("Error while open file "+e.getMessage());
				}				
			}
		}
		
		if (dvReqFileName!=null) {			
			try {
				tempBytes = FileSystem.readFile(dvReqFileName);
				dvReq = CVCertificateRequest.getInstance(tempBytes);
			} catch (ASN1ParsingException e) {
				System.out.println(e.getLocalizedMessage());				
			} catch (IOException e) {
				System.err.println("Error while open file "+e.getMessage());
			}	
		}
		
		if (linkCertFileName!=null) {
			try {
				tempBytes = FileSystem.readFile(linkCertFileName);
				linkCert = CVCertificate.getInstance(tempBytes);
			} catch (ASN1ParsingException e) {
				System.out.println(e.getLocalizedMessage());				
			} catch (IOException e) {
				System.err.println("Error while open file "+e.getMessage());
			}	
		}
		
		if (masterListFileName!=null) {
			try {
				tempBytes = FileSystem.readFile(masterListFileName);
				mlParser = new MasterListParser(tempBytes);			
			} catch (Exception e) {
				System.err.println("Error while open file "+e.getMessage());
			}	
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
			if (showFingerprints) printFingerprints(cert);
			
			int role = cert.getHolderAuthorizationRole()&0xC0;
			if (role==CertificateHolderAuthorization.CVCA) {
				//TODO this is a CVCA, is there anything to do?
			}
			if (role==CertificateHolderAuthorization.DV_OFFICIAL_DOMESTIC||role==CertificateHolderAuthorization.DV_NON_OFFICIAL_FOREIGN) {
				//TODO this is a DV, is there anything to do?
			}
			if (role==CertificateHolderAuthorization.TERMINAL) {
				//TODO this is a TERMINAL, is there anything to do?
			}
			
			cvParser.setBody(cert.getBody(), true);
			System.out.println(cvParser.getContentString(showDetails));		
			
			if (showDetails) System.out.println("Signature:\n"+HexString.bufferToHex(cert.getSignature(), true));
			
			//verfiy signature		
			String cvcaChrStr = getCvcaChr(cert.getChrString(),3);
			CVCertificate cvcaCert = certStore.getCertByCHR(cvcaChrStr);
			CVCertificate parentCert = certStore.getCertByCHR(cert.getCarString());
			
			if (cvcaCert!=null) {
				try {
					if (!cert.getRoleDescription().equals("CVCA")) // Terminal or DV
					{
						verifier = new CertVerifier(cvcaCert.getBody().getPublicKey(),parentCert.getBody().getPublicKey());
					}
					else {	// CVCA certifcate
						verifier = new CertVerifier(cvcaCert.getBody().getPublicKey());
					}
					System.out.println("Signature is " + (verifier.hasValidSignature(cert) ? "VALID" : "!!! INVALID !!!"));
				} catch (Exception e) {
					System.out.println("Couldn't verifiy signature: " + e.getLocalizedMessage());
				}
			} else {
				System.out.println("Can't check signature. No matching certificate (chain) available.");
			}
		}
	}


	/**
	 * Check the DV request
	 */
	private void checkDvRequest() {
		cvParser.setBody(dvReq.getCertificateBody(), false);
		
		printBanner("Request for "+dvReq.getCertificateBody().getChrString());
		if (showFingerprints) printFingerprints(dvReq);
		
		System.out.println(cvParser.getContentString(showDetails));
		
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
		
		
		if (showDetails) System.out.println("Inner Signature:\n"+HexString.bufferToHex(dvReq.getInnerSignature(),true));
		
		//verify inner signature
		try {
			verifier = new CertVerifier(dvReq.getCertificateBody().getPublicKey());
			System.out.println("Inner Signature is " + (verifier.hasValidSignature(dvReq) ? "VALID" : "!!! INVALID !!!"));
		} catch (Exception e) {
			System.out.println("Verfifier throws exception: " + e.getLocalizedMessage());
		}	
		
		if (dvReq.hasOuterSignature()) {
			String outerCarString = dvReq.getOuterCarStr();
			System.out.println("\nOuter CAR: "+outerCarString);
			
			if (showDetails) System.out.println("Outer Signature:\n"+HexString.bufferToHex(dvReq.getOuterSignature(),true));
			
			CVCertificate outerCarCert = certStore.getCertByCHR(outerCarString);
							
			if (outerCarCert!=null) {
				// If outer CAR is a DV cert get the matching CVCA cert
				int parentCertRole = outerCarCert.getHolderAuthorizationRole()&0xC0;
				if (parentCertRole==CertificateHolderAuthorization.DV_OFFICIAL_DOMESTIC||parentCertRole==CertificateHolderAuthorization.DV_NON_OFFICIAL_FOREIGN) {
					String cvcaChrString = getCvcaChr(outerCarString,3);
					CVCertificate cvcaCert = certStore.getCertByCHR(cvcaChrString);
					
					if (cvcaCert!=null) {
						try {
							verifier = new CertVerifier(cvcaCert.getBody().getPublicKey(),outerCarCert.getBody().getPublicKey());
							System.out.println("Outer Signature is " + (verifier.hasValidOuterSignature(dvReq) ? "VALID" : "!!! INVALID !!!"));
						} catch (Exception e) {
							System.out.println("Verfifier throws exception: " + e.getLocalizedMessage());
						}
					} else {
						System.out.println("Can't check outer signature without matching DV and CVCA certifcate.");
					}
					
				} else if (parentCertRole==CertificateHolderAuthorization.CVCA) { // Outer Car is CVCA cert  
					try {
						verifier = new CertVerifier(outerCarCert.getBody().getPublicKey());
						System.out.println("Outer Signature is " + (verifier.hasValidOuterSignature(dvReq) ? "VALID" : "!!! INVALID !!!"));
					} catch (Exception e) {
						System.out.println("Verfifier throws exception: " + e.getLocalizedMessage());
					}
				}
				
			} else {
				System.out.println("Can't check outer signature without matching parent DV and/or CVCA certifcate.");
			}
		} else System.out.println("No outer signature");
	}
	
	/**
	 * Check the Link certificate
	 */
	private void checkLinkCert() {
		printBanner("Link "+linkCert.getCarString()+" -> "+linkCert.getChrString());
		if (showFingerprints) printFingerprints(linkCert);
		
		//Find machting Public Key
		CVCertificate cvca1 = certStore.getCertByCHR(linkCert.getChrString());
		if (cvca1 != null) {
			boolean hasEqualPk = equalPublicKeys(linkCert.getBody().getPublicKey(), cvca1.getBody().getPublicKey());
			System.out.println((hasEqualPk ? "The public key in this linkcert is equal to the public key in\n"
					: "The public key in this linkcert IS NOT EQUAL to the public key in\n") + cvca1.getCarString() + "\n");
		} else {
			System.out.println("No CVCA was given. Can't check matching public point to any CVCA.\n");
		}
		
		cvParser.setBody(linkCert.getBody(), true);				
		System.out.println(cvParser.getContentString(showDetails));
				
		//print Signature
		if (showDetails) System.out.println("Signature:\n"+HexString.bufferToHex(linkCert.getSignature(),true));
				
		//verify signature
		CVCertificate cvca2 = certStore.getCertByCHR(linkCert.getCarString());
		if (cvca2!=null) {
			try {
				verifier = new CertVerifier(cvca2.getBody().getPublicKey());
				System.out.println("Signature is " + (verifier.hasValidSignature(linkCert) ? "VALID" : "!!! INVALID !!!"));
			} catch (Exception e) {
				System.out.println("Verfifier throws exception: " + e.getLocalizedMessage());
			}
		} else {
			System.out.println("Can't check signature. No matching CVCA certificate available.");
		}
	}
	
	/**
	 * Show Master List Infos
	 */
	private void printMasterListInfo() {
		List<Certificate> certs = mlParser.getCertificates();
		int i=0;
		
		System.out.println("Master List contains "+certs.size()+" CSCA certificates.");
		
//		for (Certificate cert : certs) {
//			printBanner("Cert no."+(++i));
//			System.out.println(cert.toString());
//		}
		    
	}
	


	/**
	 * Rekursive Suche nach dem CVCA CHR
	 * @param chrStr Start CHR
	 * @param maxDepth begrenzt die Rekursionstiefe um Endlosschleifen zu vermeiden
	 * @return CHR des CVCA Zertifikats
	 */
	private String getCvcaChr(String chrStr, int maxDepth) {
		
		if (maxDepth==0) return null;
		
		CVCertificate cert = certStore.getCertByCHR(chrStr);
		if (cert==null) return null;
		
		String role = cert.getRoleDescription();
		String carStr = cert.getCarString();	
		
		if (role=="CVCA") return cert.getChrString();
		else if (carStr==null) return null;
		
		else return getCvcaChr(carStr, --maxDepth);
	}
	
	
	private void printBanner(String name) {
		System.out.println("\n---------------------------------------------------");
		System.out.println("Parsing " + name);
		System.out.println("---------------------------------------------------");
	}
	
	
	
	private void printFingerprints(CVCertificateRequest req) {
		try {
			printFingerprints(req.getEncoded());
		} catch (IOException e) {
			System.out.println("Couldn't calculate the fingerprints: "+e.getLocalizedMessage());
		}
	}
	
	private void printFingerprints(CVCertificate cert) {
		try {
			printFingerprints(cert.getEncoded());
		} catch (IOException e) {
			System.out.println("Couldn't calculate the fingerprints: "+e.getLocalizedMessage());
		}
	}

	private void printFingerprints(byte[] bytesToHash) {
		
		HashCalculator hashes = new HashCalculator(bytesToHash);
		
		System.out.println("Fingerprint MD5:");
		try {			
			System.out.println(HexString.bufferToHex(hashes.getMD5(), true));
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getLocalizedMessage());
		}
		
		System.out.println("Fingerprint SHA1:");
		try {			
			System.out.println(HexString.bufferToHex(hashes.getSHA1(), true));
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getLocalizedMessage());
		}
		
		System.out.println("Fingerprint SHA224:");
		try {			
			System.out.println(HexString.bufferToHex(hashes.getSHA224(), true));
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getLocalizedMessage());
		}
		
		System.out.println("Fingerprint SHA256:");
		try {			
			System.out.println(HexString.bufferToHex(hashes.getSHA256(), true)+"\n");
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getLocalizedMessage());
		}		
	}
	
	private boolean equalPublicKeys(PublicKeyDataObject pk1, PublicKeyDataObject pk2) {
		ASN1ObjectIdentifier pk1Oid = pk1.getUsage();
		ASN1ObjectIdentifier pk2Oid = pk2.getUsage();
		if (!pk1Oid.equals(pk2Oid)) return false;

		if (pk1Oid.on(EACObjectIdentifiers.id_TA_ECDSA)) {
			ECDSAPublicKey ecdsapk1 = (ECDSAPublicKey) pk1;
			ECDSAPublicKey ecdsapk2 = (ECDSAPublicKey) pk2;
			if (!Arrays.equals(ecdsapk1.getPublicPointY(), ecdsapk2.getPublicPointY())) return false;
			return true;
		} else if (pk1Oid.on(EACObjectIdentifiers.id_TA_RSA)) {
			RSAPublicKey rsapk1 = (RSAPublicKey) pk1;
			RSAPublicKey rsapk2 = (RSAPublicKey) pk2;
			if (!rsapk1.getModulus().equals(rsapk2.getModulus())) return false;
			if (!rsapk1.getPublicExponent().equals(rsapk2.getPublicExponent())) return false;
			return true;
		}
		return false;
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
	
	private final byte[] data = new byte[] {0x54,0x68,0x65,0x72,0x65,0x20,0x69,0x73,0x20,0x6E,0x6F,0x20,0x68,0x65,0x6C,0x70,0x21,0x20,0x41,0x73,0x6B,0x20,0x54,0x6F,0x62,0x69,0x61,0x73,0x20,0x3A,0x29};
	

}
