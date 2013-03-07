package de.tsenger.certain;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Security;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import de.tsenger.certain.asn1.eac.CVCertificate;
import de.tsenger.certain.asn1.eac.CVCertificateRequest;
import de.tsenger.certain.asn1.eac.CertificateHolderAuthorization;
import de.tsenger.certain.asn1.eac.CertificationAuthorityReference;
import de.tsenger.certain.asn1.eac.EACObjectIdentifiers;
import de.tsenger.certain.asn1.eac.ECDSAPublicKey;
import de.tsenger.certain.asn1.eac.PublicKeyDataObject;

public class CertainMain {
	
	private static final String version = "0.2";

	@Option(name = "-cvca", usage = "CVCA certificate input file", metaVar = "<file>", multiValued=true)
	private List<File> cvcaCertFiles;

	@Option(name = "-dv", usage = "DV certificate input file", metaVar = "<file>")
	private File dvCertFile;

	@Option(name = "-dvreq", usage = "DV request input file", metaVar = "<file>")
	private File dvReqFile;
	
	@Option(name ="-linkcert", usage = "link certificate to for new CVCA", metaVar = "<file>")
	private File linkCertFile;
	
	
	
	private CVCertificateRequest dvReq = null;
	
	private CertainParser cvParser = null;
	
	private CertStorage certStore = null;

	private CertainVerifier verifier;


	/**
	 * @param args
	 * @throws IOException
	 * @throws ParseException
	 */
	public static void main(String[] args) throws IOException {
		System.out.println("certain (v"+ version + ") - a cv certificate parser");
		Security.addProvider(new BouncyCastleProvider());
		CertainMain cm = new CertainMain();
		
		CmdLineParser parser = new CmdLineParser(cm);
		try {
			parser.parseArgument(args);
			if (args.length==0) throw new CmdLineException(parser, "No arguments given");
			cm.run();
		} catch (CmdLineException e) {
			// handling of wrong arguments
			System.out.println(e.getMessage());
			parser.printUsage(System.out);
		}
	}

	public void run() {
		
		readFilesToCVC();
		cvParser = new CertainParser(certStore);
		
		if (!certStore.isEmpty()) {
			for (Iterator<String> i = certStore.getKeys().iterator(); i.hasNext();) {			
				String chr = i.next();
				
				CVCertificate cert = certStore.getCertByCHR(chr);
				
				int role = cert.getHolderAuthorizationRole()&0xC0;
				if (role==CertificateHolderAuthorization.CVCA) {
					//TODO this is a CVCA, so what shall we do?
				}
				if (role==CertificateHolderAuthorization.DV_DOMESTIC||role==CertificateHolderAuthorization.DV_FOREIGN) {
					//TODO this is a DV, so what shall we do?
				}
				
				printBanner(chr, true);
				System.out.println(cvParser.parse(chr));
				printSignatureVerification(cert);
				printBanner(chr, false);
			}
		}
		
//		if (dvCertFile!=null) {						
//			CVCertificate cert = certStore.getCertByCHR(dvChrStr);
//			
//			int role = cert.getHolderAuthorizationRole()&0xC0;
//			if (!(role==CertificateHolderAuthorization.DV_DOMESTIC||role==CertificateHolderAuthorization.DV_FOREIGN)) {
//				System.out.println(dvCertFile.getName()+" is not a DV certificate!");
//			}
//			
//			printBanner(dvCertFile.getName(), true);
//			System.out.println(cvParser.parse(dvChrStr));			
//			printSignatureVerification(cert);			
//			printBanner(dvCertFile.getName(), false);
//		}
		
		if (dvReq!=null) {			
			printBanner(dvReqFile.getName(), true);

			CertainParser reqParser = new CertainParser(dvReq.getCertificateBody(), false);
			printContent(reqParser);
			
			if (!cvcaCertFiles.isEmpty()) {
				String cvcaChrStr = getCvcaChr(dvReq.getCertificateBody().getCarString(), 3);
				if (cvcaChrStr==null) {
					System.out.println("Can't find parent a matching parent CVCA certifcate to this request.");
				}
				if (!equalDomainParameters(certStore.getCertByCHR(cvcaChrStr).getBody().getPublicKey(), dvReq.getCertificateBody().getPublicKey())) {
					System.out.println("Domain parameters of this request don't match domain parameters of any provided CVCA certificate.");
				}
			}
			
			try {
				verifier = new CertainVerifier(dvReq.getCertificateBody().getPublicKey());
				System.out.println("Inner Signature is " + (verifier.hasValidSignature(dvReq) ? "VALID" : "!!! INVALID !!!"));
			} catch (Exception e) {
				System.out.println("Verfifier throws exception: " + e.getLocalizedMessage());
			}	
			
			if (dvReq.hasOuterSignature()) {
				CertificationAuthorityReference outerCar = dvReq.getOuterCAR();
				String outerCarString = outerCar.getCountryCode()+outerCar.getHolderMnemonic()+outerCar.getSequenceNumber();
				System.out.println("\nOuter CAR:"+outerCarString);
				
				CVCertificate parentCert = certStore.getCertByCHR(outerCarString);
				CVCertificate parentCvcaCert = null;
								
				if (parentCert!=null) {
					int parentCertRole = parentCert.getHolderAuthorizationRole()&0xC0;
					
					// If outer CAR is a DV cert get the matching CVCA cert
					if (parentCertRole==CertificateHolderAuthorization.DV_DOMESTIC||parentCertRole==CertificateHolderAuthorization.DV_FOREIGN) {
						CertificationAuthorityReference parentCertCar = parentCert.getAuthorityReference();
						String parentCertCarString = parentCertCar.getCountryCode()+parentCertCar.getHolderMnemonic()+parentCertCar.getSequenceNumber();
						parentCvcaCert = certStore.getCertByCHR(parentCertCarString);
						
						if (parentCvcaCert!=null) {
							try {
								verifier = new CertainVerifier(parentCvcaCert.getBody().getPublicKey(),parentCert.getBody().getPublicKey());
								System.out.println("Outer Signature is " + (verifier.hasValidOuterSignature(dvReq) ? "VALID" : "!!! INVALID !!!"));
							} catch (Exception e) {
								System.out.println("Verfifier throws exception: " + e.getLocalizedMessage());
							}
						} else {
							System.out.println("Can't check outer signature without matching parent DV and/or CVCA certifcate.");
						}
						
					} else if (parentCertRole==CertificateHolderAuthorization.CVCA) { // Outer Car is CVCA cert  
						try {
							verifier = new CertainVerifier(parentCert.getBody().getPublicKey());
							System.out.println("Outer Signature is " + (verifier.hasValidOuterSignature(dvReq) ? "VALID" : "!!! INVALID !!!"));
						} catch (Exception e) {
							System.out.println("Verfifier throws exception: " + e.getLocalizedMessage());
						}
					}
					
				} else {
					System.out.println("Can't check outer signature without matching parent DV and/or CVCA certifcate.");
				}
			}
			printBanner(dvReqFile.getName(), false);
		}
		
		if (linkCertFile!=null) {
			//TODO What shall we do with the Link cert
		}
	}
	
	private void printSignatureVerification(CVCertificate cert) {
//		String carStr = certStore.getCarString(cert.getChrString());
//		CVCertificate cvcaCert = certStore.getCertByCHR(carStr);
		
		String cvcaChrStr = getCvcaChr(cert.getChrString(),3);
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
		return null;
	}

	
	private void printBanner(String fileName, boolean start) {
		System.out.println("---------------------------------------------------");
		if (start) System.out.print("Start ");
		else System.out.print("End ");
		System.out.println("parsing " + fileName);
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

	
	private void readFilesToCVC() {
		byte[] tempCvcBytes;
		certStore = new CertStorage();
		
		if ((cvcaCertFiles!=null)&&(!cvcaCertFiles.isEmpty())) {		
			for (Iterator<File> i = cvcaCertFiles.iterator(); i.hasNext();) {	
				File cvcaCertFile = i.next();
				tempCvcBytes = readFile(cvcaCertFile);	
				certStore.storeCert(CVCertificate.getInstance(tempCvcBytes));
			}
		}
		
		if (dvCertFile!=null) {
			tempCvcBytes = readFile(dvCertFile);
			certStore.storeCert(CVCertificate.getInstance(tempCvcBytes));
		}
		
		if (dvReqFile!=null) {
			tempCvcBytes = readFile(dvReqFile);
			dvReq = CVCertificateRequest.getInstance(tempCvcBytes);
		}
		
	}

	private void printContent(CertainParser parser) {
		System.out.print("Certificate Authority Reference (CAR): ");
		System.out.println(parser.getCarString()+"\n");
		
		System.out.println("Public Key");
		System.out.println(parser.getPublicKeyString()+"\n");

		System.out.print("Certificate Holder Reference (CHR): ");
		System.out.println(parser.getChrString()+"\n");

		if (parser.isCertificate) {
			System.out.println("Certificate Holder Authorization Template (CHAT)");
			System.out.print("Terminal Type: ");
			System.out.println(parser.getTerminalType());
			System.out.print("Role: ");
			System.out.println(parser.getCertificateRole());
			System.out.print("Authorizations: ");
			System.out.println(parser.getAuthorizationBitString());
			System.out.println(parser.getAuthorizationString()+"\n");
		
			System.out.print("Certificate Effective Date: ");
			System.out.println(parser.getEffectiveDateString());
			System.out.print("Certificate Expiration Date: ");
			System.out.println(parser.getExpirationDateString()+"\n");
		}
	}

	

	/**
	 * Get the content of the given file
	 * 
	 * @param filename
	 *            path and filename
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
