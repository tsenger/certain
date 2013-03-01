package de.tsenger.certain;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Security;
import java.text.ParseException;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import de.tsenger.certain.asn1.eac.CVCertificate;
import de.tsenger.certain.asn1.eac.CVCertificateRequest;
import de.tsenger.certain.asn1.eac.CertificateHolderReference;
import de.tsenger.certain.asn1.eac.CertificationAuthorityReference;
import de.tsenger.certain.asn1.eac.EACObjectIdentifiers;
import de.tsenger.certain.asn1.eac.ECDSAPublicKey;
import de.tsenger.certain.asn1.eac.PublicKeyDataObject;

public class CertainMain {

	@Option(name = "-cvca", usage = "CVCA certificate input file")
	private File cvcaCertFile;

	@Option(name = "-dv", usage = "DV certificate input file")
	private File dvCertFile;

	@Option(name = "-dvreq", usage = "DV request input file")
	private File dvReqFile;

	private CVCertificate cvcaCert = null;
	private CVCertificate dvCert = null;
	private CVCertificateRequest dvReq = null;
	private CertainVerifier verifier = null;
	
	private CertainParser cvcaParser = null;
	private CertainParser dvParser = null;
	private CertainParser reqParser = null;

	/**
	 * @param args
	 * @throws IOException
	 * @throws ParseException
	 */
	public static void main(String[] args) throws IOException {
		Security.addProvider(new BouncyCastleProvider());
		CertainMain cm = new CertainMain();

		CmdLineParser parser = new CmdLineParser(cm);
		try {
			parser.parseArgument(args);
			if (args.length==0) throw new CmdLineException(parser, "No arguments given");
			cm.run();
		} catch (CmdLineException e) {
			// handling of wrong arguments
			System.err.println(e.getMessage());
			parser.printUsage(System.err);
		}
	}

	public void run() {

		readFilesToCVC();
		
		if (cvcaCert!=null) {			

			System.out.println("--- start parsing of "+ cvcaCertFile.getName()+" ---");
			
			try {
				cvcaParser = new CertainParser(cvcaCert.getBody(), true);
			} catch (CVParserException e) {
				System.out.println(e.getMessage());
			}
			
			String role = cvcaParser.getCertificateRole();
			if (!(role.equals("CVCA"))) {
				System.out.println(cvcaCertFile.getName()+" is not a CVCA certificate. Found "+role);
				return;
			}
			
			printContent(cvcaParser);
			
			try {
				verifier = new CertainVerifier(cvcaCert.getBody().getPublicKey());
				System.out.println("Signature is " + (verifier.hasValidSignature(cvcaCert) ? "VALID" : "!!! INVALID !!!"));
			} catch (Exception e) {
				System.out.println("Couldn't verifiy signature: " + e.getLocalizedMessage());
			}
			
			System.out.println("--- end parsing of "+ cvcaCertFile.getName()+" ---\n");
		}
		
		if (dvCert!=null) {
			
			System.out.println("--- start parsing of "+ dvCertFile.getName()+" ---");
			
			try {
				dvParser = new CertainParser(dvCert.getBody(), true);
			} catch (CVParserException e) {
				System.out.println(e.getMessage());
			}
			
			String role = dvParser.getCertificateRole();
			if (!(role.equals("DV_DOMESTIC")||role.equals("DV_FOREIGN"))) {
				System.out.println(dvCertFile.getName()+" is not a DV certificate!. Found "+role);
				return;
			}
			
			printContent(dvParser);
			
			if (verifier!=null&&cvcaParser.getChrString().equals(dvParser.getCarString())) {
				try {					
					System.out.println("Signature is " + (verifier.hasValidSignature(dvCert) ? "VALID" : "!!! INVALID !!!"));
				} catch (Exception e) {
					System.out.println("Couldn't verifiy signature: " + e.getLocalizedMessage());
				}
			} else {
				System.out.println("\tCan't check signature. No matching CVCA Certificate available.");
			}
			System.out.println("--- end parsing of "+ dvCertFile.getName()+" ---\n");
		}
		
		if (dvReq!=null) {
			
			System.out.println("--- start parsing of "+ dvReqFile.getName()+" ---");

			try {
				reqParser = new CertainParser(dvReq.getCertificateBody(), false);
			} catch (CVParserException e) {
				System.out.println(e.getMessage());
			}
			
			printContent(reqParser);
			
			if (cvcaCert!= null) {
				if (!equalDomainParameters(cvcaCert.getBody().getPublicKey(), dvReq.getCertificateBody().getPublicKey())) {
					System.out.println("- !Domain parameters of this request don't match the domain parameters of the CVCA certificate! -");
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
				if (cvcaCert!=null&&dvCert!=null&&isParent(dvCert.getHolderReference(), outerCar)&&isParent(cvcaCert.getHolderReference(),dvCert.getAuthorityReference())) {
					try {
						verifier = new CertainVerifier(cvcaCert.getBody().getPublicKey());
						System.out.println("Outer Signature is " + (verifier.hasValidOuterSignature(dvReq) ? "VALID" : "!!! INVALID !!!"));
					} catch (Exception e) {
						System.out.println("Verfifier throws exception: " + e.getLocalizedMessage());
					}
					
				} else {
					System.out.println("Can't check outer signature without matching parent DV and CVCA certifcate.");
				}
			}
			System.out.println("--- end parsing of "+ dvReqFile.getName()+" ---\n");
			
		}
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
		
		if (cvcaCertFile!=null) {			
			tempCvcBytes = readFile(cvcaCertFile);				
			cvcaCert = CVCertificate.getInstance(tempCvcBytes);
		}
		
		if (dvCertFile!=null) {
			tempCvcBytes = readFile(dvCertFile);
			dvCert = CVCertificate.getInstance(tempCvcBytes);
		}
		
		if (dvReqFile!=null) {
			tempCvcBytes = readFile(dvReqFile);
			dvReq = CVCertificateRequest.getInstance(tempCvcBytes);
		}
		
	}

	private boolean isParent(CertificateHolderReference parent, CertificationAuthorityReference child) {
		byte[] chr = parent.getEncoded();
		byte[] car = child.getEncoded();
		return Arrays.equals(chr, car);
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

	// private boolean verifyECDSASignature(byte[] signature, byte[]
	// dataToVerify, ECDSAPublicKey key) {
	//
	// if (key.getUsage().equals(EACObjectIdentifiers.id_TA_ECDSA_SHA_1)) {
	// signingAlgorithm = "SHA1withCVC-ECDSA";
	// } else if
	// (key.getUsage().equals(EACObjectIdentifiers.id_TA_ECDSA_SHA_224)) {
	// signingAlgorithm = "SHA224withCVC-ECDSA";
	// } else if
	// (key.getUsage().equals(EACObjectIdentifiers.id_TA_ECDSA_SHA_256)) {
	// signingAlgorithm = "SHA256withCVC-ECDSA";
	// } else if
	// (key.getUsage().equals(EACObjectIdentifiers.id_TA_ECDSA_SHA_384)) {
	// signingAlgorithm = "SHA384withCVC-ECDSA";
	// } else if
	// (key.getUsage().equals(EACObjectIdentifiers.id_TA_ECDSA_SHA_512)) {
	// signingAlgorithm = "SHA512withCVC-ECDSA";
	// }
	//
	// ECCurve.Fp curve = new ECCurve.Fp(key.getPrimeModulusP(),
	// key.getFirstCoefA(), key.getSecondCoefB());
	// ECPoint pointG = Converter.byteArrayToECPoint(key.getBasePointG(),
	// curve);
	// ECParameterSpec ecp = new ECParameterSpec(curve, pointG,
	// key.getOrderOfBasePointR());
	// ECPoint publicPointY =
	// Converter.byteArrayToECPoint(key.getPublicPointY(), curve);
	//
	// Signature sig = null;
	// try {
	// sig = Signature.getInstance(signingAlgorithm,"BC");
	// } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
	// e.printStackTrace();
	// }
	//
	//
	// boolean verifyResult = false;
	// try {
	// KeyFactory kef = KeyFactory.getInstance("ECDSA", "BC");
	// ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(publicPointY, ecp);
	// PublicKey pubKey = kef.generatePublic(pubKeySpec);
	// sig.initVerify(pubKey);
	// sig.update(dataToVerify);
	// verifyResult = sig.verify(signature);
	//
	// } catch (NoSuchAlgorithmException e) {
	// e.printStackTrace();
	// } catch (NoSuchProviderException e) {
	// e.printStackTrace();
	// } catch (InvalidKeySpecException e) {
	// e.printStackTrace();
	// } catch (InvalidKeyException e) {
	// e.printStackTrace();
	// } catch (SignatureException e) {
	// e.printStackTrace();
	// }
	//
	// return verifyResult;
	// }

}
