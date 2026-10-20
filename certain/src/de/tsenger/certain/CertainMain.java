package de.tsenger.certain;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;

import de.tsenger.certain.asn1.eac.CVCertificate;
import de.tsenger.certain.asn1.eac.CVCertificateRequest;
import de.tsenger.certain.asn1.eac.CertificateBody;
import de.tsenger.tools.FileSystem;
import de.tsenger.tools.HexString;

/**
 * Command line interface of certain: reads the given files, detects their type from the content (CV certificate,
 * link certificate, CV certificate request or signed list), prints their contents and the results of the checks in
 * the order of the arguments, and returns an exit code that summarizes the checks ({@link #EXIT_OK},
 * {@link #EXIT_INVALID}, {@link #EXIT_USAGE}, {@link #EXIT_NOT_CHECKED}).
 * <p>
 * The output goes to stdout, error messages and the banner go to stderr.
 *
 * @author Tobias Senger
 */
public class CertainMain {

	/** Every check passed. */
	public static final int EXIT_OK = 0;
	/** At least one check failed, e.g. an invalid signature. */
	public static final int EXIT_INVALID = 1;
	/** Wrong usage, or an input file could not be read or parsed. */
	public static final int EXIT_USAGE = 2;
	/** At least one check could not be done, e.g. because the issuer certificate is missing. */
	public static final int EXIT_NOT_CHECKED = 3;

	/** The exit codes in increasing priority: if several apply, the last one wins. */
	private static final List<Integer> EXIT_PRIORITY = Arrays.asList(EXIT_OK, EXIT_NOT_CHECKED, EXIT_USAGE, EXIT_INVALID);

	private static final String EXIT_CODES_HELP = "  Exit codes:\n"
			+ "    0  every check passed\n"
			+ "    1  at least one check failed (e.g. an invalid signature)\n"
			+ "    2  wrong usage, or an input file could not be read or parsed\n"
			+ "    3  at least one check could not be done (e.g. missing issuer certificate)\n";

	private static final String VERSION = readVersion();

	private static final String BANNER = "certain " + VERSION + " - parses and verifies CV certificates (BSI TR-03110), "
			+ "master, signer, deviation, defect and block lists (ICAO Doc 9303, BSI TR-03129)";

	@Parameter(description = "<file>...")
	private List<String> files = new ArrayList<String>();

	// Deprecated since 2.0.0, the file type is detected from the content. Their files are treated like the other
	// arguments. Remove them in the next major version.
	@Parameter(names = {"--cert","-c"}, variableArity = true, hidden = true)
	private List<String> certFileNames;

	@Parameter(names = {"--dvreq","-r"}, hidden = true)
	private List<String> dvReqFileNames;

	@Parameter(names = {"--linkcert","-l"}, hidden = true)
	private List<String> linkCertFileNames;

	@Parameter(names = {"--masterlist","-ml"}, hidden = true)
	private List<String> masterListFileNames;

	@Parameter(names = {"--dlist","-dl"}, hidden = true)
	private List<String> dListFileNames;

	@Parameter(names = {"--help", "-h"}, description = "Show this help and exit", help = true)
	private boolean help;

	@Parameter(names = {"--version", "-V"}, description = "Show the version and exit")
	private boolean version;

	@Parameter(names = {"--details", "-d"}, description = "Show more details: full public key values and signature bytes of CV certificates and requests, "
			+ "the X.509 certificates of master and signer lists, replacement certificates of defect lists and the IDs of block lists")
	private boolean showDetails = false;

	@Parameter(names = {"--fingerprint", "-f"}, description = "Show MD5, SHA-1, SHA-224 and SHA-256 fingerprints of certificates and requests")
	private boolean showFingerprints = false;

	/** The date expiration dates are compared with. */
	private final LocalDate today;

	/** The CV certificates except link certificates, which have the CHR of the new CVCA and would replace it. */
	private final CertStorage certStore = new CertStorage();
	/** Shows and checks the recognized files, in the order of the arguments. */
	private final List<Runnable> outputs = new ArrayList<Runnable>();

	private final CertParser cvParser = new CertParser();
	private CvChecker checker;
	private int exitCode = EXIT_OK;

	/** Parses the content of an input file. */
	private interface FileParser<T> {
		T parse(byte[] content) throws Exception;
	}

	private CertainMain(LocalDate today) {
		this.today = today;
	}

	public static void main(String[] args) {
		System.exit(run(args));
	}

	/**
	 * Runs certain with the given command line arguments.
	 *
	 * @return the exit code
	 */
	public static int run(String... args) {
		return run(LocalDate.now(ZoneOffset.UTC), args);
	}

	/**
	 * Runs certain as of the given date, so that tests do not depend on the current date.
	 *
	 * @return the exit code
	 */
	static int run(LocalDate today, String... args) {
		CertainMain cm = new CertainMain(today);
		JCommander jcmdr = JCommander.newBuilder().addObject(cm).programName("certain").build();

		try {
			jcmdr.parse(args);
		} catch (ParameterException e) {
			System.err.println("certain: " + e.getMessage());
			System.err.println("Try 'certain --help' for more information.");
			return EXIT_USAGE;
		}
		if (cm.help) {
			System.out.print(usage(jcmdr));
			return EXIT_OK;
		}
		if (cm.version) {
			System.out.println("certain " + VERSION);
			return EXIT_OK;
		}
		if (cm.fileNames().isEmpty()) {
			System.err.println("certain: no input file given");
			System.err.print(usage(jcmdr));
			return EXIT_USAGE;
		}

		System.err.println(BANNER);
		Security.addProvider(new BouncyCastleProvider());
		return cm.check();
	}

	private static String usage(JCommander jcmdr) {
		StringBuilder sb = new StringBuilder(BANNER + "\n");
		jcmdr.getUsageFormatter().usage(sb);
		return sb.append(EXIT_CODES_HELP).toString();
	}

	private static String readVersion() {
		Properties properties = new Properties();
		try (InputStream in = CertainMain.class.getResourceAsStream("version.properties")) {
			properties.load(in);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
		return properties.getProperty("version");
	}

	/** The deprecated file options with their files (null if the option is not used). */
	private Map<String, List<String>> deprecatedOptions() {
		Map<String, List<String>> options = new LinkedHashMap<String, List<String>>();
		options.put("-c", certFileNames);
		options.put("-r", dvReqFileNames);
		options.put("-l", linkCertFileNames);
		options.put("-ml", masterListFileNames);
		options.put("-dl", dListFileNames);
		return options;
	}

	/** All input files: the arguments, then the files of the deprecated options. */
	private List<String> fileNames() {
		List<String> names = new ArrayList<String>(files);
		for (List<String> optionFiles : deprecatedOptions().values()) {
			if (optionFiles != null) names.addAll(optionFiles);
		}
		return names;
	}

	/**
	 * Reads all input files, then prints their contents and checks them. All files are read first, so that the
	 * chain checks see every given certificate.
	 *
	 * @return the exit code
	 */
	private int check() {
		for (Map.Entry<String, List<String>> option : deprecatedOptions().entrySet()) {
			if (option.getValue() != null) {
				System.err.println("certain: option " + option.getKey() + " is deprecated, pass the files as arguments");
			}
		}
		for (String fileName : fileNames()) {
			readFile(fileName);
		}
		checker = new CvChecker(certStore);
		for (Runnable output : outputs) {
			output.run();
		}
		return exitCode;
	}

	/**
	 * Reads a file and detects its type from the content: the first byte chooses the parser (SEQUENCE {@code 30} for
	 * CMS SignedData, {@code 67} for a request with outer signature, {@code 7F} for {@code 7F21}, a CV certificate or
	 * a request without outer signature). Files that can't be read, recognized or parsed are reported and skipped.
	 */
	private void readFile(String fileName) {
		byte[] content;
		try {
			content = FileSystem.readFile(fileName);
		} catch (IOException e) {
			error(e.getMessage());
			return;
		}
		int tag = content.length > 0 ? content[0] & 0xFF : -1;
		if (tag == 0x30) {
			SignedDataParser parser = parse(fileName, content, "signed list", SignedDataParser::new);
			if (parser != null) outputs.add(() -> printListInfo(parser));
		} else if (tag == 0x67) {
			addRequest(fileName, content);
		} else if (tag == 0x7F) {
			CVCertificate cert = parse(fileName, content, "CV certificate", bytes -> {
				CVCertificate parsed = CVCertificate.getInstance(bytes);
				if (parsed.getBody() == null) throw new IllegalArgumentException("no certificate body (7F4E)");
				return parsed;
			});
			if (cert == null) {
				return;
			}
			CertificateBody body = cert.getBody();
			// A request has neither CHAT nor dates (BSI TR-03110 Part 3, C.2), a certificate has all of them (C.1).
			if (body.getCertificateHolderAuthorization() == null && body.getCertificateEffectiveDate() == null
					&& body.getCertificateExpirationDate() == null) {
				addRequest(fileName, content);
			} else if ("CVCA".equals(cert.getRoleDescription()) && !cert.getChrString().equals(cert.getCarString())) {
				outputs.add(() -> checkLinkCert(cert));
			} else {
				certStore.putCert(cert);
				outputs.add(() -> checkCert(cert));
			}
		} else {
			error("can't recognize " + fileName);
		}
	}

	private void addRequest(String fileName, byte[] content) {
		CVCertificateRequest req = parse(fileName, content, "CV certificate request", CVCertificateRequest::getInstance);
		if (req != null) outputs.add(() -> checkDvRequest(req));
	}

	/**
	 * Parses the content of a file. If that fails, the error is reported and null is returned.
	 *
	 * @param type what the file should contain, for the error message
	 */
	private <T> T parse(String fileName, byte[] content, String type, FileParser<T> parser) {
		try {
			return parser.parse(content);
		} catch (Exception e) {
			// The parsers throw different runtime exceptions on invalid input, the message describes the problem.
			error("can't parse " + fileName + " as " + type + ": " + e.getMessage());
			return null;
		}
	}

	private void error(String message) {
		System.err.println("certain: " + message);
		raise(EXIT_USAGE);
	}

	/** Prints the text of a check (if any) and takes its status into account for the exit code. */
	private void print(CheckResult result) {
		if (!result.getText().isEmpty()) System.out.println(result.getText());
		switch (result.getStatus()) {
		case VALID: break;
		case NOT_CHECKED: raise(EXIT_NOT_CHECKED); break;
		case INVALID: raise(EXIT_INVALID); break;
		}
	}

	private void raise(int code) {
		if (EXIT_PRIORITY.indexOf(code) > EXIT_PRIORITY.indexOf(exitCode)) {
			exitCode = code;
		}
	}

	/**
	 * Shows and checks a CVCA, DV or terminal certificate
	 */
	private void checkCert(CVCertificate cert) {
		printBanner(cert.getChrString());
		if (showFingerprints) printFingerprints(cert);

		if (cert.getBody().getCertificateHolderAuthorization() == null) {
			print(new CheckResult(CheckResult.Status.INVALID, "Couldn't find a CHAT -> No valid certificate!"));
			return;
		}

		cvParser.setBody(cert.getBody(), true);
		System.out.println(cvParser.getContentString(showDetails));
		printExpirationNote(cert);

		if (showDetails) System.out.println("Signature:\n" + HexString.bufferToHex(cert.getSignature(), true));

		print(checker.checkSignature(cert));
	}

	/**
	 * Shows and checks a DV request
	 */
	private void checkDvRequest(CVCertificateRequest dvReq) {
		cvParser.setBody(dvReq.getCertificateBody(), false);

		printBanner("Request for " + dvReq.getCertificateBody().getChrString());
		if (showFingerprints) printFingerprints(dvReq);

		System.out.println(cvParser.getContentString(showDetails));

		print(checker.checkDomainParameters(dvReq));

		if (showDetails) System.out.println("Inner Signature:\n" + HexString.bufferToHex(dvReq.getInnerSignature(), true));
		print(checker.checkInnerSignature(dvReq));

		if (dvReq.hasOuterSignature()) {
			System.out.println("\nOuter CAR: " + dvReq.getOuterCarStr());
			if (showDetails) System.out.println("Outer Signature:\n" + HexString.bufferToHex(dvReq.getOuterSignature(), true));
			print(checker.checkOuterSignature(dvReq));
		} else {
			System.out.println("No outer signature");
		}
	}

	/**
	 * Shows and checks a link certificate
	 */
	private void checkLinkCert(CVCertificate linkCert) {
		printBanner("Link " + linkCert.getCarString() + " -> " + linkCert.getChrString());
		if (showFingerprints) printFingerprints(linkCert);

		print(checker.checkLinkPublicKey(linkCert));

		cvParser.setBody(linkCert.getBody(), true);
		System.out.println(cvParser.getContentString(showDetails));
		printExpirationNote(linkCert);

		if (showDetails) System.out.println("Signature:\n" + HexString.bufferToHex(linkCert.getSignature(), true));

		print(checker.checkSignature(linkCert));
	}

	/**
	 * Shows and checks a signed list: master list, signer list, deviation list or defect list
	 */
	private void printListInfo(SignedDataParser parser) {
		print(parser.checkSignedData());
		DListParser dlParser = parser.getDListParser();
		if (dlParser != null) {
			System.out.println(dlParser.getDListInfoString(showDetails));
			print(dlParser.check());
		}
	}

	/** Notes an expired certificate; this does not affect the exit code, certain is not a chip with a current date. */
	private void printExpirationNote(CVCertificate cert) {
		String date = cert.getBody().getCertificateExpirationDate().toString();
		LocalDate expiration;
		try {
			// YYMMDD in GMT, the year is 20YY (BSI TR-03110 Part 3, D.2.1.3)
			expiration = LocalDate.parse("20" + date, DateTimeFormatter.BASIC_ISO_DATE);
		} catch (DateTimeParseException e) {
			System.out.println("Note: the certificate expiration date " + date + " is not a valid date.\n");
			return;
		}
		if (expiration.isBefore(today)) {
			System.out.println("Note: this certificate expired on " + expiration + ". Except for CVCA link certificates, "
					+ "expired certificates are rejected by the certificate validation (BSI TR-03110 Part 3, 2.5.1).\n");
		}
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
			System.out.println("Couldn't calculate the fingerprints: " + e.getLocalizedMessage());
		}
	}

	private void printFingerprints(CVCertificate cert) {
		try {
			printFingerprints(cert.getEncoded());
		} catch (IOException e) {
			System.out.println("Couldn't calculate the fingerprints: " + e.getLocalizedMessage());
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
			System.out.println(HexString.bufferToHex(hashes.getSHA256(), true) + "\n");
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getLocalizedMessage());
		}
	}
}
