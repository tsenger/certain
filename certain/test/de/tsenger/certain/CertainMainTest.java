package de.tsenger.certain;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.time.LocalDate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.eac.CertificateHolderAuthorization;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import de.tsenger.certain.asn1.eac.BSIObjectIdentifiers;
import de.tsenger.certain.asn1.eac.CVCertificate;

/**
 * Exit codes and output streams of the command line tool, with certificates created by {@link TestCertificates}.
 */
public class CertainMainTest {

	@Rule
	public TemporaryFolder folder = new TemporaryFolder();

	private final ByteArrayOutputStream out = new ByteArrayOutputStream();
	private final ByteArrayOutputStream err = new ByteArrayOutputStream();
	private PrintStream originalOut;
	private PrintStream originalErr;

	private KeyPair cvcaKeys;
	private KeyPair dvKeys;
	private String cvcaFile;
	private String dvFile;

	@Before
	public void setUp() throws Exception {
		originalOut = System.out;
		originalErr = System.err;
		System.setOut(new PrintStream(out, true, "UTF-8"));
		System.setErr(new PrintStream(err, true, "UTF-8"));

		cvcaKeys = TestCertificates.rsaKeyPair();
		dvKeys = TestCertificates.rsaKeyPair();
		cvcaFile = write("cvca.cvcert", TestCertificates.rsaCertificate(cvcaKeys, "00001", cvcaKeys, "00001",
				CertificateHolderAuthorization.CVCA).getEncoded());
		dvFile = write("dv.cvcert", TestCertificates.rsaCertificate(cvcaKeys, "00001", dvKeys, "00002",
				CertificateHolderAuthorization.DV_DOMESTIC).getEncoded());
	}

	@After
	public void tearDown() {
		System.setOut(originalOut);
		System.setErr(originalErr);
	}

	private String write(String name, byte[] content) throws Exception {
		File file = folder.newFile(name);
		Files.write(file.toPath(), content);
		return file.getPath();
	}

	private String stdout() {
		return new String(out.toByteArray(), StandardCharsets.UTF_8);
	}

	private String stderr() {
		return new String(err.toByteArray(), StandardCharsets.UTF_8);
	}

	@Test
	public void validChain() {
		assertEquals(CertainMain.EXIT_OK, CertainMain.run(cvcaFile, dvFile));
		assertTrue(stdout().contains("Signature is VALID"));
		assertTrue("banner goes to stderr", stderr().startsWith("certain "));
	}

	@Test
	public void missingIssuer() {
		assertEquals(CertainMain.EXIT_NOT_CHECKED, CertainMain.run(dvFile));
	}

	@Test
	public void invalidSignature() throws Exception {
		CVCertificate cvca = CVCertificate.getInstance(Files.readAllBytes(new File(cvcaFile).toPath()));
		cvca.getSignature()[0] ^= 0x01;
		String changed = write("changed.cvcert", cvca.getEncoded());

		assertEquals(CertainMain.EXIT_INVALID, CertainMain.run(changed));
		// An invalid signature takes precedence over input errors
		assertEquals(CertainMain.EXIT_INVALID, CertainMain.run(changed, "missing.cvcert"));
	}

	@Test
	public void unreadableFiles() throws Exception {
		assertEquals(CertainMain.EXIT_USAGE, CertainMain.run("missing.cvcert"));
		assertEquals(CertainMain.EXIT_USAGE, CertainMain.run(write("garbage.cvcert", new byte[] { 0x7F, 0x21, 0x00 })));
		assertTrue(stderr().contains("can't parse"));
		assertEquals("", stdout());
	}

	@Test
	public void unknownFile() throws Exception {
		String garbage = write("garbage.txt", "no certificate".getBytes());
		assertEquals(CertainMain.EXIT_USAGE, CertainMain.run(garbage));
		assertTrue(stderr(), stderr().contains("certain: can't recognize " + garbage));
		assertEquals(CertainMain.EXIT_USAGE, CertainMain.run(write("empty.bin", new byte[0])));
		assertEquals("", stdout());
	}

	@Test
	public void requestWithoutOuterSignature() throws Exception {
		String request = write("request.cvreq", TestCertificates.rsaRequest(dvKeys, null, null));
		assertEquals(CertainMain.EXIT_OK, CertainMain.run(request));
		assertTrue(stdout().contains("Parsing Request for DETEST00002"));
		assertTrue(stdout().contains("No outer signature"));
	}

	@Test
	public void requestWithOuterSignature() throws Exception {
		// The DV requests a new certificate, signed with its current key (certificate DETEST00002)
		String request = write("request.cvreq", TestCertificates.rsaRequest(TestCertificates.rsaKeyPair(), dvKeys, "00002"));
		assertEquals(CertainMain.EXIT_OK, CertainMain.run(request, cvcaFile, dvFile));
		assertTrue(stdout().contains("Parsing Request for DETEST00002"));
		assertTrue(stdout().contains("Outer CAR: DETEST00002"));
		assertTrue(stdout(), stdout().contains("Outer Signature is VALID"));
	}

	@Test
	public void linkCertificateWithNewCvca() throws Exception {
		KeyPair newCvcaKeys = TestCertificates.rsaKeyPair();
		String newCvca = write("cvca3.cvcert", TestCertificates.rsaCertificate(newCvcaKeys, "00003", newCvcaKeys, "00003",
				CertificateHolderAuthorization.CVCA).getEncoded());
		String link = write("link.cvcert", TestCertificates.rsaCertificate(cvcaKeys, "00001", newCvcaKeys, "00003",
				CertificateHolderAuthorization.CVCA).getEncoded());

		// The link certificate has the CHR of the new CVCA, it must not replace it
		assertEquals(CertainMain.EXIT_OK, CertainMain.run(link, newCvca, cvcaFile));
		assertTrue(stdout().contains("Parsing Link DETEST00001 -> DETEST00003"));
		assertTrue(stdout().contains("The public key in this linkcert is equal to the public key in\nDETEST00003"));
		assertTrue("output in the order of the arguments",
				stdout().indexOf("Parsing Link") < stdout().indexOf("Parsing DETEST00003"));
	}

	@Test
	public void signedList() throws Exception {
		KeyPair keyPair = TestSignedData.keyPair();
		// Complete block list of version 1 (BSI TR-03129 V1.10) without IDs
		byte[] blockList = new DERSequence(new ASN1Encodable[] { new ASN1Integer(0), new ASN1Integer(0),
				new DEROctetString(new byte[] { 0x01 }), new DERSequence() }).getEncoded();
		String list = write("list.bin", TestSignedData.sign(BSIObjectIdentifiers.BlackList, blockList, keyPair,
				TestSignedData.certificate(keyPair), true, "Sector"));
		CertainMain.run(list);
		assertTrue(stderr(), !stderr().contains("certain: can't"));
		assertTrue(stdout(), stdout().contains("Block List"));
	}

	@Test
	public void deprecatedOptions() throws Exception {
		String request = write("request.cvreq", TestCertificates.rsaRequest(dvKeys, null, null));
		assertEquals(CertainMain.EXIT_OK, CertainMain.run("-c", cvcaFile, dvFile, "-r", request));
		assertTrue(stdout().contains("Parsing Request for DETEST00002"));
		assertTrue(stderr().contains("certain: option -c is deprecated, pass the files as arguments"));
		assertTrue(stderr().contains("certain: option -r is deprecated, pass the files as arguments"));
		assertTrue(!stderr().contains("option -l"));
	}

	@Test
	public void helpHidesDeprecatedOptions() {
		assertEquals(CertainMain.EXIT_OK, CertainMain.run("-h"));
		assertTrue(stdout(), stdout().contains("<file>..."));
		assertTrue(stdout(), !stdout().contains("--cert"));
	}

	@Test
	public void wrongUsage() {
		assertEquals(CertainMain.EXIT_USAGE, CertainMain.run());
		assertEquals(CertainMain.EXIT_USAGE, CertainMain.run("--unknown"));
		assertEquals(CertainMain.EXIT_USAGE, CertainMain.run("-d"));
		assertEquals("", stdout());
	}

	@Test
	public void helpDoesNotCheckFiles() {
		assertEquals(CertainMain.EXIT_OK, CertainMain.run("-h", "missing.cvcert"));
		assertTrue(stdout().contains("Usage: certain"));
		assertEquals("", stderr());
	}

	@Test
	public void version() {
		assertEquals(CertainMain.EXIT_OK, CertainMain.run("--version"));
		assertTrue(stdout(), stdout().matches("certain \\d+\\.\\d+\\.\\d+\\R"));
	}

	@Test
	public void expiredCertificateIsOnlyNoted() {
		// The test certificates expire on 2030-01-01
		assertEquals(CertainMain.EXIT_OK, CertainMain.run(LocalDate.of(2030, 1, 1), cvcaFile));
		assertTrue(!stdout().contains("expired"));
		assertEquals(CertainMain.EXIT_OK, CertainMain.run(LocalDate.of(2030, 1, 2), cvcaFile));
		assertTrue(stdout().contains("Note: this certificate expired on 2030-01-01."));
	}
}
