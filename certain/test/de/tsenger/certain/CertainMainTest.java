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

import org.bouncycastle.asn1.eac.CertificateHolderAuthorization;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

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

	private String cvcaFile;
	private String dvFile;

	@Before
	public void setUp() throws Exception {
		originalOut = System.out;
		originalErr = System.err;
		System.setOut(new PrintStream(out, true, "UTF-8"));
		System.setErr(new PrintStream(err, true, "UTF-8"));

		KeyPair cvcaKeys = TestCertificates.rsaKeyPair();
		cvcaFile = write("cvca.cvcert", TestCertificates.rsaCertificate(cvcaKeys, "00001", cvcaKeys, "00001",
				CertificateHolderAuthorization.CVCA).getEncoded());
		dvFile = write("dv.cvcert", TestCertificates.rsaCertificate(cvcaKeys, "00001", TestCertificates.rsaKeyPair(), "00002",
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
		assertEquals(CertainMain.EXIT_OK, CertainMain.run("-c", cvcaFile, dvFile));
		assertTrue(stdout().contains("Signature is VALID"));
		assertTrue("banner goes to stderr", stderr().startsWith("certain "));
	}

	@Test
	public void missingIssuer() {
		assertEquals(CertainMain.EXIT_NOT_CHECKED, CertainMain.run("-c", dvFile));
	}

	@Test
	public void invalidSignature() throws Exception {
		CVCertificate cvca = CVCertificate.getInstance(Files.readAllBytes(new File(cvcaFile).toPath()));
		cvca.getSignature()[0] ^= 0x01;
		String changed = write("changed.cvcert", cvca.getEncoded());

		assertEquals(CertainMain.EXIT_INVALID, CertainMain.run("-c", changed));
		// An invalid signature takes precedence over input errors
		assertEquals(CertainMain.EXIT_INVALID, CertainMain.run("-c", changed, "missing.cvcert"));
	}

	@Test
	public void unreadableFiles() throws Exception {
		assertEquals(CertainMain.EXIT_USAGE, CertainMain.run("-c", "missing.cvcert"));
		assertEquals(CertainMain.EXIT_USAGE, CertainMain.run("-c", write("garbage.cvcert", "no certificate".getBytes())));
		assertTrue(stderr().contains("can't parse"));
		assertEquals("", stdout());
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
		assertEquals(CertainMain.EXIT_OK, CertainMain.run("-h", "-c", "missing.cvcert"));
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
		assertEquals(CertainMain.EXIT_OK, CertainMain.run(LocalDate.of(2030, 1, 1), "-c", cvcaFile));
		assertTrue(!stdout().contains("expired"));
		assertEquals(CertainMain.EXIT_OK, CertainMain.run(LocalDate.of(2030, 1, 2), "-c", cvcaFile));
		assertTrue(stdout().contains("Note: this certificate expired on 2030-01-01."));
	}
}
