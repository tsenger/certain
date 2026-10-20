package de.tsenger.certain;

import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.io.IOException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.tsenger.certain.asn1.eac.CVCertificate;
import de.tsenger.certain.asn1.eac.CVCertificateRequest;
import de.tsenger.tools.FileSystem;

/**
 * Access to the local, untracked test data in {@code testdata/} (see {@code .gitignore}).
 * <p>
 * Layout (paths are relative to {@code testdata/}):
 * <ul>
 * <li>{@code dev/<AT|IS|ST>/}: self-made chain {@code cvca.cvcert} -> {@code dv.cvcert} -> {@code ta.cvcert}</li>
 * <li>{@code de-test/<eid|epass|esign>/}: German test CVCAs ({@code cvca.cv}) and DV certificates</li>
 * <li>{@code it/}: Italian CVCA certificates</li>
 * <li>{@code requests/}: DV certificate requests</li>
 * <li>{@code master-lists/}: ICAO CSCA master lists ({@code de.ml}: German master list of 2026-10-01)</li>
 * <li>{@code deviation-lists/}: ICAO deviation lists ({@code cms/} signed, {@code raw/} unsigned)</li>
 * <li>{@code iso18013/}: certificates of ISO/IEC 18013 (EC keys with other object identifiers), not supported</li>
 * </ul>
 * Tests using this class are skipped (not failed) if the data is not available.
 */
final class TestData {

	static final File ROOT = new File("testdata");

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private TestData() {
	}

	/** Skips the calling test if the file {@code relativePath} does not exist. */
	static byte[] read(String relativePath) throws IOException {
		File file = new File(ROOT, relativePath);
		assumeTrue("Test data missing: " + file, file.isFile());
		return FileSystem.readFile(file.getPath());
	}

	static CVCertificate certificate(String relativePath) throws IOException {
		return CVCertificate.getInstance(read(relativePath));
	}

	static CVCertificateRequest request(String relativePath) throws IOException {
		return CVCertificateRequest.getInstance(read(relativePath));
	}
}
