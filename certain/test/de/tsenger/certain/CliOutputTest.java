package de.tsenger.certain;

import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * Regression test for the command line output: runs {@link CertainMain} for every file in
 * {@code testdata/} and compares the output with the golden files in {@code testdata/golden/}.
 * <p>
 * Create or refresh the golden files with {@code mvn test -Dtest=CliOutputTest -Dgolden.update=true},
 * but only from a state whose output is known to be correct.
 */
public class CliOutputTest {

	private static final File GOLDEN = new File(TestData.ROOT, "golden");
	private static final boolean UPDATE = Boolean.getBoolean("golden.update");

	@Test
	public void outputMatchesGoldenFiles() throws Exception {
		assumeTrue("Test data missing: " + TestData.ROOT, TestData.ROOT.isDirectory());
		assumeTrue("Golden files missing: " + GOLDEN, UPDATE || GOLDEN.isDirectory());
		GOLDEN.mkdirs();

		List<String> mismatches = new ArrayList<String>();
		for (String[] testCase : testCases()) {
			String name = testCase[0];
			String output = runCertain(Arrays.copyOfRange(testCase, 1, testCase.length));
			File golden = new File(GOLDEN, name + ".txt");
			if (UPDATE) {
				Files.write(golden.toPath(), output.getBytes(StandardCharsets.UTF_8));
			} else if (!golden.isFile() || !output.equals(new String(Files.readAllBytes(golden.toPath()), StandardCharsets.UTF_8))) {
				mismatches.add(name);
			}
		}
		assertTrue("Output differs from golden files: " + mismatches, mismatches.isEmpty());
	}

	/** Each test case is its name followed by the command line arguments. */
	private static List<String[]> testCases() {
		List<String[]> cases = new ArrayList<String[]>();
		for (File file : filesBelow(TestData.ROOT)) {
			String path = relative(file);
			String name = path.replace('/', '_');
			if (path.startsWith("golden/")) {
				continue;
			}
			if (path.endsWith(".cvcert") || path.endsWith(".cv")) {
				cases.add(new String[] { name, "-c", file.getPath() });
				cases.add(new String[] { name + "_details", "-c", file.getPath(), "-d", "-f" });
			} else if (path.endsWith(".cvreq")) {
				cases.add(new String[] { name, "-r", file.getPath() });
				cases.add(new String[] { name + "_details", "-r", file.getPath(), "-d", "-f" });
			} else if (path.endsWith(".ml")) {
				cases.add(new String[] { name, "-ml", file.getPath() });
			} else if (path.startsWith("deviation-lists/") && path.endsWith(".bin")) {
				cases.add(new String[] { name, "-dl", file.getPath() });
			}
		}
		for (String dir : new String[] { "dev/AT", "dev/IS", "dev/ST", "de-test/eid", "de-test/epass" }) {
			String cvca = new File(TestData.ROOT, dir + "/cvca.cvcert").isFile() ? "cvca.cvcert" : "cvca.cv";
			List<String> chain = new ArrayList<String>(Arrays.asList(dir.replace('/', '_') + "_chain", "-c"));
			for (String file : new String[] { cvca, "dv.cvcert", "ta.cvcert" }) {
				if (new File(TestData.ROOT, dir + "/" + file).isFile()) {
					chain.add(new File(TestData.ROOT, dir + "/" + file).getPath());
				}
			}
			chain.add("-d");
			cases.add(chain.toArray(new String[0]));
		}
		return cases;
	}

	/** Runs the command line tool in-process and returns what it wrote to stdout and stderr and its exit code. */
	private static String runCertain(String[] args) throws Exception {
		PrintStream originalOut = System.out;
		PrintStream originalErr = System.err;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ByteArrayOutputStream err = new ByteArrayOutputStream();
		String result;
		System.setOut(new PrintStream(out, true, "UTF-8"));
		System.setErr(new PrintStream(err, true, "UTF-8"));
		try {
			result = "exit code " + CertainMain.run(args);
		} catch (Throwable t) {
			// Only the type: messages and stack traces contain class names and line numbers that change with refactorings.
			result = "EXCEPTION " + t.getClass().getName();
		} finally {
			System.setOut(originalOut);
			System.setErr(originalErr);
		}
		return new String(out.toByteArray(), StandardCharsets.UTF_8)
				+ "\n--- stderr ---\n" + new String(err.toByteArray(), StandardCharsets.UTF_8)
				+ "--- " + result + " ---\n";
	}

	private static List<File> filesBelow(File dir) {
		List<File> files = new ArrayList<File>();
		File[] children = dir.listFiles();
		if (children == null) {
			return files;
		}
		Arrays.sort(children);
		for (File child : children) {
			if (child.isDirectory()) {
				files.addAll(filesBelow(child));
			} else {
				files.add(child);
			}
		}
		return files;
	}

	private static String relative(File file) {
		return TestData.ROOT.toPath().relativize(file.toPath()).toString().replace(File.separatorChar, '/');
	}
}
