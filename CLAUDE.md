# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Principles

- Clean code with documentation (Javadoc on public classes/methods, comments for the *why*) and the KISS principle: prefer the simplest solution, no speculative abstractions.
- certain is tolerant: on a deviation from the specification it names it clearly (with the TR-03110 reference) and continues with whatever can still be checked instead of aborting. A violated MUST counts as a failed check (exit code 1), purely informative findings (e.g. an expired certificate) are printed as a note without affecting the exit code.
- Commit messages follow Conventional Commits (`feat:`, `fix:`, `test:`, `build:`, `chore:`, `docs:`, ...) and never mention AI agents (no `Co-Authored-By` or session trailers).

## Overview

`certain` is a command line parser/verifier (Java) for card verifiable (CV) certificates per BSI TR-03110, plus ICAO master lists and deviation/defect lists. The Maven project lives in the `certain/` subdirectory (not the repo root). The default branch is `main`.

## Commands

Run from `certain/`:

- Build fat jar: `mvn package` (Shade plugin, `minimizeJar` on; output `target/certain-1.0.0.jar`, main class `de.tsenger.certain.CertainMain`)
- Run: `java -jar target/certain-1.0.0.jar -c <cert files...>` (see README for options: `-r` DV request, `-l` link cert, `-ml` master list, `-dl` deviation/defect list, `-d` details, `-f` fingerprints)
- Run tests: `mvn test` (single class: `mvn test -Dtest=CvCertificateChainTest`). JUnit 4 tests live in `test/` (`testSourceDirectory`), not `src/test`.
- Most tests use local, untracked test data in `certain/testdata/` (gitignored; the layout is documented in `TestData.java`). If it is missing, they are skipped, not failed. A raw, unsorted copy of the data is in `~/cv-certs`. `RsaSignatureTest` (creates its own certificates) and `AuthorizationTextTest` need no test data.
- `CliOutputTest` compares the CLI output (stdout, stderr and exit code) for all test data with golden files in `certain/testdata/golden/`, as of a fixed date (`CertainMain.run(LocalDate, args)`) so that the expiration notes do not change over time. Refresh them only from a known-good state: `mvn test -Dtest=CliOutputTest -Dgolden.update=true`.
- `CertainMainTest` (exit codes) and `CvCheckerTest` create their certificates and requests with `TestCertificates` and need no test data.
- Known bugs are kept as `@Ignore`d tests with the reason in the annotation (currently one in `CvCheckerTest`: EC domain parameters without the optional cofactor, not supported on purpose because Bouncy Castle rejects them and no known certificate lacks the cofactor; certain reports such a key as unsupported).
- The golden files are generated with the test classpath. The fat jar can differ (e.g. `SHA1withRSA` instead of `SHA1WITHRSA` in the master list output) because `minimizeJar` changes which provider creates the certificates; this was already the case before the Bouncy Castle 1.86 update.

There is no lint configuration.

## Architecture

- Non-standard Maven layout: `sourceDirectory` is `src` (not `src/main/java`); non-`.java` files under `src` are packaged as resources. Compiled with `<release>8</release>`.
- `CertainMain` (JCommander CLI) is the entry point: `run(args)` returns the exit code (0 all checks passed, 1 a check failed, 2 wrong usage or unreadable input file, 3 a check could not be done; 1 > 2 > 3 if several apply), `main` only calls `System.exit`. It reads the files given by the options, prints their contents to stdout (errors and the banner to stderr) and the results of the checks. The version comes from the Maven filtered resource `version.properties`.
- `CvChecker` does the checks of CV certificates, link certificates and requests against a `CertStorage` and returns `CheckResult`s (status and text); `SignedDataParser.checkSignedData()` does the same for deviation/defect lists. ECDSA keys without domain parameters get them from the CVCA of the chain; for requests, well-known curves are tried if the CVCA is missing.
- `de.tsenger.certain`: parsers (`CertParser`, `MasterListParser`, `SignedDataParser`, `DeviationListParser`, `DefectListParser`, `DListParser`), verification (`CertVerifier`, `SignedDataVerifier`, `CVSigner`), `CertStorage` (holds parsed certs for chain verification), and helpers (`HashCalculator`, `CountryCode`).
- `de.tsenger.certain.asn1.eac`: only what Bouncy Castle (`org.bouncycastle.asn1.eac`, in `bcutil`) cannot do: CV certificates and requests with certificate extensions (`CertificateExtensions`, `DiscretionaryDataTemplate`), the 40-bit CHAT of authentication terminals (`CertificateHolderAuthorization`), the outer CAR of requests, and the full BSI OID list. Reference, date and public key types come from Bouncy Castle. `ApplicationObjects` reads and creates the APPLICATION tagged data objects (`ASN1TaggedObject`), `References` builds Bouncy Castle references and dates from raw contents.
- `de.tsenger.certain.asn1.icao` and `asn1.mrtdpki`: ASN.1 structures for deviation lists and defect lists.
- `de.tsenger.tools`: small utilities (hex, file, conversion).
- Dependencies: BouncyCastle 1.86 (`bcprov`, `bcpkix`, `bcutil`, all jdk18on) and JCommander. The shade config uses `minimizeJar`, which drops classes not statically reachable; BC's `jcajce/provider/asymmetric/**` is force-kept via a filter because it is loaded reflectively, so other reflectively loaded classes may need adding to that filter in `pom.xml`.

## Domain notes (BSI TR-03110, verified against the PDFs)

- Authentication terminal CHAT (Part 4, Table 4): five bytes, role in bits 39/38 (`11` CVCA, `10` DV official domestic, `01` DV non-official/foreign, `00` terminal), write access DG17 to DG22 in bits 37 to 32, PSA bit 30, read access DG1 to DG22 in bits 8 to 29 (DG n = bit 7+n), special functions in bits 7 to 0. The constants in `CertificateHolderAuthorization` follow this layout.
- Terminal Authentication supports RSA and ECDSA (Part 3, Appendix A.7): six RSA object identifiers below `0.4.0.127.0.7.2.2.2.1` (v1.5 and PSS with SHA-1/256/512, modulus 1024 to 3072 bit) and five ECDSA ones below `...2.2.2.2`. The SHA-1 variants are deprecated. All certificates of a chain use the algorithm of the CVCA, only link certificates may switch it.
- EC domain parameters (Part 3, D.3.3): all present (the cofactor may be missing) or all absent. Self-signed CVCA certificates SHALL contain them, link certificates MAY, DV and terminal certificates MUST NOT (they inherit them from the CVCA), requests MUST always contain them. Dates are YYMMDD in GMT, the year is 20YY (D.2.1.3).
- ISO/IEC 18013 certificates (object identifiers below `1.0.18013`, EC keys, DER encoded signatures) are not supported and are reported as an unsupported public key algorithm.
