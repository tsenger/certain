# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Principles

- Clean code with documentation (Javadoc on public classes/methods, comments for the *why*) and the KISS principle: prefer the simplest solution, no speculative abstractions.
- Commit messages follow Conventional Commits (`feat:`, `fix:`, `test:`, `build:`, `chore:`, `docs:`, ...) and never mention AI agents (no `Co-Authored-By` or session trailers).

## Overview

`certain` is a command line parser/verifier (Java) for card verifiable (CV) certificates per BSI TR-03110, plus ICAO master lists and deviation/defect lists. The Maven project lives in the `certain/` subdirectory (not the repo root).

## Commands

Run from `certain/`:

- Build fat jar: `mvn package` (Shade plugin, `minimizeJar` on; output `target/certain-1.0.0.jar`, main class `de.tsenger.certain.CertainMain`)
- Run: `java -jar target/certain-1.0.0.jar -c <cert files...>` (see README for options: `-r` DV request, `-l` link cert, `-ml` master list, `-dl` deviation/defect list, `-d` details, `-f` fingerprints)

- Run tests: `mvn test` (single class: `mvn test -Dtest=CvCertificateChainTest`). JUnit 4 tests live in `test/` (`testSourceDirectory`), not `src/test`.
- Tests use local, untracked test data in `certain/testdata/` (gitignored; the layout is documented in `TestData.java`). If it is missing, the tests are skipped, not failed. A raw, unsorted copy of the data is in `~/cv-certs`.
- `CliOutputTest` compares the CLI output for all test data with golden files in `certain/testdata/golden/`. Refresh them only from a known-good state: `mvn test -Dtest=CliOutputTest -Dgolden.update=true`.
- Known bugs are kept as `@Ignore`d tests with the reason in the annotation.

There is no lint configuration.

## Architecture

- Non-standard Maven layout: `sourceDirectory` is `src` (not `src/main/java`); non-`.java` files under `src` are packaged as resources. Compiled with `<release>8</release>`.
- `CertainMain` (JCommander CLI) is the entry point: registers the BouncyCastle provider, then dispatches to parsers depending on the options given.
- `de.tsenger.certain`: parsers (`CertParser`, `MasterListParser`, `SignedDataParser`, `DeviationListParser`, `DefectListParser`, `DListParser`), verification (`CertVerifier`, `SignedDataVerifier`, `CVSigner`), `CertStorage` (holds parsed certs for chain verification), and helpers (`HashCalculator`, `CountryCode`).
- `de.tsenger.certain.asn1.eac`: only what Bouncy Castle (`org.bouncycastle.asn1.eac`, in `bcutil`) cannot do: CV certificates and requests with certificate extensions (`CertificateExtensions`, `DiscretionaryDataTemplate`), the 40-bit CHAT of authentication terminals (`CertificateHolderAuthorization`), the outer CAR of requests, and the full BSI OID list. Reference, date and public key types come from Bouncy Castle. `ApplicationObjects` reads and creates the APPLICATION tagged data objects (`ASN1TaggedObject`), `References` builds Bouncy Castle references and dates from raw contents.
- `de.tsenger.certain.asn1.icao` and `asn1.mrtdpki`: ASN.1 structures for deviation lists and defect lists.
- `de.tsenger.tools`: small utilities (hex, file, conversion).
- Dependencies: BouncyCastle (`bcprov`/`bcpkix` jdk18on) and JCommander. The shade config uses `minimizeJar`, which drops classes not statically reachable; BC's `jcajce/provider/asymmetric/**` is force-kept via a filter because it is loaded reflectively, so other reflectively loaded classes may need adding to that filter in `pom.xml`.
