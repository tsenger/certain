# Changelog

All notable changes to certain are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and certain follows [Semantic Versioning](https://semver.org/).

## 2.0.0 - 2026-10-20

### Changed (breaking)
- New command line: `certain [-d] [-f] <file>...`. The type of every file is detected from its content (CV certificate, link certificate, CV certificate request or signed list), and any number of files of each type can be given. All files are read before they are checked, and the output follows the order of the arguments.
- The options `-c`, `-r`, `-l`, `-ml` and `-dl` are deprecated and hidden from the help. They still work (their files are treated like the arguments) and print a note on stderr. They will be removed in the next major version.
- Exit codes: `0` every check passed, `1` a check failed, `2` wrong usage or an input file could not be read, recognized or parsed, `3` a check could not be done. Error messages and the banner go to stderr, the contents and results to stdout.
- Bouncy Castle 1.86 (`jdk18on`); the CV certificate classes use the Bouncy Castle reference, date and public key types.
- The Maven project is in the repository root with the standard layout (`src/main/java`, `src/test/java`).

### Added
- `--version`/`-V`.
- ICAO Deviation Lists (Doc 9303 Part 3 and Part 12): shown and checked against the SignedData profile, the extended key usage of the signer and the deviation types.
- ICAO CSCA Master Lists and BSI Signer Lists (TR-03129-2, 9): checked against their SignedData profile, the extended key usage and the private key usage period of the signer.
- BSI Defect Lists of versions 1 to 3 (TR-03129-2, 8), checked against the SignedData profile of TR-03129-3, Appendix C.
- BSI Block Lists of Restricted Identification (TR-03129-3, B) and the Black Lists of TR-03129 V1.10.
- Deviations from the EC domain parameter rules of BSI TR-03110 Part 3, D.3.3 are reported.
- A note for expired certificates (does not affect the exit code).
- Unsupported public key algorithms are reported with their object identifier.
- Unit tests and a regression test of the command line output.

### Fixed
- A link certificate given together with the new CVCA certificate no longer replaces it in the chain check.
- The SignedData signature of deviation and defect lists is verified correctly; files without SignedData object are rejected.
- Deviation list parsing of documents, chip OID and description; crashes and wrong results in the defect list output.
- The read access to data groups 5 and 6 of an authentication terminal is listed correctly.
- A CV certificate without body no longer crashes certain.

## 1.0.0 - 2023-10-31

### Added
- CHAT bits for PSA and read/write access to DG22.

### Fixed
- Missing leading zero in the CHAT bit representation.

### Changed
- Updated Bouncy Castle to 1.74.

## 0.99 - 2022-02-24

Older versions are documented only in the commit history.

