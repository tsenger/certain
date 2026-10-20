package de.tsenger.certain.asn1.eac;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.asn1.eac.CertificateHolderReference;
import org.bouncycastle.asn1.eac.CertificationAuthorityReference;
import org.bouncycastle.asn1.eac.PackedDate;

/**
 * Creates the Bouncy Castle reference and date types from the raw contents of a data object.
 * <p>
 * Bouncy Castle only offers package-private constructors for raw contents, so the contents are
 * split into the parts of its public constructors here.
 */
final class References {

	/** Length of the sequence number at the end of a CHR/CAR (TR-03110). */
	private static final int SEQUENCE_NUMBER_LENGTH = 5;

	/** Length of the country code at the start of a CHR/CAR (TR-03110). */
	private static final int COUNTRY_CODE_LENGTH = 2;

	private References() {
	}

	static CertificateHolderReference holderReference(byte[] contents) {
		String[] parts = split(contents);
		return new CertificateHolderReference(parts[0], parts[1], parts[2]);
	}

	static CertificationAuthorityReference authorityReference(byte[] contents) {
		String[] parts = split(contents);
		return new CertificationAuthorityReference(parts[0], parts[1], parts[2]);
	}

	/** @param contents six bytes, each one decimal digit (YYMMDD) */
	static PackedDate packedDate(byte[] contents) {
		StringBuilder digits = new StringBuilder();
		for (byte digit : contents) {
			digits.append((char) ('0' + digit));
		}
		return new PackedDate(digits.toString());
	}

	/** @return country code, holder mnemonic and sequence number */
	private static String[] split(byte[] contents) {
		String reference = new String(contents, StandardCharsets.ISO_8859_1);
		int sequenceStart = reference.length() - SEQUENCE_NUMBER_LENGTH;
		return new String[] { reference.substring(0, COUNTRY_CODE_LENGTH),
				reference.substring(COUNTRY_CODE_LENGTH, sequenceStart), reference.substring(sequenceStart) };
	}
}
