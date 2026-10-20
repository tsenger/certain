package de.tsenger.certain;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;

import de.tsenger.tools.HexString;

/**
 * Shows and checks Block Lists of Restricted Identification (BSI TR-03129-3, B.1, version 2) and their predecessor,
 * the Black Lists (BSI TR-03129 V1.10, B.1, version 1):
 * <pre>
 *  BlockList ::= SEQUENCE {
 *  	version			INTEGER {v1(0), v2(1)},
 *  	type			INTEGER {complete(0), added(1), removed(2)},
 *  	listID			ListID,
 *  	deltaBase		ListID OPTIONAL,	-- required for delta lists
 *  	finalEntries	INTEGER OPTIONAL,	-- required for delta lists, only in v2
 *  	content			SEQUENCE OF BlockListDetails
 *  }
 *  BlockListDetails ::= SEQUENCE {
 *  	sectorID			OCTET STRING,
 *  	sectorSpecificIDs	SEQUENCE OF OCTET STRING
 *  }
 *  ListID ::= OCTET STRING
 * </pre>
 */
public class BlockListParser extends DListParser {

	private static final String[] TYPES = { "complete", "added", "removed" };

	private final int version;
	private final int type;
	private final ASN1OctetString listID;
	private ASN1OctetString deltaBase;
	private ASN1Integer finalEntries;
	private final ASN1Sequence content;

	BlockListParser(byte[] encoded) {
		ASN1Sequence seq = ASN1Sequence.getInstance(encoded);
		version = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().intValue();
		type = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue().intValue();
		listID = ASN1OctetString.getInstance(seq.getObjectAt(2));
		int index = 3;
		if (seq.size() < 4) throw new IllegalArgumentException("Bad sequence size: " + seq.size());
		if (seq.getObjectAt(index) instanceof ASN1OctetString) deltaBase = ASN1OctetString.getInstance(seq.getObjectAt(index++));
		if (seq.getObjectAt(index) instanceof ASN1Integer) finalEntries = ASN1Integer.getInstance(seq.getObjectAt(index++));
		content = ASN1Sequence.getInstance(seq.getObjectAt(index++));
		if (index != seq.size()) throw new IllegalArgumentException("Bad sequence size: " + seq.size());
	}

	@Override
	public String getDListInfoString(boolean showDetails) {
		StringWriter sw = new StringWriter();
		sw.write("\nBlock List version: v" + (version + 1) + (version == 0 ? " (Black List of BSI TR-03129 V1.10)" : "") + "\n");
		sw.write("Type: " + (type >= 0 && type < TYPES.length ? TYPES[type] : "unknown") + " (" + type + ")\n");
		sw.write("List ID: " + hex(listID) + "\n");
		if (deltaBase != null) sw.write("Delta base: " + hex(deltaBase) + "\n");
		if (finalEntries != null) sw.write("Final entries: " + finalEntries.getValue() + "\n");
		sw.write("This Block List contains " + content.size() + " sectors\n");
		for (int i = 0; i < content.size(); i++) {
			try {
				ASN1Sequence details = ASN1Sequence.getInstance(content.getObjectAt(i));
				ASN1Sequence ids = ASN1Sequence.getInstance(details.getObjectAt(1));
				sw.write("\nSector ID: " + hex(ASN1OctetString.getInstance(details.getObjectAt(0))) + "\n");
				sw.write("Sector-specific IDs: " + ids.size() + (showDetails ? "" : " (shown with --details)") + "\n");
				if (showDetails) {
					for (ASN1Encodable id : ids) sw.write("\t" + hex(ASN1OctetString.getInstance(id)) + "\n");
				}
			} catch (RuntimeException e) {
				sw.write("\n! BlockListDetails No. " + (i + 1) + " can't be parsed: " + e.getLocalizedMessage() + "\n");
			}
		}
		return sw.toString();
	}

	/** Checks the version, the type and the fields that delta lists need (BSI TR-03129-3, B.1). */
	@Override
	public CheckResult check() {
		List<String> violations = new ArrayList<String>();
		if (version != 0 && version != 1) {
			violations.add("version MUST be v1 (BSI TR-03129 V1.10, B.1) or v2 (BSI TR-03129-3, B.1) but is v" + (version + 1));
		}
		if (type < 0 || type >= TYPES.length) {
			violations.add("type MUST be complete(0), added(1) or removed(2) but is " + type + " (BSI TR-03129-3, B.1)");
		}
		boolean delta = type == 1 || type == 2;
		if (type == 0 && deltaBase != null) {
			violations.add("deltaBase MUST be omitted for complete Block Lists (BSI TR-03129-3, B.1)");
		}
		if (delta && deltaBase == null) {
			violations.add("deltaBase is required for delta lists (BSI TR-03129-3, B.1)");
		}
		if (version == 0 && finalEntries != null) {
			violations.add("finalEntries is not defined in version 1 (BSI TR-03129 V1.10, B.1)");
		}
		if (version == 1 && delta && finalEntries == null) {
			violations.add("finalEntries is required for delta lists (BSI TR-03129-3, B.1)");
		}
		for (int i = 0; i < content.size(); i++) {
			try {
				ASN1Sequence details = ASN1Sequence.getInstance(content.getObjectAt(i));
				ASN1OctetString.getInstance(details.getObjectAt(0));
				for (ASN1Encodable id : ASN1Sequence.getInstance(details.getObjectAt(1))) ASN1OctetString.getInstance(id);
			} catch (RuntimeException e) {
				violations.add("BlockListDetails No. " + (i + 1) + " can't be parsed: " + e.getLocalizedMessage());
			}
		}
		StringWriter sw = new StringWriter();
		for (String violation : violations) sw.write("Block List: " + violation + "!\n");
		return new CheckResult(violations.isEmpty() ? CheckResult.Status.VALID : CheckResult.Status.INVALID, sw.toString());
	}

	private static String hex(ASN1OctetString octets) {
		return HexString.bufferToHex(octets.getOctets());
	}
}
