package de.tsenger.certain;

import static de.tsenger.certain.TestSignedData.certificate;
import static de.tsenger.certain.TestSignedData.keyPair;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.junit.Test;

import de.tsenger.certain.asn1.eac.BSIObjectIdentifiers;

/**
 * Shows and checks Block Lists (BSI TR-03129-3, B) and Black Lists (BSI TR-03129 V1.10, B) created by the test.
 */
public class BlockListTest {

	private static final int V1 = 0, V2 = 1, COMPLETE = 0, ADDED = 1;

	@Test
	public void completeBlockListIsShownAndAccepted() throws Exception {
		SignedDataParser parser = parser(blockList(V2, COMPLETE, false, false));
		String output = parser.getDListParser().getDListInfoString(true);

		assertTrue(output, output.contains("Block List version: v2"));
		assertTrue(output, output.contains("Type: complete (0)"));
		assertTrue(output, output.contains("List ID: 0102"));
		assertTrue(output, output.contains("Sector ID: 0a0b"));
		assertTrue(output, output.contains("Sector-specific IDs: 2"));
		assertTrue(output, output.contains("\tcafe"));
		assertEquals(CheckResult.Status.VALID, parser.getDListParser().check().getStatus());

		CheckResult signedData = parser.checkSignedData();
		assertEquals(signedData.getText(), CheckResult.Status.VALID, signedData.getStatus());
		assertTrue(signedData.getText(), signedData.getText().contains("eContentType: 0.4.0.127.0.7.3.2.2 (BSI Block List)"));
	}

	@Test
	public void sectorSpecificIdsAreOnlyCountedWithoutDetails() throws Exception {
		String output = parser(blockList(V2, COMPLETE, false, false)).getDListParser().getDListInfoString(false);

		assertTrue(output, output.contains("Sector-specific IDs: 2 (shown with --details)"));
		assertFalse(output, output.contains("cafe"));
	}

	@Test
	public void deltaListWithDeltaBaseAndFinalEntriesIsAccepted() throws Exception {
		DListParser parser = parser(blockList(V2, ADDED, true, true)).getDListParser();

		assertTrue(parser.getDListInfoString(false).contains("Delta base: 0101"));
		assertTrue(parser.getDListInfoString(false).contains("Final entries: 42"));
		assertEquals(parser.check().getText(), CheckResult.Status.VALID, parser.check().getStatus());
	}

	@Test
	public void deltaListWithoutDeltaBaseAndFinalEntriesFails() throws Exception {
		CheckResult result = parser(blockList(V2, ADDED, false, false)).getDListParser().check();

		assertEquals(CheckResult.Status.INVALID, result.getStatus());
		assertTrue(result.getText(), result.getText().contains("deltaBase is required for delta lists"));
		assertTrue(result.getText(), result.getText().contains("finalEntries is required for delta lists"));
	}

	@Test
	public void completeListWithDeltaBaseFails() throws Exception {
		CheckResult result = parser(blockList(V2, COMPLETE, true, false)).getDListParser().check();

		assertEquals(CheckResult.Status.INVALID, result.getStatus());
		assertTrue(result.getText(), result.getText().contains("deltaBase MUST be omitted for complete Block Lists"));
	}

	@Test
	public void blackListOfVersion1IsAccepted() throws Exception {
		DListParser parser = parser(blockList(V1, ADDED, true, false)).getDListParser();

		assertTrue(parser.getDListInfoString(false).contains("Block List version: v1 (Black List of BSI TR-03129 V1.10)"));
		assertEquals(parser.check().getText(), CheckResult.Status.VALID, parser.check().getStatus());
	}

	@Test
	public void finalEntriesInVersion1Fails() throws Exception {
		CheckResult result = parser(blockList(V1, ADDED, true, true)).getDListParser().check();

		assertEquals(CheckResult.Status.INVALID, result.getStatus());
		assertTrue(result.getText(), result.getText().contains("finalEntries is not defined in version 1"));
	}

	/** Block list with one sector and two sector-specific IDs. */
	private static byte[] blockList(int version, int type, boolean deltaBase, boolean finalEntries) throws Exception {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(new ASN1Integer(version));
		v.add(new ASN1Integer(type));
		v.add(new DEROctetString(new byte[] { 0x01, 0x02 }));
		if (deltaBase) v.add(new DEROctetString(new byte[] { 0x01, 0x01 }));
		if (finalEntries) v.add(new ASN1Integer(42));
		ASN1Encodable ids = new DERSequence(new ASN1Encodable[] { new DEROctetString(new byte[] { (byte) 0xca, (byte) 0xfe }),
				new DEROctetString(new byte[] { (byte) 0xbe, (byte) 0xef }) });
		v.add(new DERSequence(new DERSequence(new ASN1Encodable[] { new DEROctetString(new byte[] { 0x0a, 0x0b }), ids })));
		return new DERSequence(v).getEncoded();
	}

	private static SignedDataParser parser(byte[] blockList) throws Exception {
		KeyPair keyPair = keyPair();
		return new SignedDataParser(TestSignedData.sign(BSIObjectIdentifiers.BlackList, blockList, keyPair, certificate(keyPair), true, "Sector"));
	}
}
