package de.tsenger.certain;

import static org.junit.Assert.assertTrue;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

import org.junit.Test;

import de.tsenger.certain.asn1.eac.CertificateHolderAuthorization;
import de.tsenger.certain.asn1.eac.EACTags;

/**
 * Checks the text for the read access rights of an authentication terminal against Table 4 of
 * BSI TR-03110 Part 4: the bits 8 (DG 1) to 29 (DG 22) grant read access to the data groups 1 to 22.
 */
public class AuthorizationTextTest {

	/** Builds the CHAT of an authentication terminal from its five bytes of authorization. */
	private static String readAccessText(long authorizationBits) throws Exception {
		byte[] rights = new byte[5];
		for (int i = 0; i < rights.length; i++) {
			rights[i] = (byte) (authorizationBits >> (8 * (rights.length - 1 - i)));
		}
		ASN1EncodableVector content = new ASN1EncodableVector();
		content.add(CertificateHolderAuthorization.id_AT);
		content.add(new DERTaggedObject(false, BERTags.APPLICATION, EACTags.DISCRETIONARY_DATA, new DEROctetString(rights)));
		DERTaggedObject chat = new DERTaggedObject(false, BERTags.APPLICATION,
				EACTags.CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE, new DERSequence(content));

		String text = new CertParser().authorizationToString(new CertificateHolderAuthorization(chat));
		return text.substring(0, text.indexOf('\n'));
	}

	private static long readBit(int dataGroup) {
		return 1L << (7 + dataGroup);
	}

	@Test
	public void readAccessToDataGroupsWithGaps() throws Exception {
		long dg4and6 = readBit(4) | readBit(6);

		assertTrue(readAccessText(dg4and6).startsWith("Read access to DG 4, 6,"));
	}

	@Test
	public void readAccessToDataGroup5Only() throws Exception {
		assertTrue(readAccessText(readBit(5)).startsWith("Read access to DG 5,"));
	}

	@Test
	public void readAccessToDataGroup6Only() throws Exception {
		assertTrue(readAccessText(readBit(6)).startsWith("Read access to DG 6,"));
	}

	@Test
	public void everyDataGroupAloneIsListedWithItsOwnNumber() throws Exception {
		for (int dataGroup = 1; dataGroup <= 21; dataGroup++) {
			String expected = "Read access to DG " + dataGroup + ", ";

			assertTrue("DG " + dataGroup, readAccessText(readBit(dataGroup)).equals(expected));
		}
	}
}
