package de.tsenger.certain;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

/**
 * Parses ICAO deviation lists wrapped in CMS SignedData.
 */
public class DeviationListTest {

	@Test
	public void signedDeviationListCanBeParsed() throws Exception {
		SignedDataParser parser = new SignedDataParser(TestData.read("deviation-lists/cms/all_deviations.bin"));

		DListParser deviationList = parser.getDListParser();

		assertNotNull(deviationList);
		assertFalse(deviationList.getDListInfoString(false).isEmpty());
	}
}
