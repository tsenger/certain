/**
 *  Copyright 2011, Tobias Senger
 *  
 *  This file is part of animamea.
 *
 *  Animamea is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Animamea is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License   
 *  along with animamea.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.tsenger.tools;

import java.math.BigInteger;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Helfer-Klasse zum Konventieren verschiedener Datentypen und Strukturen
 * 
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class Converter {
	
	public static Date BCDtoDate(byte[] yymmdd) {
		if( yymmdd==null || yymmdd.length!=6 ){
	         throw new IllegalArgumentException("Argument must have length 6, was " + (yymmdd==null?0:yymmdd.length));
	      }
		int year  = 2000 + yymmdd[0]*10 + yymmdd[1];
	    int month = yymmdd[2]*10 + yymmdd[3] - 1; // Java month index starts with 0...
	    int day   = yymmdd[4]*10 + yymmdd[5];
		GregorianCalendar gregCal = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
		gregCal.set(year, month, day,0,0,0);
		return gregCal.getTime();
	}

	/**
	 * Converts a byte into a unsigned integer value.
	 * 
	 * @param value
	 * @return
	 */
	public static int toUnsignedInt(byte value) {
		return (value & 0x7F) + (value < 0 ? 128 : 0);
	}

	public static long ByteArrayToLong(byte[] bytes) {

		long lo = 0;
		for (int i = 0; i < bytes.length ; i++) {
			lo <<= 8;
			lo += (bytes[i] & 0x000000FF);
		}
		return lo;
	}

	/**
	 * Writes a <code>long</code> to byte array as eight bytes, high byte
	 * first.
	 * 
	 * @param v
	 *            a <code>long</code> to be converted.
	 */
	public static byte[] longToByteArray(long v) {
		byte[] ivByes = new byte[8];
		ivByes[0] = (byte) (v >>> 56);
		ivByes[1] = (byte) (v >>> 48);
		ivByes[2] = (byte) (v >>> 40);
		ivByes[3] = (byte) (v >>> 32);
		ivByes[4] = (byte) (v >>> 24);
		ivByes[5] = (byte) (v >>> 16);
		ivByes[6] = (byte) (v >>> 8);
		ivByes[7] = (byte) (v >>> 0);
		return ivByes;
	}

	/**
	 * Konvertiert ein BigInteger in ein ByteArray. Ein führendes Byte mit dem
	 * Wert 0 wird dabei angeschnitten. (Kennzeichen für einen positiven Wert,
	 * bei BigIntger)
	 * 
	 * @param bi
	 *            Das zu konvertierende BigInteger-Objekt.
	 * @return Byte-Array ohne führendes 0-Byte
	 */
	public static byte[] bigIntToByteArray(BigInteger bi) {
		return cutLeadingZero(bi.toByteArray());
	}
	
	public static byte[] cutLeadingZero(byte[] array) {
		byte[] returnbytes = null;
		if (array[0] == 0) {
			returnbytes = new byte[array.length - 1];
			System.arraycopy(array, 1, returnbytes, 0, returnbytes.length);
			return returnbytes;
		} else
			return array;
	}


}
