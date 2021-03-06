package de.tsenger.tools;
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


/**
 * 
 * @author Tobias Senger (jsmex@t-senger.de)
 */
public class HexString {

	public static String stringToHex(String s) {
		byte[] stringBytes = s.getBytes();
		return HexString.bufferToHex(stringBytes);
	}

	public static String bufferToHex(byte buffer[]) {
		return HexString.bufferToHex(buffer, 0, buffer.length, false);
	}
	
	public static String bufferToHex(byte buffer[], boolean wrapLines) {
		return HexString.bufferToHex(buffer, 0, buffer.length, wrapLines);
	}
	
	public static String bufferToHex(byte buffer[], int startOffset, int length) {
		return HexString.bufferToHex(buffer, startOffset, length, false);
	}

	public static String bufferToHex(byte buffer[], int startOffset, int length, boolean wrapLines) {
		StringBuffer hexString = new StringBuffer(2 * length);
		int endOffset = startOffset + length;
		for (int i = startOffset; i < endOffset; i++) {
			HexString.appendHexPair(buffer[i], hexString);
			if (wrapLines) {
				hexString.append(" ");
				if (((i + 1) % 16 == 0)&&(i+1!=endOffset))
					hexString.append("\n");
			}
		}
		return hexString.toString();
	}

	public static String hexToString(String hexString)
			throws NumberFormatException {
		byte[] bytes = HexString.hexToBuffer(hexString);
		return new String(bytes);
	}

	public static byte[] hexToBuffer(String hexString) throws NumberFormatException {
		hexString = hexString.replaceAll(" ", "");
		int length = hexString.length();
		byte[] buffer = new byte[(length + 1) / 2];
		boolean evenByte = true;
		byte nextByte = 0;
		int bufferOffset = 0;
		if ((length % 2) == 1)
			evenByte = false;
		for (int i = 0; i < length; i++) {
			char c = hexString.charAt(i);
			int nibble;
			if ((c >= '0') && (c <= '9'))
				nibble = c - '0';
			else if ((c >= 'A') && (c <= 'F'))
				nibble = c - 'A' + 0x0A;
			else if ((c >= 'a') && (c <= 'f'))
				nibble = c - 'a' + 0x0A;
			else
				throw new NumberFormatException("Invalid hex digit '" + c
						+ "'.");
			if (evenByte) {
				nextByte = (byte) (nibble << 4);
			} else {
				nextByte += (byte) nibble;
				buffer[bufferOffset++] = nextByte;
			}
			evenByte = !evenByte;
		}
		return buffer;
	}

	private static void appendHexPair(byte b, StringBuffer hexString) {
		char highNibble = kHexChars[(b & 0xF0) >> 4];
		char lowNibble = kHexChars[b & 0x0F];
		hexString.append(highNibble);
		hexString.append(lowNibble);
	}

	private static final char kHexChars[] = { '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
}