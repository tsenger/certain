package de.tsenger.certain;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class HashCalculator {
	
	byte[] data = null;
	byte[] md5 = null;
	byte[] sha1 = null;
	byte[] sha224 = null;
	byte[] sha256 = null;
	
	MessageDigest md = null;
	
	public HashCalculator(byte[] certBytes)  {
		
		Security.addProvider(new BouncyCastleProvider());
		
		data = new byte[certBytes.length];
		System.arraycopy(certBytes, 0, data, 0, certBytes.length);
	}
	
	public byte[] getMD5() throws NoSuchAlgorithmException {
		return getDigest("MD5");
	}
	
	public byte[] getSHA1() throws NoSuchAlgorithmException{
		return getDigest("SHA1");
	}
	
	public byte[] getSHA224() throws NoSuchAlgorithmException{
		return getDigest("SHA-224");
	}
	
	public byte[] getSHA256() throws NoSuchAlgorithmException {
		return getDigest("SHA-256");
	}
	
	private byte[] getDigest(String algorithm) throws NoSuchAlgorithmException {

		md = MessageDigest.getInstance(algorithm);
		md.update(data);
		return md.digest();		
	}

}
