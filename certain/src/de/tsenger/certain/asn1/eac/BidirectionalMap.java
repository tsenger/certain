//package org.bouncycastle.asn1.eac;
package de.tsenger.certain.asn1.eac;

import java.util.Hashtable;

public class BidirectionalMap extends Hashtable<Object, Object>{
	private static final long serialVersionUID = -7457289971962812909L;
	
	Hashtable<Object, Object> reverseMap = new Hashtable<Object, Object>();
	
	public Object getReverse(Object o)
	{
		return reverseMap.get(o);
	}
	
	@Override
	public Object put(Object key, Object o)
	{
		reverseMap.put(o, key);
		return super.put(key, o);
	}
	
}
