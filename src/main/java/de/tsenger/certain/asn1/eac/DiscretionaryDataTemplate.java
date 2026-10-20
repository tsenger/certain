package de.tsenger.certain.asn1.eac;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.eac.BidirectionalMap;

/**
 * A discretionary data template: an object identifier followed by none, one or several data objects.
 * <p>
 * The data objects are kept as they were read, so that the template is encoded exactly as it was
 * signed. An extension like the terminal sector carries two of them (context tags 0 and 1).
 */
public class DiscretionaryDataTemplate extends ASN1Object {

	private ASN1ObjectIdentifier oid;
	private final List<ASN1TaggedObject> dataObjects = new ArrayList<ASN1TaggedObject>();
	
	static BidirectionalMap ExtensionType = new BidirectionalMap();
    static
    {
    	ExtensionType.put(BSIObjectIdentifiers.AT_eIDAccess, "AT eID Access");
    	ExtensionType.put(BSIObjectIdentifiers.AT_specialFunctions, "AT Special Functions");
    	ExtensionType.put(BSIObjectIdentifiers.AT_eID_Biometrics, "AT eID Biometrics");
    	ExtensionType.put(BSIObjectIdentifiers.description, "Hash of Certificate Description");
    	ExtensionType.put(BSIObjectIdentifiers.sector, "Terminal Sector for RI");
    	ExtensionType.put(BSIObjectIdentifiers.PS_sector, "Terminal Sector for Pseudonymous Signatures");
    	ExtensionType.put(BSIObjectIdentifiers.uif, "UiF - Update im Feld");
    }

	public DiscretionaryDataTemplate(ASN1ObjectIdentifier oid, byte[] data) {
		this.oid = oid;
		if (data != null) {
			dataObjects.add(ApplicationObjects.create(EACTags.DISCRETIONARY_DATA, data));
		}
	}

	private DiscretionaryDataTemplate(ASN1TaggedObject appSpe) throws IOException {
		setDiscretionaryData(appSpe);
	}

	private void setDiscretionaryData(ASN1TaggedObject appSpe) throws IOException {
		if (!appSpe.hasTag(BERTags.APPLICATION, EACTags.DISCRETIONARY_DATA_TEMPLATE)) {
			throw new IOException("not a DISCRETIONARY DATA TEMPLATE :" + appSpe.getTagNo());
		}

		for (ASN1Encodable tmpObj : ApplicationObjects.children(appSpe)) {

			if (tmpObj instanceof ASN1ObjectIdentifier) {
				oid = ASN1ObjectIdentifier.getInstance(tmpObj);
			}
			else if (ApplicationObjects.isApplication(tmpObj)) {
				ASN1TaggedObject dataObject = (ASN1TaggedObject) tmpObj;
				if (dataObject.getTagNo() != EACTags.DISCRETIONARY_DATA) {
					throw new IOException("Invalid Object, no discretionaray data");
				}
				dataObjects.add(dataObject);
			}
			else if (tmpObj instanceof ASN1TaggedObject) {
				ASN1TaggedObject dataObject = (ASN1TaggedObject) tmpObj;
				//Tag 0x80 and 0x81 are valid tags here
				if (dataObject.getTagNo() != 0x00 && dataObject.getTagNo() != 0x01) {
					throw new IOException("Invalid Object, no valid data");
				}
				dataObjects.add(dataObject);
			}
		}
	}

	/**
	 * @return the contents of all data objects one after another, or null if there are none
	 */
	public byte[] getDataContent() {
		if (dataObjects.isEmpty()) {
			return null;
		}
		ByteArrayOutputStream content = new ByteArrayOutputStream();
		for (ASN1TaggedObject dataObject : dataObjects) {
			byte[] octets = ((ASN1OctetString) dataObject.getBaseUniversal(false, BERTags.OCTET_STRING)).getOctets();
			content.write(octets, 0, octets.length);
		}
		return content.toByteArray();
	}
	
	public ASN1ObjectIdentifier getOid() {
		return oid;
	}
	
	public String getExtensionDescription() {
		String extDescriptionString = (String)ExtensionType.get(this.oid);
		if(extDescriptionString==null) extDescriptionString = "unknown Extension (OID: "+this.oid.toString()+")";
    	return extDescriptionString;
    }

	public static DiscretionaryDataTemplate getInstance(Object obj) throws IOException {
		if (obj instanceof DiscretionaryDataTemplate) {
			return (DiscretionaryDataTemplate) obj;
		} else if (obj != null) {
			return new DiscretionaryDataTemplate(ApplicationObjects.getInstance(obj));
		}

		return null;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(oid);
		for (ASN1TaggedObject dataObject : dataObjects) {
			v.add(dataObject);
		}
		
		return ApplicationObjects.create(EACTags.DISCRETIONARY_DATA_TEMPLATE, v);
	}

}
