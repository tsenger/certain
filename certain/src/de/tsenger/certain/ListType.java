package de.tsenger.certain;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import de.tsenger.certain.asn1.eac.BSIObjectIdentifiers;
import de.tsenger.certain.asn1.icao.ICAOObjectIdentifiers;

/**
 * The signed lists certain knows, identified by the eContentType of their SignedData object, with the key purpose
 * that the extended key usage of their signer certificate contains.
 */
enum ListType {
	/** ICAO Doc 9303 Part 12, 10 */
	DEVIATION_LIST(ICAOObjectIdentifiers.id_icao_DeviationList, "ICAO Deviation List", ICAOObjectIdentifiers.id_icao_DeviationListSigningKey),
	/** ICAO Doc 9303 Part 12, 9 */
	MASTER_LIST(ICAOObjectIdentifiers.id_icao_cscaMasterList, "ICAO CSCA Master List", ICAOObjectIdentifiers.id_icao_cscaMasterListSigningKey),
	/** BSI TR-03129-2, 8 */
	DEFECT_LIST(BSIObjectIdentifiers.DefectList, "BSI Defect List", BSIObjectIdentifiers.electronicDefectListSigningKey),
	// Signer lists, BSI TR-03129-2, 9
	DOCUMENT_SIGNER_LIST(BSIObjectIdentifiers.DocumentSignerList, "BSI Document Signer List", BSIObjectIdentifiers.documentSignerListSigningKey),
	EU_HEALTH_SEAL_SIGNER_LIST(BSIObjectIdentifiers.euHealthSealSignerList, "BSI EU Health Seal Signer List", BSIObjectIdentifiers.euHealthSealSignerListSigningKey),
	EU_HEALTH_SEAL_CSCA_LIST(BSIObjectIdentifiers.euHealthSealCscaList, "BSI EU Health Seal CSCA List", BSIObjectIdentifiers.euHealthSealCscaListSigningKey),
	ICAO_HEALTH_SEAL_SIGNER_LIST(BSIObjectIdentifiers.icaoHealthSealSignerList, "BSI ICAO Health Seal Signer List", BSIObjectIdentifiers.icaoHealthSealSignerListSigningKey),
	ICAO_HEALTH_SEAL_CSCA_LIST(BSIObjectIdentifiers.icaoHealthSealCscaList, "BSI ICAO Health Seal CSCA List", BSIObjectIdentifiers.icaoHealthSealCscaListSigningKey),
	SOVEREIGN_SEAL_SIGNER_LIST(BSIObjectIdentifiers.sovereignSealSignerList, "BSI Sovereign Seal Signer List", BSIObjectIdentifiers.sovereignSealSignerListSigningKey),
	SOVEREIGN_SEAL_CSCA_LIST(BSIObjectIdentifiers.sovereignSealCscaList, "BSI Sovereign Seal CSCA List", BSIObjectIdentifiers.sovereignSealCscaListSigningKey);

	final ASN1ObjectIdentifier contentType;
	final String name;
	final KeyPurposeId signingKey;

	ListType(ASN1ObjectIdentifier contentType, String name, ASN1ObjectIdentifier signingKey) {
		this.contentType = contentType;
		this.name = name;
		this.signingKey = KeyPurposeId.getInstance(signingKey);
	}

	/** @return the list type with this eContentType or null if it is unknown */
	static ListType of(String contentType) {
		for (ListType type : values()) {
			if (type.contentType.getId().equals(contentType)) return type;
		}
		return null;
	}

	/** @return true for the signer lists of BSI TR-03129-2, 9 */
	boolean isSignerList() {
		return compareTo(DOCUMENT_SIGNER_LIST) >= 0;
	}
}
