//package org.bouncycastle.asn1.eac;
package de.tsenger.certain.asn1.eac;

import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;

public abstract class PublicKeyDataObject
    extends ASN1Object
{
	
	private static final Hashtable<ASN1ObjectIdentifier, String> AlgorithmNames = new Hashtable<ASN1ObjectIdentifier, String>();
    static
    {
    	AlgorithmNames.put(EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_1, "id_TA_RSA_v1_5_SHA_1");
    	AlgorithmNames.put(EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_256, "id_TA_RSA_v1_5_SHA_256");
    	AlgorithmNames.put(EACObjectIdentifiers.id_TA_RSA_PSS_SHA_1, "id_TA_RSA_PSS_SHA_1");
    	AlgorithmNames.put(EACObjectIdentifiers.id_TA_RSA_PSS_SHA_256, "id_TA_RSA_PSS_SHA_256");
    	AlgorithmNames.put(EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_512, "id_TA_RSA_v1_5_SHA_512");
    	AlgorithmNames.put(EACObjectIdentifiers.id_TA_RSA_PSS_SHA_512, "id_TA_RSA_PSS_SHA_512");
    	AlgorithmNames.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_1, "id_TA_ECDSA_SHA_1");
    	AlgorithmNames.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_224, "id_TA_ECDSA_SHA_224");
    	AlgorithmNames.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, "id_TA_ECDSA_SHA_256");
    	AlgorithmNames.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_384, "id_TA_ECDSA_SHA_384");
    	AlgorithmNames.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_512, "id_TA_ECDSA_SHA_512");
    }
    
    public String getAlgorithmName() {
    	return AlgorithmNames.get(this.getUsage());
    }
	
    public static PublicKeyDataObject getInstance(Object obj)
    {
        if (obj instanceof PublicKeyDataObject)
        {
            return (PublicKeyDataObject)obj;
        }
        if (obj != null)
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(obj);
            ASN1ObjectIdentifier usage = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));

            if (usage.on(EACObjectIdentifiers.id_TA_ECDSA))
            {
                return new ECDSAPublicKey(seq);
            }
            else
            {
                return new RSAPublicKey(seq);
            }
        }

        return null;
    }

    public abstract ASN1ObjectIdentifier getUsage();
}
