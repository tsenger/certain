package de.tsenger.certain.asn1.eac;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;

public class CertificateExtensions extends ASN1Object {
	
	private List<DiscretionaryDataTemplate> DiscretionaryDataTemplateList = new ArrayList<DiscretionaryDataTemplate>(5);
	
	public CertificateExtensions() {
		
	}
	
	public CertificateExtensions(DiscretionaryDataTemplate ddt) {
		this.DiscretionaryDataTemplateList.add(ddt);
	}
	
	private CertificateExtensions(ASN1TaggedObject appSpe)
	        throws IOException
	    {
	        setCertificateExtensions(appSpe);
	    }

	private void setCertificateExtensions(ASN1TaggedObject appSpe) throws IOException {
        if (!appSpe.hasTag(BERTags.APPLICATION, EACTags.CERTIFICATE_EXTENSIONS))
        {
            throw new IOException("Bad tag : not CERTIFICATE_EXTENSIONS");
        }
        for (ASN1Encodable obj : ApplicationObjects.children(appSpe)) {
            ASN1TaggedObject aSpe;

            if (ApplicationObjects.isApplication(obj))
            {
                aSpe = (ASN1TaggedObject)obj;
            }
            else
            {
                throw new IOException("Not a valid iso7816 content : not an APPLICATION tagged object :" + obj.getClass());
            }
            if (aSpe.hasTag(BERTags.APPLICATION, EACTags.DISCRETIONARY_DATA_TEMPLATE)) {
	            addDiscretionaryDataTemplate(DiscretionaryDataTemplate.getInstance(aSpe));
            }
            else {
                throw new IOException("Not a valid Discretionary Data Template, instead found tag: " + aSpe.getTagNo());
            }
        }
	}

	public void addDiscretionaryDataTemplate(DiscretionaryDataTemplate ddt) throws IOException {
		DiscretionaryDataTemplateList.add(ddt);		
	}
	
	public List<DiscretionaryDataTemplate> getDiscretionaryDataTemplateList() {
		return DiscretionaryDataTemplateList;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		
		for (DiscretionaryDataTemplate item : DiscretionaryDataTemplateList) {
			v.add(item);
		}
		
		return ApplicationObjects.create(EACTags.CERTIFICATE_EXTENSIONS, v);
	}
	
	public static CertificateExtensions getInstance(Object appSpe)
	        throws IOException
	    {
	        if (appSpe instanceof CertificateExtensions)
	        {
	            return (CertificateExtensions)appSpe;
	        }
	        else if (appSpe != null)
	        {
	            return new CertificateExtensions(ApplicationObjects.getInstance(appSpe));
	        }

	        return null;
	    }
	
	

}
