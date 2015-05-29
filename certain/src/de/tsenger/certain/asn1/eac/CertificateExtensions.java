package de.tsenger.certain.asn1.eac;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERApplicationSpecific;

public class CertificateExtensions extends ASN1Object {
	
	private List<DiscretionaryDataTemplate> DiscretionaryDataTemplateList = new ArrayList<DiscretionaryDataTemplate>(5);
	
	private CertificateExtensions(DERApplicationSpecific appSpe)
	        throws IOException
	    {
	        setCertificateExtensions(appSpe);
	    }

	private void setCertificateExtensions(DERApplicationSpecific appSpe) throws IOException {
		byte[] content;
        if (appSpe.getApplicationTag() == EACTags.CERTIFICATE_EXTENSIONS)
        {
            content = appSpe.getContents();
        }
        else
        {
            throw new IOException("Bad tag : not CERTIFICATE_EXTENSIONS");
        }
        ASN1InputStream aIS = new ASN1InputStream(content);
        ASN1Primitive obj;
        while ((obj = aIS.readObject()) != null) {
            DERApplicationSpecific aSpe;

            if (obj instanceof DERApplicationSpecific)
            {
                aSpe = (DERApplicationSpecific)obj;
            }
            else
            {
            	aIS.close();
                throw new IOException("Not a valid iso7816 content : not a DERApplicationSpecific Object :" + EACTags.encodeTag(appSpe) + obj.getClass());           
            }
            if (aSpe.getApplicationTag()==EACTags.DISCRETIONARY_DATA_TEMPLATE) {
	            addDiscretionaryDataTemplate(aSpe);
            }
            else {
            	aIS.close();
                throw new IOException("Not a valid Discretionary Data Template, instead found tag: " + aSpe.getApplicationTag());
            }
        }
        aIS.close();
		
	}

	public void addDiscretionaryDataTemplate(DERApplicationSpecific aSpe) throws IOException {
		DiscretionaryDataTemplateList.add(DiscretionaryDataTemplate.getInstance(aSpe));		
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
		
		return ASN1Sequence.getInstance(v);
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
	            return new CertificateExtensions(DERApplicationSpecific.getInstance(appSpe));
	        }

	        return null;
	    }
	
	

}
