package de.tsenger.certain.asn1.eac;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.DERSequence;

public class CertificateExtensions extends ASN1Object {
	
	private List<DiscretionaryDataTemplate> DiscretionaryDataTemplateList = new ArrayList<DiscretionaryDataTemplate>(5);
	
	public CertificateExtensions() {
		
	}
	
	public CertificateExtensions(DiscretionaryDataTemplate ddt) {
		this.DiscretionaryDataTemplateList.add(ddt);
	}
	
	private CertificateExtensions(ASN1ApplicationSpecific appSpe)
	        throws IOException
	    {
	        setCertificateExtensions(appSpe);
	    }

	private void setCertificateExtensions(ASN1ApplicationSpecific appSpe) throws IOException {
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
            ASN1ApplicationSpecific aSpe;

            if (obj instanceof ASN1ApplicationSpecific)
            {
                aSpe = (ASN1ApplicationSpecific)obj;
            }
            else
            {
            	aIS.close();
                throw new IOException("Not a valid iso7816 content : not a ASN1ApplicationSpecific Object :" + EACTags.encodeTag(appSpe) + obj.getClass());           
            }
            if (aSpe.getApplicationTag()==EACTags.DISCRETIONARY_DATA_TEMPLATE) {
	            addDiscretionaryDataTemplate(DiscretionaryDataTemplate.getInstance(aSpe));
            }
            else {
            	aIS.close();
                throw new IOException("Not a valid Discretionary Data Template, instead found tag: " + aSpe.getApplicationTag());
            }
        }
        aIS.close();
		
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
		
		try {
			return new DERApplicationSpecific(false, EACTags.CERTIFICATE_EXTENSIONS, new DERSequence(v));
		} catch (IOException e) {
			throw new IllegalStateException("unable to convert Certificate Extensions");
		}
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
	            return new CertificateExtensions(ASN1ApplicationSpecific.getInstance(appSpe));
	        }

	        return null;
	    }
	
	

}
