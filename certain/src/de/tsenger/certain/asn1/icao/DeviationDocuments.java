package de.tsenger.certain.asn1.icao;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;



/**
 * DeviationDocuments as specified in DOC9303 Part 3
 * <p/>
 * <pre>
 *  DeviationDocuments ::= SEQUENCE {
 *  	documentType	[0] PrintableString (SIZE(2)) OPTIONAL,
 *  	dscIdentifier	DocumentSignerIdentifier OPTIONAL,
 *  	issuingDate		[4] IssuancePeriod OPTIONAL,
 *  	documentNumbers	[5] SET OF PrintableString OPTIONAL
 *  }
 * </pre>
 */

public class DeviationDocuments extends ASN1Object 
{
	private DERPrintableString documentType;
	private DocumentSignerIdentifier dscIdentifier ;
	private IssuancePeriod issuingDate;
	private ASN1Set documentNumbers;
	
	private DeviationDocuments(ASN1Sequence seq) {
		
		int index = 0;
		
		if (seq.size() > 4) throw new IllegalArgumentException("Bad sequence size: " + seq.size());
   
		for (int i=0; i<seq.size();i++) {

			if (seq.getObjectAt(index) instanceof ASN1TaggedObject) {
				ASN1TaggedObject tagObj = ASN1TaggedObject.getInstance(seq.getObjectAt(index));
				if (tagObj.getTagNo() == 0)	documentType = DERPrintableString.getInstance(tagObj, false);
				else if (tagObj.getTagNo() == 4) issuingDate = IssuancePeriod.getInstance(ASN1Sequence.getInstance(tagObj, false));
				else if (tagObj.getTagNo() == 5) documentNumbers = ASN1Set.getInstance(tagObj, false);
			}

			if (seq.getObjectAt(index) instanceof ASN1Choice) {
				dscIdentifier = DocumentSignerIdentifier.getInstance(seq.getObjectAt(index));
			}
//			if (seq.getObjectAt(index) instanceof IssuancePeriod) {
//				issuingDate = IssuancePeriod.getInstance(seq.getObjectAt(index++));
//			}
//			if (seq.getObjectAt(index) instanceof ASN1Set) {
//				documentNumbers = ASN1Set.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(index++)), false);
//			}
		}
		
		
	}
	
	public static DeviationDocuments getInstance(Object obj)
    {
        if (obj instanceof DeviationDocuments)
        {
            return (DeviationDocuments)obj;
        }
        else if (obj != null)
        {
            return new DeviationDocuments(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

	@Override
	public ASN1Primitive toASN1Primitive() {
		
		ASN1EncodableVector v = new ASN1EncodableVector();
		
		if (documentType != null) {
			v.add(documentType);
		}
		
		if (dscIdentifier != null) {
			v.add(dscIdentifier);
		}
		
		if (issuingDate != null) {
			v.add(issuingDate);
		}
		
		if (documentNumbers != null) {
			v.add(documentNumbers);
		}
		
		return DERSequence.getInstance(v);
	}
	
	public String getDocumentType() {
		if (documentType != null) return documentType.getString();
		return null;
	}
	
	public DocumentSignerIdentifier getDscIdentifier() {
		return dscIdentifier;
	}
	
	public IssuancePeriod getIssuingDate() {
		return issuingDate;
	}

	public ASN1Set getDocumentNumbers() {
		return documentNumbers;
	}
	

}
