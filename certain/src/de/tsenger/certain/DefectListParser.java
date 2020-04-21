package de.tsenger.certain;

import java.io.StringWriter;
import java.security.cert.Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;

import de.tsenger.certain.asn1.eac.BSIObjectIdentifiers;
import de.tsenger.certain.asn1.mrtdpki.Defect;
import de.tsenger.certain.asn1.mrtdpki.DefectList;
import de.tsenger.certain.asn1.mrtdpki.KnownDefect;
import de.tsenger.tools.HexString;

public class DefectListParser extends DListParser{
	
	private DefectList defectList;

	public DefectListParser(ASN1Object dListObject) {
		defectList = DefectList.getInstance(dListObject);
	}
	
	@Override
	public String getDListInfoString(boolean showDetails) {
		
		Defect defect;
		
		StringWriter sw = new StringWriter();
				
		sw.write("\nThis Defect List contains defects from "+defectList.getDefects().size()+" different DS certificates\n");
						
		for (int i=0;i<defectList.getDefects().size();i++) {
			sw.write("\n++++++++++++++++++++++++++++++++++ DEFECT No. "+(i+1)+" ++++++++++++++++++++++++++++++++++\n");
			defect = Defect.getInstance(defectList.getDefects().getObjectAt(i));
			
			if (defect.getSignerId().getId() instanceof ASN1Encodable) { //SignerIdentifier CHOICE is IssuerAndSerialNumber 
				IssuerAndSerialNumber iasn = IssuerAndSerialNumber.getInstance(defect.getSignerId().getId());
				
				sw.write("DS Issuer: "+iasn.getName().toString()+"; DS Serial No.: "+iasn.getSerialNumber()+"\n");
				
				
			} else if (defect.getSignerId().getId() instanceof ASN1OctetString) {	//SignerIdentifier CHOICE is SubjectKeyIdentifier 
				byte[] encoded = ((ASN1OctetString)defect.getSignerId().getId()).getOctets();
				sw.write(HexString.bufferToHex(encoded)+"\n");
				
			}
			
			if (defect.getCertificateHash()!=null) { //optional Hash available?
				byte[] encoded = defect.getCertificateHash().getOctets();
				sw.write("Certificate Hash: "+ HexString.bufferToHex(encoded)+"\n");
			}
			sw.write("This DS certificate has "+defect.getKnownDefects().size()+" known defects:\n");
			
			KnownDefect knownDefect;
			for (int j=0;j<defect.getKnownDefects().size();j++) {
				knownDefect = KnownDefect.getInstance(defect.getKnownDefects().getObjectAt(j));
				ASN1ObjectIdentifier id_defectType = knownDefect.getDefectType();
				
				if (id_defectType.equals(BSIObjectIdentifiers.certRevoked)) {
					sw.write("+ Authentication Deviation: DS certificate revoked (OID: "+id_defectType+")");
					ASN1Enumerated statusCode = (ASN1Enumerated)knownDefect.getParameters();
					
					switch (statusCode.getValue().intValue()) {
					case 0: sw.write("\tno details given (status code 0: noIndication)\n");
					case 1: sw.write("\trevocation under investigation (status code 1: onHold)\n");
					case 2: sw.write("\tthe certificate has been used for testing purpose (status code 2: testing)\n");
					case 3: sw.write("\tthe issuer has revoked the certificate by CRL (status code 3: revoked by Issuer)\n");
					case 4: sw.write("\tthe Deviation List Signer has revoked the certificate (status code 4: revoked DLS)\n");
					default: sw.write("\tstatus codes >=32 can be used for internal purpose (status code "+statusCode.getValue().intValue()+": proprietary)\n");
					}
					
				} else if (id_defectType.equals(BSIObjectIdentifiers.certReplaced)) {
					sw.write("+ Authentication Deviation: DS certificate malformed (OID: "+id_defectType+")\n");
					Certificate replacementCert= (Certificate)knownDefect.getParameters();
					sw.write("\tReplacement Certificate:\n\t"+replacementCert.toString()+"\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.certChipAuthKeyRevoked)) {
					sw.write("+ Authentication Deviation: Chip Authentication private keys compromised (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.certActiveAuthKeyRevoked)) {
					sw.write("+ Authentication Deviation: Active Authentication private keys compromised (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.ePassportDGMalformed)) {
					sw.write("+ Personalisation Deviation ePassport: data group malformed (OID: "+id_defectType+")\n");
					DLSet malformedDgs = (DLSet)knownDefect.getParameters();
					sw.write("\tDatagroups:");
					for (int k=0;k<malformedDgs.size();k++){
						int dgno = ASN1Integer.getInstance(malformedDgs.getObjectAt(k)).getValue().intValue();
						sw.write(dgno+" ");
					}
					sw.write("\n");
					
				} else if (id_defectType.equals(BSIObjectIdentifiers.SODInvalid)) {
					sw.write("+ Personalisation Deviation ePassport: SOD malformed (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.COMSODDiscrepancy)) {
					sw.write("+ Personalisation Deviation ePassport: COM SOD discrepancy (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.eIDDGMalformed)) {
					sw.write("+ Personalisation Deviation eID: data group malformed (OID: "+id_defectType+")\n");
					DLSet malformedDgs = (DLSet)knownDefect.getParameters();
					sw.write("\tDatagroups: ");
					for (int l=0;l<malformedDgs.size();l++){
						int dgno = ASN1Integer.getInstance(malformedDgs.getObjectAt(l)).getValue().intValue();
						sw.write(dgno+" ");
					}
					sw.write("\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.eIDIntegrity)) {
					sw.write("+ Personalisation Deviation eID: application integrity uncertain (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.eIDSecurityInfoMissing)) {
					sw.write("+ Personalisation Deviation eID: SecurityInfo missing (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.eIDDGMissing)) {
					sw.write("+ Personalisation Deviation eID: data group missing (OID: "+id_defectType+")\n");
					DLSet malformedDgs = (DLSet)knownDefect.getParameters();
					sw.write("\tDatagroups: ");
					for (int m=0;m<malformedDgs.size();m++){
						int dgno = ASN1Integer.getInstance(malformedDgs.getObjectAt(m)).getValue().intValue();
						sw.write(dgno+" ");
					}
					sw.write("\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.CardSecurityMalformed)) {
					sw.write("+ General Document Defects: Card Security Object malformed (OID: "+id_defectType+")\n");
					DERSequence cardSecurity = (DERSequence)knownDefect.getParameters();
					sw.write("\tSize of new CardSecurity: "+cardSecurity.size()+"\n");
					//TODO Print whole new DS cert if showDetails is set
				} else if (id_defectType.equals(BSIObjectIdentifiers.ChipSecurityMalformed)) {
					sw.write("+ General Document Defects: Chip Security Object malformed (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.PowerDownReq)) {
					sw.write("+ General Document Defects: Power Down is required (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.DSMalformed)) {
					sw.write("+ General Document Defects: Document Signer is malformed (OID: "+id_defectType+")\n");
				} else if (id_defectType.equals(BSIObjectIdentifiers.EAC2PrivilegedTerminalInfoMissing)) {
					sw.write("+ General Document Defects: EAC2 PrivilegedTerminalInfo missing (OID: "+id_defectType+")\n");
				} else {
					sw.write("! Unknown Deviation OID: "+id_defectType+")\n");
				}
				
			}
						
		}

		return sw.toString();
	}
	
}
