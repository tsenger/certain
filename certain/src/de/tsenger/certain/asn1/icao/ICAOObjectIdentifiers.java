/**
 *  Copyright 2013, Tobias Senger
 *  
 *  This file is part of "certain".
 *
 *  certain is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  certain is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License   
 *  along with certain.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.tsenger.certain.asn1.icao;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */

public interface ICAOObjectIdentifiers {

	public static final ASN1ObjectIdentifier id_icao = new ASN1ObjectIdentifier("2.23.136");
	
	public static final ASN1ObjectIdentifier id_icao_mrtd = id_icao.branch("1");	
	public static final ASN1ObjectIdentifier id_icao_mrtd_security = id_icao_mrtd.branch("1");
	
	public static final ASN1ObjectIdentifier id_icao_DeviationList = id_icao_mrtd_security.branch("7");
	public static final ASN1ObjectIdentifier id_icao_DeviationListSigningKey = id_icao_mrtd_security.branch("8");
	
	public static final ASN1ObjectIdentifier id_Deviation_CertOrKey = id_icao_DeviationList.branch("1");
	public static final ASN1ObjectIdentifier id_Deviation_CertOrKey_DSSignature = id_Deviation_CertOrKey.branch("1");
	public static final ASN1ObjectIdentifier id_Deviation_CertOrKey_DSEncoding = id_Deviation_CertOrKey.branch("2");
	public static final ASN1ObjectIdentifier id_Deviation_CertOrKey_CSCAEncoding = id_Deviation_CertOrKey.branch("3");
	public static final ASN1ObjectIdentifier id_Deviation_CertOrKey_AAKeyCompromised = id_Deviation_CertOrKey.branch("4");
	
	public static final ASN1ObjectIdentifier id_Deviation_LDS = id_icao_DeviationList.branch("2");
	public static final ASN1ObjectIdentifier id_Deviation_LDS_DGMalformed = id_Deviation_LDS.branch("1");
	public static final ASN1ObjectIdentifier id_Deviation_LDS_DGHashWrong = id_Deviation_LDS.branch("2");
	public static final ASN1ObjectIdentifier id_Deviation_LDS_SODSignatureWrong = id_Deviation_LDS.branch("3");
	public static final ASN1ObjectIdentifier id_Deviation_LDS_COMInconsistent = id_Deviation_LDS.branch("4");
	
	public static final ASN1ObjectIdentifier id_Deviation_MRZ = id_icao_DeviationList.branch("3");
	public static final ASN1ObjectIdentifier id_Deviation_MRZ_WrongData = id_Deviation_MRZ.branch("1");
	public static final ASN1ObjectIdentifier id_Deviation_MRZ_WrongCheckDigit = id_Deviation_MRZ.branch("2");
	
	public static final ASN1ObjectIdentifier id_Deviation_Chip = id_icao_DeviationList.branch("3");
}
