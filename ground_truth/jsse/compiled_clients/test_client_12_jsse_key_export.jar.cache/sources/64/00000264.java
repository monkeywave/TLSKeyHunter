package org.bouncycastle.asn1.cryptopro;

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.p003x9.X9ECParameters;
import org.bouncycastle.asn1.p003x9.X9ECPoint;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.p010ec.ECConstants;
import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.math.p010ec.WNafUtil;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/cryptopro/ECGOST3410NamedCurves.class */
public class ECGOST3410NamedCurves {
    static final Hashtable objIds = new Hashtable();
    static final Hashtable params = new Hashtable();
    static final Hashtable names = new Hashtable();

    private static ECPoint configureBasepoint(ECCurve eCCurve, BigInteger bigInteger, BigInteger bigInteger2) {
        ECPoint createPoint = eCCurve.createPoint(bigInteger, bigInteger2);
        WNafUtil.configureBasepoint(createPoint);
        return createPoint;
    }

    private static ECCurve configureCurve(ECCurve eCCurve) {
        return eCCurve;
    }

    private static BigInteger fromHex(String str) {
        return new BigInteger(1, Hex.decodeStrict(str));
    }

    public static ECDomainParameters getByOID(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (ECDomainParameters) params.get(aSN1ObjectIdentifier);
    }

    public static X9ECParameters getByOIDX9(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        ECDomainParameters eCDomainParameters = (ECDomainParameters) params.get(aSN1ObjectIdentifier);
        if (eCDomainParameters == null) {
            return null;
        }
        return new X9ECParameters(eCDomainParameters.getCurve(), new X9ECPoint(eCDomainParameters.getG(), false), eCDomainParameters.getN(), eCDomainParameters.getH(), eCDomainParameters.getSeed());
    }

    public static Enumeration getNames() {
        return names.elements();
    }

    public static ECDomainParameters getByName(String str) {
        ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) objIds.get(str);
        if (aSN1ObjectIdentifier == null) {
            return null;
        }
        return (ECDomainParameters) params.get(aSN1ObjectIdentifier);
    }

    public static X9ECParameters getByNameX9(String str) {
        ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) objIds.get(str);
        if (aSN1ObjectIdentifier == null) {
            return null;
        }
        return getByOIDX9(aSN1ObjectIdentifier);
    }

    public static String getName(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (String) names.get(aSN1ObjectIdentifier);
    }

    public static ASN1ObjectIdentifier getOID(String str) {
        return (ASN1ObjectIdentifier) objIds.get(str);
    }

    static {
        BigInteger fromHex = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97");
        BigInteger fromHex2 = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893");
        ECCurve configureCurve = configureCurve(new ECCurve.C0277Fp(fromHex, fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94"), fromHex("A6"), fromHex2, ECConstants.ONE));
        params.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A, new ECDomainParameters(configureCurve, configureBasepoint(configureCurve, ECConstants.ONE, fromHex("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14")), fromHex2, ECConstants.ONE));
        BigInteger fromHex3 = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97");
        BigInteger fromHex4 = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893");
        ECCurve configureCurve2 = configureCurve(new ECCurve.C0277Fp(fromHex3, fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94"), fromHex("A6"), fromHex4, ECConstants.ONE));
        params.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA, new ECDomainParameters(configureCurve2, configureBasepoint(configureCurve2, ECConstants.ONE, fromHex("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14")), fromHex4, ECConstants.ONE));
        BigInteger fromHex5 = fromHex("8000000000000000000000000000000000000000000000000000000000000C99");
        BigInteger fromHex6 = fromHex("800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F");
        ECCurve configureCurve3 = configureCurve(new ECCurve.C0277Fp(fromHex5, fromHex("8000000000000000000000000000000000000000000000000000000000000C96"), fromHex("3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B"), fromHex6, ECConstants.ONE));
        params.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_B, new ECDomainParameters(configureCurve3, configureBasepoint(configureCurve3, ECConstants.ONE, fromHex("3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC")), fromHex6, ECConstants.ONE));
        BigInteger fromHex7 = fromHex("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B");
        BigInteger fromHex8 = fromHex("9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9");
        ECCurve configureCurve4 = configureCurve(new ECCurve.C0277Fp(fromHex7, fromHex("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598"), fromHex("805A"), fromHex8, ECConstants.ONE));
        params.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchB, new ECDomainParameters(configureCurve4, configureBasepoint(configureCurve4, ECConstants.ZERO, fromHex("41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67")), fromHex8, ECConstants.ONE));
        BigInteger fromHex9 = fromHex("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B");
        BigInteger fromHex10 = fromHex("9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9");
        ECCurve configureCurve5 = configureCurve(new ECCurve.C0277Fp(fromHex9, fromHex("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598"), fromHex("805A"), fromHex10, ECConstants.ONE));
        params.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_C, new ECDomainParameters(configureCurve5, configureBasepoint(configureCurve5, ECConstants.ZERO, fromHex("41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67")), fromHex10, ECConstants.ONE));
        BigInteger fromHex11 = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97");
        BigInteger fromHex12 = fromHex("400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67");
        ECCurve configureCurve6 = configureCurve(new ECCurve.C0277Fp(fromHex11, fromHex("C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335"), fromHex("295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513"), fromHex12, ECConstants.FOUR));
        params.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA, new ECDomainParameters(configureCurve6, configureBasepoint(configureCurve6, fromHex("91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28"), fromHex("32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C")), fromHex12, ECConstants.FOUR));
        BigInteger fromHex13 = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7");
        BigInteger fromHex14 = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275");
        ECCurve configureCurve7 = configureCurve(new ECCurve.C0277Fp(fromHex13, fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4"), fromHex("E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760"), fromHex14, ECConstants.ONE));
        params.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA, new ECDomainParameters(configureCurve7, configureBasepoint(configureCurve7, ECConstants.THREE, fromHex("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4")), fromHex14, ECConstants.ONE));
        BigInteger fromHex15 = fromHex("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F");
        BigInteger fromHex16 = fromHex("800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD");
        ECCurve configureCurve8 = configureCurve(new ECCurve.C0277Fp(fromHex15, fromHex("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C"), fromHex("687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116"), fromHex16, ECConstants.ONE));
        params.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetB, new ECDomainParameters(configureCurve8, configureBasepoint(configureCurve8, ECConstants.TWO, fromHex("1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD")), fromHex16, ECConstants.ONE));
        BigInteger fromHex17 = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7");
        BigInteger fromHex18 = fromHex("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED");
        ECCurve configureCurve9 = configureCurve(new ECCurve.C0277Fp(fromHex17, fromHex("DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3"), fromHex("B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1"), fromHex18, ECConstants.FOUR));
        params.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetC, new ECDomainParameters(configureCurve9, configureBasepoint(configureCurve9, fromHex("E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148"), fromHex("F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F")), fromHex18, ECConstants.FOUR));
        objIds.put("GostR3410-2001-CryptoPro-A", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A);
        objIds.put("GostR3410-2001-CryptoPro-B", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_B);
        objIds.put("GostR3410-2001-CryptoPro-C", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_C);
        objIds.put("GostR3410-2001-CryptoPro-XchA", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA);
        objIds.put("GostR3410-2001-CryptoPro-XchB", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchB);
        objIds.put("Tc26-Gost-3410-12-256-paramSetA", RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA);
        objIds.put("Tc26-Gost-3410-12-512-paramSetA", RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA);
        objIds.put("Tc26-Gost-3410-12-512-paramSetB", RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetB);
        objIds.put("Tc26-Gost-3410-12-512-paramSetC", RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetC);
        names.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A, "GostR3410-2001-CryptoPro-A");
        names.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_B, "GostR3410-2001-CryptoPro-B");
        names.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_C, "GostR3410-2001-CryptoPro-C");
        names.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA, "GostR3410-2001-CryptoPro-XchA");
        names.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchB, "GostR3410-2001-CryptoPro-XchB");
        names.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA, "Tc26-Gost-3410-12-256-paramSetA");
        names.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA, "Tc26-Gost-3410-12-512-paramSetA");
        names.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetB, "Tc26-Gost-3410-12-512-paramSetB");
        names.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetC, "Tc26-Gost-3410-12-512-paramSetC");
    }
}