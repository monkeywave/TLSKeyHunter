package org.bouncycastle.pqc.crypto.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.McElieceCCA2PublicKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.asn1.XMSSKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import org.bouncycastle.pqc.asn1.XMSSPublicKey;
import org.bouncycastle.pqc.crypto.lms.HSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/util/PublicKeyFactory.class */
public class PublicKeyFactory {
    private static Map converters = new HashMap();

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/util/PublicKeyFactory$LMSConverter.class */
    private static class LMSConverter extends SubjectPublicKeyInfoConverter {
        private LMSConverter() {
            super();
        }

        @Override // org.bouncycastle.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo subjectPublicKeyInfo, Object obj) throws IOException {
            byte[] octets = ASN1OctetString.getInstance(subjectPublicKeyInfo.parsePublicKey()).getOctets();
            if (Pack.bigEndianToInt(octets, 0) == 1) {
                return LMSPublicKeyParameters.getInstance(Arrays.copyOfRange(octets, 4, octets.length));
            }
            if (octets.length == 64) {
                octets = Arrays.copyOfRange(octets, 4, octets.length);
            }
            return HSSPublicKeyParameters.getInstance(octets);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/util/PublicKeyFactory$McElieceCCA2Converter.class */
    private static class McElieceCCA2Converter extends SubjectPublicKeyInfoConverter {
        private McElieceCCA2Converter() {
            super();
        }

        @Override // org.bouncycastle.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo subjectPublicKeyInfo, Object obj) throws IOException {
            McElieceCCA2PublicKey mcElieceCCA2PublicKey = McElieceCCA2PublicKey.getInstance(subjectPublicKeyInfo.parsePublicKey());
            return new McElieceCCA2PublicKeyParameters(mcElieceCCA2PublicKey.getN(), mcElieceCCA2PublicKey.getT(), mcElieceCCA2PublicKey.getG(), Utils.getDigestName(mcElieceCCA2PublicKey.getDigest().getAlgorithm()));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/util/PublicKeyFactory$NHConverter.class */
    private static class NHConverter extends SubjectPublicKeyInfoConverter {
        private NHConverter() {
            super();
        }

        @Override // org.bouncycastle.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo subjectPublicKeyInfo, Object obj) throws IOException {
            return new NHPublicKeyParameters(subjectPublicKeyInfo.getPublicKeyData().getBytes());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/util/PublicKeyFactory$QTeslaConverter.class */
    private static class QTeslaConverter extends SubjectPublicKeyInfoConverter {
        private QTeslaConverter() {
            super();
        }

        @Override // org.bouncycastle.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo subjectPublicKeyInfo, Object obj) throws IOException {
            return new QTESLAPublicKeyParameters(Utils.qTeslaLookupSecurityCategory(subjectPublicKeyInfo.getAlgorithm()), subjectPublicKeyInfo.getPublicKeyData().getOctets());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/util/PublicKeyFactory$SPHINCSConverter.class */
    private static class SPHINCSConverter extends SubjectPublicKeyInfoConverter {
        private SPHINCSConverter() {
            super();
        }

        @Override // org.bouncycastle.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo subjectPublicKeyInfo, Object obj) throws IOException {
            return new SPHINCSPublicKeyParameters(subjectPublicKeyInfo.getPublicKeyData().getBytes(), Utils.sphincs256LookupTreeAlgName(SPHINCS256KeyParams.getInstance(subjectPublicKeyInfo.getAlgorithm().getParameters())));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/util/PublicKeyFactory$SubjectPublicKeyInfoConverter.class */
    public static abstract class SubjectPublicKeyInfoConverter {
        private SubjectPublicKeyInfoConverter() {
        }

        abstract AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo subjectPublicKeyInfo, Object obj) throws IOException;
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/util/PublicKeyFactory$XMSSConverter.class */
    private static class XMSSConverter extends SubjectPublicKeyInfoConverter {
        private XMSSConverter() {
            super();
        }

        @Override // org.bouncycastle.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo subjectPublicKeyInfo, Object obj) throws IOException {
            XMSSKeyParams xMSSKeyParams = XMSSKeyParams.getInstance(subjectPublicKeyInfo.getAlgorithm().getParameters());
            if (xMSSKeyParams == null) {
                byte[] octets = ASN1OctetString.getInstance(subjectPublicKeyInfo.parsePublicKey()).getOctets();
                return new XMSSPublicKeyParameters.Builder(XMSSParameters.lookupByOID(Pack.bigEndianToInt(octets, 0))).withPublicKey(octets).build();
            }
            ASN1ObjectIdentifier algorithm = xMSSKeyParams.getTreeDigest().getAlgorithm();
            XMSSPublicKey xMSSPublicKey = XMSSPublicKey.getInstance(subjectPublicKeyInfo.parsePublicKey());
            return new XMSSPublicKeyParameters.Builder(new XMSSParameters(xMSSKeyParams.getHeight(), Utils.getDigest(algorithm))).withPublicSeed(xMSSPublicKey.getPublicSeed()).withRoot(xMSSPublicKey.getRoot()).build();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/util/PublicKeyFactory$XMSSMTConverter.class */
    private static class XMSSMTConverter extends SubjectPublicKeyInfoConverter {
        private XMSSMTConverter() {
            super();
        }

        @Override // org.bouncycastle.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo subjectPublicKeyInfo, Object obj) throws IOException {
            XMSSMTKeyParams xMSSMTKeyParams = XMSSMTKeyParams.getInstance(subjectPublicKeyInfo.getAlgorithm().getParameters());
            if (xMSSMTKeyParams == null) {
                byte[] octets = ASN1OctetString.getInstance(subjectPublicKeyInfo.parsePublicKey()).getOctets();
                return new XMSSMTPublicKeyParameters.Builder(XMSSMTParameters.lookupByOID(Pack.bigEndianToInt(octets, 0))).withPublicKey(octets).build();
            }
            ASN1ObjectIdentifier algorithm = xMSSMTKeyParams.getTreeDigest().getAlgorithm();
            XMSSPublicKey xMSSPublicKey = XMSSPublicKey.getInstance(subjectPublicKeyInfo.parsePublicKey());
            return new XMSSMTPublicKeyParameters.Builder(new XMSSMTParameters(xMSSMTKeyParams.getHeight(), xMSSMTKeyParams.getLayers(), Utils.getDigest(algorithm))).withPublicSeed(xMSSPublicKey.getPublicSeed()).withRoot(xMSSPublicKey.getRoot()).build();
        }
    }

    public static AsymmetricKeyParameter createKey(byte[] bArr) throws IOException {
        return createKey(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(bArr)));
    }

    public static AsymmetricKeyParameter createKey(InputStream inputStream) throws IOException {
        return createKey(SubjectPublicKeyInfo.getInstance(new ASN1InputStream(inputStream).readObject()));
    }

    public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo subjectPublicKeyInfo) throws IOException {
        return createKey(subjectPublicKeyInfo, null);
    }

    public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo subjectPublicKeyInfo, Object obj) throws IOException {
        AlgorithmIdentifier algorithm = subjectPublicKeyInfo.getAlgorithm();
        SubjectPublicKeyInfoConverter subjectPublicKeyInfoConverter = (SubjectPublicKeyInfoConverter) converters.get(algorithm.getAlgorithm());
        if (subjectPublicKeyInfoConverter != null) {
            return subjectPublicKeyInfoConverter.getPublicKeyParameters(subjectPublicKeyInfo, obj);
        }
        throw new IOException("algorithm identifier in public key not recognised: " + algorithm.getAlgorithm());
    }

    static {
        converters.put(PQCObjectIdentifiers.qTESLA_p_I, new QTeslaConverter());
        converters.put(PQCObjectIdentifiers.qTESLA_p_III, new QTeslaConverter());
        converters.put(PQCObjectIdentifiers.sphincs256, new SPHINCSConverter());
        converters.put(PQCObjectIdentifiers.newHope, new NHConverter());
        converters.put(PQCObjectIdentifiers.xmss, new XMSSConverter());
        converters.put(PQCObjectIdentifiers.xmss_mt, new XMSSMTConverter());
        converters.put(IsaraObjectIdentifiers.id_alg_xmss, new XMSSConverter());
        converters.put(IsaraObjectIdentifiers.id_alg_xmssmt, new XMSSMTConverter());
        converters.put(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, new LMSConverter());
        converters.put(PQCObjectIdentifiers.mcElieceCca2, new McElieceCCA2Converter());
    }
}