package org.bouncycastle.crypto.util;

import java.io.OutputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RC2CBCParameter;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.CAST5Engine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.p011io.CipherOutputStream;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RC2Parameters;
import org.bouncycastle.internal.asn1.cms.CCMParameters;
import org.bouncycastle.internal.asn1.cms.GCMParameters;
import org.bouncycastle.internal.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.internal.asn1.misc.CAST5CBCParameters;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.internal.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.HandshakeType;

/* loaded from: classes2.dex */
public class CipherFactory {
    private static final short[] rc2Ekb = {93, 190, 155, 139, 17, 153, AlertDescription.unsupported_extension, 77, 89, 243, 133, 166, 63, 183, 131, 197, 228, AlertDescription.unknown_psk_identity, 107, 58, 104, 90, 192, 71, 160, 100, 52, 12, 241, 208, 82, 165, 185, 30, 150, 67, 65, 216, 212, 44, 219, 248, 7, 119, 42, 202, 235, 239, 16, 28, 22, 13, 56, AlertDescription.bad_certificate_hash_value, 47, 137, 193, 249, 128, 196, AlertDescription.missing_extension, 174, 48, 61, 206, 32, 99, HandshakeType.message_hash, 230, 26, 199, 184, 80, 232, 36, 23, 252, 37, AlertDescription.certificate_unobtainable, 187, 106, 163, 68, 83, 217, 162, 1, 171, 188, 182, 31, 152, 238, 154, 167, 45, 79, 158, 142, 172, 224, 198, 73, 70, 41, 244, 148, 138, 175, 225, 91, 195, 179, 123, 87, 209, 124, 156, 237, 135, 64, 140, 226, 203, 147, 20, 201, 97, 46, 229, 204, 246, 94, 168, 92, 214, 117, 141, 98, 149, 88, 105, 118, 161, 74, 181, 85, 9, AlertDescription.no_application_protocol, 51, 130, 215, 221, 121, 245, 27, 11, 222, 38, 33, 40, AlertDescription.certificate_required, 4, 151, 86, 223, 60, 240, 55, 57, 220, 255, 6, 164, 234, 66, 8, 218, 180, AlertDescription.bad_certificate_status_response, 176, 207, 18, 122, 78, 250, 108, 29, 132, 0, 200, 127, 145, 69, 170, 43, 194, 177, 143, 213, 186, 242, 173, 25, 178, 103, 54, 247, 15, 10, 146, 125, 227, 157, 233, 144, 62, 35, 39, 102, 19, 236, 129, 21, 189, 34, 191, 159, 126, 169, 81, 75, 76, 251, 2, 211, AlertDescription.unrecognized_name, 134, 49, 231, 59, 5, 3, 84, 96, 72, 101, 24, 210, 205, 95, 50, 136, 14, 53, 253};

    private static AEADBlockCipher createAEADCipher(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        if (NISTObjectIdentifiers.id_aes128_GCM.equals((ASN1Primitive) aSN1ObjectIdentifier) || NISTObjectIdentifiers.id_aes192_GCM.equals((ASN1Primitive) aSN1ObjectIdentifier) || NISTObjectIdentifiers.id_aes256_GCM.equals((ASN1Primitive) aSN1ObjectIdentifier)) {
            return GCMBlockCipher.newInstance(AESEngine.newInstance());
        }
        if (NISTObjectIdentifiers.id_aes128_CCM.equals((ASN1Primitive) aSN1ObjectIdentifier) || NISTObjectIdentifiers.id_aes192_CCM.equals((ASN1Primitive) aSN1ObjectIdentifier) || NISTObjectIdentifiers.id_aes256_CCM.equals((ASN1Primitive) aSN1ObjectIdentifier)) {
            return CCMBlockCipher.newInstance(AESEngine.newInstance());
        }
        throw new IllegalArgumentException("cannot recognise cipher: " + aSN1ObjectIdentifier);
    }

    private static BufferedBlockCipher createCipher(ASN1ObjectIdentifier aSN1ObjectIdentifier) throws IllegalArgumentException {
        BlockCipher newInstance;
        if (NISTObjectIdentifiers.id_aes128_CBC.equals((ASN1Primitive) aSN1ObjectIdentifier) || NISTObjectIdentifiers.id_aes192_CBC.equals((ASN1Primitive) aSN1ObjectIdentifier) || NISTObjectIdentifiers.id_aes256_CBC.equals((ASN1Primitive) aSN1ObjectIdentifier)) {
            newInstance = AESEngine.newInstance();
        } else if (PKCSObjectIdentifiers.des_EDE3_CBC.equals((ASN1Primitive) aSN1ObjectIdentifier)) {
            newInstance = new DESedeEngine();
        } else if (OIWObjectIdentifiers.desCBC.equals((ASN1Primitive) aSN1ObjectIdentifier)) {
            newInstance = new DESEngine();
        } else if (PKCSObjectIdentifiers.RC2_CBC.equals((ASN1Primitive) aSN1ObjectIdentifier)) {
            newInstance = new RC2Engine();
        } else if (!MiscObjectIdentifiers.cast5CBC.equals((ASN1Primitive) aSN1ObjectIdentifier)) {
            throw new IllegalArgumentException("cannot recognise cipher: " + aSN1ObjectIdentifier);
        } else {
            newInstance = new CAST5Engine();
        }
        return new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(newInstance), new PKCS7Padding());
    }

    public static Object createContentCipher(boolean z, CipherParameters cipherParameters, AlgorithmIdentifier algorithmIdentifier) throws IllegalArgumentException {
        AEADBlockCipher createAEADCipher;
        AEADParameters aEADParameters;
        ParametersWithIV parametersWithIV;
        ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();
        if (algorithm.equals((ASN1Primitive) PKCSObjectIdentifiers.rc4)) {
            RC4Engine rC4Engine = new RC4Engine();
            rC4Engine.init(z, cipherParameters);
            return rC4Engine;
        }
        if (algorithm.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes128_GCM) || algorithm.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes192_GCM) || algorithm.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes256_GCM)) {
            createAEADCipher = createAEADCipher(algorithmIdentifier.getAlgorithm());
            GCMParameters gCMParameters = GCMParameters.getInstance(algorithmIdentifier.getParameters());
            if (!(cipherParameters instanceof KeyParameter)) {
                throw new IllegalArgumentException("key data must be accessible for GCM operation");
            }
            aEADParameters = new AEADParameters((KeyParameter) cipherParameters, gCMParameters.getIcvLen() * 8, gCMParameters.getNonce());
        } else if (!algorithm.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes128_CCM) && !algorithm.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes192_CCM) && !algorithm.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes256_CCM)) {
            BufferedBlockCipher createCipher = createCipher(algorithmIdentifier.getAlgorithm());
            ASN1Primitive aSN1Primitive = algorithmIdentifier.getParameters().toASN1Primitive();
            if (aSN1Primitive == null || (aSN1Primitive instanceof ASN1Null)) {
                if (algorithm.equals((ASN1Primitive) PKCSObjectIdentifiers.des_EDE3_CBC) || algorithm.equals((ASN1Primitive) AlgorithmIdentifierFactory.IDEA_CBC) || algorithm.equals((ASN1Primitive) AlgorithmIdentifierFactory.CAST5_CBC)) {
                    createCipher.init(z, new ParametersWithIV(cipherParameters, new byte[8]));
                }
                createCipher.init(z, cipherParameters);
            } else {
                if (algorithm.equals((ASN1Primitive) PKCSObjectIdentifiers.des_EDE3_CBC) || algorithm.equals((ASN1Primitive) AlgorithmIdentifierFactory.IDEA_CBC) || algorithm.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes128_CBC) || algorithm.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes192_CBC) || algorithm.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes256_CBC) || algorithm.equals((ASN1Primitive) NTTObjectIdentifiers.id_camellia128_cbc) || algorithm.equals((ASN1Primitive) NTTObjectIdentifiers.id_camellia192_cbc) || algorithm.equals((ASN1Primitive) NTTObjectIdentifiers.id_camellia256_cbc) || algorithm.equals((ASN1Primitive) KISAObjectIdentifiers.id_seedCBC) || algorithm.equals((ASN1Primitive) OIWObjectIdentifiers.desCBC)) {
                    parametersWithIV = new ParametersWithIV(cipherParameters, ASN1OctetString.getInstance(aSN1Primitive).getOctets());
                } else if (algorithm.equals((ASN1Primitive) AlgorithmIdentifierFactory.CAST5_CBC)) {
                    parametersWithIV = new ParametersWithIV(cipherParameters, CAST5CBCParameters.getInstance(aSN1Primitive).getIV());
                } else if (!algorithm.equals((ASN1Primitive) PKCSObjectIdentifiers.RC2_CBC)) {
                    throw new IllegalArgumentException("cannot match parameters");
                } else {
                    RC2CBCParameter rC2CBCParameter = RC2CBCParameter.getInstance(aSN1Primitive);
                    cipherParameters = new ParametersWithIV(new RC2Parameters(((KeyParameter) cipherParameters).getKey(), getRC2EffectiveKeyBits(rC2CBCParameter)), rC2CBCParameter.getIV());
                    createCipher.init(z, cipherParameters);
                }
                createCipher.init(z, parametersWithIV);
            }
            return createCipher;
        } else {
            createAEADCipher = createAEADCipher(algorithmIdentifier.getAlgorithm());
            CCMParameters cCMParameters = CCMParameters.getInstance(algorithmIdentifier.getParameters());
            if (!(cipherParameters instanceof KeyParameter)) {
                throw new IllegalArgumentException("key data must be accessible for CCM operation");
            }
            aEADParameters = new AEADParameters((KeyParameter) cipherParameters, cCMParameters.getIcvLen() * 8, cCMParameters.getNonce());
        }
        createAEADCipher.init(z, aEADParameters);
        return createAEADCipher;
    }

    public static CipherOutputStream createOutputStream(OutputStream outputStream, Object obj) {
        if (obj instanceof BufferedBlockCipher) {
            return new CipherOutputStream(outputStream, (BufferedBlockCipher) obj);
        }
        if (obj instanceof StreamCipher) {
            return new CipherOutputStream(outputStream, (StreamCipher) obj);
        }
        if (obj instanceof AEADBlockCipher) {
            return new CipherOutputStream(outputStream, (AEADBlockCipher) obj);
        }
        throw new IllegalArgumentException("unknown cipher object: " + obj);
    }

    private static int getRC2EffectiveKeyBits(RC2CBCParameter rC2CBCParameter) {
        ASN1Integer rC2ParameterVersionData = rC2CBCParameter.getRC2ParameterVersionData();
        if (rC2ParameterVersionData == null) {
            return 32;
        }
        int intPositiveValueExact = rC2ParameterVersionData.intPositiveValueExact();
        return intPositiveValueExact >= 256 ? intPositiveValueExact : rc2Ekb[intPositiveValueExact] & 65535;
    }
}