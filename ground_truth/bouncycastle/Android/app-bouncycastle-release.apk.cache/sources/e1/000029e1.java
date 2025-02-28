package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;

/* loaded from: classes2.dex */
class LMS {
    static final short D_INTR = -31869;
    static final short D_LEAF = -32126;

    LMS() {
    }

    public static LMSPrivateKeyParameters generateKeys(LMSigParameters lMSigParameters, LMOtsParameters lMOtsParameters, int i, byte[] bArr, byte[] bArr2) throws IllegalArgumentException {
        if (bArr2 == null || bArr2.length < lMSigParameters.getM()) {
            throw new IllegalArgumentException("root seed is less than " + lMSigParameters.getM());
        }
        return new LMSPrivateKeyParameters(lMSigParameters, lMOtsParameters, i, bArr, 1 << lMSigParameters.getH(), bArr2);
    }

    public static LMSSignature generateSign(LMSContext lMSContext) {
        return new LMSSignature(lMSContext.getPrivateKey().getQ(), LM_OTS.lm_ots_generate_signature(lMSContext.getPrivateKey(), lMSContext.getQ(), lMSContext.getC()), lMSContext.getSigParams(), lMSContext.getPath());
    }

    public static LMSSignature generateSign(LMSPrivateKeyParameters lMSPrivateKeyParameters, byte[] bArr) {
        LMSContext generateLMSContext = lMSPrivateKeyParameters.generateLMSContext();
        generateLMSContext.update(bArr, 0, bArr.length);
        return generateSign(generateLMSContext);
    }

    public static boolean verifySignature(LMSPublicKeyParameters lMSPublicKeyParameters, LMSContext lMSContext) {
        LMSSignature lMSSignature = (LMSSignature) lMSContext.getSignature();
        LMSigParameters parameter = lMSSignature.getParameter();
        int h = parameter.getH();
        byte[][] y = lMSSignature.getY();
        byte[] lm_ots_validate_signature_calculate = LM_OTS.lm_ots_validate_signature_calculate(lMSContext);
        int q = (1 << h) + lMSSignature.getQ();
        byte[] i = lMSPublicKeyParameters.getI();
        Digest digest = DigestUtil.getDigest(parameter);
        int digestSize = digest.getDigestSize();
        byte[] bArr = new byte[digestSize];
        digest.update(i, 0, i.length);
        LmsUtils.u32str(q, digest);
        LmsUtils.u16str(D_LEAF, digest);
        digest.update(lm_ots_validate_signature_calculate, 0, lm_ots_validate_signature_calculate.length);
        digest.doFinal(bArr, 0);
        int i2 = 0;
        while (q > 1) {
            if ((q & 1) == 1) {
                digest.update(i, 0, i.length);
                LmsUtils.u32str(q / 2, digest);
                LmsUtils.u16str(D_INTR, digest);
                byte[] bArr2 = y[i2];
                digest.update(bArr2, 0, bArr2.length);
                digest.update(bArr, 0, digestSize);
            } else {
                digest.update(i, 0, i.length);
                LmsUtils.u32str(q / 2, digest);
                LmsUtils.u16str(D_INTR, digest);
                digest.update(bArr, 0, digestSize);
                byte[] bArr3 = y[i2];
                digest.update(bArr3, 0, bArr3.length);
            }
            digest.doFinal(bArr, 0);
            q /= 2;
            i2++;
            if (i2 == y.length && q > 1) {
                return false;
            }
        }
        return lMSPublicKeyParameters.matchesT1(bArr);
    }

    public static boolean verifySignature(LMSPublicKeyParameters lMSPublicKeyParameters, LMSSignature lMSSignature, byte[] bArr) {
        LMSContext generateOtsContext = lMSPublicKeyParameters.generateOtsContext(lMSSignature);
        LmsUtils.byteArray(bArr, generateOtsContext);
        return verifySignature(lMSPublicKeyParameters, generateOtsContext);
    }

    public static boolean verifySignature(LMSPublicKeyParameters lMSPublicKeyParameters, byte[] bArr, byte[] bArr2) {
        LMSContext generateLMSContext = lMSPublicKeyParameters.generateLMSContext(bArr);
        LmsUtils.byteArray(bArr2, generateLMSContext);
        return verifySignature(lMSPublicKeyParameters, generateLMSContext);
    }
}