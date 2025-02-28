package org.bouncycastle.pqc.crypto.lms;

import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

/* loaded from: classes2.dex */
public class LMSigParameters {
    private final ASN1ObjectIdentifier digestOid;

    /* renamed from: h */
    private final int f1336h;

    /* renamed from: m */
    private final int f1337m;
    private final int type;
    public static final LMSigParameters lms_sha256_n32_h5 = new LMSigParameters(5, 32, 5, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h10 = new LMSigParameters(6, 32, 10, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h15 = new LMSigParameters(7, 32, 15, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h20 = new LMSigParameters(8, 32, 20, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h25 = new LMSigParameters(9, 32, 25, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n24_h5 = new LMSigParameters(10, 24, 5, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n24_h10 = new LMSigParameters(11, 24, 10, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n24_h15 = new LMSigParameters(12, 24, 15, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n24_h20 = new LMSigParameters(13, 24, 20, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n24_h25 = new LMSigParameters(14, 24, 25, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_shake256_n32_h5 = new LMSigParameters(15, 32, 5, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n32_h10 = new LMSigParameters(16, 32, 10, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n32_h15 = new LMSigParameters(17, 32, 15, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n32_h20 = new LMSigParameters(18, 32, 20, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n32_h25 = new LMSigParameters(19, 32, 25, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n24_h5 = new LMSigParameters(20, 24, 5, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n24_h10 = new LMSigParameters(21, 24, 10, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n24_h15 = new LMSigParameters(22, 24, 15, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n24_h20 = new LMSigParameters(23, 24, 20, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n24_h25 = new LMSigParameters(24, 24, 25, NISTObjectIdentifiers.id_shake256_len);
    private static Map<Object, LMSigParameters> paramBuilders = new HashMap<Object, LMSigParameters>() { // from class: org.bouncycastle.pqc.crypto.lms.LMSigParameters.1
        {
            put(Integer.valueOf(LMSigParameters.lms_sha256_n32_h5.type), LMSigParameters.lms_sha256_n32_h5);
            put(Integer.valueOf(LMSigParameters.lms_sha256_n32_h10.type), LMSigParameters.lms_sha256_n32_h10);
            put(Integer.valueOf(LMSigParameters.lms_sha256_n32_h15.type), LMSigParameters.lms_sha256_n32_h15);
            put(Integer.valueOf(LMSigParameters.lms_sha256_n32_h20.type), LMSigParameters.lms_sha256_n32_h20);
            put(Integer.valueOf(LMSigParameters.lms_sha256_n32_h25.type), LMSigParameters.lms_sha256_n32_h25);
            put(Integer.valueOf(LMSigParameters.lms_sha256_n24_h5.type), LMSigParameters.lms_sha256_n24_h5);
            put(Integer.valueOf(LMSigParameters.lms_sha256_n24_h10.type), LMSigParameters.lms_sha256_n24_h10);
            put(Integer.valueOf(LMSigParameters.lms_sha256_n24_h15.type), LMSigParameters.lms_sha256_n24_h15);
            put(Integer.valueOf(LMSigParameters.lms_sha256_n24_h20.type), LMSigParameters.lms_sha256_n24_h20);
            put(Integer.valueOf(LMSigParameters.lms_sha256_n24_h25.type), LMSigParameters.lms_sha256_n24_h25);
            put(Integer.valueOf(LMSigParameters.lms_shake256_n32_h5.type), LMSigParameters.lms_shake256_n32_h5);
            put(Integer.valueOf(LMSigParameters.lms_shake256_n32_h10.type), LMSigParameters.lms_shake256_n32_h10);
            put(Integer.valueOf(LMSigParameters.lms_shake256_n32_h15.type), LMSigParameters.lms_shake256_n32_h15);
            put(Integer.valueOf(LMSigParameters.lms_shake256_n32_h20.type), LMSigParameters.lms_shake256_n32_h20);
            put(Integer.valueOf(LMSigParameters.lms_shake256_n32_h25.type), LMSigParameters.lms_shake256_n32_h25);
            put(Integer.valueOf(LMSigParameters.lms_shake256_n24_h5.type), LMSigParameters.lms_shake256_n24_h5);
            put(Integer.valueOf(LMSigParameters.lms_shake256_n24_h10.type), LMSigParameters.lms_shake256_n24_h10);
            put(Integer.valueOf(LMSigParameters.lms_shake256_n24_h15.type), LMSigParameters.lms_shake256_n24_h15);
            put(Integer.valueOf(LMSigParameters.lms_shake256_n24_h20.type), LMSigParameters.lms_shake256_n24_h20);
            put(Integer.valueOf(LMSigParameters.lms_shake256_n24_h25.type), LMSigParameters.lms_shake256_n24_h25);
        }
    };

    protected LMSigParameters(int i, int i2, int i3, ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        this.type = i;
        this.f1337m = i2;
        this.f1336h = i3;
        this.digestOid = aSN1ObjectIdentifier;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static LMSigParameters getParametersForType(int i) {
        return paramBuilders.get(Integer.valueOf(i));
    }

    public ASN1ObjectIdentifier getDigestOID() {
        return this.digestOid;
    }

    public int getH() {
        return this.f1336h;
    }

    public int getM() {
        return this.f1337m;
    }

    public int getType() {
        return this.type;
    }
}