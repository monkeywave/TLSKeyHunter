package org.bouncycastle.pqc.crypto.lms;

import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.core.view.PointerIconCompat;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.tls.CipherSuite;

/* loaded from: classes2.dex */
public class LMOtsParameters {
    public static final int reserved = 0;
    private final ASN1ObjectIdentifier digestOID;

    /* renamed from: ls */
    private final int f1317ls;

    /* renamed from: n */
    private final int f1318n;

    /* renamed from: p */
    private final int f1319p;
    private final int sigLen;
    private final int type;

    /* renamed from: w */
    private final int f1320w;
    public static final LMOtsParameters sha256_n32_w1 = new LMOtsParameters(1, 32, 1, 265, 7, 8516, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w2 = new LMOtsParameters(2, 32, 2, CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA, 6, 4292, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w4 = new LMOtsParameters(3, 32, 4, 67, 4, 2180, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w8 = new LMOtsParameters(4, 32, 8, 34, 0, 1124, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n24_w1 = new LMOtsParameters(5, 24, 1, 200, 8, 5436, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n24_w2 = new LMOtsParameters(6, 24, 2, TypedValues.TYPE_TARGET, 6, 2940, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n24_w4 = new LMOtsParameters(7, 24, 4, 51, 4, 1500, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n24_w8 = new LMOtsParameters(8, 24, 8, 26, 0, PointerIconCompat.TYPE_GRAB, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters shake256_n32_w1 = new LMOtsParameters(9, 32, 1, 265, 7, 8516, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n32_w2 = new LMOtsParameters(10, 32, 2, CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA, 6, 4292, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n32_w4 = new LMOtsParameters(11, 32, 4, 67, 4, 2180, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n32_w8 = new LMOtsParameters(12, 32, 8, 34, 0, 1124, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n24_w1 = new LMOtsParameters(13, 24, 1, 200, 8, 5436, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n24_w2 = new LMOtsParameters(14, 24, 2, TypedValues.TYPE_TARGET, 6, 2940, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n24_w4 = new LMOtsParameters(15, 24, 4, 51, 4, 1500, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n24_w8 = new LMOtsParameters(16, 24, 8, 26, 0, PointerIconCompat.TYPE_GRAB, NISTObjectIdentifiers.id_shake256_len);
    private static final Map<Object, LMOtsParameters> suppliers = new HashMap<Object, LMOtsParameters>() { // from class: org.bouncycastle.pqc.crypto.lms.LMOtsParameters.1
        {
            put(Integer.valueOf(LMOtsParameters.sha256_n32_w1.type), LMOtsParameters.sha256_n32_w1);
            put(Integer.valueOf(LMOtsParameters.sha256_n32_w2.type), LMOtsParameters.sha256_n32_w2);
            put(Integer.valueOf(LMOtsParameters.sha256_n32_w4.type), LMOtsParameters.sha256_n32_w4);
            put(Integer.valueOf(LMOtsParameters.sha256_n32_w8.type), LMOtsParameters.sha256_n32_w8);
            put(Integer.valueOf(LMOtsParameters.sha256_n24_w1.type), LMOtsParameters.sha256_n24_w1);
            put(Integer.valueOf(LMOtsParameters.sha256_n24_w2.type), LMOtsParameters.sha256_n24_w2);
            put(Integer.valueOf(LMOtsParameters.sha256_n24_w4.type), LMOtsParameters.sha256_n24_w4);
            put(Integer.valueOf(LMOtsParameters.sha256_n24_w8.type), LMOtsParameters.sha256_n24_w8);
            put(Integer.valueOf(LMOtsParameters.shake256_n32_w1.type), LMOtsParameters.shake256_n32_w1);
            put(Integer.valueOf(LMOtsParameters.shake256_n32_w2.type), LMOtsParameters.shake256_n32_w2);
            put(Integer.valueOf(LMOtsParameters.shake256_n32_w4.type), LMOtsParameters.shake256_n32_w4);
            put(Integer.valueOf(LMOtsParameters.shake256_n32_w8.type), LMOtsParameters.shake256_n32_w8);
            put(Integer.valueOf(LMOtsParameters.shake256_n24_w1.type), LMOtsParameters.shake256_n24_w1);
            put(Integer.valueOf(LMOtsParameters.shake256_n24_w2.type), LMOtsParameters.shake256_n24_w2);
            put(Integer.valueOf(LMOtsParameters.shake256_n24_w4.type), LMOtsParameters.shake256_n24_w4);
            put(Integer.valueOf(LMOtsParameters.shake256_n24_w8.type), LMOtsParameters.shake256_n24_w8);
        }
    };

    protected LMOtsParameters(int i, int i2, int i3, int i4, int i5, int i6, ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        this.type = i;
        this.f1318n = i2;
        this.f1320w = i3;
        this.f1319p = i4;
        this.f1317ls = i5;
        this.sigLen = i6;
        this.digestOID = aSN1ObjectIdentifier;
    }

    public static LMOtsParameters getParametersForType(int i) {
        return suppliers.get(Integer.valueOf(i));
    }

    public ASN1ObjectIdentifier getDigestOID() {
        return this.digestOID;
    }

    public int getLs() {
        return this.f1317ls;
    }

    public int getN() {
        return this.f1318n;
    }

    public int getP() {
        return this.f1319p;
    }

    public int getSigLen() {
        return this.sigLen;
    }

    public int getType() {
        return this.type;
    }

    public int getW() {
        return this.f1320w;
    }
}