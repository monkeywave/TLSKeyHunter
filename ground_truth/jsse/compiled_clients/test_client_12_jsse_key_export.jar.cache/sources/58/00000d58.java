package org.bouncycastle.pqc.crypto.lms;

import java.util.HashMap;
import java.util.Map;
import javassist.bytecode.Opcode;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/lms/LMOtsParameters.class */
public class LMOtsParameters {
    public static final int reserved = 0;
    public static final LMOtsParameters sha256_n32_w1 = new LMOtsParameters(1, 32, 1, 265, 7, 8516, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w2 = new LMOtsParameters(2, 32, 2, Opcode.I2L, 6, 4292, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w4 = new LMOtsParameters(3, 32, 4, 67, 4, 2180, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w8 = new LMOtsParameters(4, 32, 8, 34, 0, 1124, NISTObjectIdentifiers.id_sha256);
    private static final Map<Object, LMOtsParameters> suppliers = new HashMap<Object, LMOtsParameters>() { // from class: org.bouncycastle.pqc.crypto.lms.LMOtsParameters.1
        {
            put(Integer.valueOf(LMOtsParameters.sha256_n32_w1.type), LMOtsParameters.sha256_n32_w1);
            put(Integer.valueOf(LMOtsParameters.sha256_n32_w2.type), LMOtsParameters.sha256_n32_w2);
            put(Integer.valueOf(LMOtsParameters.sha256_n32_w4.type), LMOtsParameters.sha256_n32_w4);
            put(Integer.valueOf(LMOtsParameters.sha256_n32_w8.type), LMOtsParameters.sha256_n32_w8);
        }
    };
    private final int type;

    /* renamed from: n */
    private final int f828n;

    /* renamed from: w */
    private final int f829w;

    /* renamed from: p */
    private final int f830p;

    /* renamed from: ls */
    private final int f831ls;
    private final int sigLen;
    private final ASN1ObjectIdentifier digestOID;

    protected LMOtsParameters(int i, int i2, int i3, int i4, int i5, int i6, ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        this.type = i;
        this.f828n = i2;
        this.f829w = i3;
        this.f830p = i4;
        this.f831ls = i5;
        this.sigLen = i6;
        this.digestOID = aSN1ObjectIdentifier;
    }

    public int getType() {
        return this.type;
    }

    public int getN() {
        return this.f828n;
    }

    public int getW() {
        return this.f829w;
    }

    public int getP() {
        return this.f830p;
    }

    public int getLs() {
        return this.f831ls;
    }

    public int getSigLen() {
        return this.sigLen;
    }

    public ASN1ObjectIdentifier getDigestOID() {
        return this.digestOID;
    }

    public static LMOtsParameters getParametersForType(int i) {
        return suppliers.get(Integer.valueOf(i));
    }
}