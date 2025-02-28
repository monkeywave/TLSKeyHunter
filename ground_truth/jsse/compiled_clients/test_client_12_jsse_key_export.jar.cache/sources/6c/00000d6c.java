package org.bouncycastle.pqc.crypto.lms;

import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/lms/LMSigParameters.class */
public class LMSigParameters {
    public static final LMSigParameters lms_sha256_n32_h5 = new LMSigParameters(5, 32, 5, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h10 = new LMSigParameters(6, 32, 10, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h15 = new LMSigParameters(7, 32, 15, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h20 = new LMSigParameters(8, 32, 20, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h25 = new LMSigParameters(9, 32, 25, NISTObjectIdentifiers.id_sha256);
    private static Map<Object, LMSigParameters> paramBuilders = new HashMap<Object, LMSigParameters>() { // from class: org.bouncycastle.pqc.crypto.lms.LMSigParameters.1
        {
            put(Integer.valueOf(LMSigParameters.lms_sha256_n32_h5.type), LMSigParameters.lms_sha256_n32_h5);
            put(Integer.valueOf(LMSigParameters.lms_sha256_n32_h10.type), LMSigParameters.lms_sha256_n32_h10);
            put(Integer.valueOf(LMSigParameters.lms_sha256_n32_h15.type), LMSigParameters.lms_sha256_n32_h15);
            put(Integer.valueOf(LMSigParameters.lms_sha256_n32_h20.type), LMSigParameters.lms_sha256_n32_h20);
            put(Integer.valueOf(LMSigParameters.lms_sha256_n32_h25.type), LMSigParameters.lms_sha256_n32_h25);
        }
    };
    private final int type;

    /* renamed from: m */
    private final int f847m;

    /* renamed from: h */
    private final int f848h;
    private final ASN1ObjectIdentifier digestOid;

    protected LMSigParameters(int i, int i2, int i3, ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        this.type = i;
        this.f847m = i2;
        this.f848h = i3;
        this.digestOid = aSN1ObjectIdentifier;
    }

    public int getType() {
        return this.type;
    }

    public int getH() {
        return this.f848h;
    }

    public int getM() {
        return this.f847m;
    }

    public ASN1ObjectIdentifier getDigestOID() {
        return this.digestOid;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static LMSigParameters getParametersForType(int i) {
        return paramBuilders.get(Integer.valueOf(i));
    }
}