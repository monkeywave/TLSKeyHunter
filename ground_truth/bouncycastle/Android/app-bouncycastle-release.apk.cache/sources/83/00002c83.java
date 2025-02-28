package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;

/* loaded from: classes2.dex */
public class LMSKeyGenParameterSpec implements AlgorithmParameterSpec {
    private static final Map<String, LMOtsParameters> otsParameters;
    private static final Map<String, LMSigParameters> sigParameters;
    private final LMOtsParameters lmOtsParameters;
    private final LMSigParameters lmSigParams;

    static {
        HashMap hashMap = new HashMap();
        sigParameters = hashMap;
        HashMap hashMap2 = new HashMap();
        otsParameters = hashMap2;
        hashMap.put("lms-sha256-n32-h5", LMSigParameters.lms_sha256_n32_h5);
        hashMap.put("lms-sha256-n32-h10", LMSigParameters.lms_sha256_n32_h10);
        hashMap.put("lms-sha256-n32-h15", LMSigParameters.lms_sha256_n32_h15);
        hashMap.put("lms-sha256-n32-h20", LMSigParameters.lms_sha256_n32_h20);
        hashMap.put("lms-sha256-n32-h25", LMSigParameters.lms_sha256_n32_h25);
        hashMap.put("lms-sha256-n24-h5", LMSigParameters.lms_sha256_n24_h5);
        hashMap.put("lms-sha256-n24-h10", LMSigParameters.lms_sha256_n24_h10);
        hashMap.put("lms-sha256-n24-h15", LMSigParameters.lms_sha256_n24_h15);
        hashMap.put("lms-sha256-n24-h20", LMSigParameters.lms_sha256_n24_h20);
        hashMap.put("lms-sha256-n24-h25", LMSigParameters.lms_sha256_n24_h25);
        hashMap.put("lms-shake256-n32-h5", LMSigParameters.lms_shake256_n32_h5);
        hashMap.put("lms-shake256-n32-h10", LMSigParameters.lms_shake256_n32_h10);
        hashMap.put("lms-shake256-n32-h15", LMSigParameters.lms_shake256_n32_h15);
        hashMap.put("lms-shake256-n32-h20", LMSigParameters.lms_shake256_n32_h20);
        hashMap.put("lms-shake256-n32-h25", LMSigParameters.lms_shake256_n32_h25);
        hashMap.put("lms-shake256-n24-h5", LMSigParameters.lms_shake256_n24_h5);
        hashMap.put("lms-shake256-n24-h10", LMSigParameters.lms_shake256_n24_h10);
        hashMap.put("lms-shake256-n24-h15", LMSigParameters.lms_shake256_n24_h15);
        hashMap.put("lms-shake256-n24-h20", LMSigParameters.lms_shake256_n24_h20);
        hashMap.put("lms-shake256-n24-h25", LMSigParameters.lms_shake256_n24_h25);
        hashMap2.put("sha256-n32-w1", LMOtsParameters.sha256_n32_w1);
        hashMap2.put("sha256-n32-w2", LMOtsParameters.sha256_n32_w2);
        hashMap2.put("sha256-n32-w4", LMOtsParameters.sha256_n32_w4);
        hashMap2.put("sha256-n32-w8", LMOtsParameters.sha256_n32_w8);
    }

    public LMSKeyGenParameterSpec(LMSigParameters lMSigParameters, LMOtsParameters lMOtsParameters) {
        this.lmSigParams = lMSigParameters;
        this.lmOtsParameters = lMOtsParameters;
    }

    public static LMSKeyGenParameterSpec fromNames(String str, String str2) {
        Map<String, LMSigParameters> map = sigParameters;
        if (map.containsKey(str)) {
            Map<String, LMOtsParameters> map2 = otsParameters;
            if (map2.containsKey(str2)) {
                return new LMSKeyGenParameterSpec(map.get(str), map2.get(str2));
            }
            throw new IllegalArgumentException("LM OTS parameter name " + str2 + " not recognized");
        }
        throw new IllegalArgumentException("LM signature parameter name " + str + " not recognized");
    }

    public LMOtsParameters getOtsParams() {
        return this.lmOtsParameters;
    }

    public LMSigParameters getSigParams() {
        return this.lmSigParams;
    }
}