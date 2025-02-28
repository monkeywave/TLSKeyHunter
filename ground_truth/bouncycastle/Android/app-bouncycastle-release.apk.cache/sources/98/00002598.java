package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class MLDSAParameterSpec implements AlgorithmParameterSpec {
    public static final MLDSAParameterSpec ml_dsa_44;
    public static final MLDSAParameterSpec ml_dsa_44_with_sha512;
    public static final MLDSAParameterSpec ml_dsa_65;
    public static final MLDSAParameterSpec ml_dsa_65_with_sha512;
    public static final MLDSAParameterSpec ml_dsa_87;
    public static final MLDSAParameterSpec ml_dsa_87_with_sha512;
    private static Map parameters;
    private final String name;

    static {
        MLDSAParameterSpec mLDSAParameterSpec = new MLDSAParameterSpec("ML-DSA-44");
        ml_dsa_44 = mLDSAParameterSpec;
        MLDSAParameterSpec mLDSAParameterSpec2 = new MLDSAParameterSpec("ML-DSA-65");
        ml_dsa_65 = mLDSAParameterSpec2;
        MLDSAParameterSpec mLDSAParameterSpec3 = new MLDSAParameterSpec("ML-DSA-87");
        ml_dsa_87 = mLDSAParameterSpec3;
        MLDSAParameterSpec mLDSAParameterSpec4 = new MLDSAParameterSpec("ML-DSA-44-WITH-SHA512");
        ml_dsa_44_with_sha512 = mLDSAParameterSpec4;
        MLDSAParameterSpec mLDSAParameterSpec5 = new MLDSAParameterSpec("ML-DSA-65-WITH-SHA512");
        ml_dsa_65_with_sha512 = mLDSAParameterSpec5;
        MLDSAParameterSpec mLDSAParameterSpec6 = new MLDSAParameterSpec("ML-DSA-87-WITH-SHA512");
        ml_dsa_87_with_sha512 = mLDSAParameterSpec6;
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put("ml-dsa-44", mLDSAParameterSpec);
        parameters.put("ml-dsa-65", mLDSAParameterSpec2);
        parameters.put("ml-dsa-87", mLDSAParameterSpec3);
        parameters.put("ml-dsa-44-with-sha512", mLDSAParameterSpec4);
        parameters.put("ml-dsa-65-with-sha512", mLDSAParameterSpec5);
        parameters.put("ml-dsa-87-with-sha512", mLDSAParameterSpec6);
    }

    private MLDSAParameterSpec(String str) {
        this.name = str;
    }

    public static MLDSAParameterSpec fromName(String str) {
        if (str != null) {
            MLDSAParameterSpec mLDSAParameterSpec = (MLDSAParameterSpec) parameters.get(Strings.toLowerCase(str));
            if (mLDSAParameterSpec != null) {
                return mLDSAParameterSpec;
            }
            throw new IllegalArgumentException("unknown parameter name: " + str);
        }
        throw new NullPointerException("name cannot be null");
    }

    public String getName() {
        return this.name;
    }
}