package org.bouncycastle.jcajce.provider.symmetric.util;

import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/symmetric/util/SpecUtil.class */
class SpecUtil {
    SpecUtil() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static AlgorithmParameterSpec extractSpec(AlgorithmParameters algorithmParameters, Class[] clsArr) {
        try {
            return algorithmParameters.getParameterSpec(AlgorithmParameterSpec.class);
        } catch (Exception e) {
            for (int i = 0; i != clsArr.length; i++) {
                if (clsArr[i] != null) {
                    try {
                        return algorithmParameters.getParameterSpec(clsArr[i]);
                    } catch (Exception e2) {
                    }
                }
            }
            return null;
        }
    }
}