package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class KyberParameterSpec implements AlgorithmParameterSpec {
    public static final KyberParameterSpec kyber1024;
    public static final KyberParameterSpec kyber512;
    public static final KyberParameterSpec kyber768;
    private static Map parameters;
    private final String name;

    static {
        KyberParameterSpec kyberParameterSpec = new KyberParameterSpec(MLKEMParameters.ml_kem_512);
        kyber512 = kyberParameterSpec;
        KyberParameterSpec kyberParameterSpec2 = new KyberParameterSpec(MLKEMParameters.ml_kem_768);
        kyber768 = kyberParameterSpec2;
        KyberParameterSpec kyberParameterSpec3 = new KyberParameterSpec(MLKEMParameters.ml_kem_1024);
        kyber1024 = kyberParameterSpec3;
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put("kyber512", kyberParameterSpec);
        parameters.put("kyber768", kyberParameterSpec2);
        parameters.put("kyber1024", kyberParameterSpec3);
    }

    private KyberParameterSpec(MLKEMParameters mLKEMParameters) {
        this.name = Strings.toUpperCase(mLKEMParameters.getName());
    }

    public static KyberParameterSpec fromName(String str) {
        return (KyberParameterSpec) parameters.get(Strings.toLowerCase(str));
    }

    public String getName() {
        return this.name;
    }
}