package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class FalconParameterSpec implements AlgorithmParameterSpec {
    public static final FalconParameterSpec falcon_1024;
    public static final FalconParameterSpec falcon_512;
    private static Map parameters;
    private final String name;

    static {
        FalconParameterSpec falconParameterSpec = new FalconParameterSpec(FalconParameters.falcon_512);
        falcon_512 = falconParameterSpec;
        FalconParameterSpec falconParameterSpec2 = new FalconParameterSpec(FalconParameters.falcon_1024);
        falcon_1024 = falconParameterSpec2;
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put("falcon-512", falconParameterSpec);
        parameters.put("falcon-1024", falconParameterSpec2);
    }

    private FalconParameterSpec(FalconParameters falconParameters) {
        this.name = Strings.toUpperCase(falconParameters.getName());
    }

    public static FalconParameterSpec fromName(String str) {
        return (FalconParameterSpec) parameters.get(Strings.toLowerCase(str));
    }

    public String getName() {
        return this.name;
    }
}