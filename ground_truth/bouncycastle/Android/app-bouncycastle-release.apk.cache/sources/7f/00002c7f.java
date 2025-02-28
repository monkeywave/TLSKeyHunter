package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class HQCParameterSpec implements AlgorithmParameterSpec {
    public static final HQCParameterSpec hqc128;
    public static final HQCParameterSpec hqc192;
    public static final HQCParameterSpec hqc256;
    private static Map parameters;
    private final String name;

    static {
        HQCParameterSpec hQCParameterSpec = new HQCParameterSpec(HQCParameters.hqc128);
        hqc128 = hQCParameterSpec;
        HQCParameterSpec hQCParameterSpec2 = new HQCParameterSpec(HQCParameters.hqc192);
        hqc192 = hQCParameterSpec2;
        HQCParameterSpec hQCParameterSpec3 = new HQCParameterSpec(HQCParameters.hqc256);
        hqc256 = hQCParameterSpec3;
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put("hqc128", hQCParameterSpec);
        parameters.put("hqc192", hQCParameterSpec2);
        parameters.put("hqc256", hQCParameterSpec3);
    }

    private HQCParameterSpec(HQCParameters hQCParameters) {
        this.name = hQCParameters.getName();
    }

    public static HQCParameterSpec fromName(String str) {
        return (HQCParameterSpec) parameters.get(Strings.toLowerCase(str));
    }

    public String getName() {
        return this.name;
    }
}