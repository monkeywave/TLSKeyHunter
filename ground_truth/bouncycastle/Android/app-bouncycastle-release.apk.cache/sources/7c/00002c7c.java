package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class DilithiumParameterSpec implements AlgorithmParameterSpec {
    public static final DilithiumParameterSpec dilithium2;
    public static final DilithiumParameterSpec dilithium3;
    public static final DilithiumParameterSpec dilithium5;
    private static Map parameters;
    private final String name;

    static {
        DilithiumParameterSpec dilithiumParameterSpec = new DilithiumParameterSpec(DilithiumParameters.dilithium2);
        dilithium2 = dilithiumParameterSpec;
        DilithiumParameterSpec dilithiumParameterSpec2 = new DilithiumParameterSpec(DilithiumParameters.dilithium3);
        dilithium3 = dilithiumParameterSpec2;
        DilithiumParameterSpec dilithiumParameterSpec3 = new DilithiumParameterSpec(DilithiumParameters.dilithium5);
        dilithium5 = dilithiumParameterSpec3;
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put("dilithium2", dilithiumParameterSpec);
        parameters.put("dilithium3", dilithiumParameterSpec2);
        parameters.put("dilithium5", dilithiumParameterSpec3);
    }

    private DilithiumParameterSpec(DilithiumParameters dilithiumParameters) {
        this.name = Strings.toUpperCase(dilithiumParameters.getName());
    }

    public static DilithiumParameterSpec fromName(String str) {
        return (DilithiumParameterSpec) parameters.get(Strings.toLowerCase(str));
    }

    public String getName() {
        return this.name;
    }
}