package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class SNTRUPrimeParameterSpec implements AlgorithmParameterSpec {
    private static Map parameters;
    public static final SNTRUPrimeParameterSpec sntrup1013;
    public static final SNTRUPrimeParameterSpec sntrup1277;
    public static final SNTRUPrimeParameterSpec sntrup653;
    public static final SNTRUPrimeParameterSpec sntrup761;
    public static final SNTRUPrimeParameterSpec sntrup857;
    public static final SNTRUPrimeParameterSpec sntrup953;
    private final String name;

    static {
        SNTRUPrimeParameterSpec sNTRUPrimeParameterSpec = new SNTRUPrimeParameterSpec(SNTRUPrimeParameters.sntrup653);
        sntrup653 = sNTRUPrimeParameterSpec;
        SNTRUPrimeParameterSpec sNTRUPrimeParameterSpec2 = new SNTRUPrimeParameterSpec(SNTRUPrimeParameters.sntrup761);
        sntrup761 = sNTRUPrimeParameterSpec2;
        SNTRUPrimeParameterSpec sNTRUPrimeParameterSpec3 = new SNTRUPrimeParameterSpec(SNTRUPrimeParameters.sntrup857);
        sntrup857 = sNTRUPrimeParameterSpec3;
        SNTRUPrimeParameterSpec sNTRUPrimeParameterSpec4 = new SNTRUPrimeParameterSpec(SNTRUPrimeParameters.sntrup953);
        sntrup953 = sNTRUPrimeParameterSpec4;
        SNTRUPrimeParameterSpec sNTRUPrimeParameterSpec5 = new SNTRUPrimeParameterSpec(SNTRUPrimeParameters.sntrup1013);
        sntrup1013 = sNTRUPrimeParameterSpec5;
        SNTRUPrimeParameterSpec sNTRUPrimeParameterSpec6 = new SNTRUPrimeParameterSpec(SNTRUPrimeParameters.sntrup1277);
        sntrup1277 = sNTRUPrimeParameterSpec6;
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put("sntrup653", sNTRUPrimeParameterSpec);
        parameters.put("sntrup761", sNTRUPrimeParameterSpec2);
        parameters.put("sntrup857", sNTRUPrimeParameterSpec3);
        parameters.put("sntrup953", sNTRUPrimeParameterSpec4);
        parameters.put("sntrup1013", sNTRUPrimeParameterSpec5);
        parameters.put("sntrup1277", sNTRUPrimeParameterSpec6);
    }

    private SNTRUPrimeParameterSpec(SNTRUPrimeParameters sNTRUPrimeParameters) {
        this.name = sNTRUPrimeParameters.getName();
    }

    public static SNTRUPrimeParameterSpec fromName(String str) {
        return (SNTRUPrimeParameterSpec) parameters.get(Strings.toLowerCase(str));
    }

    public String getName() {
        return this.name;
    }
}