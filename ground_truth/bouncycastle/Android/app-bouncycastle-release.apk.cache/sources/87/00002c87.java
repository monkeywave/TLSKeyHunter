package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeParameters;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class NTRULPRimeParameterSpec implements AlgorithmParameterSpec {
    public static final NTRULPRimeParameterSpec ntrulpr1013;
    public static final NTRULPRimeParameterSpec ntrulpr1277;
    public static final NTRULPRimeParameterSpec ntrulpr653;
    public static final NTRULPRimeParameterSpec ntrulpr761;
    public static final NTRULPRimeParameterSpec ntrulpr857;
    public static final NTRULPRimeParameterSpec ntrulpr953;
    private static Map parameters;
    private final String name;

    static {
        NTRULPRimeParameterSpec nTRULPRimeParameterSpec = new NTRULPRimeParameterSpec(NTRULPRimeParameters.ntrulpr653);
        ntrulpr653 = nTRULPRimeParameterSpec;
        NTRULPRimeParameterSpec nTRULPRimeParameterSpec2 = new NTRULPRimeParameterSpec(NTRULPRimeParameters.ntrulpr761);
        ntrulpr761 = nTRULPRimeParameterSpec2;
        NTRULPRimeParameterSpec nTRULPRimeParameterSpec3 = new NTRULPRimeParameterSpec(NTRULPRimeParameters.ntrulpr857);
        ntrulpr857 = nTRULPRimeParameterSpec3;
        NTRULPRimeParameterSpec nTRULPRimeParameterSpec4 = new NTRULPRimeParameterSpec(NTRULPRimeParameters.ntrulpr953);
        ntrulpr953 = nTRULPRimeParameterSpec4;
        NTRULPRimeParameterSpec nTRULPRimeParameterSpec5 = new NTRULPRimeParameterSpec(NTRULPRimeParameters.ntrulpr1013);
        ntrulpr1013 = nTRULPRimeParameterSpec5;
        NTRULPRimeParameterSpec nTRULPRimeParameterSpec6 = new NTRULPRimeParameterSpec(NTRULPRimeParameters.ntrulpr1277);
        ntrulpr1277 = nTRULPRimeParameterSpec6;
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put("ntrulpr653", nTRULPRimeParameterSpec);
        parameters.put("ntrulpr761", nTRULPRimeParameterSpec2);
        parameters.put("ntrulpr857", nTRULPRimeParameterSpec3);
        parameters.put("ntrulpr953", nTRULPRimeParameterSpec4);
        parameters.put("ntrulpr1013", nTRULPRimeParameterSpec5);
        parameters.put("ntrulpr1277", nTRULPRimeParameterSpec6);
    }

    private NTRULPRimeParameterSpec(NTRULPRimeParameters nTRULPRimeParameters) {
        this.name = nTRULPRimeParameters.getName();
    }

    public static NTRULPRimeParameterSpec fromName(String str) {
        return (NTRULPRimeParameterSpec) parameters.get(Strings.toLowerCase(str));
    }

    public String getName() {
        return this.name;
    }
}