package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.pqc.crypto.picnic.PicnicParameters;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class PicnicParameterSpec implements AlgorithmParameterSpec {
    private static Map parameters;
    public static final PicnicParameterSpec picnic3l1;
    public static final PicnicParameterSpec picnic3l3;
    public static final PicnicParameterSpec picnic3l5;
    public static final PicnicParameterSpec picnicl1fs;
    public static final PicnicParameterSpec picnicl1full;
    public static final PicnicParameterSpec picnicl1ur;
    public static final PicnicParameterSpec picnicl3fs;
    public static final PicnicParameterSpec picnicl3full;
    public static final PicnicParameterSpec picnicl3ur;
    public static final PicnicParameterSpec picnicl5fs;
    public static final PicnicParameterSpec picnicl5full;
    public static final PicnicParameterSpec picnicl5ur;
    private final String name;

    static {
        PicnicParameterSpec picnicParameterSpec = new PicnicParameterSpec(PicnicParameters.picnicl1fs);
        picnicl1fs = picnicParameterSpec;
        PicnicParameterSpec picnicParameterSpec2 = new PicnicParameterSpec(PicnicParameters.picnicl1ur);
        picnicl1ur = picnicParameterSpec2;
        PicnicParameterSpec picnicParameterSpec3 = new PicnicParameterSpec(PicnicParameters.picnicl3fs);
        picnicl3fs = picnicParameterSpec3;
        PicnicParameterSpec picnicParameterSpec4 = new PicnicParameterSpec(PicnicParameters.picnicl3ur);
        picnicl3ur = picnicParameterSpec4;
        PicnicParameterSpec picnicParameterSpec5 = new PicnicParameterSpec(PicnicParameters.picnicl5fs);
        picnicl5fs = picnicParameterSpec5;
        PicnicParameterSpec picnicParameterSpec6 = new PicnicParameterSpec(PicnicParameters.picnicl5ur);
        picnicl5ur = picnicParameterSpec6;
        PicnicParameterSpec picnicParameterSpec7 = new PicnicParameterSpec(PicnicParameters.picnic3l1);
        picnic3l1 = picnicParameterSpec7;
        PicnicParameterSpec picnicParameterSpec8 = new PicnicParameterSpec(PicnicParameters.picnic3l3);
        picnic3l3 = picnicParameterSpec8;
        PicnicParameterSpec picnicParameterSpec9 = new PicnicParameterSpec(PicnicParameters.picnic3l5);
        picnic3l5 = picnicParameterSpec9;
        PicnicParameterSpec picnicParameterSpec10 = new PicnicParameterSpec(PicnicParameters.picnicl1full);
        picnicl1full = picnicParameterSpec10;
        PicnicParameterSpec picnicParameterSpec11 = new PicnicParameterSpec(PicnicParameters.picnicl3full);
        picnicl3full = picnicParameterSpec11;
        PicnicParameterSpec picnicParameterSpec12 = new PicnicParameterSpec(PicnicParameters.picnicl5full);
        picnicl5full = picnicParameterSpec12;
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put("picnicl1fs", picnicParameterSpec);
        parameters.put("picnicl1ur", picnicParameterSpec2);
        parameters.put("picnicl3fs", picnicParameterSpec3);
        parameters.put("picnicl3ur", picnicParameterSpec4);
        parameters.put("picnicl5fs", picnicParameterSpec5);
        parameters.put("picnicl5ur", picnicParameterSpec6);
        parameters.put("picnic3l1", picnicParameterSpec7);
        parameters.put("picnic3l3", picnicParameterSpec8);
        parameters.put("picnic3l5", picnicParameterSpec9);
        parameters.put("picnicl1full", picnicParameterSpec10);
        parameters.put("picnicl3full", picnicParameterSpec11);
        parameters.put("picnicl5full", picnicParameterSpec12);
    }

    private PicnicParameterSpec(PicnicParameters picnicParameters) {
        this.name = picnicParameters.getName();
    }

    public static PicnicParameterSpec fromName(String str) {
        return (PicnicParameterSpec) parameters.get(Strings.toLowerCase(str));
    }

    public String getName() {
        return this.name;
    }
}