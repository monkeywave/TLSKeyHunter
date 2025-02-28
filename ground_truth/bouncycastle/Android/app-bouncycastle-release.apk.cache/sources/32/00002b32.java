package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

/* loaded from: classes2.dex */
public interface DilithiumKey extends Key {
    DilithiumParameterSpec getParameterSpec();
}