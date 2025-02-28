package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;
import org.bouncycastle.pqc.jcajce.spec.RainbowParameterSpec;

/* loaded from: classes2.dex */
public interface RainbowKey extends Key {
    RainbowParameterSpec getParameterSpec();
}