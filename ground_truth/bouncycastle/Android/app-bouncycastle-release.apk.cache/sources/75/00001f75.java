package org.bouncycastle.jcajce.interfaces;

import java.security.Key;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;

/* loaded from: classes2.dex */
public interface MLDSAKey extends Key {
    MLDSAParameterSpec getParameterSpec();
}