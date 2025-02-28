package org.bouncycastle.jcajce.interfaces;

import java.security.Key;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

/* loaded from: classes2.dex */
public interface MLKEMKey extends Key {
    MLKEMParameterSpec getParameterSpec();
}