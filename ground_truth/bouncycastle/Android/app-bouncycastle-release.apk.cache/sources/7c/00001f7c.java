package org.bouncycastle.jcajce.interfaces;

import java.security.PrivateKey;

/* loaded from: classes2.dex */
public interface SLHDSAPrivateKey extends PrivateKey, SLHDSAKey {
    SLHDSAPublicKey getPublicKey();
}