package org.bouncycastle.jcajce.interfaces;

import java.security.PrivateKey;

/* loaded from: classes2.dex */
public interface MLDSAPrivateKey extends PrivateKey, MLDSAKey {
    MLDSAPublicKey getPublicKey();
}