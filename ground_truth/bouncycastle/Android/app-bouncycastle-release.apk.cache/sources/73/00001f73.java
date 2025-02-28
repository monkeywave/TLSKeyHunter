package org.bouncycastle.jcajce.interfaces;

import java.security.PrivateKey;

/* loaded from: classes2.dex */
public interface EdDSAPrivateKey extends EdDSAKey, PrivateKey {
    EdDSAPublicKey getPublicKey();
}