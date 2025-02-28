package org.bouncycastle.jcajce.interfaces;

import java.security.PrivateKey;

/* loaded from: classes2.dex */
public interface MLKEMPrivateKey extends PrivateKey, MLKEMKey {
    MLKEMPublicKey getPublicKey();
}