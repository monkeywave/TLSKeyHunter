package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.PrivateKey;

/* loaded from: classes2.dex */
public interface SPHINCSPlusPrivateKey extends PrivateKey, SPHINCSPlusKey {
    SPHINCSPlusPublicKey getPublicKey();
}