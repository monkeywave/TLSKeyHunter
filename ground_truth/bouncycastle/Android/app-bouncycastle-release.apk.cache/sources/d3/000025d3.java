package org.bouncycastle.jce.interfaces;

import java.math.BigInteger;
import java.security.PrivateKey;

/* loaded from: classes2.dex */
public interface GOST3410PrivateKey extends GOST3410Key, PrivateKey {
    BigInteger getX();
}