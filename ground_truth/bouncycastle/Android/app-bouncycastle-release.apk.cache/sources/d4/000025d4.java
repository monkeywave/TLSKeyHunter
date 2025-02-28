package org.bouncycastle.jce.interfaces;

import java.math.BigInteger;
import java.security.PublicKey;

/* loaded from: classes2.dex */
public interface GOST3410PublicKey extends GOST3410Key, PublicKey {
    BigInteger getY();
}