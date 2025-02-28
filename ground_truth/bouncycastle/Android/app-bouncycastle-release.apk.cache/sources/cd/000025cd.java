package org.bouncycastle.jce.interfaces;

import java.security.PublicKey;
import org.bouncycastle.math.p016ec.ECPoint;

/* loaded from: classes2.dex */
public interface ECPublicKey extends ECKey, PublicKey {
    ECPoint getQ();
}