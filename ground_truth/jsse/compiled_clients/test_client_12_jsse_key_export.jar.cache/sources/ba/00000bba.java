package org.bouncycastle.jce.interfaces;

import java.security.PublicKey;
import org.bouncycastle.math.p010ec.ECPoint;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/interfaces/ECPublicKey.class */
public interface ECPublicKey extends ECKey, PublicKey {
    ECPoint getQ();
}