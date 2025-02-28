package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.DHGroup;

/* loaded from: classes2.dex */
public interface TlsDHGroupVerifier {
    boolean accept(DHGroup dHGroup);
}