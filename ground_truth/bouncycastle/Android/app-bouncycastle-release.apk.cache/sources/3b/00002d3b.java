package org.bouncycastle.tls;

import java.io.IOException;

/* loaded from: classes2.dex */
public interface DatagramReceiver {
    int getReceiveLimit() throws IOException;

    int receive(byte[] bArr, int i, int i2, int i3) throws IOException;
}