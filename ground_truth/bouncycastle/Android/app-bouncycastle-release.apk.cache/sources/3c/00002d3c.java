package org.bouncycastle.tls;

import java.io.IOException;

/* loaded from: classes2.dex */
public interface DatagramSender {
    int getSendLimit() throws IOException;

    void send(byte[] bArr, int i, int i2) throws IOException;
}