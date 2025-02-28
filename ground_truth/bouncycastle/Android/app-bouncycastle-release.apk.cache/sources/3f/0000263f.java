package org.bouncycastle.jsse;

/* loaded from: classes2.dex */
public interface BCSSLConnection {
    String getApplicationProtocol();

    byte[] getChannelBinding(String str);

    String getID();

    BCExtendedSSLSession getSession();
}