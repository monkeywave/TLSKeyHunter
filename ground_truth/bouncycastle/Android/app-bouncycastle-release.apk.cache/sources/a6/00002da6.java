package org.bouncycastle.tls;

import java.io.EOFException;

/* loaded from: classes2.dex */
public class TlsNoCloseNotifyException extends EOFException {
    public TlsNoCloseNotifyException() {
        super("No close_notify alert received before connection closed");
    }
}