package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InterruptedIOException;

/* loaded from: classes2.dex */
public class DTLSTransport implements DatagramTransport {
    private final DTLSRecordLayer recordLayer;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DTLSTransport(DTLSRecordLayer dTLSRecordLayer) {
        this.recordLayer = dTLSRecordLayer;
    }

    @Override // org.bouncycastle.tls.TlsCloseable
    public void close() throws IOException {
        this.recordLayer.close();
    }

    @Override // org.bouncycastle.tls.DatagramReceiver
    public int getReceiveLimit() throws IOException {
        return this.recordLayer.getReceiveLimit();
    }

    @Override // org.bouncycastle.tls.DatagramSender
    public int getSendLimit() throws IOException {
        return this.recordLayer.getSendLimit();
    }

    @Override // org.bouncycastle.tls.DatagramReceiver
    public int receive(byte[] bArr, int i, int i2, int i3) throws IOException {
        return receive(bArr, i, i2, i3, null);
    }

    public int receive(byte[] bArr, int i, int i2, int i3, DTLSRecordCallback dTLSRecordCallback) throws IOException {
        if (bArr != null) {
            if (i < 0 || i >= bArr.length) {
                throw new IllegalArgumentException("'off' is an invalid offset: " + i);
            }
            if (i2 < 0 || i2 > bArr.length - i) {
                throw new IllegalArgumentException("'len' is an invalid length: " + i2);
            }
            if (i3 >= 0) {
                try {
                    return this.recordLayer.receive(bArr, i, i2, i3, dTLSRecordCallback);
                } catch (InterruptedIOException e) {
                    throw e;
                } catch (IOException e2) {
                    this.recordLayer.fail((short) 80);
                    throw e2;
                } catch (RuntimeException e3) {
                    this.recordLayer.fail((short) 80);
                    throw new TlsFatalAlert((short) 80, (Throwable) e3);
                } catch (TlsFatalAlert e4) {
                    if (20 == e4.getAlertDescription()) {
                        return -1;
                    }
                    this.recordLayer.fail(e4.getAlertDescription());
                    throw e4;
                }
            }
            throw new IllegalArgumentException("'waitMillis' cannot be negative");
        }
        throw new NullPointerException("'buf' cannot be null");
    }

    public int receivePending(byte[] bArr, int i, int i2) throws IOException {
        return receivePending(bArr, i, i2, null);
    }

    public int receivePending(byte[] bArr, int i, int i2, DTLSRecordCallback dTLSRecordCallback) throws IOException {
        if (bArr != null) {
            if (i < 0 || i >= bArr.length) {
                throw new IllegalArgumentException("'off' is an invalid offset: " + i);
            }
            if (i2 < 0 || i2 > bArr.length - i) {
                throw new IllegalArgumentException("'len' is an invalid length: " + i2);
            }
            try {
                return this.recordLayer.receivePending(bArr, i, i2, dTLSRecordCallback);
            } catch (InterruptedIOException e) {
                throw e;
            } catch (RuntimeException e2) {
                this.recordLayer.fail((short) 80);
                throw new TlsFatalAlert((short) 80, (Throwable) e2);
            } catch (TlsFatalAlert e3) {
                if (20 == e3.getAlertDescription()) {
                    return -1;
                }
                this.recordLayer.fail(e3.getAlertDescription());
                throw e3;
            } catch (IOException e4) {
                this.recordLayer.fail((short) 80);
                throw e4;
            }
        }
        throw new NullPointerException("'buf' cannot be null");
    }

    @Override // org.bouncycastle.tls.DatagramSender
    public void send(byte[] bArr, int i, int i2) throws IOException {
        if (bArr == null) {
            throw new NullPointerException("'buf' cannot be null");
        }
        if (i < 0 || i >= bArr.length) {
            throw new IllegalArgumentException("'off' is an invalid offset: " + i);
        }
        if (i2 < 0 || i2 > bArr.length - i) {
            throw new IllegalArgumentException("'len' is an invalid length: " + i2);
        }
        try {
            this.recordLayer.send(bArr, i, i2);
        } catch (InterruptedIOException e) {
            throw e;
        } catch (RuntimeException e2) {
            this.recordLayer.fail((short) 80);
            throw new TlsFatalAlert((short) 80, (Throwable) e2);
        } catch (TlsFatalAlert e3) {
            this.recordLayer.fail(e3.getAlertDescription());
            throw e3;
        } catch (IOException e4) {
            this.recordLayer.fail((short) 80);
            throw e4;
        }
    }
}