package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public class DTLSRequest {
    private final ClientHello clientHello;
    private final byte[] message;
    private final long recordSeq;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DTLSRequest(long j, byte[] bArr, ClientHello clientHello) {
        this.recordSeq = j;
        this.message = bArr;
        this.clientHello = clientHello;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ClientHello getClientHello() {
        return this.clientHello;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] getMessage() {
        return this.message;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getMessageSeq() {
        return TlsUtils.readUint16(this.message, 4);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public long getRecordSeq() {
        return this.recordSeq;
    }
}