package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class ServerSRPParams {

    /* renamed from: B */
    protected BigInteger f1546B;

    /* renamed from: N */
    protected BigInteger f1547N;

    /* renamed from: g */
    protected BigInteger f1548g;

    /* renamed from: s */
    protected byte[] f1549s;

    public ServerSRPParams(BigInteger bigInteger, BigInteger bigInteger2, byte[] bArr, BigInteger bigInteger3) {
        this.f1547N = bigInteger;
        this.f1548g = bigInteger2;
        this.f1549s = Arrays.clone(bArr);
        this.f1546B = bigInteger3;
    }

    public static ServerSRPParams parse(InputStream inputStream) throws IOException {
        return new ServerSRPParams(TlsSRPUtils.readSRPParameter(inputStream), TlsSRPUtils.readSRPParameter(inputStream), TlsUtils.readOpaque8(inputStream, 1), TlsSRPUtils.readSRPParameter(inputStream));
    }

    public void encode(OutputStream outputStream) throws IOException {
        TlsSRPUtils.writeSRPParameter(this.f1547N, outputStream);
        TlsSRPUtils.writeSRPParameter(this.f1548g, outputStream);
        TlsUtils.writeOpaque8(this.f1549s, outputStream);
        TlsSRPUtils.writeSRPParameter(this.f1546B, outputStream);
    }

    public BigInteger getB() {
        return this.f1546B;
    }

    public BigInteger getG() {
        return this.f1548g;
    }

    public BigInteger getN() {
        return this.f1547N;
    }

    public byte[] getS() {
        return this.f1549s;
    }
}