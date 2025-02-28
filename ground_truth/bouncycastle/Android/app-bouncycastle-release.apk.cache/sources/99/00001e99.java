package org.bouncycastle.crypto.parsers;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import org.bouncycastle.crypto.KeyParser;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.util.p019io.Streams;

/* loaded from: classes2.dex */
public class DHIESPublicKeyParser implements KeyParser {
    private DHParameters dhParams;

    public DHIESPublicKeyParser(DHParameters dHParameters) {
        this.dhParams = dHParameters;
    }

    @Override // org.bouncycastle.crypto.KeyParser
    public AsymmetricKeyParameter readKey(InputStream inputStream) throws IOException {
        int bitLength = (this.dhParams.getP().bitLength() + 7) / 8;
        byte[] bArr = new byte[bitLength];
        Streams.readFully(inputStream, bArr, 0, bitLength);
        return new DHPublicKeyParameters(new BigInteger(1, bArr), this.dhParams);
    }
}