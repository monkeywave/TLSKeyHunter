package org.bouncycastle.crypto.parsers;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.crypto.KeyParser;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.util.p019io.Streams;

/* loaded from: classes2.dex */
public class ECIESPublicKeyParser implements KeyParser {
    private ECDomainParameters ecParams;

    public ECIESPublicKeyParser(ECDomainParameters eCDomainParameters) {
        this.ecParams = eCDomainParameters;
    }

    @Override // org.bouncycastle.crypto.KeyParser
    public AsymmetricKeyParameter readKey(InputStream inputStream) throws IOException {
        boolean z;
        int read = inputStream.read();
        if (read >= 0) {
            if (read != 0) {
                if (read == 2 || read == 3) {
                    z = true;
                } else if (read != 4 && read != 6 && read != 7) {
                    throw new IOException("Sender's public key has invalid point encoding 0x" + Integer.toString(read, 16));
                } else {
                    z = false;
                }
                ECCurve curve = this.ecParams.getCurve();
                int affinePointEncodingLength = curve.getAffinePointEncodingLength(z);
                byte[] bArr = new byte[affinePointEncodingLength];
                bArr[0] = (byte) read;
                int i = affinePointEncodingLength - 1;
                if (Streams.readFully(inputStream, bArr, 1, i) == i) {
                    return new ECPublicKeyParameters(curve.decodePoint(bArr), this.ecParams);
                }
                throw new EOFException();
            }
            throw new IOException("Sender's public key invalid.");
        }
        throw new EOFException();
    }
}