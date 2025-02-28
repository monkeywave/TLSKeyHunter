package org.openjsse.com.sun.crypto.provider;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.IvParameterSpec;
import org.openjsse.sun.security.util.HexDumpEncoder;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/ChaCha20Poly1305Parameters.class */
public final class ChaCha20Poly1305Parameters extends AlgorithmParametersSpi {
    private static final String DEFAULT_FMT = "ASN.1";
    private byte[] nonce;

    @Override // java.security.AlgorithmParametersSpi
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (!(paramSpec instanceof IvParameterSpec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }
        IvParameterSpec ivps = (IvParameterSpec) paramSpec;
        this.nonce = ivps.getIV();
        if (this.nonce.length != 12) {
            throw new InvalidParameterSpecException("ChaCha20-Poly1305 nonce must be 12 bytes in length");
        }
    }

    @Override // java.security.AlgorithmParametersSpi
    protected void engineInit(byte[] encoded) throws IOException {
        DerValue val = new DerValue(encoded);
        this.nonce = val.getOctetString();
        if (this.nonce.length != 12) {
            throw new IOException("ChaCha20-Poly1305 nonce must be 12 bytes in length");
        }
    }

    @Override // java.security.AlgorithmParametersSpi
    protected void engineInit(byte[] encoded, String decodingMethod) throws IOException {
        if (decodingMethod == null || decodingMethod.equalsIgnoreCase(DEFAULT_FMT)) {
            engineInit(encoded);
            return;
        }
        throw new IOException("Unsupported parameter format: " + decodingMethod);
    }

    @Override // java.security.AlgorithmParametersSpi
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) throws InvalidParameterSpecException {
        if (IvParameterSpec.class.isAssignableFrom(paramSpec)) {
            return paramSpec.cast(new IvParameterSpec(this.nonce));
        }
        throw new InvalidParameterSpecException("Inappropriate parameter specification");
    }

    @Override // java.security.AlgorithmParametersSpi
    protected byte[] engineGetEncoded() throws IOException {
        DerOutputStream out = new DerOutputStream();
        out.write((byte) 4, this.nonce);
        return out.toByteArray();
    }

    @Override // java.security.AlgorithmParametersSpi
    protected byte[] engineGetEncoded(String encodingMethod) throws IOException {
        if (encodingMethod == null || encodingMethod.equalsIgnoreCase(DEFAULT_FMT)) {
            return engineGetEncoded();
        }
        throw new IOException("Unsupported encoding format: " + encodingMethod);
    }

    @Override // java.security.AlgorithmParametersSpi
    protected String engineToString() {
        String LINE_SEP = System.lineSeparator();
        HexDumpEncoder encoder = new HexDumpEncoder();
        StringBuilder sb = new StringBuilder(LINE_SEP + "nonce:" + LINE_SEP + "[" + encoder.encodeBuffer(this.nonce) + "]");
        return sb.toString();
    }
}