package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.jcajce.spec.RawEncodedKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.TlsFatalAlert;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class XDHUtil {
    XDHUtil() {
    }

    private static X509EncodedKeySpec createX509EncodedKeySpec(ASN1ObjectIdentifier aSN1ObjectIdentifier, byte[] bArr) throws IOException {
        return new X509EncodedKeySpec(new SubjectPublicKeyInfo(new AlgorithmIdentifier(aSN1ObjectIdentifier), bArr).getEncoded(ASN1Encoding.DER));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static PublicKey decodePublicKey(JcaTlsCrypto jcaTlsCrypto, String str, ASN1ObjectIdentifier aSN1ObjectIdentifier, byte[] bArr) throws TlsFatalAlert {
        try {
            KeyFactory createKeyFactory = jcaTlsCrypto.getHelper().createKeyFactory(str);
            if (createKeyFactory.getProvider() instanceof BouncyCastleProvider) {
                try {
                    return createKeyFactory.generatePublic(new RawEncodedKeySpec(bArr));
                } catch (Exception unused) {
                }
            }
            return createKeyFactory.generatePublic(createX509EncodedKeySpec(aSN1ObjectIdentifier, bArr));
        } catch (Exception e) {
            throw new TlsFatalAlert((short) 47, (Throwable) e);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] encodePublicKey(PublicKey publicKey) throws TlsFatalAlert {
        if (publicKey instanceof XDHPublicKey) {
            return ((XDHPublicKey) publicKey).getUEncoding();
        }
        if ("X.509".equals(publicKey.getFormat())) {
            try {
                return SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getPublicKeyData().getOctets();
            } catch (Exception e) {
                throw new TlsFatalAlert((short) 80, (Throwable) e);
            }
        }
        throw new TlsFatalAlert((short) 80, "Public key format unrecognized");
    }
}