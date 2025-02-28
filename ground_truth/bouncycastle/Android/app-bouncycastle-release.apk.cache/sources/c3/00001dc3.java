package org.bouncycastle.crypto.hpke;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/* loaded from: classes2.dex */
public abstract class KEM {
    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract byte[] AuthDecap(byte[] bArr, AsymmetricCipherKeyPair asymmetricCipherKeyPair, AsymmetricKeyParameter asymmetricKeyParameter);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract byte[][] AuthEncap(AsymmetricKeyParameter asymmetricKeyParameter, AsymmetricCipherKeyPair asymmetricCipherKeyPair);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract byte[] Decap(byte[] bArr, AsymmetricCipherKeyPair asymmetricCipherKeyPair);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract AsymmetricCipherKeyPair DeriveKeyPair(byte[] bArr);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract AsymmetricCipherKeyPair DeserializePrivateKey(byte[] bArr, byte[] bArr2);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract AsymmetricKeyParameter DeserializePublicKey(byte[] bArr);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract byte[][] Encap(AsymmetricKeyParameter asymmetricKeyParameter);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract byte[][] Encap(AsymmetricKeyParameter asymmetricKeyParameter, AsymmetricCipherKeyPair asymmetricCipherKeyPair);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract AsymmetricCipherKeyPair GeneratePrivateKey();

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract byte[] SerializePrivateKey(AsymmetricKeyParameter asymmetricKeyParameter);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract byte[] SerializePublicKey(AsymmetricKeyParameter asymmetricKeyParameter);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract int getEncryptionSize();
}