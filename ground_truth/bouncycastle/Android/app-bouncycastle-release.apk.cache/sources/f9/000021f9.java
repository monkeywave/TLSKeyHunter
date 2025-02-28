package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Exceptions;

/* loaded from: classes2.dex */
public abstract class BaseDeterministicOrRandomSignature extends Signature {
    protected AlgorithmParameters engineParams;
    private final JcaJceHelper helper;
    protected boolean isInitState;
    protected AsymmetricKeyParameter keyParams;
    private final AlgorithmParameterSpec originalSpec;
    protected ContextParameterSpec paramSpec;

    /* JADX INFO: Access modifiers changed from: protected */
    public BaseDeterministicOrRandomSignature(String str) {
        super(str);
        this.helper = new BCJcaJceHelper();
        this.isInitState = true;
        this.originalSpec = ContextParameterSpec.EMPTY_CONTEXT_SPEC;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v3, types: [org.bouncycastle.crypto.params.ParametersWithContext] */
    /* JADX WARN: Type inference failed for: r1v8, types: [org.bouncycastle.crypto.params.ParametersWithContext] */
    /* JADX WARN: Type inference failed for: r1v9, types: [org.bouncycastle.crypto.params.ParametersWithRandom] */
    /* JADX WARN: Type inference failed for: r3v0, types: [org.bouncycastle.jcajce.provider.asymmetric.util.BaseDeterministicOrRandomSignature] */
    private void reInit() {
        boolean z;
        AsymmetricKeyParameter asymmetricKeyParameter = this.keyParams;
        if (asymmetricKeyParameter.isPrivate()) {
            if (((BaseDeterministicOrRandomSignature) this).appRandom != null) {
                asymmetricKeyParameter = new ParametersWithRandom(asymmetricKeyParameter, ((BaseDeterministicOrRandomSignature) this).appRandom);
            }
            if (this.paramSpec != null) {
                asymmetricKeyParameter = new ParametersWithContext(asymmetricKeyParameter, this.paramSpec.getContext());
            }
            z = true;
        } else {
            if (this.paramSpec != null) {
                asymmetricKeyParameter = new ParametersWithContext(asymmetricKeyParameter, this.paramSpec.getContext());
            }
            z = false;
        }
        reInitialize(z, asymmetricKeyParameter);
    }

    @Override // java.security.SignatureSpi
    protected final Object engineGetParameter(String str) {
        throw new UnsupportedOperationException("GetParameter unsupported");
    }

    @Override // java.security.SignatureSpi
    protected final AlgorithmParameters engineGetParameters() {
        if (this.engineParams == null && this.paramSpec != null) {
            try {
                AlgorithmParameters createAlgorithmParameters = this.helper.createAlgorithmParameters("CONTEXT");
                this.engineParams = createAlgorithmParameters;
                createAlgorithmParameters.init(this.paramSpec);
            } catch (Exception e) {
                throw Exceptions.illegalStateException(e.toString(), e);
            }
        }
        return this.engineParams;
    }

    @Override // java.security.SignatureSpi
    protected final void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        signInit(privateKey, null);
        this.paramSpec = ContextParameterSpec.EMPTY_CONTEXT_SPEC;
        this.isInitState = true;
        reInit();
    }

    @Override // java.security.SignatureSpi
    protected final void engineInitSign(PrivateKey privateKey, SecureRandom secureRandom) throws InvalidKeyException {
        signInit(privateKey, secureRandom);
        this.paramSpec = ContextParameterSpec.EMPTY_CONTEXT_SPEC;
        this.isInitState = true;
        reInit();
    }

    @Override // java.security.SignatureSpi
    protected final void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        verifyInit(publicKey);
        this.paramSpec = ContextParameterSpec.EMPTY_CONTEXT_SPEC;
        this.isInitState = true;
        reInit();
    }

    @Override // java.security.SignatureSpi
    protected final void engineSetParameter(String str, Object obj) {
        throw new UnsupportedOperationException("SetParameter unsupported");
    }

    @Override // java.security.SignatureSpi
    protected void engineSetParameter(AlgorithmParameterSpec algorithmParameterSpec) throws InvalidAlgorithmParameterException {
        if (algorithmParameterSpec == null && (algorithmParameterSpec = this.originalSpec) == null) {
            return;
        }
        if (!this.isInitState) {
            throw new ProviderException("cannot call setParameter in the middle of update");
        }
        if (!(algorithmParameterSpec instanceof ContextParameterSpec)) {
            throw new InvalidAlgorithmParameterException("unknown AlgorithmParameterSpec in signature");
        }
        this.paramSpec = (ContextParameterSpec) algorithmParameterSpec;
        reInit();
    }

    @Override // java.security.SignatureSpi
    protected final void engineUpdate(byte b) throws SignatureException {
        this.isInitState = false;
        updateEngine(b);
    }

    @Override // java.security.SignatureSpi
    protected final void engineUpdate(byte[] bArr, int i, int i2) throws SignatureException {
        this.isInitState = false;
        updateEngine(bArr, i, i2);
    }

    protected abstract void reInitialize(boolean z, CipherParameters cipherParameters);

    protected abstract void signInit(PrivateKey privateKey, SecureRandom secureRandom) throws InvalidKeyException;

    protected abstract void updateEngine(byte b) throws SignatureException;

    protected abstract void updateEngine(byte[] bArr, int i, int i2) throws SignatureException;

    protected abstract void verifyInit(PublicKey publicKey) throws InvalidKeyException;
}