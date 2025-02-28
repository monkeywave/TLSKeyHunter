package org.bouncycastle.pqc.crypto.newhope;

import java.io.IOException;
import java.security.SecureRandom;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.util.DEROtherInfo;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.crypto.ExchangePair;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/newhope/NHOtherInfoGenerator.class */
public class NHOtherInfoGenerator {
    protected final DEROtherInfo.Builder otherInfoBuilder;
    protected final SecureRandom random;
    protected boolean used = false;

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/newhope/NHOtherInfoGenerator$PartyU.class */
    public static class PartyU extends NHOtherInfoGenerator {
        private AsymmetricCipherKeyPair aKp;
        private NHAgreement agreement;

        public PartyU(AlgorithmIdentifier algorithmIdentifier, byte[] bArr, byte[] bArr2, SecureRandom secureRandom) {
            super(algorithmIdentifier, bArr, bArr2, secureRandom);
            this.agreement = new NHAgreement();
            NHKeyPairGenerator nHKeyPairGenerator = new NHKeyPairGenerator();
            nHKeyPairGenerator.init(new KeyGenerationParameters(secureRandom, 2048));
            this.aKp = nHKeyPairGenerator.generateKeyPair();
            this.agreement.init(this.aKp.getPrivate());
        }

        public NHOtherInfoGenerator withSuppPubInfo(byte[] bArr) {
            this.otherInfoBuilder.withSuppPubInfo(bArr);
            return this;
        }

        public byte[] getSuppPrivInfoPartA() {
            return NHOtherInfoGenerator.getEncoded((NHPublicKeyParameters) this.aKp.getPublic());
        }

        public DEROtherInfo generate(byte[] bArr) {
            if (this.used) {
                throw new IllegalStateException("builder already used");
            }
            this.used = true;
            this.otherInfoBuilder.withSuppPrivInfo(this.agreement.calculateAgreement(NHOtherInfoGenerator.getPublicKey(bArr)));
            return this.otherInfoBuilder.build();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/newhope/NHOtherInfoGenerator$PartyV.class */
    public static class PartyV extends NHOtherInfoGenerator {
        public PartyV(AlgorithmIdentifier algorithmIdentifier, byte[] bArr, byte[] bArr2, SecureRandom secureRandom) {
            super(algorithmIdentifier, bArr, bArr2, secureRandom);
        }

        public NHOtherInfoGenerator withSuppPubInfo(byte[] bArr) {
            this.otherInfoBuilder.withSuppPubInfo(bArr);
            return this;
        }

        public byte[] getSuppPrivInfoPartB(byte[] bArr) {
            ExchangePair generateExchange = new NHExchangePairGenerator(this.random).generateExchange(NHOtherInfoGenerator.getPublicKey(bArr));
            this.otherInfoBuilder.withSuppPrivInfo(generateExchange.getSharedValue());
            return NHOtherInfoGenerator.getEncoded((NHPublicKeyParameters) generateExchange.getPublicKey());
        }

        public DEROtherInfo generate() {
            if (this.used) {
                throw new IllegalStateException("builder already used");
            }
            this.used = true;
            return this.otherInfoBuilder.build();
        }
    }

    public NHOtherInfoGenerator(AlgorithmIdentifier algorithmIdentifier, byte[] bArr, byte[] bArr2, SecureRandom secureRandom) {
        this.otherInfoBuilder = new DEROtherInfo.Builder(algorithmIdentifier, bArr, bArr2);
        this.random = secureRandom;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static byte[] getEncoded(NHPublicKeyParameters nHPublicKeyParameters) {
        try {
            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.newHope), nHPublicKeyParameters.getPubData()).getEncoded();
        } catch (IOException e) {
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static NHPublicKeyParameters getPublicKey(byte[] bArr) {
        return new NHPublicKeyParameters(SubjectPublicKeyInfo.getInstance(bArr).getPublicKeyData().getOctets());
    }
}