package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.Digest;

/* loaded from: classes2.dex */
class Utils {

    /* loaded from: classes2.dex */
    private static class DefaultProperties implements CryptoServiceProperties {
        private final String algorithmName;
        private final int bitsOfSecurity;
        private final CryptoServicePurpose purpose;

        public DefaultProperties(int i, String str, CryptoServicePurpose cryptoServicePurpose) {
            this.bitsOfSecurity = i;
            this.algorithmName = str;
            this.purpose = cryptoServicePurpose;
        }

        @Override // org.bouncycastle.crypto.CryptoServiceProperties
        public int bitsOfSecurity() {
            return this.bitsOfSecurity;
        }

        @Override // org.bouncycastle.crypto.CryptoServiceProperties
        public Object getParams() {
            return null;
        }

        @Override // org.bouncycastle.crypto.CryptoServiceProperties
        public CryptoServicePurpose getPurpose() {
            return this.purpose;
        }

        @Override // org.bouncycastle.crypto.CryptoServiceProperties
        public String getServiceName() {
            return this.algorithmName;
        }
    }

    /* loaded from: classes2.dex */
    private static class DefaultPropertiesWithPRF implements CryptoServiceProperties {
        private final String algorithmName;
        private final int bitsOfSecurity;
        private final int prfBitsOfSecurity;
        private final CryptoServicePurpose purpose;

        public DefaultPropertiesWithPRF(int i, int i2, String str, CryptoServicePurpose cryptoServicePurpose) {
            this.bitsOfSecurity = i;
            this.prfBitsOfSecurity = i2;
            this.algorithmName = str;
            this.purpose = cryptoServicePurpose;
        }

        @Override // org.bouncycastle.crypto.CryptoServiceProperties
        public int bitsOfSecurity() {
            return this.purpose == CryptoServicePurpose.PRF ? this.prfBitsOfSecurity : this.bitsOfSecurity;
        }

        @Override // org.bouncycastle.crypto.CryptoServiceProperties
        public Object getParams() {
            return null;
        }

        @Override // org.bouncycastle.crypto.CryptoServiceProperties
        public CryptoServicePurpose getPurpose() {
            return this.purpose;
        }

        @Override // org.bouncycastle.crypto.CryptoServiceProperties
        public String getServiceName() {
            return this.algorithmName;
        }
    }

    Utils() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static CryptoServiceProperties getDefaultProperties(Digest digest, int i, CryptoServicePurpose cryptoServicePurpose) {
        return new DefaultPropertiesWithPRF(digest.getDigestSize() * 4, i, digest.getAlgorithmName(), cryptoServicePurpose);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static CryptoServiceProperties getDefaultProperties(Digest digest, CryptoServicePurpose cryptoServicePurpose) {
        return new DefaultProperties(digest.getDigestSize() * 4, digest.getAlgorithmName(), cryptoServicePurpose);
    }
}