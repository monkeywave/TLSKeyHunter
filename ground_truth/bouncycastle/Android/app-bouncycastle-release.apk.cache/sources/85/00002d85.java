package org.bouncycastle.tls;

import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.tls.crypto.SRP6Group;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.tls.crypto.TlsMAC;
import org.bouncycastle.tls.crypto.TlsSRP6VerifierGenerator;
import org.bouncycastle.tls.crypto.TlsSRPConfig;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class SimulatedTlsSRPIdentityManager implements TlsSRPIdentityManager {
    private static final byte[] PREFIX_PASSWORD = Strings.toByteArray("password");
    private static final byte[] PREFIX_SALT = Strings.toByteArray("salt");
    protected SRP6Group group;
    protected TlsMAC mac;
    protected TlsSRP6VerifierGenerator verifierGenerator;

    public SimulatedTlsSRPIdentityManager(SRP6Group sRP6Group, TlsSRP6VerifierGenerator tlsSRP6VerifierGenerator, TlsMAC tlsMAC) {
        this.group = sRP6Group;
        this.verifierGenerator = tlsSRP6VerifierGenerator;
        this.mac = tlsMAC;
    }

    public static SimulatedTlsSRPIdentityManager getRFC5054Default(TlsCrypto tlsCrypto, SRP6Group sRP6Group, byte[] bArr) throws IOException {
        TlsHMAC createHMAC = tlsCrypto.createHMAC(2);
        createHMAC.setKey(bArr, 0, bArr.length);
        TlsSRPConfig tlsSRPConfig = new TlsSRPConfig();
        tlsSRPConfig.setExplicitNG(new BigInteger[]{sRP6Group.getN(), sRP6Group.getG()});
        return new SimulatedTlsSRPIdentityManager(sRP6Group, tlsCrypto.createSRP6VerifierGenerator(tlsSRPConfig), createHMAC);
    }

    @Override // org.bouncycastle.tls.TlsSRPIdentityManager
    public TlsSRPLoginParameters getLoginParameters(byte[] bArr) {
        TlsMAC tlsMAC = this.mac;
        byte[] bArr2 = PREFIX_SALT;
        tlsMAC.update(bArr2, 0, bArr2.length);
        this.mac.update(bArr, 0, bArr.length);
        byte[] calculateMAC = this.mac.calculateMAC();
        TlsMAC tlsMAC2 = this.mac;
        byte[] bArr3 = PREFIX_PASSWORD;
        tlsMAC2.update(bArr3, 0, bArr3.length);
        this.mac.update(bArr, 0, bArr.length);
        BigInteger generateVerifier = this.verifierGenerator.generateVerifier(calculateMAC, bArr, this.mac.calculateMAC());
        TlsSRPConfig tlsSRPConfig = new TlsSRPConfig();
        tlsSRPConfig.setExplicitNG(new BigInteger[]{this.group.getN(), this.group.getG()});
        return new TlsSRPLoginParameters(bArr, tlsSRPConfig, generateVerifier, calculateMAC);
    }
}