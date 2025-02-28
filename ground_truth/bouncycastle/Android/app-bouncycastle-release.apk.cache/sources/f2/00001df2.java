package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.MultiBlockCipher;

/* loaded from: classes2.dex */
public interface CBCModeCipher extends MultiBlockCipher {
    BlockCipher getUnderlyingCipher();
}