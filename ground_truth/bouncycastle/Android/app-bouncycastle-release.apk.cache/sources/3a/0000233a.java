package org.bouncycastle.jcajce.provider.drbg;

import org.bouncycastle.crypto.prng.EntropySource;

/* loaded from: classes2.dex */
interface IncrementalEntropySource extends EntropySource {
    byte[] getEntropy(long j) throws InterruptedException;
}