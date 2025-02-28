package org.bouncycastle.oer;

import org.bouncycastle.oer.OERDefinition;

/* loaded from: classes2.dex */
public class DeferredElementSupplier implements ElementSupplier {
    private Element buildProduct;
    private final OERDefinition.Builder src;

    public DeferredElementSupplier(OERDefinition.Builder builder) {
        this.src = builder;
    }

    @Override // org.bouncycastle.oer.ElementSupplier
    public Element build() {
        Element element;
        synchronized (this) {
            if (this.buildProduct == null) {
                this.buildProduct = this.src.build();
            }
            element = this.buildProduct;
        }
        return element;
    }
}