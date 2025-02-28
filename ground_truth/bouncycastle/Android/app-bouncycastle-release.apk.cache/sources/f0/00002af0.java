package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.pqc.crypto.xmss.XMSSAddress;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
final class HashTreeAddress extends XMSSAddress {
    private static final int PADDING = 0;
    private static final int TYPE = 2;
    private final int padding;
    private final int treeHeight;
    private final int treeIndex;

    /* JADX INFO: Access modifiers changed from: protected */
    /* loaded from: classes2.dex */
    public static class Builder extends XMSSAddress.Builder<Builder> {
        private int treeHeight;
        private int treeIndex;

        /* JADX INFO: Access modifiers changed from: protected */
        public Builder() {
            super(2);
            this.treeHeight = 0;
            this.treeIndex = 0;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // org.bouncycastle.pqc.crypto.xmss.XMSSAddress.Builder
        public XMSSAddress build() {
            return new HashTreeAddress(this);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // org.bouncycastle.pqc.crypto.xmss.XMSSAddress.Builder
        public Builder getThis() {
            return this;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        public Builder withTreeHeight(int i) {
            this.treeHeight = i;
            return this;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        public Builder withTreeIndex(int i) {
            this.treeIndex = i;
            return this;
        }
    }

    private HashTreeAddress(Builder builder) {
        super(builder);
        this.padding = 0;
        this.treeHeight = builder.treeHeight;
        this.treeIndex = builder.treeIndex;
    }

    protected int getPadding() {
        return this.padding;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public int getTreeHeight() {
        return this.treeHeight;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public int getTreeIndex() {
        return this.treeIndex;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.pqc.crypto.xmss.XMSSAddress
    public byte[] toByteArray() {
        byte[] byteArray = super.toByteArray();
        Pack.intToBigEndian(this.padding, byteArray, 16);
        Pack.intToBigEndian(this.treeHeight, byteArray, 20);
        Pack.intToBigEndian(this.treeIndex, byteArray, 24);
        return byteArray;
    }
}