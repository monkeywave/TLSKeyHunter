package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public final class RecordPreview {
    private final int contentLimit;
    private final int recordSize;

    /* JADX INFO: Access modifiers changed from: package-private */
    public RecordPreview(int i, int i2) {
        this.recordSize = i;
        this.contentLimit = i2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static RecordPreview combineAppData(RecordPreview recordPreview, RecordPreview recordPreview2) {
        return new RecordPreview(recordPreview.getRecordSize() + recordPreview2.getRecordSize(), recordPreview.getContentLimit() + recordPreview2.getContentLimit());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static RecordPreview extendRecordSize(RecordPreview recordPreview, int i) {
        return new RecordPreview(recordPreview.getRecordSize() + i, recordPreview.getContentLimit());
    }

    public int getApplicationDataLimit() {
        return this.contentLimit;
    }

    public int getContentLimit() {
        return this.contentLimit;
    }

    public int getRecordSize() {
        return this.recordSize;
    }
}