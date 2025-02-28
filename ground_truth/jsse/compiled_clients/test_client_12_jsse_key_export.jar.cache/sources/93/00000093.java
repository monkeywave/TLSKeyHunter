package javassist.bytecode;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/LongVector.class */
public final class LongVector {
    static final int ASIZE = 128;
    static final int ABITS = 7;
    static final int VSIZE = 8;
    private ConstInfo[][] objects;
    private int elements;

    /* JADX WARN: Type inference failed for: r1v1, types: [javassist.bytecode.ConstInfo[], javassist.bytecode.ConstInfo[][]] */
    public LongVector() {
        this.objects = new ConstInfo[8];
        this.elements = 0;
    }

    /* JADX WARN: Type inference failed for: r1v4, types: [javassist.bytecode.ConstInfo[], javassist.bytecode.ConstInfo[][]] */
    public LongVector(int initialSize) {
        int vsize = ((initialSize >> 7) & (-8)) + 8;
        this.objects = new ConstInfo[vsize];
        this.elements = 0;
    }

    public int size() {
        return this.elements;
    }

    public int capacity() {
        return this.objects.length * 128;
    }

    public ConstInfo elementAt(int i) {
        if (i < 0 || this.elements <= i) {
            return null;
        }
        return this.objects[i >> 7][i & Opcode.LAND];
    }

    /* JADX WARN: Type inference failed for: r0v21, types: [javassist.bytecode.ConstInfo[], javassist.bytecode.ConstInfo[][], java.lang.Object] */
    public void addElement(ConstInfo value) {
        int nth = this.elements >> 7;
        int offset = this.elements & Opcode.LAND;
        int len = this.objects.length;
        if (nth >= len) {
            ?? r0 = new ConstInfo[len + 8];
            System.arraycopy(this.objects, 0, r0, 0, len);
            this.objects = r0;
        }
        if (this.objects[nth] == null) {
            this.objects[nth] = new ConstInfo[128];
        }
        this.objects[nth][offset] = value;
        this.elements++;
    }
}