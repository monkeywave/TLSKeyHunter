package javassist;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/CtPrimitiveType.class */
public final class CtPrimitiveType extends CtClass {
    private char descriptor;
    private String wrapperName;
    private String getMethodName;
    private String mDescriptor;
    private int returnOp;
    private int arrayType;
    private int dataSize;

    /* JADX INFO: Access modifiers changed from: package-private */
    public CtPrimitiveType(String name, char desc, String wrapper, String methodName, String mDesc, int opcode, int atype, int size) {
        super(name);
        this.descriptor = desc;
        this.wrapperName = wrapper;
        this.getMethodName = methodName;
        this.mDescriptor = mDesc;
        this.returnOp = opcode;
        this.arrayType = atype;
        this.dataSize = size;
    }

    @Override // javassist.CtClass
    public boolean isPrimitive() {
        return true;
    }

    @Override // javassist.CtClass
    public int getModifiers() {
        return 17;
    }

    public char getDescriptor() {
        return this.descriptor;
    }

    public String getWrapperName() {
        return this.wrapperName;
    }

    public String getGetMethodName() {
        return this.getMethodName;
    }

    public String getGetMethodDescriptor() {
        return this.mDescriptor;
    }

    public int getReturnOp() {
        return this.returnOp;
    }

    public int getArrayType() {
        return this.arrayType;
    }

    public int getDataSize() {
        return this.dataSize;
    }
}