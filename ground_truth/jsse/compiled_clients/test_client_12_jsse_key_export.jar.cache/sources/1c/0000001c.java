package javassist;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:javassist/CtArray.class */
public final class CtArray extends CtClass {
    protected ClassPool pool;
    private CtClass[] interfaces;

    /* JADX INFO: Access modifiers changed from: package-private */
    public CtArray(String name, ClassPool cp) {
        super(name);
        this.interfaces = null;
        this.pool = cp;
    }

    @Override // javassist.CtClass
    public ClassPool getClassPool() {
        return this.pool;
    }

    @Override // javassist.CtClass
    public boolean isArray() {
        return true;
    }

    @Override // javassist.CtClass
    public int getModifiers() {
        int mod = 16;
        try {
            mod = 16 | (getComponentType().getModifiers() & 7);
        } catch (NotFoundException e) {
        }
        return mod;
    }

    @Override // javassist.CtClass
    public CtClass[] getInterfaces() throws NotFoundException {
        if (this.interfaces == null) {
            Class<?>[] intfs = Object[].class.getInterfaces();
            this.interfaces = new CtClass[intfs.length];
            for (int i = 0; i < intfs.length; i++) {
                this.interfaces[i] = this.pool.get(intfs[i].getName());
            }
        }
        return this.interfaces;
    }

    @Override // javassist.CtClass
    public boolean subtypeOf(CtClass clazz) throws NotFoundException {
        if (super.subtypeOf(clazz)) {
            return true;
        }
        String cname = clazz.getName();
        if (cname.equals("java.lang.Object")) {
            return true;
        }
        CtClass[] intfs = getInterfaces();
        for (CtClass ctClass : intfs) {
            if (ctClass.subtypeOf(clazz)) {
                return true;
            }
        }
        return clazz.isArray() && getComponentType().subtypeOf(clazz.getComponentType());
    }

    @Override // javassist.CtClass
    public CtClass getComponentType() throws NotFoundException {
        String name = getName();
        return this.pool.get(name.substring(0, name.length() - 2));
    }

    @Override // javassist.CtClass
    public CtClass getSuperclass() throws NotFoundException {
        return this.pool.get("java.lang.Object");
    }

    @Override // javassist.CtClass
    public CtMethod[] getMethods() {
        try {
            return getSuperclass().getMethods();
        } catch (NotFoundException e) {
            return super.getMethods();
        }
    }

    @Override // javassist.CtClass
    public CtMethod getMethod(String name, String desc) throws NotFoundException {
        return getSuperclass().getMethod(name, desc);
    }

    @Override // javassist.CtClass
    public CtConstructor[] getConstructors() {
        try {
            return getSuperclass().getConstructors();
        } catch (NotFoundException e) {
            return super.getConstructors();
        }
    }
}