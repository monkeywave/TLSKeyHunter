package javassist.compiler;

import java.util.HashMap;
import java.util.Map;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;
import javassist.bytecode.Bytecode;
import javassist.bytecode.ClassFile;
import javassist.bytecode.ConstPool;
import javassist.bytecode.Descriptor;
import javassist.bytecode.ExceptionsAttribute;
import javassist.bytecode.FieldInfo;
import javassist.bytecode.MethodInfo;
import javassist.bytecode.SyntheticAttribute;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/compiler/AccessorMaker.class */
public class AccessorMaker {
    private CtClass clazz;
    private int uniqueNumber = 1;
    private Map<String, Object> accessors = new HashMap();
    static final String lastParamType = "javassist.runtime.Inner";

    public AccessorMaker(CtClass c) {
        this.clazz = c;
    }

    public String getConstructor(CtClass c, String desc, MethodInfo orig) throws CompileError {
        String key = "<init>:" + desc;
        String consDesc = (String) this.accessors.get(key);
        if (consDesc != null) {
            return consDesc;
        }
        String consDesc2 = Descriptor.appendParameter(lastParamType, desc);
        ClassFile cf = this.clazz.getClassFile();
        try {
            ConstPool cp = cf.getConstPool();
            ClassPool pool = this.clazz.getClassPool();
            MethodInfo minfo = new MethodInfo(cp, "<init>", consDesc2);
            minfo.setAccessFlags(0);
            minfo.addAttribute(new SyntheticAttribute(cp));
            ExceptionsAttribute ea = orig.getExceptionsAttribute();
            if (ea != null) {
                minfo.addAttribute(ea.copy(cp, null));
            }
            CtClass[] params = Descriptor.getParameterTypes(desc, pool);
            Bytecode code = new Bytecode(cp);
            code.addAload(0);
            int regno = 1;
            for (CtClass ctClass : params) {
                regno += code.addLoad(regno, ctClass);
            }
            code.setMaxLocals(regno + 1);
            code.addInvokespecial(this.clazz, "<init>", desc);
            code.addReturn(null);
            minfo.setCodeAttribute(code.toCodeAttribute());
            cf.addMethod(minfo);
            this.accessors.put(key, consDesc2);
            return consDesc2;
        } catch (CannotCompileException e) {
            throw new CompileError(e);
        } catch (NotFoundException e2) {
            throw new CompileError(e2);
        }
    }

    public String getMethodAccessor(String name, String desc, String accDesc, MethodInfo orig) throws CompileError {
        String key = name + ":" + desc;
        String accName = (String) this.accessors.get(key);
        if (accName != null) {
            return accName;
        }
        ClassFile cf = this.clazz.getClassFile();
        String accName2 = findAccessorName(cf);
        try {
            ConstPool cp = cf.getConstPool();
            ClassPool pool = this.clazz.getClassPool();
            MethodInfo minfo = new MethodInfo(cp, accName2, accDesc);
            minfo.setAccessFlags(8);
            minfo.addAttribute(new SyntheticAttribute(cp));
            ExceptionsAttribute ea = orig.getExceptionsAttribute();
            if (ea != null) {
                minfo.addAttribute(ea.copy(cp, null));
            }
            CtClass[] params = Descriptor.getParameterTypes(accDesc, pool);
            int regno = 0;
            Bytecode code = new Bytecode(cp);
            for (CtClass ctClass : params) {
                regno += code.addLoad(regno, ctClass);
            }
            code.setMaxLocals(regno);
            if (desc == accDesc) {
                code.addInvokestatic(this.clazz, name, desc);
            } else {
                code.addInvokevirtual(this.clazz, name, desc);
            }
            code.addReturn(Descriptor.getReturnType(desc, pool));
            minfo.setCodeAttribute(code.toCodeAttribute());
            cf.addMethod(minfo);
            this.accessors.put(key, accName2);
            return accName2;
        } catch (CannotCompileException e) {
            throw new CompileError(e);
        } catch (NotFoundException e2) {
            throw new CompileError(e2);
        }
    }

    public MethodInfo getFieldGetter(FieldInfo finfo, boolean is_static) throws CompileError {
        String accDesc;
        String fieldName = finfo.getName();
        String key = fieldName + ":getter";
        Object res = this.accessors.get(key);
        if (res != null) {
            return (MethodInfo) res;
        }
        ClassFile cf = this.clazz.getClassFile();
        String accName = findAccessorName(cf);
        try {
            ConstPool cp = cf.getConstPool();
            ClassPool pool = this.clazz.getClassPool();
            String fieldType = finfo.getDescriptor();
            if (is_static) {
                accDesc = "()" + fieldType;
            } else {
                accDesc = "(" + Descriptor.m129of(this.clazz) + ")" + fieldType;
            }
            MethodInfo minfo = new MethodInfo(cp, accName, accDesc);
            minfo.setAccessFlags(8);
            minfo.addAttribute(new SyntheticAttribute(cp));
            Bytecode code = new Bytecode(cp);
            if (is_static) {
                code.addGetstatic(Bytecode.THIS, fieldName, fieldType);
            } else {
                code.addAload(0);
                code.addGetfield(Bytecode.THIS, fieldName, fieldType);
                code.setMaxLocals(1);
            }
            code.addReturn(Descriptor.toCtClass(fieldType, pool));
            minfo.setCodeAttribute(code.toCodeAttribute());
            cf.addMethod(minfo);
            this.accessors.put(key, minfo);
            return minfo;
        } catch (CannotCompileException e) {
            throw new CompileError(e);
        } catch (NotFoundException e2) {
            throw new CompileError(e2);
        }
    }

    public MethodInfo getFieldSetter(FieldInfo finfo, boolean is_static) throws CompileError {
        String accDesc;
        int reg;
        String fieldName = finfo.getName();
        String key = fieldName + ":setter";
        Object res = this.accessors.get(key);
        if (res != null) {
            return (MethodInfo) res;
        }
        ClassFile cf = this.clazz.getClassFile();
        String accName = findAccessorName(cf);
        try {
            ConstPool cp = cf.getConstPool();
            ClassPool pool = this.clazz.getClassPool();
            String fieldType = finfo.getDescriptor();
            if (is_static) {
                accDesc = "(" + fieldType + ")V";
            } else {
                accDesc = "(" + Descriptor.m129of(this.clazz) + fieldType + ")V";
            }
            MethodInfo minfo = new MethodInfo(cp, accName, accDesc);
            minfo.setAccessFlags(8);
            minfo.addAttribute(new SyntheticAttribute(cp));
            Bytecode code = new Bytecode(cp);
            if (is_static) {
                reg = code.addLoad(0, Descriptor.toCtClass(fieldType, pool));
                code.addPutstatic(Bytecode.THIS, fieldName, fieldType);
            } else {
                code.addAload(0);
                reg = code.addLoad(1, Descriptor.toCtClass(fieldType, pool)) + 1;
                code.addPutfield(Bytecode.THIS, fieldName, fieldType);
            }
            code.addReturn(null);
            code.setMaxLocals(reg);
            minfo.setCodeAttribute(code.toCodeAttribute());
            cf.addMethod(minfo);
            this.accessors.put(key, minfo);
            return minfo;
        } catch (CannotCompileException e) {
            throw new CompileError(e);
        } catch (NotFoundException e2) {
            throw new CompileError(e2);
        }
    }

    private String findAccessorName(ClassFile cf) {
        String accName;
        do {
            StringBuilder append = new StringBuilder().append("access$");
            int i = this.uniqueNumber;
            this.uniqueNumber = i + 1;
            accName = append.append(i).toString();
        } while (cf.getMethod(accName) != null);
        return accName;
    }
}