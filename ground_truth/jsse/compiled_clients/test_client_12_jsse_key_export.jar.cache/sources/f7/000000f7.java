package javassist.bytecode.annotation;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/annotation/MemberValueVisitor.class */
public interface MemberValueVisitor {
    void visitAnnotationMemberValue(AnnotationMemberValue annotationMemberValue);

    void visitArrayMemberValue(ArrayMemberValue arrayMemberValue);

    void visitBooleanMemberValue(BooleanMemberValue booleanMemberValue);

    void visitByteMemberValue(ByteMemberValue byteMemberValue);

    void visitCharMemberValue(CharMemberValue charMemberValue);

    void visitDoubleMemberValue(DoubleMemberValue doubleMemberValue);

    void visitEnumMemberValue(EnumMemberValue enumMemberValue);

    void visitFloatMemberValue(FloatMemberValue floatMemberValue);

    void visitIntegerMemberValue(IntegerMemberValue integerMemberValue);

    void visitLongMemberValue(LongMemberValue longMemberValue);

    void visitShortMemberValue(ShortMemberValue shortMemberValue);

    void visitStringMemberValue(StringMemberValue stringMemberValue);

    void visitClassMemberValue(ClassMemberValue classMemberValue);
}