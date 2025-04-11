package de.fraunhofer.fkie.tlskeyhunter;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import de.fraunhofer.fkie.tlskeyhunter.TKHunterJava.Pair;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/**
 * Next ToDo 
 * 
 * use the Key Methods in ASM's Trace API in order to be more accurate
 */
public final class TKHunterJava {
    private TKHunterJava() {
    }

        // Custom implementation of Pair class
        public static class Pair<K, V> {
            private final K first;
            private final V second;

            public Pair(K first, V second) {
                this.first = first;
                this.second = second;
            }

            public K getFirst() {
                return first;
            }

            public V getSecond() {
                return second;
            }
        }

    static boolean already_identified_prf = false;
    static boolean already_identified_hkdf = false;
    static boolean follow_argument_hkdf = false;
    static String hkdf_follow_usage = "";
    static String targetField = ""; // Field name to search for
    static List<Pair<String, String>> targetClassMethodPairs = new ArrayList<>();
    private static Map<String, ClassNode> analyzedClasses = new HashMap<>();

    private static void print_function_label(String label, String detailed_label, Boolean is_hkdf){
        if(is_hkdf){
            System.out.println("[*] HKDF-Function identified with label: " + label+  " ("+ detailed_label +")");
        }else{
            System.out.println("[*] PRF-Function identified with label: " + label+  " ("+ detailed_label +")");
        }
    }

    private static void  print_thx_msg(){
        System.out.println("\n[*] Thx for using TKHunterJava. Have a nice day :)");
        System.out.println();
    }

    private static String getFieldOperation(int opcode) {
        switch (opcode) {
            case Opcodes.GETSTATIC:
                return "GETSTATIC (read static field)";
            case Opcodes.PUTSTATIC:
                return "PUTSTATIC (write static field)";
            case Opcodes.GETFIELD:
                return "GETFIELD (read instance field)";
            case Opcodes.PUTFIELD:
                return "PUTFIELD (write instance field)";
            default:
                return "UNKNOWN";
        }
    }

    private static List<Byte> extractByteArrayValues(List<AbstractInsnNode> instructions) {
        List<Byte> byteArray = new ArrayList<>();
        boolean inArrayInit = false;

        for (AbstractInsnNode insn : instructions) {
            if (insn.getOpcode() == Opcodes.NEWARRAY && ((IntInsnNode) insn).operand == Opcodes.T_BYTE) {
                //System.out.println();
                inArrayInit = true; // Start of byte[] initialization
            } else if (inArrayInit && insn.getOpcode() == Opcodes.BASTORE) {
                // Handle byte array element initialization
                AbstractInsnNode prev = insn.getPrevious();
                while (prev != null && prev.getOpcode() != Opcodes.BIPUSH) {
                    prev = prev.getPrevious();
                }

                if (prev instanceof IntInsnNode) {
                    byteArray.add((byte) ((IntInsnNode) prev).operand);
                }
            }
        }

        return byteArray.isEmpty() ? null : byteArray;
    }

    private static boolean matchesTarget(List<Byte> arrayValues, byte[] target) {
        if (arrayValues.size() != target.length) return false;
        for (int i = 0; i < target.length; i++) {
            if (arrayValues.get(i) != target[i]) return false;
        }
        return true;
    }

    private static int findLocalVarIndex(AbstractInsnNode insn, InsnList instructions) {
        AbstractInsnNode next = insn.getNext();
        while (next != null) {
            if (next.getOpcode() >= Opcodes.ASTORE && next.getOpcode() <= Opcodes.ASTORE + 3) {
                return next.getOpcode() - Opcodes.ASTORE;
            } else if (next.getOpcode() == Opcodes.ASTORE) {
                return ((VarInsnNode) next).var;
            }
            next = next.getNext();
        }
        return -1;
    }

    private static List<Integer> getMethodArgumentIndices(MethodInsnNode methodInsn, InsnList instructions) {
        List<Integer> argumentIndices = new ArrayList<>();
        AbstractInsnNode current = methodInsn.getPrevious();

        int argumentCount = Type.getArgumentTypes(methodInsn.desc).length;
        while (argumentCount > 0 && current != null) {
            if (current instanceof VarInsnNode) {
                VarInsnNode varInsn = (VarInsnNode) current;
                argumentIndices.add(0, varInsn.var);
                argumentCount--;
            }
            current = current.getPrevious();
        }
        return argumentIndices;
    }


    // Track all method invocations inside a specific method
    public static void trackMethodInvocations(String className, String methodName) {
        //System.out.println("Analyzing now class "+className + " with method: "+methodName);
        ClassNode classNode = analyzedClasses.get(className);
        //System.out.println("Classnode recieved: "+classNode);
        if (classNode != null) {
            //System.out.println("Number of methods in it: "+classNode.methods);
            for (MethodNode method : classNode.methods) {
                //System.out.println("[*] Cheking for method: "+method.name);
                if (method.name.equals(methodName)) {
                    //System.out.println("Tracking invocations in method: " + methodName);
                    for (AbstractInsnNode instruction : method.instructions) {
                        //System.out.println(instruction.toString());
                        if (instruction instanceof MethodInsnNode) {
                            MethodInsnNode methodInsnNode = (MethodInsnNode) instruction;
                            int arg = 4;
                            String methodDesc = methodInsnNode.desc; // Get the descriptor (e.g. "(Ljava/lang/String;I)V")

                            //TrackArgumentVisitor argumentTracker = new TrackArgumentVisitor(4);  // 4th argument
                            //method.accept(argumentTracker);

                            if(methodDesc.contains("java/lang/String") && !TKHunterJava.already_identified_hkdf){
                                String parsed_owner = parseToJavaNamingConvention(methodInsnNode.owner);
                                String method_with_class_name =  parsed_owner + "." + methodInsnNode.name;
                                print_function_label(methodInsnNode.name, method_with_class_name, true);
                                System.out.println("[*] Target function details: "+ methodInsnNode.name+methodInsnNode.desc);
                                TKHunterJava.already_identified_hkdf = true;
                            }

                            /* 
                            // Extract the arguments from the descriptor
                            Type[] argumentTypes = Type.getArgumentTypes(methodDesc);
                            //System.out.println(argumentTypes.toString);
                            if (argumentTypes.length >= 4) {
                                
                                System.out.println("This m,ethod has more than 3 arguments: "+methodInsnNode.owner + "." + methodInsnNode.name);
                                Type fourthArg = argumentTypes[3];
                                System.out.println("Foruth: "+fourthArg.getClassName());
                                if (fourthArg.getClassName().equals("java.lang.String")) {
                                    System.out.println("Method invoked: " + methodInsnNode.owner + "." + methodInsnNode.name);
                                }
                            }*/
                            
                            
                        }
                    }
                }
            }
        }else{
            System.out.println("[-] Entry is empty: "+classNode);
        }
    }

    private static String parseToJavaNamingConvention(String name){
        return name.replaceAll("/", ".").replace(".class", "");
    }

    private static boolean isReturnTypeVoid(String descriptor){
        return descriptor.endsWith(")V");
    }

    public static void analyzeJarFile(String jarPath) throws IOException {
        // Open the JAR file
        JarFile jarFile = new JarFile(jarPath);
        jarFile.stream().filter(entry -> entry.getName().endsWith(".class")).forEach(entry -> {
            try {
                analyzeClass(jarFile, entry);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        if(!targetClassMethodPairs.isEmpty()){
            for(Pair<String, String> pair : targetClassMethodPairs){
                //System.out.println("[*] Analyzing method "+pair.getSecond() + " from class"+pair.getFirst()+ " further..");
                trackMethodInvocations(pair.getFirst(), pair.getSecond());
            }
        }

    }

    private static void analyzeClass(JarFile jarFile, JarEntry entry) {
        try (InputStream fis = jarFile.getInputStream(entry)) {
            final Map<String, String> loadedStrings = new HashMap<>();

            ClassNode classNode = new ClassNode(Opcodes.ASM9);
            

            ClassReader classReader = new ClassReader(fis);
            classReader.accept(new ClassVisitor(Opcodes.ASM9) {
                  @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor, String signature,
                        String[] exceptions) {

                        return new MethodVisitor(Opcodes.ASM9) {
                        

                            @Override
                            public void visitLdcInsn(Object value) {
                                if (value instanceof byte[]) {
                                    byte[] byteArray = (byte[]) value;
                                    byte[] target = "master secret".getBytes();
                                    if (Arrays.equals(byteArray, target)) {
                                        String className = parseToJavaNamingConvention(entry.getName());
                                        System.out.print("[*] Found string reference: '");
                                        System.out.println(value + "' in method: " + name + " of class: " + className);
                                        String strValue = (String) value;
                                        loadedStrings.put("master_secret", strValue);
                                        System.out.println("Found matching byte array in field: " + name);
                                    }

                                    byte[] LABEL_MASTER_SECRET = {109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116};

                                    if (Arrays.equals(byteArray, LABEL_MASTER_SECRET)) {
                                        String className = parseToJavaNamingConvention(entry.getName());
                                        System.out.print("[**] Found string reference: '");
                                        System.out.println(value + "' in method: " + name + " of class: " + className);
                                        String strValue = (String) value;
                                        loadedStrings.put("master_secret", strValue);
                                        System.out.println("Found matching byte array in field: " + name);
                                    }


                                }
                                if (value instanceof String) {
                                    if (value.toString().toLowerCase().equals("master secret")) {   
                                        String className = parseToJavaNamingConvention(entry.getName());
                                        if(!className.contains("META-INF")){
                                            System.out.print("[*] Found string reference: '");
                                            System.out.println(value + "' in method: " + name + " of class: " + className);
                                            String strValue = (String) value;
                                            loadedStrings.put("master_secret", strValue);
                                        }
                                    }else if (value.toString().toLowerCase().equals("s hs traffic")) {   
                                        String className = parseToJavaNamingConvention(entry.getName());
                                        if(!className.contains("META-INF")){
                                            String identifier_tls13_hkdf = "s hs traffic";
                                            System.out.println("[*] Start identifying the HKDF by looking for String \"" + identifier_tls13_hkdf+"\"");
                                            System.out.print("[*] Found string reference: '");
                                            System.out.println(value + "' in method: " + name + " of class: " + className);
                                            String strValue = (String) value;
                                            loadedStrings.put("hkdf", strValue);
                                        }
                                    }
                                }
                            }


                            @Override
                            public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                                // Check if the method is being called and if the string "master secret" is being passed as an argument
                                if (opcode == Opcodes.INVOKEVIRTUAL || opcode == Opcodes.INVOKESTATIC || opcode == Opcodes.INVOKESPECIAL) {
                                    
                                    // Get argument types from the method descriptor
                                    Type[] argumentTypes = Type.getArgumentTypes(descriptor);
                                    for (int i = 0; i < argumentTypes.length; i++) {
                                        // If argument is a String and matches "master secret"
                                        if (argumentTypes[i].getClassName().equals("java.lang.String")) {
                        
                                            // Now track the string passed to the method (if it is the one we loaded)
                                            if (loadedStrings.containsKey("master_secret") && !TKHunterJava.already_identified_prf) {
                                                String parsed_owner = parseToJavaNamingConvention(owner);
                                                String method_with_class_name =  parsed_owner + "." + name;
                                                System.out.println("[*] \"master secret\" used as " + (i + 1) + " th argument in method: "+name);
                                                print_function_label(name, method_with_class_name, false);
                                                System.out.println("[*] Target function details: "+ name+descriptor);

                                                TKHunterJava.already_identified_prf = true;
                                                System.out.println();
                                            }


                                            if (loadedStrings.containsKey("hkdf") && !TKHunterJava.already_identified_hkdf && !TKHunterJava.follow_argument_hkdf) {
                                                String parsed_owner = parseToJavaNamingConvention(owner);
                                                String method_with_class_name =  parsed_owner + "." + name;
                                                System.out.println("[*] \"s hs traffic\" used as " + (i + 1) + " th argument in method: "+name);
                                                if(isReturnTypeVoid(descriptor)){
                                                    TKHunterJava.already_identified_hkdf = false;
                                                    TKHunterJava.follow_argument_hkdf =  true;
                                                    hkdf_follow_usage = name;

                        
                                                    
                                                    targetClassMethodPairs.add(new Pair<>(owner, name));
                                                    //System.out.println("We need to trace further with: "+hkdf_follow_usage);

                                                }else{
                                                    print_function_label(name, method_with_class_name, true);
                                                    System.out.println("[*] Target function details: "+ name+descriptor);
                                                    TKHunterJava.already_identified_hkdf = true;
                                                }
                                                
                                            }

                                        
                                        }
                                    }
                                }
                            }


                
                        };
                    }
                }, 0);


            String classEntry = entry.getName().substring(0, entry.getName().length() - 6);
            
            classReader.accept(classNode, 0);
            byte[] target = {109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116}; // "master secret"

            // Find and process the <clinit> method
            for (MethodNode method : classNode.methods) {
                if ("<clinit>".equals(method.name)) {
                    //List<AbstractInsnNode> instructions = method.instructions.stream().collect(Collectors.toList());
                    List<AbstractInsnNode> instructions = new ArrayList<>();
                    for (AbstractInsnNode insn : method.instructions) {
                        instructions.add(insn);
                    }

                    List<Byte> arrayValues = extractByteArrayValues(instructions);

                    if (arrayValues != null && matchesTarget(arrayValues, target)) {
                        System.out.println("Found matching byte array in class: " + classNode.name);
                    }
                }
            }

           


            for (MethodNode method : classNode.methods) {
                for (AbstractInsnNode insn : method.instructions) {
                    if (insn.getOpcode() == Opcodes.PUTSTATIC) { // sput corresponds to PUTSTATIC
                        FieldInsnNode fieldInsn = (FieldInsnNode) insn;
                        if (fieldInsn.desc.equals("[B") && fieldInsn.name.toLowerCase().contains("master")) {
                            targetField = fieldInsn.name;
                            System.out.println("Found field: " + fieldInsn.name + " in class: " + classNode.name);
                        }
                    }
                }
            }

            
            String targetDescriptor = "[B"; // Descriptor for byte[]

            for (MethodNode method : classNode.methods) {
                for (AbstractInsnNode insn : method.instructions) {
                    if (insn instanceof FieldInsnNode) {
                        FieldInsnNode fieldInsn = (FieldInsnNode) insn;
                        if (fieldInsn.name.equals(targetField) && fieldInsn.desc.equals(targetDescriptor)) {
                            String operation = getFieldOperation(fieldInsn.getOpcode());
                            System.out.printf("Found usage of field '%s' in method '%s.%s%s' with operation '%s'%n",
                                    targetField,
                                    classNode.name.replace('/', '.'),
                                    method.name,
                                    method.desc,
                                    operation);
                        }
                        
                        if(fieldInsn.name.equals("LABEL_MASTER_SECRET")){
                            String operation = getFieldOperation(fieldInsn.getOpcode());
                            System.out.printf("*Found usage of field '%s' in method '%s.%s%s' with operation '%s'%n",
                                    targetField,
                                    classNode.name.replace('/', '.'),
                                    method.name,
                                    method.desc,
                                    operation);

                        }
                    }
                }
            }

            for (MethodNode method : classNode.methods) {
                Map<Integer, String> variableTracking = new HashMap<>();
                for (AbstractInsnNode insn : method.instructions) {
                    if (insn instanceof FieldInsnNode) {
                        FieldInsnNode fieldInsn = (FieldInsnNode) insn;
                        if (fieldInsn.name.equals(targetField) && fieldInsn.desc.equals(targetDescriptor) && fieldInsn.getOpcode() == Opcodes.GETSTATIC) {
                            int localVarIndex = findLocalVarIndex(insn, method.instructions);
                            if (localVarIndex != -1) {
                                variableTracking.put(localVarIndex, targetField);
                            }
                        }
                    } else if (insn instanceof MethodInsnNode) {
                        MethodInsnNode methodInsn = (MethodInsnNode) insn;
                        List<Integer> argumentIndices = getMethodArgumentIndices(methodInsn, method.instructions);
    
                        for (Integer index : argumentIndices) {
                            if (variableTracking.containsKey(index)) {
                                System.out.printf("Field '%s' used as an argument in method '%s.%s%s' in class '%s'%n",
                                        targetField,
                                        classNode.name.replace('/', '.'),
                                        methodInsn.name,
                                        methodInsn.desc,
                                        classNode.name.replace('/', '.'));
                            }
                        }
                    }
                }
            }




            analyzedClasses.put(classEntry, classNode);

            //System.out.println("Class analyzed: " + className);
        } catch (IOException e) {
            System.out.println("Error reading class: " + entry.getName());
            e.printStackTrace();
        }
    }

    private static final String VERSION = "0.9.3.5";
    private static final boolean DEBUG_RUN = true;

    private static void printTLSKeyHunterLogo() {
        System.out.println("");
        System.out.println("""
                        TLSKeyHunter For Java
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⢉⣉⣉⣉⡉⠛⠷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣠⣴⣿⣿⣿⣿⣿⡿⣿⣶⣌⠹⣷⡀⠀⠀⠀⠀⠀⠀⠀
         ⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣆⠉⠻⣧⠘⣷⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠈⠀⢹⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠛⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⢿⡆⠈⠛⠻⠟⠛⠉⠀⠀⠀⠀⠀⠀⣾⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⠿⣦⣄⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⣠⣾⣿⣦⠀⠀⠈⠉⠛⠓⠲⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⣄⠈⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        """);
        System.out.println("Identifying the TLS PRF and the HKDF function for extracting TLS key material using Frida.");
        System.out.println("Version: " + VERSION + " by Anonymous\n");
    }

    /**
     * Says hello to the world.
     * @param args The arguments of the program.
     */
    public static void main(String[] args) {
        printTLSKeyHunterLogo();

        if (args.length == 0) {
            System.out.println("Error: No arguments provided. Please provide the path to the target class/JAR archive.");
            return;
        }

        String inputPath = args[0];
        Path path = Paths.get(inputPath);
        String targetJAR = "";

        if (Files.exists(path)) {
            if (Files.isDirectory(path)) {
                System.err.println("[-] The provided path is a directory: " + path.toAbsolutePath()+ "\n[-] TKHunterJava is only able to analzye JAR archives and class files.");
                print_thx_msg();
                System.exit(2);
            } else if (Files.isRegularFile(path)) {
                targetJAR = path.toAbsolutePath().toString();
            } else {
                System.err.println("[-] The provided path exists but is not a file");
                print_thx_msg();
                System.exit(2);
            }
        } else {
            System.err.println("[-] Error: The provided path is not valid or does not exist.");
            print_thx_msg();
            System.exit(2);
        }


        System.out.println("[*] Analysing JAR file: " + targetJAR);
        System.out.println();
        String identifier_tls12_prf = "master secret";
        System.out.println("[*] Start identifying the PRF by looking for String \"" + identifier_tls12_prf+"\"");
        
        try {
           analyzeJarFile(targetJAR);
        } catch (Exception e) {
            e.printStackTrace();
        }
        print_thx_msg();
        
    }
}
