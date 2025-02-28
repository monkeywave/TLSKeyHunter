import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

import java.util.List;
import java.util.Map;

import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.*;
import java.util.AbstractMap;
import java.util.ArrayList;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;


/*
 * invocation:
 *   cd ghidra/ghidra_11.2_PUBLIC/support
 * than:
 *   ./analyzeHeadless ~/ghidra_scripts TLSKeyHunter -import "<PATH to TLS Binary>" -overwrite -prescript MinimalAnalysisOption.java -postScript TLSKeyHunter.java

 * To-Do:
 *  - Split this into severals files and refactor the code
 *  - Add support for Rust and Java (right now we aren't able to identify there the PRF/HKDF-functions)
 *  - Check if the identified function is the same as the one used for exp master
 *    like in OpenSSL where the exp master String is directly provided to the tls13_hkdf_expand and else the derive_secret is used before
        mov     r9, [rsp+1C8h+var_180]
        lea     rcx, exporter_master_secret_5 ; "exp master"
        mov     rdx, [rsp+1C8h+var_188]
        call    tls13_hkdf_expand


    - In the cases the developer of libray decided to create on lib for the P_Hash (TLS 1.2) and the normal PRF (TLS 1.0-1.1) we will propbably find two provided prfs
    - For NSS we print both and for MatrixSSL we have to do this (here we have to retry output)
    - In GoTLS if we have a short pattern and the last instruction was a jbe (just below or equals) check than 
        -- if we find multpile references like here we should check if its are 3 --> if there take last ref and there get the last function invocation which should be call    crypto_tls_pHash
        -- than as always (In GoTLS the extends and normal master secret have different function wrappers)
    - In Future releases we can check if the identified PRF is using MD5 or SHA1 --> than it is very likely the TLS 1.0-1.1 version. Sha256/Sha384 is TLS 1.2 with P-Hash
   - The ARM64 register following does not work so good at least on ncryptsslp.dll
    - https://github.com/SySS-Research/hallucinate/blob/main/java/src/main/java/gs/sy/m8/hallucinate/Agent.java and BYteBuddy are used for hooking Java-Programs
   - The x64 version to identify the   TLSDeriveSecret is working (ubfornatly Ghidra seems not to hace access to global debug symbols?) it find the following offsets:
   [*] Function offset (Ghidra): 1800110EC (0x1800110EC) --> this is also the one for IDA so it seems that the IDA offset is here wrong
[*] Function offset (IDA with base 0x0): 17FF110EC (0x17FF110EC)


 */
public class TLSKeyHunter extends GhidraScript {


    // Custom implementation of Pair class
public class Pair<K, V> {
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


    // Global variable
    private static List<Pair<Function, Address>> globalFunctionAddressPairs = new ArrayList<>();
    private static final String VERSION = "0.9.4.0";
    private static final boolean DEBUG_RUN = true;

    private void printTLSKeyHunterLogo() {
        System.out.println("");
        System.out.println("""
                        TLSKeyHunter
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



    // Utility function to append a byte to a byte array
    private byte[] appendByte(byte[] original, byte value) {
        byte[] result = new byte[original.length + 1];
        System.arraycopy(original, 0, result, 0, original.length);
        result[original.length] = value;
        return result;
    }


    private String byteArrayToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }
    
    public Pair<Function, Address> traceDataSectionPointer(Program program, Address startAddress, int maxAttempts) {
        Listing listing = program.getListing();
        int addressSize = program.getAddressFactory().getDefaultAddressSpace().getPointerSize();
        Address refAddress = null;
    
        Address currentAddress = startAddress;
    
        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            // Check if the current address contains a pointer to a function
            Function function = listing.getFunctionAt(currentAddress);
            

            ReferenceManager referenceManager = currentProgram.getReferenceManager();
            ReferenceIterator references = referenceManager.getReferencesTo(currentAddress);

            Reference reference = references.next();
            if(reference != null){
                refAddress = reference.getFromAddress();
                Function function1 = getFunctionContaining(refAddress);
                function = function1;
            }
            




            if (function != null && refAddress != null) {
                System.out.println("[*] Found reference to function: " + function.getName() +
                                    " at target address: " + currentAddress);
                Pair<Function, Address> funcPair = new Pair<>(function,refAddress);
                return funcPair; // Found the function reference
            }
           
    
            // Move one address size backward
            currentAddress = currentAddress.subtract(addressSize);
            if (currentAddress == null) {
                System.out.println("[-] Reached invalid address while stepping back.");
                break;
            }
        }
    
        System.out.println("[*] No function reference found after " + maxAttempts + " attempts.");
        return null; // No valid function reference found
    }


    private Address searchPatterns(Memory memory, Address start, Address end, byte[][] patterns) throws Exception {
        for (byte[] pattern : patterns) {
            Address foundAddress = searchForPattern(memory, start, end, pattern);
            if (foundAddress != null) {
                System.out.println("[*] Found pattern: " + byteArrayToHex(pattern) + " at: " + foundAddress);
                return foundAddress;
            }
        }
        return null;
    }


    private Address findStringInRodata() throws Exception {
        Memory memory = currentProgram.getMemory();
        MemoryBlock rodataBlock = memory.getBlock(".rodata");
    
        if (rodataBlock == null) {
            System.err.println("[-] No .rodata section found.");
            return null;
        }
    
        Address start = rodataBlock.getStart();
        Address end = rodataBlock.getEnd();
    
        // Define the byte pattern in both big-endian and little-endian
        byte[] bigEndianPattern = {(byte) 0x63, (byte) 0x20, (byte) 0x68, (byte) 0x73,
                                    (byte) 0x20, (byte) 0x74, (byte) 0x72, (byte) 0x61,
                                    (byte) 0x66, (byte) 0x66, (byte) 0x69, (byte) 0x63};
        byte[] littleEndianPattern = new byte[bigEndianPattern.length];
        for (int i = 0; i < bigEndianPattern.length; i++) {
            littleEndianPattern[i] = bigEndianPattern[bigEndianPattern.length - 1 - i];
        }

        // Variants of the pattern
        byte[] bigEndianWithNull = appendByte(bigEndianPattern, (byte) 0x00);
        byte[] bigEndianWithSpace = appendByte(bigEndianPattern, (byte) 0x20);
        byte[] littleEndianWithNull = appendByte(littleEndianPattern, (byte) 0x00);
        byte[] littleEndianWithSpace = appendByte(littleEndianPattern, (byte) 0x20);
    
        // First, search for the big-endian pattern
        Address foundAddress = searchPatterns(memory, start, end,
            new byte[][] {bigEndianWithNull, bigEndianWithSpace, bigEndianPattern});
        if (foundAddress != null) {
            System.out.println("[*] Found big-endian pattern at: " + foundAddress);
            return foundAddress;
        }
    
        // If not found, search for the little-endian pattern
        foundAddress = searchPatterns(memory, start, end,
            new byte[][] {littleEndianWithNull, littleEndianWithSpace, littleEndianPattern});
        if (foundAddress != null) {
            System.out.println("[*] Found little-endian pattern at: " + foundAddress);
            return foundAddress;
        }
    
        System.out.println("[*] Pattern not found in .rodata section.");
        return null;
    }


    private Address searchForPattern(Memory memory, Address start, Address end, byte[] pattern) {
        Address current = start;
    
        try {
            while (current.compareTo(end) <= 0) {
                byte[] memoryBytes = new byte[pattern.length];
                memory.getBytes(current, memoryBytes);
    
                if (java.util.Arrays.equals(memoryBytes, pattern)) {
                    return current; // Pattern found
                }
    
                current = current.add(1); // Increment address by 1 byte
            }
        } catch (MemoryAccessException e) {
            println("Memory access error at: " + current);
        }
    
        return null; // Pattern not found
    }


    private List<Pair<Function, Address>> findFunctionReferences(Address dataRelRoAddress, String sectionName) {
        List<Pair<Function, Address>> functionAddressPairs = new ArrayList<>();

        ReferenceManager referenceManager = currentProgram.getReferenceManager();
        ReferenceIterator references = referenceManager.getReferencesTo(dataRelRoAddress);

        while (references.hasNext()) {
            Reference reference = references.next();
            Address refAddress = reference.getFromAddress();
            Function function = getFunctionContaining(refAddress);

            if (function != null) {
                System.out.println("[*] Found reference to "+sectionName+" at " + refAddress + " in function: " + function.getName());
                functionAddressPairs.add(new Pair<>(function, refAddress));
            }else{
                
                Memory memory = currentProgram.getMemory();
                MemoryBlock block = memory.getBlock(refAddress);
                if (block != null) {
                    String blockName = block.getName();
            
                    // Determine if the address belongs to a data section
                    if (blockName.contains(".data") || blockName.contains(".rodata")) {
                        if(DEBUG_RUN){
                            System.out.println("[!] The address is pointing to another data section:"+blockName+ " at address: "+refAddress);
                        }

                        Pair<Function, Address> dataPair = traceDataSectionPointer(currentProgram, refAddress,4);
                        if(dataPair.first != null && dataPair.second != null){
                            functionAddressPairs.add(dataPair);
                        }
                    }else {
                        System.out.println("The address is in an unknown section.");
                    }
                } else {
                    System.out.println("No memory block found for address: " + refAddress);
                }
            }

        }

        return functionAddressPairs;
    }



    /**
     * This is a workaround for the rare cases where we found that the .data.rel.ro section has a reference to the actually string in the .data section but
     * Ghidra wasn't able to identify this reference but was able to identidy the target string. This happens for instance in the s2n library for the "s hs traffic" string
     * 
     * 
     * @param stringAddress
     * @return
     */
    private Address findPointerInDataRelRo(Address stringAddress) {
        Memory memory = currentProgram.getMemory();
        MemoryBlock dataRelRo = memory.getBlock(".data.rel.ro");
    
        if (dataRelRo == null) {
            dataRelRo = memory.getBlock(".rdata");

            if(dataRelRo == null) {
                System.err.println("[-] No .data.rel.ro section found.");
                return null;
            }
        }
    
        Address start = dataRelRo.getStart();
        Address end = dataRelRo.getEnd();

        System.out.println("pointer size: "+get_pointer_size());

    
        byte[] targetBytes = new byte[get_pointer_size()]; // Assuming 64-bit architecture; adjust for 32-bit

         // Get the offset of the string address and convert it to bytes
         long addrValue = stringAddress.getOffset(); // Retrieve the raw address value

        if (currentProgram.getLanguage().isBigEndian()) {
            System.out.println("Doing big endian research...");
            // Big-endian: Address bytes as-is
            for (int i = targetBytes.length - 1; i >= 0; i--) {
                targetBytes[i] = (byte) (addrValue & 0xFF);
                addrValue >>= 8;
            }
        } else {
            System.out.println("Doing little endian research...");
            for (int i = 0; i < targetBytes.length; i++) {
                targetBytes[i] = (byte) (addrValue & 0xFF);
                addrValue >>= 8;
            }
        }
    
        while (start.compareTo(end) <= 0) {
            try {
                byte[] memoryBytes = new byte[targetBytes.length];
                memory.getBytes(start, memoryBytes);
    
                if (java.util.Arrays.equals(memoryBytes, targetBytes)) {
                    System.err.println("[*] Found reference to string address in .data.rel.ro: " + start);
                    return start; // Found the pointer in .data.rel.ro
                }
            } catch (MemoryAccessException e) {
                System.err.println("[-] Memory access error at (findPointerInDataRelRo): " + start);
            }
    
            start = start.add(targetBytes.length); // Increment by pointer size
        }
    
        println("No reference found in .data.rel.ro for address: " + stringAddress);
        return null;
    }


    /**
     * Checks if a given function contains any call to a function with "printf" in its name.
     * @param function The function to search within.
     * @return true if a call to a "printf" function is found, false otherwise.
     */
    private boolean hasPrintfCall(Function function, boolean is_indirect_call) {
        Listing listing = currentProgram.getListing();

        if(is_indirect_call){
            return true; // because we behave the same when we have an indirect call
        }

        // Iterate over all instructions within the function's body
        for (Instruction instruction : listing.getInstructions(function.getBody(), true)) {
            if (instruction.getMnemonicString().toUpperCase().equals("CALL")) {
                // Get all references from the CALL instruction
                for (Reference ref : instruction.getReferencesFrom()) {
                    if (ref.getReferenceType() == RefType.UNCONDITIONAL_CALL) {
                        // Check if the reference points to a function
                        Function calledFunction = getFunctionAt(ref.getToAddress());
                        if (calledFunction != null && functionNameContainsPrintf(calledFunction.getName())) {
                            return true;  // Found a "printf" call
                        }
                    }
                }
            }
        }
        return false; // No "printf" call found
    }

    /**
     * Checks if a function name contains "printf".
     * @param functionName The name of the function to check.
     * @return true if "printf" is in the function name, false otherwise.
     */
    private boolean functionNameContainsPrintf(String functionName) {
        return functionName.toLowerCase().contains("printf") && !functionName.toLowerCase().startsWith("pr_");
    }


    public static String toSignedHexString(long number) {
        // Get the absolute value of the number and convert to hex
        String hexValue = Long.toHexString(Math.abs(number));

        // Prepend "-" if the original number is negative
        return (number < 0 ? "-" : "") + "0x" + hexValue;
    }


    // Function to decode a 64-bit value to ASCII
    private String decodeToAscii(long value) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            char c = (char) (value & 0xFF);
            if (c < 32 || c > 126) {  // Check if character is printable
                return null;  // Not a valid ASCII string
            }
            sb.append(c);
            value >>= 8;
        }
        return sb.reverse().toString(); // Reverse due to little-endian storage
    }

    private String analyzeInstructionOperands(Instruction instruction){
        if(DEBUG_RUN){
            System.out.println("[!] (analyzeInstructionOperands) instr.getNumOperands(): "+instruction.getNumOperands());
        }
        String base_register_name = "UNKNOWN";
        String hex_offset = "0";

        // Analyze the first operand (destination) to extract RBP and offset
        if (instruction.getMnemonicString().toUpperCase().equals("MOV") && instruction.getNumOperands() > 0) {
            Object[] opObjects = instruction.getOpObjects(0);

            Register baseRegister = null;
            long offset = 0;

            for (Object opObject : opObjects) {
                if (opObject instanceof Register) {
                    baseRegister = (Register) opObject;
                    base_register_name =  baseRegister.getName();
                    if(DEBUG_RUN){
                        System.out.println("[!] Base register: " + base_register_name);
                    }
                }
                else if (opObject instanceof Scalar) {
                    offset = ((Scalar) opObject).getValue();
                    hex_offset = toSignedHexString(offset);
                    if(DEBUG_RUN){
                        System.out.println("[!] Offset: " + hex_offset);
                    }
                }
            }

            if (baseRegister != null) {
                if(DEBUG_RUN){
                    System.out.println("[!] Found base register " + base_register_name + " with offset " + hex_offset);
                }
                
            } else {
                System.err.println("[-] No base register found in the instruction.");
            }


        }

        return "["+base_register_name+" +"+hex_offset+"]";
    }


    
    
    // Function to check if the next instruction stores the value on the stack
    private boolean isStackStorage(Instruction instr) {
        //analyzeInstructionOperands(instr);
        if (instr.getNumOperands() > 0) {
            Object operand = instr.getOpObjects(0)[0];
            
            //System.out.println("[!] operand instanceof Address : "+(operand instanceof Address));
            if (operand instanceof Address) {
                Address address = (Address) operand;
                return address.isStackAddress();
            }
            if(operand instanceof Register){
                Register reg = (Register) operand;
                 //System.out.println("[!] reg.isBaseRegister(): "+reg.isBaseRegister());
                 return reg.isBaseRegister();
            }
        }
        return false;
    }


    public List<Pair<Function, Address>> FindStackStrings(boolean is_hkdf) {
        List<Pair<Function, Address>> functionAddressPairs = new ArrayList<>();
        Address referenceAddress = null;
        Listing listing = currentProgram.getListing();
        String stack_string = "s retsam";
        if(is_hkdf){
            stack_string = "art sh s";
        }


        

        // Iterate through all instructions
        for (Instruction instr : listing.getInstructions(true)) {
            // Look for "mov" instructions that load a 64-bit constant
            if (instr.getMnemonicString().toLowerCase().equals("mov") &&
                instr.getNumOperands() > 1 &&
                instr.getOperandType(1) == OperandType.SCALAR) {

                Scalar scalar = instr.getScalar(1);
                if (scalar != null && scalar.bitLength() == 64) {
                    long value = scalar.getValue();

                    // Convert the 64-bit constant to ASCII if possible
                    String asciiString = decodeToAscii(value);
                    if (asciiString != null) {

                        if(asciiString.equals(stack_string)){
                            referenceAddress = instr.getAddress();
                            Function func = getFunctionContaining(referenceAddress);
                            if (func != null) {
                                functionAddressPairs.add(new Pair<>(func, referenceAddress));
                            }
                            System.out.println("[*] Found 64-bit constant at " + instr.getAddress() +
                                " with ASCII interpretation (Little Endian): " + asciiString + " in function "+func.getName().toUpperCase());
                            if(is_hkdf){
                                System.out.println("[*] Stack-String for \"s hs traffic\" found: "+instr);
                            }else{
                                System.out.println("[*] Stack-String for \"master secret\" found: "+instr);
                            }

                            // Check if this constant is stored on the stack
                            Instruction nextInstr = instr.getNext();
                            if (nextInstr != null && nextInstr.getMnemonicString().toLowerCase().equals("mov") &&
                                isStackStorage(nextInstr)) {
                                    System.out.println("[*] Stored on stack at " + nextInstr.getAddress());
                            }
                        }

                        
                    }
                }
            }
        }
       
        return functionAddressPairs;
    }
    


    private List<Pair<Function, Address>> findStringUsageWithOffset(String substringToFind) {
        List<Pair<Function, Address>> functionAddressPairs = new ArrayList<>();
        Listing listing = currentProgram.getListing();
        DataIterator dataIterator = listing.getDefinedData(true);
    
        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            
            // Check if the data type is a string and contains the substring
            if (data.getDataType().getName().equals("string")) {
                String fullString = data.getValue().toString();
                int substringOffset = fullString.indexOf(substringToFind);
                
                if (substringOffset != -1) {
                    // Found the larger string containing the substring
                    Address baseAddress = data.getAddress();
                    Address targetAddress = baseAddress.add(substringOffset); // Calculate target address for substring
    
                    if (DEBUG_RUN) {
                        System.out.println("[!] Found larger string containing substring at: " + baseAddress);
                        System.out.println("[!] Substring target address: " + targetAddress);
                    }
    
                    // Get references to the calculated target address (substring's address within larger string)
                    Reference[] references = getReferencesTo(targetAddress);
    
                    for (Reference ref : references) {
                        Address referenceAddress = ref.getFromAddress(); // Reference address pointing to the substring's location
                        if (DEBUG_RUN) {
                            System.out.println("[!] Found reference to substring at: " + referenceAddress);
                            Instruction instruction = listing.getInstructionAt(referenceAddress);
                            System.out.println("[!] Instruction using substring: " + instruction);
                        }
                        // Find the function containing this reference
                        Function func = getFunctionContaining(referenceAddress);
                        if (func != null) {
                            functionAddressPairs.add(new Pair<>(func, referenceAddress));
                        }
                    }
                }
            }
        }
        return functionAddressPairs;
    }
    


    private List<Pair<Function, Address>> findStringUsage(String stringToFind) {
        List<Pair<Function, Address>> functionAddressPairs = new ArrayList<>();
        Address referenceAddress = null;
    
        Listing listing = currentProgram.getListing();
        DataIterator dataIterator = listing.getDefinedData(true);
    
        while (dataIterator.hasNext()) {
            Data data = dataIterator.next(); // toLowerCase ggfs. als weiter verbesserung?
            if (data.getDataType().getName().equals("string") && data.getValue().toString().equals(stringToFind)) {
                Reference[] references = getReferencesTo(data.getAddress());

                if(references.length < 1){
                    if(DEBUG_RUN){
                        System.out.println("[!] String found but has no reference: "+data.getAddress());
                    }
                    Address dataRelRoPointer = findPointerInDataRelRo(data.getAddress());
                    functionAddressPairs = findFunctionReferences(dataRelRoPointer,".data.rel.ro");
                    return functionAddressPairs;          
                                           
                }
                
                for (Reference ref : references) {
                    referenceAddress = ref.getFromAddress(); // Store the reference address
                    if(DEBUG_RUN){
                        System.out.println("[!] Found String at ref: "+referenceAddress);          
                        Instruction instruction = listing.getInstructionAt(referenceAddress);
                        System.out.println("[!] Instruction used there: "+instruction);
                    }
                    Function func = getFunctionContaining(ref.getFromAddress());
                    if (func != null) {
                        functionAddressPairs.add(new Pair<>(func, referenceAddress));
                    }
                }
            }
        }
        return functionAddressPairs;
    }


    private int getArgumentIndexForStack(PcodeOp callPcodeOp, Varnode trackedVarnode, Register resultRegister) {
        Instruction currentInstruction = currentProgram.getListing().getInstructionContaining(callPcodeOp.getSeqnum().getTarget());
        int argumentIndex = -1;
        int pushCount = 0;  // Count the number of push operations
        if(DEBUG_RUN){
            System.out.println("[!] Start identifying the argument index of the provided 32bit instruction\nBeginning with: "+currentInstruction);
        }

        // first current instruction will of course the call invocation therefore we have to start with the first instruction before that
        currentInstruction = currentInstruction.getPrevious();
        
        while (currentInstruction != null && !currentInstruction.getFlowType().isCall()) {
            if(DEBUG_RUN){
                System.out.println("[!!] argument analyzer: "+currentInstruction);
            }
            // Iterate backwards to find push instructions before the call
            if (currentInstruction.getMnemonicString().equalsIgnoreCase("PUSH")) {
                PcodeOp[] pcodeOps = currentInstruction.getPcode();
                for (PcodeOp pcodeOp : pcodeOps) {
                    Varnode input = pcodeOp.getInput(0);  // PUSH instructions usually have one input
                    if (input != null && input.equals(trackedVarnode)) {
                        argumentIndex = pushCount;  // Found the matching PUSH for the register
                    }
                }
                pushCount++;  // Increment the number of arguments pushed onto the stack
            }
    
            // Move to the previous instruction (because pushes happen before the CALL)
            currentInstruction = currentInstruction.getPrevious();
        }
    
        // If the trackedVarnode was found in a PUSH instruction, return the argument index
        if (argumentIndex != -1) {
            return argumentIndex;
        }
    
        // If not found in a PUSH instruction, return an error code (-1)
        return -1;
    }

    
    private long getLongValueAtAddress(Address address) {
        // Get the Memory object from the current program
        Memory memory = currentProgram.getMemory();
    
        // Read 8 bytes from the memory at the given address
        byte[] bytes = new byte[8];  // Long is 8 bytes
        try {
            memory.getBytes(address, bytes);
        } catch (MemoryAccessException e) {
            // Handle error if memory access fails
            System.err.println("[-] Failed to read memory at address: " + address);
            return -1; // Return an error value (you could handle this differently)
        }
    
        // Convert the bytes to a long (assuming little-endian order)
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value |= (long) (bytes[i] & 0xFF) << (i * 8);
        }
    
        return value;
    }


private Pair<Function, StringBuilder> getFunctionBytesAsStringBuilder(Function resolvedFunction, boolean is_hkdf, boolean do_we_have_two_master_sec_labels){
    Pair<Integer, Instruction> lengthPair = getLengthUntilBranch(resolvedFunction, is_hkdf, do_we_have_two_master_sec_labels, false);
    int numBytes = lengthPair.getFirst();

    Pair<Instruction, Boolean> instPair = isFunctionReturnAJumpWithInst(resolvedFunction);

    if(numBytes < 0){
        if(instPair.getSecond()){
            Reference reference = instPair.getFirst().getReferencesFrom()[0];
            Address targetAddress = reference.getToAddress();
            Function originalResolvedFunction = resolvedFunction;
            resolvedFunction = getFunctionAt(targetAddress);
            if(DEBUG_RUN){
                System.out.println("[!] The function "+originalResolvedFunction.getName()+" is a wrapper (actually jumping) function of "+resolvedFunction.getName());
            }
            lengthPair = getLengthUntilBranch(resolvedFunction, is_hkdf, do_we_have_two_master_sec_labels, false);
            numBytes = lengthPair.getFirst();
        }else{
            return null;
        }
    }

    // Now invoke readBytes on the resolved function
    Memory memory = currentProgram.getMemory();
    byte[] resolvedByteData = readBytes(memory, resolvedFunction.getEntryPoint(), numBytes);

    StringBuilder bytePattern = new StringBuilder();
    for (byte b : resolvedByteData) {
        bytePattern.append(String.format("%02X ", b & 0xFF)); // Ensure uppercase hex values
    }
    Pair<Function, StringBuilder> funcPair = new Pair<>(resolvedFunction,bytePattern);
    return funcPair;
}

private Pair<Instruction, Boolean> isFunctionReturnAJumpWithInst(Function function) {
    
    // Get the function body instructions
    InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
    
    // Initialize a flag to track if the function ends with a jump
    boolean endsWithJump = false;

    // Loop through all instructions of the function
    Instruction lastInstruction = null;
    while (instructions.hasNext()) {
        lastInstruction = instructions.next();
    }

    // Now check if the last instruction is a jump
    if (lastInstruction != null && isJumpInstruction(lastInstruction)) {
        endsWithJump = true;
    }

    Pair<Instruction, Boolean> instPair = new Pair<>(lastInstruction,endsWithJump);

    // Output the result
    if (endsWithJump) {
        if(DEBUG_RUN){
            System.out.println("[!] Function " + function.getName() + " does not return and ends with a jump.");
        }
        
        return instPair;
    } else {
        if(DEBUG_RUN){
            System.out.println("[!] Function " + function.getName() + " either returns or does not end with a jump.");
        }
        return instPair;
    }
}


private static boolean isJumpInstruction(Instruction instruction) {
    String mnemonic = instruction.getMnemonicString();
    if (mnemonic.equalsIgnoreCase("jmp") || mnemonic.equalsIgnoreCase("call")) {
        return true;
    }

    FlowType flowType = instruction.getFlowType();

    return flowType == FlowType.JUMP_TERMINATOR || flowType.isJump();
}
    

private Pair<Function, StringBuilder> resolveAndInvoke(Address targetAddress, boolean is_hkdf, boolean do_we_have_two_master_sec_labels) {
    // Check if the target address is in the GOT
    Data data = currentProgram.getListing().getDataAt(targetAddress);
    
    if (data != null && data.getDataType().getName().equalsIgnoreCase("pointer")) {
        // If it's a pointer, read the value (which is another address)
        long resolvedAddressLong = getLongValueAtAddress(targetAddress);

        // Use the AddressFactory to get an Address from a long value
        Address resolvedAddress = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(resolvedAddressLong);

        Function resolvedFunction = getFunctionAt(resolvedAddress);
                
        if (resolvedFunction != null) {
            if(DEBUG_RUN){
                System.out.println("[*] Trying to get functions bytes as StringBuilder from "+resolvedFunction.getName()+ " which is at address: "+resolvedAddress);
            }
            
            return getFunctionBytesAsStringBuilder(resolvedFunction, is_hkdf, do_we_have_two_master_sec_labels);
        }
            
        
    }else {
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();

        for (MemoryBlock block : blocks) {
            // Check if the block is the text section or similar code section
            if (block.getName().toLowerCase().contains("text")) {
                // Check if the target address is within this memory block (text section)
                if (block.contains(targetAddress)) {
                    Function resolvedFunction = getFunctionAt(targetAddress);
                    if (resolvedFunction != null) {
                        return getFunctionBytesAsStringBuilder(resolvedFunction, is_hkdf, do_we_have_two_master_sec_labels);
                    }
                }
            }
        }
    }
    return null;
}
    
public int countInstructionsInFunction(Function function) {
    // Get the Listing object to work with the instructions
    Listing listing = currentProgram.getListing();
    
    AddressSetView functionBody = function.getBody(); 
    
    // Get the first instruction at the entry point
    InstructionIterator instructions = listing.getInstructions(functionBody, true);
  
    int instructionCount = 0;
    
    // Iterate through the instructions and count them
    while (instructions.hasNext()) {
        Instruction instruction = instructions.next();   
        //System.out.println("["+instruction.getAddress()+"] "+instruction.toString());
        instructionCount++;
    }
    
    return instructionCount;
}

private boolean check_mnemonic_for_jmp(Instruction instruction){
    return instruction != null && instruction.getMnemonicString().toLowerCase().equals("jmp");
}

private Pair<Function, StringBuilder> do_reference_analysis(Instruction instruction, Function function,boolean is_hkdf, boolean do_we_have_two_master_sec_labels){
    Address targetAddress = null;

    int numInstructions = countInstructionsInFunction(function);
    if(DEBUG_RUN){
        System.out.println("[!] jmp instruction in a function with only "+numInstructions +" instructions in the function: "+instruction.toString());
        
    }

    
    Reference reference = instruction.getReferencesFrom()[0];
    targetAddress = reference.getToAddress();

    if(DEBUG_RUN){
        System.out.println("[!] Jump target (Ghidra): 0x" + targetAddress);
        System.out.println("[!] Jump target (IDA): 0x" + get_ida_address(targetAddress));

    }
    
    // Now we need to follow the jump and check if the target is in the GOT
    if(targetAddress != null){
        Pair<Function, StringBuilder> funcPair = resolveAndInvoke(targetAddress, is_hkdf, do_we_have_two_master_sec_labels);
        return funcPair;
    }


    return null;
    
}


private Pair<Function, StringBuilder> checkIfWrapperFunction(Function function,boolean is_hkdf, boolean do_we_have_two_master_sec_labels) {
    // Get the first instruction in the function    
    Address entryPoint = function.getEntryPoint();
    Listing listing = currentProgram.getListing();
    Instruction firstInstruction = listing.getInstructionAt(entryPoint);
    Instruction secondtInstruction = listing.getInstructionAt(entryPoint).getNext();
    
    Address targetAddress = null;
        
    // Check if the first or second instruction is a jump (to an address)
    if(firstInstruction == null || secondtInstruction == null){
        if(DEBUG_RUN){
            System.out.println("[!] Unable to identify first (" + firstInstruction+") or second ("+secondtInstruction+") instruction.");
        }
    }

    if(check_mnemonic_for_jmp(firstInstruction)){
        return do_reference_analysis(firstInstruction, function, is_hkdf, do_we_have_two_master_sec_labels);
    }else if(check_mnemonic_for_jmp(secondtInstruction)){
        return do_reference_analysis(secondtInstruction, function, is_hkdf, do_we_have_two_master_sec_labels);
    }else{
        return null;
    }
}

private String get_rustcall_mangled_function_name(Address targetAddress){
    SymbolTable symbolTable = currentProgram.getSymbolTable();

        for (Symbol symbol : symbolTable.getAllSymbols(false)) {
            Function function = getFunctionAt(symbol.getAddress());
            if (function != null) {
                if(targetAddress == symbol.getAddress() || function.getName().toLowerCase().contains("log_secret")){
                String mangledName = symbol.getName(); // Raw symbol name (likely mangled)

                // Only process symbols with "Rust" style mangling (_ZN...)
                if (mangledName.startsWith("_ZN")) {
                    return mangledName;
                }

                }
                
            }
        }
        return "";

}


private void print_function_label(String label, String detailed_label, Boolean is_hkdf, String signature){
    if(is_hkdf){
        System.out.println("[*] HKDF-Function identified with label: " + label+  " ("+ detailed_label +")");
        System.out.println("[*] HKDF-Function signature: "+signature);
    }else{
        System.out.println("[*] PRF-Function identified with label: " + label+  " ("+ detailed_label +")");
        System.out.println("[*] PRF-Function signature: "+signature);
    }
}


private void getPatternFunctionInfo(Function function,StringBuilder bytePattern,Boolean containsPrintfCall, Boolean is_hkdf, String argument_infos){
    String label = function.getName().toUpperCase();
    String signature = function.getSignature().toString();
    Address entryPoint = function.getEntryPoint();
    // Print the function information to the terminal
    System.out.println();

    if(function.getCallingConventionName().contains("rust")){
        System.out.println("[!] Keep in mind that hooking function using the "+function.getCallingConventionName()+" with frida is a little bit tricky...");
        String mangled_target_function_name = get_rustcall_mangled_function_name(entryPoint);
        print_function_label(label, mangled_target_function_name, is_hkdf, signature);
    }else{
        print_function_label(label, function.toString(), is_hkdf, signature);
    }   
    
    if(!containsPrintfCall){
        System.out.println(argument_infos);
    }        
    System.out.println("[*] Function offset (Ghidra): " + entryPoint.toString().toUpperCase() + " (0x" + entryPoint.toString().toUpperCase() + ")");
    System.out.println("[*] Function offset (IDA with base 0x0): " + get_ida_address(entryPoint) + " (0x" + get_ida_address(entryPoint) + ")");
    System.out.println("[*] Byte pattern for frida: " + bytePattern.toString().trim());
    System.out.println();
}
        


// Function to extract function information
private void extractFunctionInfo(Function function, Address referenceAddress, Boolean is_hkdf, String argument_infos, Address nextInstructionAddr, List<Pair<Function, Address>> list_of_string_refs) {
    Address entryPoint = null;
    boolean is_indirect_call = false;
    boolean do_we_have_two_master_sec_labels = false;
    String label = "unknown";
    String labelType = is_hkdf ? "HKDF" : "PRF";

    if(function != null){
        entryPoint = function.getEntryPoint();
        label = function.getName().toUpperCase();
    }else{
        is_indirect_call = true;
    }


    boolean containsPrintfCall = hasPrintfCall(function, is_indirect_call);
    if(DEBUG_RUN && containsPrintfCall && !is_indirect_call){
            System.out.println("[*] Function " + function.getName() + " contains 'printf' call: " + containsPrintfCall);
    }

    if(containsPrintfCall || is_indirect_call){
        Function function_using_string = currentProgram.getFunctionManager().getFunctionContaining(referenceAddress);

        if (function_using_string == null) {
            System.err.println("No function found at the current location.");
            return;
        }
        function = function_using_string;
        label = function_using_string.getName();
        entryPoint = function_using_string.getEntryPoint();
        if(is_indirect_call == false){
            System.out.println("[*] We couldn't identify the right "+labelType+" function. Using the calling function as the "+labelType+" function.");
        }else{
            System.out.println("[*] The identified "+labelType+" function is called indirectly, making it undetectable through static analysis alone.");
            System.out.println("[*] To assist, we provide the offset of the indirect call, the argument index of the label for the "+labelType+"-function being used, and byte patterns of the calling function for Frida hooking.");
        }

    }

     // Get the memory object
     Memory memory = currentProgram.getMemory();

     // Ensure the memory block is valid and readable
     if (memory.getBlock(entryPoint) == null) {
         System.err.println("[-] Memory block not found for entry point: " + entryPoint);
         return;
     }

     if(list_of_string_refs.size() == 2){
        do_we_have_two_master_sec_labels = true;
     }



    // Determine the length of bytes until the first branch
    Pair<Integer, Instruction> lengthPair = getLengthUntilBranch(function, is_hkdf, do_we_have_two_master_sec_labels, false);
    int numBytes = lengthPair.getFirst();
    Instruction lastInstruction = lengthPair.getSecond();
    //System.out.println("numBytes: "+numBytes+" | length of master secrets: "+list_of_string_refs.size()+ " |  ishkdf: "+is_hkdf+ "   | do_we_have_two_master_sec_labels: "+do_we_have_two_master_sec_labels);
    if(numBytes == -42){
        if(nextInstructionAddr != null){
            System.out.println("[<>] Phase 2.1: "+nextInstructionAddr.toString());
            analyzeSpanResult(nextInstructionAddr, is_hkdf,list_of_string_refs);
            return;
        }
        System.out.println("[<>] Phase 1: "+referenceAddress);
        analyzeSpanResult(referenceAddress, is_hkdf, list_of_string_refs);
        return;
    }else if(numBytes == -43){
        Pair<Function, Address> lastPair = list_of_string_refs.get(list_of_string_refs.size() - 1);
        Address last_ref_Address = lastPair.getSecond();
        if(nextInstructionAddr != null){
            System.out.println("[<>] Phase43 2.1: "+nextInstructionAddr.toString());
            
            analyzeSpanResult(nextInstructionAddr, is_hkdf,list_of_string_refs);
            return;
        }
        System.out.println("[<>] Phase43 1: "+last_ref_Address);
        analyzeSpanResult(last_ref_Address, is_hkdf,list_of_string_refs);
        return;
    }else if(numBytes == -44){
        Pair<Function, Address> lastPair = list_of_string_refs.get(list_of_string_refs.size() - 1);
        Address last_ref_Address = lastPair.getSecond();
        if(nextInstructionAddr != null){
            //System.out.println("[<>] Phase44 2.1: "+nextInstructionAddr.toString());
            analyzeSpanResult(nextInstructionAddr, is_hkdf,list_of_string_refs);
            return;
        }
        //System.out.println("[<>] Phase44 1: "+last_ref_Address);
        analyzeSpanResult(last_ref_Address, is_hkdf,list_of_string_refs);
        return;
    }else if(numBytes == -66){
        Pair<Function, Address> lastElement = list_of_string_refs.get(list_of_string_refs.size() - 1);

        Function function_which_has_reference = lastElement.getFirst();
        Address stringReferenceAddress = lastElement.getSecond();

        // Remove the last element from the list
        list_of_string_refs.remove(list_of_string_refs.size() - 1);

        do_analysis(function_which_has_reference,  stringReferenceAddress,false, true, list_of_string_refs);
        return;
    }

    // Use the custom readBytes function to read the dynamically determined length of bytes
    byte[] byteData = readBytes(memory, entryPoint, numBytes);

    

    // Convert the byte array into a formatted string of hex values
    StringBuilder bytePattern = new StringBuilder();
    for (byte b : byteData) {
        bytePattern.append(String.format("%02X ", b & 0xFF)); // Ensure uppercase hex values
    }
    Pair<Function, StringBuilder> funcPair = null;
    
    if(byteData.length <= 12){
        System.out.println("[*] LAst Instruction: "+lastInstruction.toString() + " last mnemomic: "+lastInstruction.getMnemonicString());
        if(lastInstruction.getMnemonicString().toLowerCase().contains("jbe")){
            System.out.println("[*] Probably a GO function. We have to extend the the length");
            
            lengthPair = getLengthUntilBranch(function, is_hkdf, do_we_have_two_master_sec_labels, true);
            numBytes = lengthPair.getFirst();

            byte[] resolvedByteData = readBytes(memory, entryPoint, numBytes);

            StringBuilder newBytePattern = new StringBuilder();
            for (byte b : resolvedByteData) {
                newBytePattern.append(String.format("%02X ", b & 0xFF)); // Ensure uppercase hex values
            }
            bytePattern = newBytePattern;

        }else{
            System.out.println("[*] Very short pattern detected ("+byteData.length+"). Trying to check if identified function is just a wrapper function...");
            funcPair = checkIfWrapperFunction(function, is_hkdf, do_we_have_two_master_sec_labels);
        }
    }

    if(is_indirect_call == true){
        // Get the listing from the current program
        Listing listing = currentProgram.getListing();
        // Retrieve the instruction at the given address
        Instruction instruction = listing.getInstructionAt(nextInstructionAddr);
        System.out.println("\n[*] "+labelType+"-Function identified as indirect call: "+instruction.toString());
        System.out.println("[*] Function offset (Ghidra): " + nextInstructionAddr.toString().toUpperCase() + " (0x" + nextInstructionAddr.toString().toUpperCase() + ")");
        System.out.println("[*] Function offset (IDA with base 0x0): " + get_ida_address(nextInstructionAddr) + " (0x" + get_ida_address(nextInstructionAddr) + ")");
    }

    // Print the function information to the terminal
    System.out.println();
    getPatternFunctionInfo(function, bytePattern, containsPrintfCall, is_hkdf, argument_infos);

    if(funcPair != null && funcPair.getFirst() != null){
        System.out.println("[*] The identified function is a wrapper for dynamic linking in the .got.plt section. The actual target function is:");
        getPatternFunctionInfo(funcPair.getFirst(), funcPair.getSecond(), containsPrintfCall, is_hkdf, argument_infos);
    }
    /* 

    if(is_hkdf){
        System.out.println("[*] HKDF-Function identified with label: " + label);
    }else{
        System.out.println("[*] PRF-Function identified with label: " + label);
    }
    
    if(!containsPrintfCall){
        System.out.println(argument_infos);
    }        
    System.out.println("[*] Function offset (Ghidra): " + entryPoint.toString().toUpperCase() + " (0x" + entryPoint.toString().toUpperCase() + ")");
    System.out.println("[*] Function offset (IDA with base 0x0): " + get_ida_address(entryPoint) + " (0x" + get_ida_address(entryPoint) + ")");
    System.out.println("[*] Byte pattern for frida: " + bytePattern.toString().trim());
    */
    System.out.println();
}

// Helper function to read bytes from memory
private byte[] readBytes(Memory memory, Address address, int numBytes) {
    byte[] byteData = new byte[numBytes];
    try {
        memory.getBytes(address, byteData);
    } catch (MemoryAccessException e) {
        System.err.println("[-] Error reading bytes from memory at " + address + ": " + e.getMessage());
    }
    return byteData;
}

private Address findReferenceToStringAtAddress(Address referenceAddr) {
    System.out.println("[*] Analyzing reference at address: " + referenceAddr);
    Listing listing = currentProgram.getListing();
    Instruction instruction = listing.getInstructionAt(referenceAddr);

    if (instruction == null) {
        System.err.println("[-] No instruction found at reference address: " + referenceAddr);
        return null;
    }

    // Look for the function containing this reference
    Function containingFunction = getFunctionContaining(referenceAddr);
    if (containingFunction != null) {
        while (instruction != null && !instruction.getFlowType().isCall()) {
            instruction = instruction.getNext();
        }

        if (instruction != null && instruction.getFlowType().isCall()) {
            Address[] flowRefs = instruction.getFlows(); // Get the flow references for function calls
            if (flowRefs.length > 0) {
                return flowRefs[0]; // Return the first flow reference as the called function address
            }
        }
    }

    System.err.println("[-] No function call found near the string reference.");
    return null;
}



// Helper method to extract the called function from an instruction
private Function getCalledFunction(Instruction instruction) {
    FlowType flowType = instruction.getFlowType();
    if (flowType.isCall()) {
        Address[] flows = instruction.getFlows();
        if (flows != null && flows.length > 0) {
            return getFunctionAt(flows[0]);
        }
    }
    return null;
}

// Helper function to check if the PCode operation is moving data between registers
private boolean isRegisterMove(PcodeOp pcodeOp, Register sourceRegister) {
    int opcode = pcodeOp.getOpcode();

    // Check if the operation is a COPY/MOVE and involves the source register
    if ((opcode == PcodeOp.COPY) &&
        pcodeOp.getInput(0).isRegister() &&
        getRegisterForVarnode(pcodeOp.getInput(0)).equals(sourceRegister)) {
        return true;
    }
    // getRegisterForVarnode(pcodeOp.getInput(0))

    return false;
}


private Varnode traceFunctionResult(Instruction functionCallInstruction) {
    Instruction currentInstruction = functionCallInstruction.getNext();
    Varnode output,result_Varnode = null;

    // Determine the return register based on architecture
    Register resultRegister = getReturnRegister();
    
    if (resultRegister == null) {
        println("[-] Unable to determine the return register for the current architecture.");
        return null;
    }

    System.out.println("[*] Initial result expected in register: " + resultRegister.getName());
    System.out.println("[*] Start identifying final register ...");
    // Trace through subsequent instructions to see if the result is moved to another register
    while (currentInstruction != null) {
        PcodeOp[] pcodeOps = currentInstruction.getPcode();

        for (PcodeOp pcodeOp : pcodeOps) {
            output = pcodeOp.getOutput();

            if (output != null && output.isRegister()) {
                Register targetRegister = getRegisterForVarnode(output);
                
                // Check if the result register is being moved to another register
                if (isRegisterMove(pcodeOp, resultRegister)) {
                    resultRegister = targetRegister;
                    result_Varnode = output;
                    if(DEBUG_RUN){
                        System.out.println("[*] Result moved to register: " + targetRegister.getName());
                    }
                    return result_Varnode;
                }
            }
        }

        // Move to the next instruction
        currentInstruction = currentInstruction.getNext();
    }

    return result_Varnode;  // Return the final register holding the result
}


// Function to get the Register associated with a Varnode (if it's a register)
private Register getRegisterForVarnode(Varnode varnode) {
    if(varnode == null){
        return null;
    }

    if (varnode.isRegister()) {
        // Use Ghidra's register lookup to find the register based on the Varnode
        return currentProgram.getRegister(varnode.getAddress());
    }
    return null;
}

private int get_pointer_size(){
    int pointer_size = 0x4;
    String languageID = currentProgram.getLanguageID().toString();
    if(languageID.contains("64")){
        pointer_size = 0x8;
    }

    return pointer_size;
}

/**
 * Get the index of the argument based on the stack offset.
 * This is based on the x86 calling convention where arguments are pushed to the stack.
 *
 * @param stackOffset The offset from the base of the stack (ESP) where the value is stored.
 * @return The argument index (0-based), or -1 if the offset does not correspond to a valid argument.
 */
private int getStackArgumentIndexFromOffset(long stackOffset, boolean is_arm32) {
    // In the x86 calling convention:
    // ESP + 0x0 = Return Address
    // ESP + 0x4 = First argument
    // ESP + 0x8 = Second argument
    // ESP + 0xC = Third argument
    // And so on...
    int pointer_size = get_pointer_size();
    


    // We subtract the offset where the first argument starts (0x4)
    long argumentOffset = stackOffset - pointer_size;

    // Each argument is 4 bytes wide on 32bit systems, so divide by 4 to get the argument index
    int argumentIndex = (int)(argumentOffset / pointer_size);

    // If the argument index is negative, it means the offset is invalid for argument passing
    if (argumentIndex < 0) {
        return -1;
    }

    if(is_arm32){
        argumentIndex = argumentIndex + 4;
    }

    return argumentIndex;
}




private long get_Register_Offset(PcodeOp addrOp){
    long totalOffset = 0; // Variable to hold the cumulative offset
    if (addrOp.getOpcode() == PcodeOp.PTRADD || addrOp.getOpcode() == PcodeOp.INT_ADD) {
        // Iterate over all inputs
        
        boolean foundESP = false; // Flag to check if ESP is found
    
        for (int j = 0; j < addrOp.getNumInputs(); j++) {
            Varnode input = addrOp.getInput(j);
            if (input.isRegister()) {
                // Check if the register is ESP (x86) or SP (ARMv7)
                Register reg = getRegisterForVarnode(input);
                if (reg != null && reg.getName().endsWith("SP")) {
                    foundESP = true; // Set flag if ESP/SP is found
                }
                //System.out.println("[*] Register: " + reg.getName());
            } else {
                // Assume it's an offset if it's not a register
                long offset = input.getOffset();
                totalOffset += offset; // Accumulate the offset
                //System.out.println("[*] Offset: 0x" + Long.toHexString(offset));
            }
        }
    
        if (foundESP) {
            if(DEBUG_RUN){
                System.out.println("[*] Writing to stack offset: 0x" + Long.toHexString(totalOffset));
            }
            
            return totalOffset;
        }
    }
    return totalOffset;
}

// Helper function to get the first argument register for a given calling convention
private String getFirstArgRegister() {
    String languageID = currentProgram.getLanguageID().toString();

    if (languageID.contains("ARM:LE:32")) {
        return "R0";
    }else if (languageID.contains("MIPS:LE")) {
        return "A0";
    }else if(languageID.contains("ARM:LE:64") || languageID.contains("AARCH64")){
        return "X0";
    }


    // Get calling convention
    String callingConvention = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();

    if (callingConvention.equalsIgnoreCase("stdcall") || callingConvention.equalsIgnoreCase("cdecl")) {
        // x86: First argument is pushed on the stack, not a register
        return null;
    } else if (callingConvention.equalsIgnoreCase("x64")) {
        // x86-64: First argument is typically in RDI
        return "RDI";
    } else if (callingConvention.equalsIgnoreCase("fastcall")) {
        // x86 fastcall: First argument is in ECX
        return "ECX";
    }else if (callingConvention.equalsIgnoreCase("__stdcall")){
        if(languageID.contains("64")){
            return "RDI";
        }
        return null;

    }else {
        System.out.println("Unsupported calling convention: " + callingConvention);
        return null;
    }
}

private boolean is_move_to_first_arg(Instruction instruction){
    System.out.println("getting first arg");
    String first_arg_register_as_String = getFirstArgRegister();
    String move_check = "MOV "+first_arg_register_as_String;
    if(instruction.toString().toUpperCase().startsWith(move_check)){
        return true;
    }

    return false;
}


private boolean is_current_instruction_moving_the_length_of_master_secret(Instruction instruction){
    if (instruction.getMnemonicString().toLowerCase().startsWith("mov")) {
        // Check if 0xD is being moved
        Object[] operands = instruction.getOpObjects(1); // Source operand (index 1)
        if (operands.length > 0 && operands[0] instanceof Scalar) {
            Scalar scalar = (Scalar) operands[0];
            if (scalar.getValue() == 0xD) {
                System.out.println("Found mov 0xD at: " + instruction.getAddress());
                return true;
                
                /* 
                // Track the destination register (index 0)
                Register destRegister = instruction.getRegister(0);
                if (destRegister != null) {
                    println("Tracking register: " + destRegister);
                    trackedRegister = destRegister;
                }
                */
            }
        }
    }
    return false;

}


private Pair<Address, Function> getCallTarget(Instruction instruction) {
    if (instruction == null) {
        return null; 
    }
    // We assume that this function is only invoked when we have a call instruction
    System.out.println("[*] Trying to find target address for instruction: "+instruction.toString());

    Object[] operands = instruction.getOpObjects(0); // Get the first operand
    for (Object operand : operands) {
        if (operand instanceof Address) {
            Address targetAddress = (Address) operand;

            // Check if there is a function at the target address
            Function targetFunction = getFunctionAt(targetAddress);

            // Return a Pair of the address and the function (can be null if no function exists)
            return new Pair<>(targetAddress, targetFunction);
        }
    }

    if(instruction.getReferencesFrom().length > 0){
        // this needs to be improved in later releases so that each aoccous needs to be considered..
        System.out.println("Actually we found more: "+instruction.getReferencesFrom().length);
        int last_ref = instruction.getReferencesFrom().length -1;
        Reference ref = instruction.getReferencesFrom()[last_ref]; // we assume that the first reference is the one we are looking for and it is better than nothing
        Address targetAddress = ref.getToAddress();
        
        // Check if there is a function at the target address
        Function targetFunction = getFunctionAt(targetAddress);

        // Return a Pair of the address and the function (can be null if no function exists)
        return new Pair<>(targetAddress, targetFunction);
    }



    return null; // No address found
}



private Map.Entry<Address, String> trackFunctionUsingRegister(Instruction startInstruction, Varnode trackedVarnode, Boolean is_hkdf, long offset) {
    Instruction currentInstruction = startInstruction.getNext();  // Move to the next instruction
    Function function = currentProgram.getFunctionManager().getFunctionContaining(startInstruction.getAddress());
    Address functionEnd = function.getBody().getMaxAddress();
    Varnode oldtrackedVarnode = trackedVarnode;


    Register resultRegister = getRegisterForVarnode(trackedVarnode);
    Address nextCallAddr = null;
    String languageID = currentProgram.getLanguageID().toString();
    String architecture_String = languageID.toString().toUpperCase();
    boolean isARM32 = architecture_String.contains("ARM:LE:32");
    boolean isARM = (architecture_String.contains("ARM") || architecture_String.contains("AARCH64"));
    boolean isARM64 = ((architecture_String.contains("ARM") || architecture_String.contains("AARCH64")) && architecture_String.contains("64"));
    boolean isX86 = architecture_String.toUpperCase().contains("X86:LE:32");
    boolean isX64 = architecture_String.toUpperCase().contains("X86:LE:64");
    String track_register_var = "untracked";
    boolean previous_pcode_was_copy = false;
    boolean previous_pcode_was_load = false;
    boolean previous_pcode_was_intadd = false;
    boolean track_register_stored_in_mem = false;
    boolean can_we_use_next_call = true;
    boolean do_rerun = false;
    boolean is_target_string_processed = false;
    boolean is_master_sec_length_provided = false;
    String registerName = "Unknown";
    long stack_offset = 0;
    Register baseRegister = null;
    Register oldRegister = null;

    // Track stack offsets (only relevant for x86)
    long stackOffset = offset;

    
    while (currentInstruction != null && currentInstruction.getAddress().compareTo(functionEnd) <= 0) {
        previous_pcode_was_copy = false; // ensure that it has only the scope for the current analyzed instruction
        previous_pcode_was_load = false;
        previous_pcode_was_intadd = false;

        if(DEBUG_RUN){
            //System.out.println("Analyzing instruction: " + currentInstruction);
        }


        PcodeOp[] pcodeOps = currentInstruction.getPcode();
        for (PcodeOp pcodeOp : pcodeOps) {

            if (isARM && (pcodeOp.getOpcode() == PcodeOp.BRANCH || pcodeOp.getOpcode() == PcodeOp.BRANCHIND)) {
                if(DEBUG_RUN){
                    System.out.println("Found a B instruction (unconditional branch) at: " + currentInstruction.getAddress());
                }
                
                // Get the target address from the branch instruction
                Varnode targetVarnode = pcodeOp.getInput(0); // Assuming the first input is the target address
                if (targetVarnode != null) {
                    // Resolve the target address
                    Address targetAddress = targetVarnode.getAddress();
                    Listing listing = currentProgram.getListing();

                    // Move to the target instruction
                    currentInstruction = listing.getInstructionAt(targetAddress);
                    if (currentInstruction == null) {
                        System.err.println("[-] No instruction found at target address: " + targetAddress);
                    } else {
                        if (DEBUG_RUN) {
                            System.out.println("[*] Jumping to instruction at target address: " + targetAddress);
                        }
                    }
                    continue; // Skip the rest of the loop and process the target instruction
                }
            }

            // Look for instructions where the tracked register is used
            for (int i = 0; i < pcodeOp.getNumInputs(); i++) {
                Varnode input = pcodeOp.getInput(i);
                
                /*if(currentInstruction.toString().toUpperCase().contains("R14") || currentInstruction.toString().toUpperCase().contains("CALL")){
                    System.out.println("DEBUG: pcodeOp.getOpcode()="+pcodeOp.getMnemonic()+"  can_we_use_next_call: "+can_we_use_next_call+"  do_rerun="+do_rerun);
                    System.out.println("[*] trackedVarnode: "+trackedVarnode);
                    System.out.println("[*] resultRegister: "+resultRegister.getName());
                    System.out.println("pcodeOp: "+pcodeOp);
                    System.out.println("Output: "+pcodeOp.getOutput());
                    for (Varnode tmpInVarnode : pcodeOp.getInputs()) {
                        System.out.print("INPUT: "+tmpInVarnode+" ;  ");
                    }
                    System.out.println(); 

                }*/
                
                if (input.equals(trackedVarnode) || pcodeOp.getOpcode() == PcodeOp.CALL || pcodeOp.getOpcode() == PcodeOp.CALLIND) { 
                    
                    if (pcodeOp.getOpcode() == PcodeOp.COPY && input.equals(trackedVarnode) && !currentInstruction.toString().toLowerCase().startsWith("push")){
                        for (int j = 0; j < pcodeOps.length; j++) {
                            PcodeOp addrOp = pcodeOps[j];
                            
                            stackOffset = get_Register_Offset(addrOp);
                            
                            if(stackOffset > 0){
                                break;
                            }
                        }
                        

                       

                    }

                    //System.out.println("INNER DEBUG: pcodeOp.getOpcode()="+pcodeOp.getOpcode()+"  can_we_use_next_call: "+can_we_use_next_call+"  do_rerun="+do_rerun);
                    
                    
                    // If it's a function call, identify which argument the register is used as
                    if ((pcodeOp.getOpcode() == PcodeOp.CALL || pcodeOp.getOpcode() == PcodeOp.CALLIND) && (can_we_use_next_call || do_rerun)) {
                        boolean provide_infos_about_old_register =  oldRegister != null;
                        int argumentIndex;
                        int oldRegisterIndex = -1;
                        
                        // Check the architecture type to determine argument location
                        if (isARM32) {
                            // ARM uses registers for argument passing
                            argumentIndex = getArgumentIndexForRegister(pcodeOp, trackedVarnode, resultRegister, stackOffset);
                            if(provide_infos_about_old_register){
                                oldRegisterIndex = getArgumentIndexForRegister(pcodeOp, oldtrackedVarnode, oldRegister, stackOffset);
                            }
                        } else if (isX86) {
                            // x86 uses the stack for argument passing
                            if (stackOffset != -1) {
                                // If we tracked a stack offset, identify the argument from it
                                argumentIndex = getStackArgumentIndexFromOffset(stackOffset, false);
                               /* / if(provide_infos_about_old_register){
                                    oldRegisterIndex = getStackArgumentIndexFromOffset(stackOffset, false);
                                }*/
                            } else {
                                argumentIndex = getArgumentIndexForStack(pcodeOp, trackedVarnode, resultRegister);
                                if(provide_infos_about_old_register){
                                    oldRegisterIndex = getArgumentIndexForStack(pcodeOp, oldtrackedVarnode, oldRegister);
                                }
                            }
                        } else {
                            // MIPS, x86-64 and ARM64 default
                            argumentIndex = getArgumentIndexForRegister(pcodeOp, trackedVarnode, resultRegister, stackOffset);
                            if(provide_infos_about_old_register){
                                oldRegisterIndex = getArgumentIndexForRegister(pcodeOp, oldtrackedVarnode, oldRegister, stackOffset);
                            }
                        }


                        Function nextCalledFunction = null;
                        String label = "";
                        if(pcodeOp.getOpcode() == PcodeOp.CALLIND){
                            
                            Pair<Address, Function> result = getCallTarget(currentInstruction);
                            if (result != null) {
                                Address targetAddress = result.first;
                                Function targetFunction = result.second;

                                System.out.println("[*] Call target address: " + targetAddress);

                                if (targetFunction != null) {
                                    System.out.println("[*] Function name: " + targetFunction.getName());
                                } else {
                                    System.err.println("[-] No function defined at the target address. Defaulting to offset-method...");
                                    label = "indirect function: "+currentInstruction.toString();
                                    // because we can only identify the actually function beeing at runtime we need this call as the nextCallAddr
                                    nextCallAddr = currentInstruction.getAddress();
                                }

                                label = targetFunction.getName().toUpperCase();
                                nextCallAddr = targetAddress; 

                            } else {
                                System.err.println("[-] No target address found for CALL instruction. Defaulting to offset-method...");
                                label = "indirect function: "+currentInstruction.toString();
                                // because we can only identify the actually function beeing at runtime we need this call as the nextCallAddr
                                nextCallAddr = currentInstruction.getAddress();
                            }
                            
                            

                        }else{
                            nextCallAddr = findFunctionCallUsingResult(currentInstruction.getAddress());
                            nextCalledFunction = getFunctionAt(nextCallAddr);
                            label = nextCalledFunction.getName().toUpperCase();
                        }

                        
                        
                        
                        String result_register_name = resultRegister.toString().toUpperCase();
                        String argument_infos = "[*] String (Register "+result_register_name+") used as " + (argumentIndex);
                        if(isARM64){
                            argument_infos = "[*] String (Register "+result_register_name+") used as " + (argumentIndex+1);
                        }
                        
                        if(stackOffset != -1 && isX86){
                            result_register_name = "ESP";
                            argument_infos = "[*] String (Stack location ["+result_register_name+" + 0x"+Long.toHexString(stackOffset)+"]) used as " + (argumentIndex);
                        }
                        if(stackOffset != -1 && isARM32){
                            result_register_name = "SP";
                            argument_infos = "[*] String (Stack location ["+result_register_name+" + 0x"+Long.toHexString(stackOffset)+"]) used as " + (argumentIndex+1);
                        }

                        
                        String argumentInfos = argument_infos + "th argument in function call at address: 0x" + currentInstruction.getAddress() +" (invoking "+label+")";
                        if(provide_infos_about_old_register){
                            argumentInfos = argumentInfos + "\n[*] We tracked also a copy operation of the previous register: "+oldRegister.toString().toUpperCase()+" used as " + (oldRegisterIndex)+ "th argument";
                        }
                        Map.Entry<Address, String> addressStringMap = new AbstractMap.SimpleEntry<>(nextCallAddr, argumentInfos);

                        if(DEBUG_RUN){
                            System.out.println(argumentInfos);
                            if(is_hkdf){
                                System.out.println("[*] HKDF function identified: "+label);
                            }else{
                                System.out.println("[*] PRF function identified: "+label);
                            }

                        }
                       
                        return addressStringMap;
                    }
                }
            }

            // here we set the memory location so that we can use it later
            if(pcodeOp.getOpcode() == PcodeOp.INT_ADD){
                previous_pcode_was_intadd = true;
                Varnode base = pcodeOp.getInput(0);   // Base register
                Varnode constant = pcodeOp.getInput(1); // Offset

                if (base.isRegister()) {
                    baseRegister = getRegisterForVarnode(base);
                    registerName = baseRegister.getName();
                }
                if (constant.isConstant()) {
                    stack_offset = constant.getOffset();
                }
            }

            // Check if the tracked register is copied/moved to another register or used to store it later
            if (pcodeOp.getOpcode() == PcodeOp.COPY) {
                Varnode output = pcodeOp.getOutput();
                if (output != null && output.isRegister()) {

                    Register targetRegister = getRegisterForVarnode(output);
                    if(is_target_string_processed){
                        is_master_sec_length_provided = is_current_instruction_moving_the_length_of_master_secret(currentInstruction);
                        is_target_string_processed = false;
                    }else if (isRegisterMove(pcodeOp, resultRegister) && track_register_stored_in_mem == false) {


                        if (targetRegister != null) {
                            oldRegister = resultRegister;
                            oldtrackedVarnode = trackedVarnode;
                            resultRegister = targetRegister;
                            System.out.println("[*] Tracked register copied to new register: " + targetRegister.getName());
                        }
                        trackedVarnode = output;  // Now track this new register
                        can_we_use_next_call = true;
                    }else if(is_master_sec_length_provided){
                        if(is_move_to_first_arg(currentInstruction)){
                            for (Varnode input : pcodeOp.getInputs()) {
                            
                                if (input.isRegister()){
                                    targetRegister = getRegisterForVarnode(input);
                                    if (targetRegister != null) {
                                        resultRegister = targetRegister;
                                        System.out.println("[*] The next function call will process our target string. Target register is now: " + targetRegister.getName());
                                    }

                                    trackedVarnode = input;
                                    is_master_sec_length_provided = false;
                                    track_register_stored_in_mem = false;
                                    previous_pcode_was_load = false;
                                    previous_pcode_was_intadd = false;

                                    continue;
                                }
                            }
                        }
                        
                    }else if(previous_pcode_was_load) {
                        previous_pcode_was_load = false;
                        can_we_use_next_call = true;
                        track_register_stored_in_mem = false;
                        track_register_var = "untracked";
                        if (targetRegister != null) {
                            resultRegister = targetRegister;
                            System.out.println("[*] Tracked memory location copied to register: " + targetRegister.getName());
                        }
                        trackedVarnode = output;  // Now track this new register
                    }
                }

                /*
                 * When reading or writing to memory we have usually the following pattern:
                 * COPY than STORE or
                 * LOAD than COPY
                 */ 
                if(previous_pcode_was_intadd){
                    // track_register_var = "["+registerName +" + "+toSignedHexString(stack_offset)+"]";
                    String tmp_mem_location =  "["+registerName +" + "+toSignedHexString(stack_offset)+"]";

                    for (Varnode input : pcodeOp.getInputs()) {
                        
                        if (input.equals(trackedVarnode) && (track_register_var.equals("untracked") || track_register_var.equals(tmp_mem_location))){
                            previous_pcode_was_copy = true; // untracked
                            previous_pcode_was_intadd = false;
                            continue;
                        }
                    }
                }


            }

            if(pcodeOp.getOpcode() == PcodeOp.LOAD && previous_pcode_was_intadd){
                String tmp_mem_location =  "["+registerName +" + "+toSignedHexString(stack_offset)+"]";

                for (Varnode input : pcodeOp.getInputs()) {
                    if (input.equals(trackedVarnode) && (track_register_var.equals("untracked") || track_register_var.equals(tmp_mem_location))){
                        System.out.println("[!] Load operation with the tracked varnode: "+currentInstruction);
                        previous_pcode_was_load = true;
                        previous_pcode_was_intadd = false;
                        continue;
                    }
                }
            }

            if(pcodeOp.getOpcode() == PcodeOp.STORE && pcodeOp.getOpcode() != PcodeOp.CALL && !currentInstruction.toString().toUpperCase().startsWith("CALL")){

                Varnode destAddress = pcodeOp.getInput(1);  // Memory address being written to ([RBP - 0x58])




                // Check if there was a copy operation which got the tracked varnode as input
                if (previous_pcode_was_copy) {
                    System.out.println("[!] Store operation with the tracked varnode: "+currentInstruction);
                    
                    //track_register_var = analyzeInstructionOperands(currentInstruction); //old way might not work with the load part --> have to check that
                    track_register_var = "["+registerName +" + "+toSignedHexString(stack_offset)+"]";

                    oldRegister = getRegisterForVarnode(trackedVarnode);

                    if(DEBUG_RUN){
                        System.out.println("[*] Tracked value ("+oldRegister.getName()+") safed at: " + track_register_var);
                        System.out.println("[*] Tracked value ("+oldRegister.getName()+") stored at address consisting of Register: "
                            + registerName + " and its offset: " + toSignedHexString(stack_offset));
                    }

                    trackedVarnode = destAddress; // Register baseRegister, long offset

                    previous_pcode_was_copy = false;
                    if(isX86 == false){ // on x86 the mem location is used for argument passing
                        can_we_use_next_call = false;
                    }
                    track_register_stored_in_mem = true;

                    if(registerName.equals("Unknown") && stack_offset == 0x0){
                        System.out.println("[-] Error in tracing the memory location ...");
                        // This typically happens when the string is somehow processed, therefore we have to take the first function invocation and its return value as the next 
                        // starting point for our analysis 
                        is_target_string_processed = true;
                        can_we_use_next_call = false;
                        track_register_stored_in_mem = false;
                    }
                }
            }





        }

        // Move to the next instruction
        if(isARM){
            // Move to the next instruction if not a branch
            if (!(pcodeOps.length > 0 && (pcodeOps[0].getOpcode() == PcodeOp.BRANCH || pcodeOps[0].getOpcode() == PcodeOp.BRANCHIND))) {
                currentInstruction = currentInstruction.getNext();
            }
        }else{
            currentInstruction = currentInstruction.getNext();
        }

         
        if (currentInstruction != null && currentInstruction.getAddress().compareTo(functionEnd) > 0) {
            if(do_rerun){
                System.out.println("[-] Error! A second rerun shouldn't happen...");
                System.exit(2);
            }
            System.out.println("[*] Next instruction is outside the function scope. Stopping analysis.");

            // Rerun the analysis (reset to the start of the function)
            System.out.println("[*] Rerunning analysis for function: " + function.getName());
            currentInstruction = startInstruction.getNext();
            /*
             * actually this has to do with the memory tracking in rare case right now when a string is copied as a stack string to vector object 
             * and than access through this. Right now we are not able to track this (for instance in BotanSSL for the PRF).
             * This means were are not tracking the memory location any more 
             */ 
            do_rerun = true;
            can_we_use_next_call = true;  
        }
        
    }
    Map.Entry<Address, String> addressStringMap = new AbstractMap.SimpleEntry<>(nextCallAddr, null);
    return addressStringMap;
}


// Determine the appropriate return register based on architecture
private Register getReturnRegister() {
    String languageID = currentProgram.getLanguageID().toString();

    if(DEBUG_RUN){
        System.out.println("[!] Program ABI: "+languageID);
    }

    if (languageID.contains("ARM:LE:64") || languageID.contains("AARCH64")) {
        return currentProgram.getRegister("X0");
    } else if (languageID.contains("x86:LE:64")) {
        return currentProgram.getRegister("RAX");
    } else if (languageID.contains("x86:LE:32")) {
        return currentProgram.getRegister("EAX"); // x86 32-bit
    } else if (languageID.contains("MIPS:LE")) {
        return currentProgram.getRegister("V0"); // MIPS uses V0 for return
    } else if (languageID.contains("ARM:LE:32")) {
        return currentProgram.getRegister("R0"); // ARM 32-bit (ARMv7)
    }

    return null;  // Unknown architecture
}

private int getArgumentIndexForRegister(PcodeOp pcodeOp, Varnode trackedVarnode, Register resultRegister, long stackOffset) {
    //Language language = currentProgram.getLanguage();
    String languageID = currentProgram.getLanguageID().toString();

    // Handle ARM64 calling convention (first 8 arguments are in X0-X7)
    if (languageID.contains("ARM:LE:64") || languageID.contains("AARCH64")) {
        if (resultRegister.getName().toUpperCase().equals("X0")) return 0;
        if (resultRegister.getName().toUpperCase().equals("X1")) return 1;
        if (resultRegister.getName().toUpperCase().equals("X2")) return 2;
        if (resultRegister.getName().toUpperCase().equals("X3")) return 3;
        if (resultRegister.getName().toUpperCase().equals("X4")) return 4;
        if (resultRegister.getName().toUpperCase().equals("X5")) return 5;
        if (resultRegister.getName().toUpperCase().equals("X6")) return 6;
        if (resultRegister.getName().toUpperCase().equals("X7")) return 7;
    }

    // Handle x86-64 calling convention (first 6 arguments are in RDI, RSI, RDX, RCX, R8, R9)
    if (languageID.contains("x86:LE:64")) {
        if (resultRegister.getName().toUpperCase().equals("RDI")) return 0;
        if (resultRegister.getName().toUpperCase().equals("RSI")) return 1;
        if (resultRegister.getName().toUpperCase().equals("RDX")) return 2;
        if (resultRegister.getName().toUpperCase().equals("RCX")) return 3;
        if (resultRegister.getName().toUpperCase().equals("R8")) return 4;
        if (resultRegister.getName().toUpperCase().equals("R9")) return 5; 
    }

    // Handle ARMv7 calling convention (first 4 arguments are in R0-R3)
    if (languageID.contains("ARM:LE:32")) {
        if (resultRegister.getName().toUpperCase().equals("R0")) return 0;
        if (resultRegister.getName().toUpperCase().equals("R1")) return 1;
        if (resultRegister.getName().toUpperCase().equals("R2")) return 2;
        if (resultRegister.getName().toUpperCase().equals("R3")) return 3;
        // If not R0-R3, then use the stack (starting at argument 4)
        return getStackArgumentIndexFromOffset(stackOffset, true);
    }

    // Handle x86 (32-bit) calling convention (all arguments are passed on the stack)
    if (languageID.contains("x86:LE:32")) {
        if (stackOffset != -1) {
            // If we tracked a stack offset, identify the argument from it
            return getStackArgumentIndexFromOffset(stackOffset, false);
        } else {
            return getArgumentIndexForStack(pcodeOp, trackedVarnode, resultRegister);
        }

    }

    // For MIPS (64-bit and 32-bit): First 4 arguments passed via A0-A3, rest on stack
    if (languageID.contains("MIPS:LE")) {
        if (resultRegister.getName().toUpperCase().equals("A0")) return 0; // First argument in A0
        if (resultRegister.getName().toUpperCase().equals("A1")) return 1; // Second argument in A1
        if (resultRegister.getName().toUpperCase().equals("A2")) return 2; // Third argument in A2
        if (resultRegister.getName().toUpperCase().equals("A3")) return 3; // Fourth argument in A3
        // Beyond A3, arguments are passed on the stack
        return getStackArgumentIndexFromOffset(stackOffset, true);
    }

    // If no match, return -1 to indicate no argument match
    return -1;
}

    // Helper method to find where the result of the span function (X0) is used
private Map.Entry<Address, String> findNextUsageOfResult(Address startAddress, Boolean is_hkdf) {
    Listing listing = currentProgram.getListing();
    Instruction instruction = listing.getInstructionAt(startAddress);

    while (instruction != null) {

        if (instruction.getFlowType().isCall()) {
            /*
             * We already know that the first function is the function that we don't have to analyze because this function 
             * contains an invocation strlen
             */
            Instruction callInstruction = instruction;
            //System.out.println("\nAnalyzing first function call at: " + callInstruction);

            // currently it doesn't consider when the string is directly pushed to the stack

            // Step 1: Trace the register holding the result of the first function call
            Varnode resultRegister = traceFunctionResult(callInstruction);
            System.out.println("[*] Our target register is: "+getRegisterForVarnode(resultRegister).getName());
            
            if (resultRegister != null) {
                // Address nextCallAddr =
                System.out.println();
                // Step 2: Trace how that register is used in subsequent instructions       
                return trackFunctionUsingRegister(callInstruction, resultRegister, is_hkdf, -1);
                

                // HashMap<Address, String>
                //return nextCallAddr;
            } else {
                System.err.println("[-] No function result found for the first call.");
                System.out.println();
                return null;
            }

        }

        instruction = instruction.getNext();
    }

    return null; // No further usage found
}

private Pair<Varnode, Long> analyzeReferenceStorage(Address referenceAddress) {
    Varnode output,result_Varnode = null;
    Listing listing = currentProgram.getListing();
    Instruction instruction = listing.getInstructionAt(referenceAddress);
    long stack_offset = -1;
    
    if (instruction == null) {
        System.err.println("[-] No instruction found at reference address: " + referenceAddress);
        return null;
    }
    
    if(DEBUG_RUN){
        System.out.println("[!] Analyzing instruction at reference address: " + instruction);
    }
    
    // Get Pcode operations of the instruction
    PcodeOp[] pcodeOps = instruction.getPcode();
    
    for (PcodeOp pcodeOp : pcodeOps) {
        // Check if the instruction is a "LOAD" or "COPY" operation involving the reference
        if (pcodeOp.getOpcode() == PcodeOp.LOAD || pcodeOp.getOpcode() == PcodeOp.COPY) {
            output = pcodeOp.getOutput();
            if (output != null && output.isRegister()) {
                Register targetRegister = getRegisterForVarnode(output);
                if (targetRegister != null) {
                    if(DEBUG_RUN){
                        System.out.println("[!] Reference stored in register: " + targetRegister.getName());
                    }
                    result_Varnode = output;
                    return new Pair<>(result_Varnode,stack_offset); 
                }
            }
        }
        
        // Check for "LEA" or "ADRL" instructions storing the reference in a register
        if (pcodeOp.getOpcode() == PcodeOp.PTRADD || pcodeOp.getOpcode() == PcodeOp.INT_ADD) {
            output = pcodeOp.getOutput();
            if (output != null && output.isRegister()) {
                Register targetRegister = getRegisterForVarnode(output);
                if (targetRegister != null) {
                    if(DEBUG_RUN){
                        System.out.println("[!] Reference stored in register (address loaded): " + targetRegister.getName());
                    }
                    result_Varnode = output; 
                    return new Pair<>(result_Varnode,stack_offset);
                }
            }

            // Get the inputs
            Varnode[] inputs = pcodeOp.getInputs();
            for (Varnode m_input : inputs) {
                // Check if the input is a register
                if (m_input.isRegister() && pcodeOp.getOpcode() == PcodeOp.INT_ADD) {
                    Register targetRegister = getRegisterForVarnode(m_input);
                    if(DEBUG_RUN){
                        System.out.println("[!] Reference stored in register (address loaded): " + targetRegister.getName());
                    }
                    result_Varnode = m_input; 
                }
                // Check if the input is a constant or an address
                else if (m_input.isConstant()) {
                    long offset = m_input.getOffset(); // This should give you the offset
                    if(DEBUG_RUN){
                        System.out.println("[!] Stack-Offset: 0x" + toSignedHexString(offset));
                    }
                    if(offset < 0x80){
                        stack_offset = offset;
                    }
                    
                }
            }

            
        }


         // Handle x86-specific memory storage (stack) cases
         if (pcodeOp.getOpcode() == PcodeOp.STORE) {
            Varnode input = pcodeOp.getInput(1); // Get the value being stored
            //Varnode addressVarnode = pcodeOp.getInput(0); // Address where it is stored

            if (input != null && input.isRegister()) {
                Register targetRegister = getRegisterForVarnode(input);
                if (targetRegister != null) {
                    if (DEBUG_RUN) {
                        System.out.println("[!] Reference stored from register: " + targetRegister.getName());
                    }
                    result_Varnode = input;
                    return new Pair<>(result_Varnode,stack_offset);
                }
            }

        }
    }

    if (result_Varnode == null) {
        System.err.println("[-] No register or storage location found for the reference");
    }


    
    return new Pair<>(result_Varnode,stack_offset);
}


private void print_reanalyze_message(boolean is_hkdf){
    if(is_hkdf){
        System.out.println("[*] First function wasn't a valid HKDF (Derive-Secret). Start reanalyzing...\n");
    }else{
        System.out.println("[*] First function wasn't a valid PRF. Start reanalyzing...\n");
    }
}

// Helper function to find the function call that uses the result
private Address findFunctionCallUsingResult(Address startAddress) {
    Listing listing = currentProgram.getListing();
    Instruction instruction = listing.getInstructionAt(startAddress);
    if(DEBUG_RUN){
        System.out.println("[!] Using infos for analysis: "+instruction);
    }
    int i = 0;

    while (instruction != null) {
        if(DEBUG_RUN){
            System.out.println("[!] analysis ("+i+"): "+instruction);
            i++;
        }

        if (instruction.getFlowType().isCall()) {

            // Return the address of the called function
            return instruction.getFlows()[0];
        }
        instruction = instruction.getNext();
    }

    return null; // No call found
}

    private Pair<Integer, Instruction> getLengthUntilBranch(Function function, boolean is_hkdf, boolean has_more_than_one_master_sec, boolean go_to_the_next_branch) {
        System.out.println("Function: "+function);
        Address entryPoint = function.getEntryPoint();
        Listing listing = currentProgram.getListing();
        Instruction instruction = listing.getInstructionAt(entryPoint);
        Instruction lastInstruction = instruction;
        int length = 0;
        boolean x86_skip_first_call = true;
        boolean stop_by_first_branch_which_is_not_a_call = false;
        
        if (instruction == null) {
            System.err.println("[-] No instruction found at entry point: " + entryPoint);
            System.err.println("[-] Defaulting to 32 bytes");
            // Default to 32 if no instructions are found
            return new Pair<>(32, null);
        }
    
        while (true) {
            Instruction currentInstruction = listing.getInstructionAt(entryPoint);
            if (currentInstruction == null) {
                break; // Break if there's no instruction at the current address
            }
            lastInstruction = currentInstruction;
    
            // Check if the instruction is a call
            //System.out.println("[!!!] inst: "+currentInstruction);
            if (currentInstruction.getFlowType().isCall()) {

                Address calledFunctionAddr = null;
                Function calledFunction = null;

                if(currentInstruction.getFlows().length < 1 && currentInstruction.toString().contains("CALL qword ptr [")){
                    //System.out.println("[!!!] inst: "+currentInstruction);
                    //System.out.println("getReferencesTo: "+currentInstruction.getReferencesFrom());
                }else{
                    calledFunctionAddr = currentInstruction.getFlows()[0];
                    calledFunction = getFunctionAt(calledFunctionAddr);
                    System.out.println("[!!!] Functionname: "+calledFunction.getName()+ " (Signature: "+calledFunction.getSignature().toString()+")");
                }

                

                /*
                 * This is just a temporary workaorund because the tracing of the string is on some architecture and corner cases not working as expected
                 */

                if(calledFunction != null){
                    if (calledFunction.getName().contains("strlen")) {
                        if(DEBUG_RUN){
                            System.out.println("[*] Found a call to 'strlen'. Returning -42.");
                        }
                        System.out.println("[*] invocation was done in the function: "+function.getName());
                        print_reanalyze_message(is_hkdf);
                        
                        //return -42;  // Special case: return -42 if "strlen" is called
                        return new Pair<>(-42, null);
                    }else if(calledFunction.getName().contains("_ZN4bssl4SpanIKhEC1EPS1_m") || calledFunction.getName().contains("Span")){
                        if(DEBUG_RUN){
                            System.out.println("[**] Found a call to 'Span'. Returning -43.");
                        }
                        System.out.println("[**] invocation was done in the function: "+function.getName());
                        print_reanalyze_message(is_hkdf);
                        return new Pair<>(-43, null); 
    
                    }else if(calledFunction.getName().contains("_ZNK4bssl8internal21StackAllocatedMovableI13en") || calledFunction.getName().contains("GET") || calledFunction.getName().contains("_M_ptr")){
                        if(DEBUG_RUN){
                            System.out.println("[***] Found a call to 'bssl::internal::StackAllocatedMovable<>::get'. Returning -44.");
                        }
                        System.out.println("[***] invocation was done in the function: "+function.getName());
                        print_reanalyze_message(is_hkdf);
                        return new Pair<>(-44, null);
                        
                    }
                }
    
                // Count the call instruction length
                length += currentInstruction.getLength();
                if(currentProgram.getLanguageID().toString().contains("32") && x86_skip_first_call){
                    // on 32bit systems the byte pattern would be to short
                    entryPoint = entryPoint.add(currentInstruction.getLength());
                    x86_skip_first_call = false;
                    //continue;
                }else{
                    //System.out.println("finish x86_skip_first_call");
                    break;
                }
                
            }

            /*if(is_hkdf == false && has_more_than_one_master_sec == true){
                System.out.println("[!!!] (currentInstruction.toString()): "+currentInstruction.toString());
            }*/

            if(is_hkdf == false && has_more_than_one_master_sec == true && currentInstruction.toString().toLowerCase().contains("0xffffffff")){
                return new Pair<>(-66, null);
            }
    
            // Check if the instruction is a branch or jump
            if (currentInstruction.getFlowType().isJump() ||
                currentInstruction.getFlowType().isConditional()) {
                    //System.out.println("[!!!] inst (jump|branch): "+currentInstruction);
                    if(currentProgram.getLanguageID().toString().contains("32") || go_to_the_next_branch){
                        if(stop_by_first_branch_which_is_not_a_call){
                            length += currentInstruction.getLength();
                            //System.out.println("finish x86_skip_first_callv2");
                            break;
                            
                        }else{
                            //System.out.println("x86_skip_first_callv2 = true");
                            stop_by_first_branch_which_is_not_a_call = true;
                        }
                    }else{
                        length += currentInstruction.getLength();
                        break;
                    }
                    
                
            }
    
            // Move to the next instruction and add the length of the current one
            length += currentInstruction.getLength();
            entryPoint = entryPoint.add(currentInstruction.getLength());
            lastInstruction = currentInstruction;
        }
    
        return new Pair<>(length, lastInstruction);
    }

    private boolean isPushInstruction(Instruction instruction) {
        // Check the opcode of the instruction for various architectures
        if (instruction.getMnemonicString().toUpperCase().contains("PUSH")) {
            return true;
        }
        return false;
    }

    private Address findNextFunctionCall(Address startAddress) {
        Listing listing = currentProgram.getListing();
        Instruction currentInstruction = listing.getInstructionAt(startAddress);
    
        while (currentInstruction != null) {
            // Check if the instruction is a function call
            if (currentInstruction.getFlowType().isCall()) {
                return currentInstruction.getAddress(); // Return the address of the function call
            }
            // Move to the next instruction
            currentInstruction = currentInstruction.getNext();
        }
        return null; // Return null if no function call is found
    }

    private void analyzeSpanResult(Address referenceAddress, Boolean is_hkdf, List<Pair<Function, Address>> list_of_string_refs) {
        Address nextInstructionAddr = null;
        boolean is_push_reference = false;
        String value = "";
        Listing listing = currentProgram.getListing();
        Instruction currentInstruction = listing.getInstructionAt(referenceAddress);
        if(isPushInstruction(currentInstruction)){ // just a temporary workaround
            System.out.println("is_push_reference = true");
            is_push_reference = true;
            nextInstructionAddr = findNextFunctionCall(referenceAddress);
            System.out.println("nextInstructionAddr = "+nextInstructionAddr);
            //nextInstructionAddr = referenceAddress.next();

        }else{
            Map.Entry<Address, String> entry = findNextUsageOfResult(referenceAddress, is_hkdf); // currently it doesn't take into account if we have at the ref address directly a push
            nextInstructionAddr = entry.getKey();
            value = entry.getValue();
        }
        

        if (nextInstructionAddr != null) {
            Function nextCalledFunction = null;

            if(is_push_reference){ // just a workaround when findNextUsageOfResult is fix we shouldn't need that anymore
                Instruction func_instruction = listing.getInstructionAt(nextInstructionAddr);
                nextCalledFunction = getCalledFunction(func_instruction);
                System.out.println("nextCalledFunction = "+nextCalledFunction);
                //FlowType flowType = instruction.getFlowType();
            }else{
                nextCalledFunction = getFunctionAt(nextInstructionAddr);
            }
            
            if (nextCalledFunction != null) {
                if(DEBUG_RUN){
                    System.out.println("[*] Found the next function where the span result is passed: " + nextCalledFunction.getName());
                }
                extractFunctionInfo(nextCalledFunction, referenceAddress, is_hkdf, value,nextInstructionAddr, list_of_string_refs);
            } else {
                System.err.println("[-] No function found at the next address: " + nextInstructionAddr);
            }
        } else {
            System.err.println("[-] No further usage of the span result found.");
        }

    }

    private String get_ida_address(Address ghidra_address){
        /*                                    
        The default base address in Ghidra is 0x00010000 for 32bit and 0x00100000 for 64bit and in IDA it is 
        just 0x0 therefore we just do the math here
        */
        long offset = 0x00010000; // offset 32bit
        String languageID = currentProgram.getLanguageID().toString();
        if(languageID.contains("64")){
            offset = 0x00100000;
        }
        

        // Get the AddressSpace to perform arithmetic
        //AddressSpace addressSpace = ghidra_address.getAddressSpace();

        // Subtract the offset from the Ghidra address
        Address ida_address = ghidra_address.subtract(offset);

        return ida_address.toString().toUpperCase();

    }

    private String getBinaryInfos() {
        String binaryNameWithPath = currentProgram.getExecutablePath();
        String architecture = currentProgram.getLanguage().getProcessor().toString();

        if(architecture.contains("AARCH64")){
            architecture = "ARM64";
        }else if(currentProgram.getLanguageID().toString().contains("x86:LE:64")){
            architecture = "x86-64";
        }
        
       
        String binaryName = new java.io.File(binaryNameWithPath).getName();




        return "[*] Start analyzing binary " + binaryName + " (CPU Architecture: "+ architecture+"). This might take a while ...";
    }

    private void identifying_TLS13_HKDF(){
        String identifier_tls13_hkdf = "s hs traffic";
        System.out.println();
        System.out.println("[*] Start identifying the HKDF by looking for String \"" + identifier_tls13_hkdf+"\"");

        try{
            List<Pair<Function, Address>> functionAddressPairs = findStringUsage(identifier_tls13_hkdf);
            if(!functionAddressPairs.isEmpty()){
                Pair<Function, Address> result = functionAddressPairs.get(0);
                Function functions = result.getFirst();
                Address referenceAddress = result.getSecond();

                do_analysis(functions,  referenceAddress,true, false, functionAddressPairs);
            }else{
                identifier_tls13_hkdf =  "hs traffic";
                System.out.println("[*] String \"s hs traffic\" wasn't found in binary! Trying to reduce string ...");
                System.out.println("[*] Start identifying the HKDF by looking for String \"" + identifier_tls13_hkdf+"\"");
                functionAddressPairs = findStringUsage(identifier_tls13_hkdf);
                if(!functionAddressPairs.isEmpty()){
                    Pair<Function, Address> result = functionAddressPairs.get(0);
                    Function functions = result.getFirst();
                    Address referenceAddress = result.getSecond();

                    do_analysis(functions,  referenceAddress,true, false, functionAddressPairs);
                }else{
                List<Pair<Function, Address>> functionAddressPairsAlternative = findStringUsageWithOffset(identifier_tls13_hkdf);

                Pair<Function, Address> result = functionAddressPairsAlternative.get(0);
                Function functions = result.getFirst();
                Address referenceAddress = result.getSecond();

                do_analysis(functions,  referenceAddress,true, false, functionAddressPairsAlternative);
                
                }
            }
        }catch(Exception e){
            System.err.println("[-] Error while trying to identify the HKDF function.");
            //System.err.println("[-] : " +e.getLocalizedMessage());
            //e.printStackTrace();

            try{
                List<Pair<Function, Address>> functionAddressPairs = null;

                System.out.println("\n[*] Start looking for the string in the .rodata section ....");

                Address foundAddress = findStringInRodata(); // this is for instance when we are analysing a go compiled file
                if (foundAddress != null) {
                    System.out.println("[*] String found in .rodata section at address: " + foundAddress);
                    functionAddressPairs = findFunctionReferences(foundAddress,".rodata");
                } else {

                    System.out.println("[*] String not found in .rodata section.");
                    System.out.println("[*] Start with the Stack String search, this might take a while ....");

                   functionAddressPairs = FindStackStrings(true); 
                }
                if(functionAddressPairs.size() < 1){
                    System.out.println("[-] Unable to find the String:\"hs traffic\" in all of its occiouns in the target binary");
                    return;
                }
                Pair<Function, Address> result = functionAddressPairs.get(0); // libnativetunnel.so error
                Function function_which_has_reference = result.getFirst();
                Address referenceAddress = result.getSecond();

                do_analysis(function_which_has_reference,  referenceAddress,true, false, functionAddressPairs);
            }catch(Exception e2){
                e2.printStackTrace();
            }
        }

    }

    private void identifying_TLS12_PRF(){
        String identifier_tls12_prf = "master secret";
        System.out.println();
        System.out.println("[*] Start identifying the PRF by looking for String \"" + identifier_tls12_prf+"\"");

        try {
            short analysis_error_code = 1;
            List<Pair<Function, Address>> functionAddressPairs = findStringUsage(identifier_tls12_prf);
            if (!functionAddressPairs.isEmpty()) {
                Pair<Function, Address> result = functionAddressPairs.get(0);
                Function function_which_has_reference = result.getFirst();
                Address referenceAddress = result.getSecond();

                analysis_error_code = do_analysis(function_which_has_reference,  referenceAddress,false, false, functionAddressPairs);
                if(functionAddressPairs.size() == 2 && analysis_error_code == 1){
                    System.out.println("\n[*] There has been two functions identified which are using the String \"" + identifier_tls12_prf+"\" as an argument. It is very likely that the second function is the real PRF.");
                    System.out.println("[*] Start analyzing second function ...");
                    Pair<Function, Address> second_result = functionAddressPairs.get(1);
                    Function second_function_which_has_reference = second_result.getFirst();
                    Address second_referenceAddress = second_result.getSecond();
                    do_analysis(second_function_which_has_reference,  second_referenceAddress,false, false, functionAddressPairs);
                }
            }
            if(analysis_error_code == 42 || functionAddressPairs.isEmpty()){
                String identifier_tls12_prf_export = "extended master secret";
                System.out.println();
                System.out.println("[*] String master secret wasn't found in binary! Trying another approach...");
                System.out.println("[*] Start identifying the PRF by looking for String \"" + identifier_tls12_prf_export+"\"");


                List<Pair<Function, Address>> functionAddressPairs_rerun = findStringUsage(identifier_tls12_prf_export);
                Pair<Function, Address> result_rerun = functionAddressPairs_rerun.get(0);
                Function function_which_has_reference_rerun = result_rerun.getFirst();
                Address referenceAddress_result_rerun = result_rerun.getSecond();
                do_analysis(function_which_has_reference_rerun,  referenceAddress_result_rerun,false, true, functionAddressPairs_rerun);
            }
        }catch(Exception e){
            System.err.println("[-] Error while trying to identify the PRF function.");
            //System.err.println("[-] : " +e.getLocalizedMessage());
            //e.printStackTrace();

            try{
                System.out.println("\n[*] Start with the Stack String search, this might take a while ....");
                List<Pair<Function, Address>> functionAddressPairs = FindStackStrings(false);
                Pair<Function, Address> result = functionAddressPairs.get(0);
                Function function_which_has_reference = result.getFirst();
                Address referenceAddress = result.getSecond();

                do_analysis(function_which_has_reference,  referenceAddress,false, false, functionAddressPairs);
            }catch(Exception e2){
                if(e2.toString().contains("IndexOutOfBoundsException")){
                    System.err.println("[-] Unable to find the String: \"master secret\" in all of its occiouns in the target binary");
                }else{
                    System.err.println("[-] Error:");
                    e2.printStackTrace();

                }
                
            }

            

            
        }

    }

    private short do_analysis(Function function_using_that_reference, Address first_referenceAddress,Boolean is_hkdf, boolean is_rerun, List<Pair<Function, Address>> list_of_string_refs){
        if (function_using_that_reference != null) {
            
            //Varnode resultRegister= analyzeReferenceStorage(referenceAddress);
            Pair<Varnode, Long> reference_analysis_results = analyzeReferenceStorage(first_referenceAddress);
            Varnode resultRegister = reference_analysis_results.getFirst();
            Listing listing = currentProgram.getListing();
            Instruction instruction = listing.getInstructionAt(first_referenceAddress);
            Address fallbackCalledFunctionAddr = null;

            if(resultRegister == null){
                System.err.println("[-] Error in identifying target location of reference. Identifiying next call as target function...");
                fallbackCalledFunctionAddr = findReferenceToStringAtAddress(first_referenceAddress);   
            }
            

                    
            Map.Entry<Address, String> addressStringMap = trackFunctionUsingRegister(instruction, resultRegister, is_hkdf, reference_analysis_results.getSecond());
            Address calledFunctionAddr = addressStringMap.getKey();

            boolean is_indirect_call = addressStringMap.getValue().contains("indirect function");

            if (calledFunctionAddr != null) {
                Function calledFunction = getFunctionAt(calledFunctionAddr);
                if (calledFunction != null || is_indirect_call) {
                    // Pass the function to extractFunctionInfo to get its details and print the byte pattern
                    if(is_indirect_call){
                        extractFunctionInfo(calledFunction, first_referenceAddress, is_hkdf, addressStringMap.getValue(), calledFunctionAddr, list_of_string_refs);
                    }else{
                        extractFunctionInfo(calledFunction, first_referenceAddress, is_hkdf, addressStringMap.getValue(), null, list_of_string_refs);
                    }
                    
                    return 1;
                } else {
                    System.err.println("[-] No function found at address: " + calledFunctionAddr);
                    System.out.println();
                }
            }

            if (fallbackCalledFunctionAddr != null) {
                Function calledFunction = getFunctionAt(fallbackCalledFunctionAddr);
                if (calledFunction != null || is_indirect_call) {
                    // Pass the function to extractFunctionInfo to get its details and print the byte pattern
                    extractFunctionInfo(calledFunction, first_referenceAddress, is_hkdf, "", null, list_of_string_refs);
                    
                } else {
                    System.err.println("[-] No function found at address: " + fallbackCalledFunctionAddr);
                    System.out.println();
                    return -1;
                }
            }
        } else {
            if(!is_hkdf && !is_rerun){
                return 42;
            }
            System.err.println("[-] No functions found that reference the specified string.");
            System.out.println();
            return -1;
        }
        return 1;
    }



/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ JAR ANALYSIS +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

private boolean isJarOrClassFile(Program program) {
    String binaryNameWithPath = currentProgram.getExecutablePath();
    String architecture = currentProgram.getLanguage().getProcessor().toString();

    if(architecture.toUpperCase().contains("JVM")){
        if(binaryNameWithPath.toLowerCase().endsWith("class")){
            System.out.println("[*] Class file identified and being analyzed.");
        }
        if(binaryNameWithPath.toLowerCase().endsWith("jar")){
            System.out.println("[*] JAR file identified and being analyzed.");
        }
        return true;

    }

    if(DEBUG_RUN){
        System.out.println("[!] The file is neither a JAR nor a .class file.");
    }
    
    return false;
}

public void do_find_master_secret_in_class_files() {
    Listing listing = currentProgram.getListing();
    SymbolTable symbolTable = currentProgram.getSymbolTable();

    System.out.println("Starting analysis for 'master secret'...");

    // Iterate through all functions in the program
    for (Function function : listing.getFunctions(true)) {
        // Extract class and method name
        String fullFunctionName = function.getName();
        String className = extractClassName(function);
        String methodName = extractMethodName(function);

        //System.out.println("Inspecting function: " + fullFunctionName);
        //System.out.println("Class: " + className + ", Method: " + methodName);

        // Search for string references in the function's body
        Address functionStart = function.getEntryPoint();
        Reference[] references = getReferencesFrom(functionStart);

        for (Reference ref : references) {
            Address refAddress = ref.getToAddress();
            String stringValue = extractString(refAddress);

            if (stringValue != null && stringValue.contains("master secret")) {
                System.out.println("'master secret' referenced in class: " + className +
                        ", method: " + methodName +
                        " at address: " + refAddress.toString());
            }
        }
    }

    //System.out.println("Analysis complete.");
}

private String extractClassName(Function function) {
    // Extract the class name from the function name (e.g., com.example.MyClass.myMethod)
    String fullName = function.getName();
    int lastDotIndex = fullName.lastIndexOf('.');
    if (lastDotIndex > 0) {
        return fullName.substring(0, lastDotIndex); // Everything before the last dot
    }
    return "UnknownClass"; // Fallback if no dot is found
}

private String extractMethodName(Function function) {
    // Extract the method name from the function name
    String fullName = function.getName();
    int lastDotIndex = fullName.lastIndexOf('.');
    if (lastDotIndex > 0) {
        return fullName.substring(lastDotIndex + 1); // Everything after the last dot
    }
    return fullName; // If no dot is found, return the full name as the method name
}

private String extractString(Address address) {
    try {
        // Get the Listing and find the Data object containing the given Address
        Listing listing = currentProgram.getListing();
        Data data = listing.getDataContaining(address);
        
        if (data != null) {
            // Extract string data from the Data object
            StringDataInstance stringInstance = StringDataInstance.getStringDataInstance(data);
            if (stringInstance != null) {
                return stringInstance.getStringValue();
            }
        }
    } catch (Exception e) {
        System.err.println("Error extracting string at address: " + address + " - " + e.getMessage());
    }
    return null;
}





private void listStringsContainingMasterSecret(Program program) {
    // Determine the file type and delegate analysis
    String filePath = program.getExecutablePath();
    if (filePath.endsWith(".class")) {
        println("Analyzing .class file...");
        analyzeClassFile(program);
    } else if (filePath.endsWith(".jar")) {
        println("Analyzing JAR file...");
        analyzeJarFile(program);
    } else {
        println("Unsupported file type for string search.");
    }
}

// Analyze strings in a .class file and report the offset of matches
private void analyzeClassFile(Program program) {
    Memory memory = program.getMemory();

    // Iterate through all memory blocks
    for (MemoryBlock block : memory.getBlocks()) {
        //println("Inspecting memory block: " + block.getName());

        byte[] data = new byte[(int) block.getSize()];
        try {
            block.getBytes(block.getStart(), data);
        } catch (Exception e) {
            System.err.println("Error reading memory block: " + e.getMessage());
            continue;
        }

        // Search for "master secret" in the current block
        String content = new String(data);
        int index = content.indexOf("master secret");
        if (index != -1) {
            long offset = block.getStart().getOffset() + index;
            System.out.println("'master secret' found in memory block '" + block.getName() +
                    "' at offset: " + Long.toHexString(offset));
            System.out.println("GEt class: "+program.getExecutablePath());
        }
    }

    //println("Analysis of .class file complete.");
}


// Analyze strings in a JAR file and report the specific JAR entry
private void analyzeJarFile(Program program) {
    Memory memory = program.getMemory();
    MemoryBlock block = memory.getBlock(".text");
    if (block == null) {
        println("No .text block found for JAR file.");
        return;
    }

    byte[] data = new byte[(int) block.getSize()];
    try {
        block.getBytes(block.getStart(), data);
    } catch (Exception e) {
        println("Error reading memory block: " + e.getMessage());
        return;
    }

    try (InputStream is = new ByteArrayInputStream(data);
         JarInputStream jarStream = new JarInputStream(is)) {

        JarEntry entry;
        while ((entry = jarStream.getNextJarEntry()) != null) {
            if (!entry.isDirectory()) {
                println("Analyzing JAR entry: " + entry.getName());

                // Read the content of the entry
                byte[] entryBytes = jarStream.readAllBytes();
                String entryContent = new String(entryBytes);

                // Search for "master secret"
                int index = entryContent.indexOf("master secret");
                if (index != -1) {
                    println("'master secret' found in JAR entry: " + entry.getName() + " at byte offset: " + index);
                }
            }
        }
    } catch (Exception e) {
        println("Error processing JAR file: " + e.getMessage());
    }
}





    /*
     * Main entry point
     */


    @Override
    protected void run() throws Exception {
        printTLSKeyHunterLogo();

        Program program = getCurrentProgram();
        if (program == null) {
            System.out.println("[-] No program loaded.");
            return;
        }

        // Check if the binary is a JAR file
        if (!isJarOrClassFile(program)) {
            System.out.println(getBinaryInfos());

        
            identifying_TLS13_HKDF();
            identifying_TLS12_PRF();
        }else{
            System.out.println("[*] Binary is a JAR file or Class file. Invoking JAR Analyzer");
            // Extract and search strings in the JAR
            listStringsContainingMasterSecret(program);
            do_find_master_secret_in_class_files();
            
        }



        System.out.println("\n[*] Thx for using TLSKeyHunter. Have a nice day :)");
        System.out.println();
        
    }
}
