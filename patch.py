import subprocess
import struct
import os
import shutil
import sys
import stm32_crc
import zipfile
import json


LOAD_SIZE_ADDR=0xe
CRC_ADDR=0x14
NUM_RELOC_ENTRIES_ADDR=0x64
OFFSET_ADDR=0x10
VIRTUAL_SIZE_ADDR=0x80
STRUCT_SIZE_BYTES=0x82
JUMP_TABLE_ADDR=0x5c


target_pbw = "/Volumes/MacintoshHD/Users/collinfair/Pebble/qibla/build/qibla.pbw"

# First, compile the mods with the shell script that I'll incorporate in here soon enough
subprocess.check_call(["sh", "build_mods.sh"])

def compile(cflags=None, linkflags=None, infiles, outfile):
    cflags = cflags if cflags else []
    linkflags = linkflags if linkflags else []

    # Common flags
    cflags = [  "-mcpu=cortex-m3",
                "-mthumb",
                "-fPIC",
                "-fPIE",
                "-ffunction-sections",
                "-fdata-sections",
                "-std=c99",
                "-I./",
                "-I./src"
                "-nostdlib"
    ] + cflags

    linkflags = ["-Wl,%s" % flag for flag in linkflags] # Since we're letting gcc link too

    subprocess.check_call(["arm-none-eabi-gcc"] + cflags + linkflags + ["-o", outfile] + infiles)

def compile_mod()

def patch_bin(bin_file):
    # By the end of this, we should have (in no particular order)
    # - compiled the mod binary with the BSS located at the end of the main app's .bss
    # - have inserted the mod binary between the app header and the main body of the app code
    # - incremented the relocation table entries, and their targets, by the size of the mod binary (so they properly relocate)
    # - incremented the entrypoint similarly
    # - appended the mod's relocation table to the main one (offsetting to account for header)
    # - updated the app CRC
    # - updated the virtual size and load_size (both incremented by size of mod's .data+.text+.bss)
    # - patched the main app's jump_to_pbl_function_addr to branch to our proxy (contained within the mod binary)
    # - increment the header's pointer to the main app's jump table addr placeholder

    # Stolen from SDK
    def write_value_at_offset(offset, format_str, value):
        bin_file.seek(offset)
        bin_file.write(struct.pack(format_str, value))
    def read_value_at_offset(offset, format_str):
        bin_file.seek(offset)
        data = bin_file.read(struct.calcsize(format_str))
        return struct.unpack(format_str, data)
    def get_virtual_size(elf_file):
        readelf_bss_process=subprocess.Popen("arm-none-eabi-readelf -S '%s'"%elf_file,shell=True,stdout=subprocess.PIPE)
        readelf_bss_output=readelf_bss_process.communicate()[0]
        last_section_end_addr=0
        for line in readelf_bss_output.splitlines():
            if len(line)<10:
                continue
            line=line[6:]
            columns=line.split()
            if len(columns)<6:
                continue
            if columns[0]=='.bss':
                addr=int(columns[2],16)
                size=int(columns[4],16)
                last_section_end_addr=addr+size
            elif columns[0]=='.data'and last_section_end_addr==0:
                addr=int(columns[2],16)
                size=int(columns[4],16)
                last_section_end_addr=addr+size
        if last_section_end_addr!=0:
            return last_section_end_addr
        raise Exception("Failed to parse ELF sections while calculating the virtual size", readelf_bss_output)
    def get_relocate_entries(elf_file):
        entries=[]
        readelf_relocs_process=subprocess.Popen(['arm-none-eabi-readelf','-r',elf_file],stdout=subprocess.PIPE)
        readelf_relocs_output=readelf_relocs_process.communicate()[0]
        lines=readelf_relocs_output.splitlines()
        i=0
        reading_section=False
        while i<len(lines):
            if not reading_section:
                if lines[i].startswith("Relocation section '.rel.data"):
                    reading_section=True
                    i+=1
            else:
                if len(lines[i])==0:
                    reading_section=False
                else:
                    entries.append(int(lines[i].split(' ')[0],16))
            i+=1
        readelf_relocs_process=subprocess.Popen(['arm-none-eabi-readelf','--sections',elf_file],stdout=subprocess.PIPE)
        readelf_relocs_output=readelf_relocs_process.communicate()[0]
        lines=readelf_relocs_output.splitlines()
        for line in lines:
            if'.got'in line and'.got.plt'not in line:
                words=line.split(' ')
                while''in words:
                    words.remove('')
                section_label_idx=words.index('.got')
                addr=int(words[section_label_idx+2],16)
                length=int(words[section_label_idx+4],16)
                for i in range(addr,addr+length,4):
                    entries.append(i)
                break
        return entries
    def get_nm_output(elf_file):
        nm_process=subprocess.Popen(['arm-none-eabi-nm',elf_file],stdout=subprocess.PIPE)
        nm_output=nm_process.communicate()[0]
        if not nm_output:
            raise RuntimeError("Invalid binary")
        nm_output=[line.split()for line in nm_output.splitlines()]
        return nm_output
    def get_symbol_addr(nm_output,symbol):
        for sym in nm_output:
            if symbol==sym[-1]and len(sym)==3:
                return int(sym[0],16)
        raise Exception("Could not locate symbol <%s> in binary! Failed to inject app metadata"%(symbol))
    def unhexify(str):
        return str.replace(" ", "").decode("hex")

    mod_pre_pad = 2 # This breaks everything
    mod_post_pad = 2 # this fixes it? We need to word-align the mod start, and the main app's entrypoint, for ARM EABI
    # Figure out the end of the .data+.text section (immediately before relocs)
    load_size = read_value_at_offset(LOAD_SIZE_ADDR, "<H")[0]
    # ...and the end of .data+.text+.bss (which includes the relocation table, which we will relocate to the end of the binary)
    virtual_size = read_value_at_offset(VIRTUAL_SIZE_ADDR, "<H")[0]
    main_entrypoint = read_value_at_offset(OFFSET_ADDR, "<L")[0]
    jump_table = read_value_at_offset(JUMP_TABLE_ADDR, "<L")[0]

    # compile the mods with the BSS set to the end of the virtual_size (i.e. the end of the main app's bss)
    # This is a bit sketch since, in order to know the final virtual_size, we need to know the size of the mod's code and BSS
    # ...which requires compiling it
    # ...so I hope the size doesn't somehow change when we move the BSS (it shouldn't, it looks like all BSS stuff is ending up in the GOT)
    mod_load_size = os.stat("mods.bin").st_size + mod_pre_pad + mod_post_pad
    mod_virtual_size = get_virtual_size("mods.o") + mod_pre_pad + mod_post_pad
    final_virtual_size = virtual_size + mod_virtual_size
    final_load_size = load_size + mod_load_size
    mod_ld_map = open("mods_layout.template.ld", "r").read()
    mod_ld_map = mod_ld_map.replace("@BSS@", hex(virtual_size + mod_load_size)) # The end of their BSS, plus what we'll insert
    mod_ld_map = mod_ld_map.replace("@APP@", hex(STRUCT_SIZE_BYTES + mod_pre_pad)) # Where the rest of the app will get mounted
    open("mods_layout.ld", "w").write(mod_ld_map)

    # Recompile & load result
    subprocess.check_call(["sh", "build_mods.sh"])
    mod_binary = open("mods.bin", "rb").read()
    mod_binary = chr(0) * mod_pre_pad + mod_binary + chr(0) * mod_post_pad
    mod_binary_nm_output = get_nm_output("mods.o")
    mod_reloc_entries = [x for x in get_relocate_entries("mods.o")]

    # Update the relocationt able entries, and their targets, by the amount we're going to insert after the header
    main_reloc_table_size = read_value_at_offset(NUM_RELOC_ENTRIES_ADDR, "<L")[0]
    print("main has ", main_reloc_table_size, "relocs")
    for entry_idx in range(main_reloc_table_size):
        target_addr = read_value_at_offset(load_size + entry_idx * 4, "<L")[0]
        target_value = read_value_at_offset(target_addr, "<L")[0]
        target_value += mod_load_size
        write_value_at_offset(target_addr, "<L", target_value)
        write_value_at_offset(load_size + entry_idx * 4, "<L", target_addr + mod_load_size)

    # Grab the code, and the relocation table
    bin_file.seek(STRUCT_SIZE_BYTES)
    main_binary = bin_file.read(load_size - STRUCT_SIZE_BYTES)
    main_reloc_table = bin_file.read()
    assert len(main_reloc_table) / 4 == main_reloc_table_size

    # Find jump_to_pbl_function
    jump_to_pbl_function_signature = unhexify("03 A3 18 68 08 44 02 68 94 46 0F BC 60 47 00 BF A8 A8 A8 A8")
    jump_to_pbl_function_addr = main_binary.index(jump_to_pbl_function_signature)
    assert jump_to_pbl_function_addr
    print("main jmp fcn", hex(jump_to_pbl_function_addr))
    # Replace with something that still grabs reads the offset table addr, but immediately hands off the the address of the method we specify (the mod's proxy)
    mod_syscall_proxy_addr = get_symbol_addr(mod_binary_nm_output, "jump_to_pbl_function__proxy")
    mod_syscall_proxy_jmp_addr = mod_syscall_proxy_addr + 1 # +1 to indicate THUMB 16-bit instruction
    replacement_fcn = unhexify("03 A3 18 68 00 4A 10 47") + struct.pack("<L", mod_syscall_proxy_jmp_addr) + unhexify("00 BF 00 BF A8 A8 A8 A8")
    # replacement_fcn = chr(0x03) + jump_to_pbl_function_signature[1:]
    assert len(replacement_fcn) == len(jump_to_pbl_function_signature)
    main_binary = main_binary.replace(jump_to_pbl_function_signature, replacement_fcn)
    print("our proxy addr", hex(mod_syscall_proxy_addr))

    # update the mod's binary with the (eventual) address of the jump table placeholder
    mod_jump_table_ptr_addr = mod_binary.index(unhexify("a8a8a8a8"))
    print("out jump table ptr", mod_jump_table_ptr_addr)
    print("their jump table", jump_table)
    mod_binary = mod_binary.replace(unhexify("a8a8a8a8"), struct.pack("<L", jump_table + mod_load_size))

    bin_file.seek(STRUCT_SIZE_BYTES)
    # Insert the mod binary
    bin_file.write(mod_binary)
    # then re-add their binary and relocation table
    bin_file.write(main_binary)
    bin_file.write(main_reloc_table)
    # and, finally, ours (plus the header since we don't compile that in)
    mod_reloc_entries.append(STRUCT_SIZE_BYTES + mod_load_size + jump_to_pbl_function_addr + 8) # For their jump to our proxy
    mod_reloc_entries.append(STRUCT_SIZE_BYTES + mod_jump_table_ptr_addr) # For our jump table ptr thing
    print("mod reloc", mod_reloc_entries)
    for entry in mod_reloc_entries:
        bin_file.write(struct.pack('<L',entry))

    # Update the header with the new size of the reloc table
    write_value_at_offset(NUM_RELOC_ENTRIES_ADDR, "<L", main_reloc_table_size + len(mod_reloc_entries))

    # Update it with the new entrypoint and sizes
    final_entrypoint = main_entrypoint + mod_load_size
    write_value_at_offset(OFFSET_ADDR, "<L", final_entrypoint)

    # Update the new sizes
    write_value_at_offset(VIRTUAL_SIZE_ADDR, "<H", final_virtual_size)
    write_value_at_offset(LOAD_SIZE_ADDR, "<H", final_load_size)

    # Update the CRC
    final_crc = stm32_crc.crc32(mod_binary + main_binary)
    write_value_at_offset(CRC_ADDR, "<L", final_crc)

    # and the jump table addr
    final_jump_table = jump_table + mod_load_size
    write_value_at_offset(JUMP_TABLE_ADDR, "<L", final_jump_table)

    print("final entrypoint %x" % final_entrypoint)
    assert final_entrypoint % 4 == 0, "Main entrypoint not byte-aligned"
    assert mod_syscall_proxy_addr % 4 == 0, "Mod code not byte-aligned, falls at %x" % (mod_syscall_proxy_addr + STRUCT_SIZE_BYTES)
    assert (mod_binary.index(unhexify("044a8a42")) + STRUCT_SIZE_BYTES) == mod_syscall_proxy_addr, "Proxy address reality mismatch"

def update_manifest(app_dir):
    def stm32crc(path):
        with open(path,'r+b')as f:
            binfile=f.read()
            return stm32_crc.crc32(binfile)&0xFFFFFFFF

    manifest_file = open(os.path.join(app_dir, "manifest.json"), "r+")
    manifest_obj = json.load(manifest_file)
    manifest_file.seek(0)

    bin_crc = stm32crc(os.path.join(app_dir, "pebble-app.bin"))
    manifest_obj["application"]["crc"] = bin_crc
    json.dump(manifest_obj, manifest_file)
    manifest_file.close()

def patch_and_repack_pbw(pbw_path, pbw_out_path):
    if os.path.exists("pbw_tmp"):
        shutil.rmtree("pbw_tmp")
    os.mkdir("pbw_tmp")

    with zipfile.ZipFile(pbw_path, "r") as z:
        z.extractall("pbw_tmp")

    patch_bin(open("pbw_tmp/pebble-app.bin", "r+b"))
    # Update CRC of binary
    update_manifest("pbw_tmp")

    if os.path.exists("pbw_tmp/basalt"):
        # Do the same for basalt
        patch_bin(open("pbw_tmp/basalt/pebble-app.bin", "r+b"))
        # Update CRC of binary
        update_manifest("pbw_tmp/basalt")

    with zipfile.ZipFile(pbw_out_path, "w") as z:
        for root, dirs, files in os.walk("pbw_tmp"):
                for file in files:
                    z.write(os.path.join(root, file), os.path.join(root, file).replace("pbw_tmp/", ""))



patch_and_repack_pbw("qibla.pbw", "qibla.patched.pbw")


