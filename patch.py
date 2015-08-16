import subprocess
import struct
import os
import shutil
import sys
import stm32_crc
import zipfile
import json
import re

LOAD_SIZE_ADDR=0xe
CRC_ADDR=0x14
NUM_RELOC_ENTRIES_ADDR=0x64
OFFSET_ADDR=0x10
VIRTUAL_SIZE_ADDR=0x80
STRUCT_SIZE_BYTES=0x82
JUMP_TABLE_ADDR=0x5c

scratch_dir = ".build-tmp"
if not os.path.exists(scratch_dir):
    os.mkdir(scratch_dir)


class Platform:
    def __init__(self, name, arch, includes, lib, cflags=None):
        self.name = name
        self.arch = arch
        self.includes = includes
        self.lib = lib
        self.syscall_table = None
        self.cflags = cflags
        self._patch()
        self._load_syscall_table()

    def _patch(self):
        def patch_pebble_header(src, dest):
            header = open(src, "r").read()
            header = header.replace('#include "src/resource_ids.auto.h"', '')
            open(dest, "w").write(header)

        def patch_pebble_lib(src, dest):
            # We take advantage of a fortuitous nop at the end of this method to insert another LDR command
            # Thus adding another layer of indirection, such that we only need to swap the table address out with the address of the main app's placeholder, not the table itself
            pre  = "03 A3 18 68 08 44 02 68 94 46 0F BC 60 47 00 BF A8 A8 A8 A8"
            post = "03 A3 18 68 00 68 08 44 02 68 94 46 0F BC 60 47 A8 A8 A8 A8"
            pre, post = (item.replace(" ", "").decode("hex") for item in (pre, post))
            bin_contents = open(src, "rb").read()
            bin_contents = bin_contents.replace(pre, post)
            open(dest, "wb").write(bin_contents)

        dest_dir = os.path.join(scratch_dir, self.name)
        if not os.path.exists(dest_dir):
            os.mkdir(dest_dir)

        new_header_path = os.path.join(dest_dir, "pebble.h")
        patch_pebble_header(os.path.join(self.includes[0], "pebble.h"), new_header_path)
        self.includes.insert(0, dest_dir) # So it gets picked first, falling back to the real dir otherwise

        new_lib_path = os.path.join(dest_dir, "libpebble.patched.a")
        patch_pebble_lib(self.lib, new_lib_path)
        self.lib = new_lib_path

    def _load_syscall_table(self):
        self.syscall_table = {}
        libpebble_dsm_output = subprocess.check_output(["arm-none-eabi-objdump", "-d", self.lib])
        for call_match in re.finditer(r"<(?P<fcn>[^>]+)>:(?:\n.+){4}8:\s*(?P<idx>[0-9a-f]{8})", libpebble_dsm_output):
            self.syscall_table[call_match.group("fcn")] = int(call_match.group("idx"), 16)

platforms = {
    "aplite": Platform("aplite", "cortex-m3", ["sdk/aplite/include"], "sdk/aplite/lib/libpebble.a"),
    "basalt": Platform("basalt", "cortex-m4", ["sdk/basalt/include"], "sdk/basalt/lib/libpebble.a", ["-D_TIME_H_"])
}

def compile(infiles, outfile, platform, cflags=None, linkflags=None):
    if not hasattr(infiles, "__iter__"):
        infiles = [infiles]

    cflags = cflags if cflags else []
    linkflags = linkflags if linkflags else []

    if "-c" not in cflags: # To avoid the harmless warning
        infiles = infiles + [platform.lib]
    # Common flags
    cflags = [  "-mcpu=%s" % platform.arch,
                "-mthumb",
                "-fPIC",
                "-fPIE",
                "-ffunction-sections",
                "-fdata-sections",
                "-std=c99",
                "-nostdlib"] + ["-I%s" % path for path in platform.includes] + cflags
    if platform.cflags:
        cflags = cflags + platform.cflags

    linkflags = ["-e_entry",
                 "--gc-sections"] + linkflags

    linkflags = ["-Wl,%s" % flag for flag in linkflags] # Since we're letting gcc link too

    subprocess.check_call(["arm-none-eabi-gcc"] + cflags + linkflags + ["-o", outfile] + infiles)

def compile_mod_user_object(infiles, outfile, platform):
    compile(infiles, outfile, platform, cflags=["-c"])

def compile_mod_bin(infiles, intermdiatefile, outfile, platform, app_addr, bss_addr, bss_section="BSS"):
    ldfile_template = open("mods_layout.template.ld", "r").read()
    ldfile_template = ldfile_template.replace("@BSS@", hex(bss_addr)) # The end of their BSS, plus what we'll insert
    ldfile_template = ldfile_template.replace("@BSS_SECTION@", bss_section) # Where to put it at all
    ldfile_template = ldfile_template.replace("@APP@", hex(app_addr)) # Where the rest of the app will get mounted
    ldfile_out_path = os.path.join(scratch_dir, "mods.ld")
    open(ldfile_out_path, "w").write(ldfile_template)
    compile(infiles, intermdiatefile, platform, linkflags=["-T" + ldfile_out_path])
    subprocess.check_call(["arm-none-eabi-objcopy", "-S", "-R", ".stack", "-R", ".priv_bss", "-R", ".bss", "-O", "binary", intermdiatefile, outfile])

def patch_bin(bin_file, platform):
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
    def get_nm_output(elf_file, raw=False):
        nm_process=subprocess.Popen(['arm-none-eabi-nm',elf_file],stdout=subprocess.PIPE)
        nm_output=nm_process.communicate()[0]
        if not nm_output:
            raise RuntimeError("Invalid binary")
        if raw:
            return nm_output
        nm_output=[line.split()for line in nm_output.splitlines()]
        return nm_output
    def get_symbol_addr(nm_output,symbol):
        for sym in nm_output:
            if symbol==sym[-1]and len(sym)==3:
                return int(sym[0],16)
        raise Exception("Could not locate symbol <%s> in binary! Failed to inject app metadata"%(symbol))
    def unhexify(str):
        return str.replace(" ", "").decode("hex")

    # Figure out the end of the .data+.text section (immediately before relocs) in the main app
    load_size = read_value_at_offset(LOAD_SIZE_ADDR, "<H")[0]
    # ...and the end of .data+.text+.bss (which includes the relocation table, which we will relocate to the end of the binary)
    virtual_size = read_value_at_offset(VIRTUAL_SIZE_ADDR, "<H")[0]
    main_entrypoint = read_value_at_offset(OFFSET_ADDR, "<L")[0]
    jump_table = read_value_at_offset(JUMP_TABLE_ADDR, "<L")[0]

    # Prep the mods by compiling the user code so we can see which functions they wish to patch
    mod_user_object_path = os.path.join(scratch_dir, "mods_user.o")
    mod_sources = ["src/mods.c"]
    compile_mod_user_object(mod_sources, mod_user_object_path, platform)

    # Redefining a syscall fcn with __patch appended to the name will cause it to be overridden in the main app
    proxied_syscalls = re.findall(r"(\w+)__patch", get_nm_output(mod_user_object_path, raw=True))
    proxied_syscalls_map = {}
    for method in proxied_syscalls:
        proxied_syscalls_map[method] = platform.syscall_table[method]

    proxy_asm = open("mods_proxy.template.s", "r").read()
    proxy_asm_path = os.path.join(scratch_dir, "mods_proxy.s")
    proxy_switch_body = ["""    ldr r2, =%s @ %s's index\n    cmp r2, r1\n    beq %s""" % (hex(method_idx), method_name, method_name + "__proxy") for method_name, method_idx in proxied_syscalls_map.items()]
    proxy_asm = proxy_asm.replace("@PROXY_SWITCH_BODY@", "\n".join(proxy_switch_body))
    proxy_fcns_body = [""".type %s function\n%s:\n    pop {r0, r1, r2, r3}\n    b %s""" % (method_name + "__proxy", method_name + "__proxy", method_name + "__patch")]
    proxy_asm = proxy_asm.replace("@PROXY_FCNS_BODY@", "\n".join(proxy_fcns_body))
    open(proxy_asm_path, "w").write(proxy_asm)


    # Compile the final binary once, since we need to know its dimensions to set the BSS section correctly the second time around
    mod_link_sources = [mod_user_object_path, proxy_asm_path]
    mods_final_intermediate_path = os.path.join(scratch_dir, "mods_final.o")
    mods_final_path = os.path.join(scratch_dir, "mods_final.bin")
    compile_mod_bin(mod_link_sources, mods_final_intermediate_path, mods_final_path, platform, 0x00, 0x00, "APP")

    # Then, Recompile the mods with the BSS set to the end of the virtual_size (i.e. the eventual end of the main app's bss) now that we know it
    # This is a bit sketch since, in order to know the final virtual_size, we need to know the size of the mod's code and BSS
    # ...which requires compiling it
    # ...so I hope the size doesn't somehow change when we move the BSS (it shouldn't, it looks like all BSS stuff is ending up in the GOT)
    mod_pre_pad = 2 # This breaks everything
    mod_post_pad = 2 # ...this fixes it? We need to word-align the mod start, and the main app's entrypoint, for ARM EABI
    mod_true_load_size = os.stat(mods_final_path).st_size # Before padding
    mod_load_size = mod_true_load_size + mod_pre_pad + mod_post_pad
    mod_virtual_size = get_virtual_size(mods_final_intermediate_path) + mod_pre_pad + mod_post_pad
    final_virtual_size = virtual_size + mod_virtual_size
    final_load_size = load_size + mod_load_size

    # Recompile & load result
    compile_mod_bin(mod_link_sources, mods_final_intermediate_path, mods_final_path, platform, STRUCT_SIZE_BYTES + mod_pre_pad, virtual_size + mod_load_size)
    mod_binary = open(mods_final_path, "rb").read()
    assert len(mod_binary) == mod_true_load_size, "Mod binary size changed after relocating BSS/APP sections"

    mod_binary = chr(0) * mod_pre_pad + mod_binary + chr(0) * mod_post_pad
    mod_binary_nm_output = get_nm_output(mods_final_intermediate_path)
    mod_reloc_entries = [x for x in get_relocate_entries(mods_final_intermediate_path)]

    # Update the relocation table entries, and their targets, by the amount we're going to insert after the header
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
    # assert (mod_binary.index(unhexify("044a8a42")) + STRUCT_SIZE_BYTES) == mod_syscall_proxy_addr, "Proxy address reality mismatch"

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
    manifest_obj["application"]["size"] = os.stat(os.path.join(app_dir, "pebble-app.bin")).st_size
    json.dump(manifest_obj, manifest_file)
    manifest_file.close()

def patch_and_repack_pbw(pbw_path, pbw_out_path):
    pbw_tmp_dir = os.path.join(scratch_dir, "pbw")
    if os.path.exists(pbw_tmp_dir):
        shutil.rmtree(pbw_tmp_dir)
    os.mkdir(pbw_tmp_dir)

    with zipfile.ZipFile(pbw_path, "r") as z:
        z.extractall(pbw_tmp_dir)

    patch_bin(open(os.path.join(pbw_tmp_dir, "pebble-app.bin"), "r+b"), platforms["aplite"])
    # Update CRC of binary
    update_manifest(pbw_tmp_dir)

    # shutil.rmtree(os.path.join(pbw_tmp_dir, "basalt"))

    if os.path.exists(os.path.join(pbw_tmp_dir, "basalt")):
        # Do the same for basalt
        patch_bin(open(os.path.join(pbw_tmp_dir, "basalt", "pebble-app.bin"), "r+b"), platforms["basalt"])
        # Update CRC of binary
        update_manifest(os.path.join(pbw_tmp_dir, "basalt"))
        # pass

    with zipfile.ZipFile(pbw_out_path, "w") as z:
        for root, dirs, files in os.walk(pbw_tmp_dir):
                for file in files:
                    z.write(os.path.join(root, file), os.path.join(root, file).replace(pbw_tmp_dir, ""))



patch_and_repack_pbw("qibla.pbw", "qibla.patched.pbw")


