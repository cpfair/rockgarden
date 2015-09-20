from .stm32_crc import crc32
import subprocess
import struct
import os
import shutil
import zipfile
import json
import re
import logging
import codecs

__all__ = ["Patcher", "PatchException", "SizeLimitExceededError"]

logger = logging.getLogger(__name__)

STRUCT_VERSION_ADDR=0x8
LOAD_SIZE_ADDR=0xe
CRC_ADDR=0x14
NUM_RELOC_ENTRIES_ADDR=0x64
OFFSET_ADDR=0x10
VIRTUAL_SIZE_ADDR=0x80
STRUCT_SIZE_BYTES=0x82
JUMP_TABLE_ADDR=0x5c
UUID_ADDR=0x68

def check_replace(obj, find, replace):
    old_obj = obj
    obj = obj.replace(find, replace)
    assert old_obj != obj, "Failed to find %s in %s to replace" % (obj, find)
    return obj

def unhexify(str):
    return codecs.decode(str.replace(" ", ""), "hex")


class SDK:
    @classmethod
    def path(cls):
        if not hasattr(cls, "_path"):
            try:
                cls._path = os.path.dirname(os.path.dirname(os.path.join(subprocess.check_output(["which", "pebble"]).decode("utf-8").strip())))
            except subprocess.CalledProcessError:
                raise RuntimeError("pebble command-line tool not found in PATH")
        return cls._path

    @classmethod
    def arm_tool(cls, tool):
        return os.path.join(cls.path(), "arm-cs-tools", "bin", "arm-none-eabi-%s" % tool)


class Platform:
    def __init__(self, name, arch, includes, lib, max_binary_size, max_memory_size, cflags=[], scratch_dir=".pbw-patch-platform-tmp"):
        self.name = name
        self.arch = arch
        self.includes = includes
        self.lib = lib
        self.max_binary_size = max_binary_size
        self.max_memory_size = max_memory_size
        self.cflags = cflags
        self._scratch_dir = scratch_dir
        if not os.path.exists(scratch_dir):
            os.makedirs(scratch_dir)
        self._patch()
        self._load_syscall_table()

    def _patch(self):
        def patch_pebble_header(src, dest):
            header = open(src, "r").read()
            header = check_replace(header, '#include "src/resource_ids.auto.h"', '')
            open(dest, "w").write(header)

        def patch_pebble_lib(src, dest):
            # We take advantage of a fortuitous nop at the end of this method to insert another LDR command
            # Thus adding another layer of indirection, such that we only need to swap the table address out with the address of the main app's placeholder, not the table itself
            pre  = "03 A3 18 68 08 44 02 68 94 46 0F BC 60 47 00 BF A8 A8 A8 A8"
            post = "03 A3 18 68 00 68 08 44 02 68 94 46 0F BC 60 47 A8 A8 A8 A8"
            pre, post = (unhexify(item) for item in (pre, post))
            bin_contents = open(src, "rb").read()
            bin_contents = check_replace(bin_contents, pre, post)
            open(dest, "wb").write(bin_contents)

        dest_dir = os.path.join(self._scratch_dir, self.name)
        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)

        new_header_path = os.path.join(dest_dir, "pebble.h")
        patch_pebble_header(os.path.join(self.includes[0], "pebble.h"), new_header_path)
        self.includes.insert(0, dest_dir) # So it gets picked first, falling back to the real dir otherwise

        new_lib_path = os.path.join(dest_dir, "libpebble.patched.a")
        patch_pebble_lib(self.lib, new_lib_path)
        self.lib = new_lib_path

    def _load_syscall_table(self):
        self.syscall_table = {}
        libpebble_dsm_output = subprocess.check_output([SDK.arm_tool("objdump"), "-d", self.lib]).decode("utf-8")
        for call_match in re.finditer(r"<(?P<fcn>[^>]+)>:(?:\n.+){4}8:\s*(?P<idx>[0-9a-f]{8})", libpebble_dsm_output):
            self.syscall_table[call_match.group("fcn")] = int(call_match.group("idx"), 16)
        logger.info("Read %d syscall table entries for %s", len(self.syscall_table.items()), self.name)


class PatchException(Exception):
    pass


class SizeLimitExceededError(PatchException):
    pass


class Patcher:
    def __init__(self, scratch_dir=".pebble-patch-tmp"):
        # Set up the scratch directory
        self._scratch_dir = scratch_dir
        if not os.path.exists(self._scratch_dir):
            os.mkdir(self._scratch_dir)

        # Prepare the SDK for compilation (we only need to do this once, really)
        if not getattr(Patcher, "_platforms", None):
            Patcher._platforms = {
                "aplite": Platform( "aplite", "cortex-m3",
                                    includes=[os.path.join(SDK.path(), "Pebble", "aplite", "include")],
                                    lib=os.path.join(SDK.path(), "Pebble", "aplite", "lib", "libpebble.a"),
                                    max_memory_size=0x6000,
                                    max_binary_size=0x10000,
                                    cflags=["-DPBL_PLATFORM_APLITE", "-DPBL_BW"],
                                    scratch_dir=self._scratch_dir),
                "basalt": Platform( "basalt", "cortex-m4",
                                    includes=[os.path.join(SDK.path(), "Pebble", "basalt", "include")],
                                    lib=os.path.join(SDK.path(), "Pebble", "basalt", "lib", "libpebble.a"),
                                    max_memory_size=0x10000,
                                    max_binary_size=0x10000,
                                    cflags=["-DPBL_PLATFORM_BASALT", "-DPBL_COLOR", "-D_TIME_H_"],
                                    scratch_dir=self._scratch_dir)
            }

    def _compile(self, infiles, outfile, platform, cflags=None, linkflags=None):
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
                    "-Os",
                    "-nostdlib"] + ["-I%s" % path for path in platform.includes] + cflags
        if platform.cflags:
            cflags = cflags + platform.cflags

        linkflags = ["-e_entry",
                     "--gc-sections"] + linkflags

        linkflags = ["-Wl,%s" % flag for flag in linkflags] # Since we're letting gcc link too
        cmd = [SDK.arm_tool("gcc")] + cflags + linkflags + ["-o", outfile] + infiles
        logger.debug("Compiling with %s" % cmd)
        subprocess.check_call(cmd)

    def _compile_mod_user_object(self, infiles, outfile, platform, cflags=None):
        self._compile(infiles, outfile, platform, cflags=["-c"] + (cflags if cflags else[]))

    def _compile_mod_bin(self, infiles, intermdiatefile, outfile, platform, app_addr, bss_addr, bss_section="BSS", cflags=None):
        ldfile_template = open(os.path.join(os.path.dirname(__file__), "mods_layout.template.ld"), "r").read()
        ldfile_template = check_replace(ldfile_template, "@BSS@", hex(bss_addr)) # The end of their BSS, plus what we'll insert
        ldfile_template = check_replace(ldfile_template, "@BSS_SECTION@", bss_section) # Where to put it at all
        ldfile_template = check_replace(ldfile_template, "@APP@", hex(app_addr)) # Where the rest of the app will get mounted
        ldfile_out_path = os.path.join(self._scratch_dir, "mods.ld")
        map_out_path = os.path.join(self._scratch_dir, "mods.map")
        open(ldfile_out_path, "w").write(ldfile_template)
        self._compile(infiles, intermdiatefile, platform, linkflags=["-T" + ldfile_out_path, "-Map,%s,--emit-relocs" % map_out_path], cflags=cflags)
        subprocess.check_call([SDK.arm_tool("objcopy"), "-S", "-R", ".stack", "-R", ".priv_bss", "-R", ".bss", "-O", "binary", intermdiatefile, outfile])

    def _patch_bin(self, mod_sources, bin_file_path, platform, new_uuid=None, cflags=None):
        # By the end of this, we should have (in no particular order)
        # - compiled the mod binary with the BSS located at the end of the main app's .bss
        # - have inserted the mod binary between the app header and the main body of the app code
        # - incremented the main app's relocation table entries, and their targets, by the size of the mod binary (so they properly relocate)
        # - incremented the main app's entrypoint similarly
        # - appended the mod's relocation table to the main one (offsetting to account for header, which isn't compiled as part of the mod, unlike a regular app where it's baked in)
        # - updated the app CRC
        # - updated the virtual size and load_size (both incremented by size of mod's .data+.text+.bss)
        # - patched the main app's jump_to_pbl_function_addr to branch to our proxy (contained within the mod binary)
        # - patched the mod's jump_to_pbl_function_addr to use the main app's jump table address (this is partially achieved in patch_pebble_lib)
        # - increment the header's pointer to the main app's jump table addr placeholder

        # The following functions are stolen from SDK:
        def write_value_at_offset(offset, format_str, value):
            bin_file.seek(offset)
            bin_file.write(struct.pack(format_str, value))
        def read_value_at_offset(offset, format_str):
            bin_file.seek(offset)
            data = bin_file.read(struct.calcsize(format_str))
            return struct.unpack(format_str, data)
        def get_virtual_size(elf_file):
            readelf_bss_process=subprocess.Popen([SDK.arm_tool("readelf"), "-S", elf_file], stdout=subprocess.PIPE)
            readelf_bss_output=readelf_bss_process.communicate()[0].decode("utf-8")
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
            readelf_relocs_process=subprocess.Popen([SDK.arm_tool("readelf"),'-r',elf_file],stdout=subprocess.PIPE)
            readelf_relocs_output=readelf_relocs_process.communicate()[0].decode("utf-8")
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
            readelf_relocs_process=subprocess.Popen([SDK.arm_tool("readelf"),'--sections',elf_file],stdout=subprocess.PIPE)
            readelf_relocs_output=readelf_relocs_process.communicate()[0].decode("utf-8")
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
            nm_process=subprocess.Popen([SDK.arm_tool("nm"),elf_file],stdout=subprocess.PIPE)
            nm_output=nm_process.communicate()[0]
            if not nm_output:
                raise RuntimeError("Invalid binary")
            nm_output = nm_output.decode("utf-8")
            if raw:
                return nm_output
            nm_output=[line.split()for line in nm_output.splitlines()]
            return nm_output
        def get_symbol_addr(nm_output,symbol):
            for sym in nm_output:
                if symbol==sym[-1]and len(sym)==3:
                    return int(sym[0],16)
            raise Exception("Could not locate symbol <%s> in binary! Failed to inject app metadata"%(symbol))

        # Open the binary
        # I guess I could do this all in memory but oh well
        bin_file = open(bin_file_path, "r+b")

        # Make sure we know what we're dealing with
        assert bin_file.read(8) == b'PBLAPP\0\0', "Invalid main binary header"
        assert read_value_at_offset(STRUCT_VERSION_ADDR, "<H")[0] == 16, "Unknown main binary header format"
        # Figure out the end of the .data+.text section (immediately before relocs) in the main app
        load_size = read_value_at_offset(LOAD_SIZE_ADDR, "<H")[0]
        # ...and the end of .data+.text+.bss (which includes the relocation table, which we will relocate to the end of the binary)
        virtual_size = read_value_at_offset(VIRTUAL_SIZE_ADDR, "<H")[0]
        main_entrypoint = read_value_at_offset(OFFSET_ADDR, "<L")[0]
        jump_table = read_value_at_offset(JUMP_TABLE_ADDR, "<L")[0]
        logger.info("Main binary:\n\tLoad size\t%x\n\tVirt size\t%x\n\tEntry pt\t%x\n\tJump tbl\t%x", load_size, virtual_size, main_entrypoint, jump_table)

        # Prep the mods by compiling the user code so we can see which functions they wish to patch
        mod_user_object_path = os.path.join(self._scratch_dir, "mods_user.o")
        self._compile_mod_user_object(mod_sources, mod_user_object_path, platform, cflags=cflags)

        # Redefining a syscall fcn with __patch appended to the name will cause it to be overridden in the main app
        proxied_syscalls = re.findall(r"(\w+)__patch", get_nm_output(mod_user_object_path, raw=True))
        proxied_syscalls_map = {}
        for method in proxied_syscalls:
            try:
                proxied_syscalls_map[method] = platform.syscall_table[method]
            except KeyError:
                raise RuntimeError("__patch method defined for unknown syscall %s" % method)

        # This __file__ shenanigans will break if someone ever tries to freeze this module, oh well.
        proxy_asm = open(os.path.join(os.path.dirname(__file__), "mods_proxy.template.s"), "r").read()
        proxy_asm_path = os.path.join(self._scratch_dir, "mods_proxy.s")
        proxy_switch_body = ["""    ldr r2, =%s @ %s's index\n    cmp r2, r1\n    beq %s""" % (hex(method_idx), method_name, method_name + "__proxy") for method_name, method_idx in proxied_syscalls_map.items()]
        proxy_asm = check_replace(proxy_asm, "@PROXY_SWITCH_BODY@", "\n".join(proxy_switch_body))
        proxy_fcns_body = [""".type %s function\n%s:\n    pop {r0, r1, r2, r3}\n    b %s""" % (method_name + "__proxy", method_name + "__proxy", method_name + "__patch") for method_name in proxied_syscalls_map.keys()]
        proxy_asm = check_replace(proxy_asm, "@PROXY_FCNS_BODY@", "\n".join(proxy_fcns_body))
        open(proxy_asm_path, "w").write(proxy_asm)


        # Compile the final binary once, since we need to know its dimensions to set the BSS section correctly the second time around
        mod_link_sources = [mod_user_object_path, proxy_asm_path]
        mods_final_intermediate_path = os.path.join(self._scratch_dir, "mods_final.o")
        mods_final_path = os.path.join(self._scratch_dir, "mods_final.bin")
        self._compile_mod_bin(mod_link_sources, mods_final_intermediate_path, mods_final_path, platform, app_addr=0x00, bss_addr=0x00, bss_section="APP", cflags=cflags)

        # Then, Recompile the mods with the BSS set to the end of the virtual_size (i.e. the eventual end of the main app's bss) now that we know it
        # This is a bit sketch since, in order to know the final virtual_size, we need to know the size of the mod's code and BSS
        # ...which requires compiling it
        # ...so I hope the size doesn't somehow change when we move the BSS (it shouldn't, it looks like all BSS stuff is ending up in the GOT)
        mod_true_load_size = os.stat(mods_final_path).st_size # Before padding
        mod_pre_pad = 2 # This breaks everything
        mod_post_pad = 2 if (mod_true_load_size + mod_pre_pad) % 4 != 0 else 0  # ...this fixes it? We need to word-align the mod start, and the main app's entrypoint, for ARM EABI
        mod_load_size = mod_true_load_size + mod_pre_pad + mod_post_pad
        mod_virtual_size = get_virtual_size(mods_final_intermediate_path) + mod_pre_pad + mod_post_pad
        logger.info("Patch binary:\n\tLoad size\t%x\n\tVirt size\t%x\n\tPrec Pad\t%x\n\tPost pad\t%x", mod_load_size, mod_virtual_size, mod_pre_pad, mod_post_pad)

        # With this info, we can also calculate the final values of most stuff
        final_entrypoint = main_entrypoint + mod_load_size
        final_jump_table = jump_table + mod_load_size
        final_virtual_size = virtual_size + mod_virtual_size
        final_load_size = load_size + mod_load_size
        logger.info("Final binary:\n\tLoad size\t%x\n\tVirt size\t%x\n\tEntry pt\t%x\n\tJump tbl\t%x", final_load_size, final_virtual_size, final_entrypoint, final_jump_table)
        if final_virtual_size > platform.max_memory_size:
            raise SizeLimitExceededError("App exceeds memory limit of %d bytes, is %d bytes" % (platform.max_memory_size, final_virtual_size))

        # Recompile & load result
        self._compile_mod_bin(mod_link_sources, mods_final_intermediate_path, mods_final_path, platform, app_addr=STRUCT_SIZE_BYTES + mod_pre_pad, bss_addr=virtual_size + mod_load_size, cflags=cflags)
        mod_binary = open(mods_final_path, "rb").read()
        assert len(mod_binary) == mod_true_load_size, "Mod binary size changed after relocating BSS/APP sections"

        mod_binary = b'\0' * mod_pre_pad + mod_binary + b'\0' * mod_post_pad
        mod_binary_nm_output = get_nm_output(mods_final_intermediate_path)
        mod_reloc_entries = [x for x in get_relocate_entries(mods_final_intermediate_path)]

        # Update the relocation table entries, and their targets, by the amount we're going to insert after the header
        main_reloc_table_size = read_value_at_offset(NUM_RELOC_ENTRIES_ADDR, "<L")[0]
        logger.info("Rewriting %d relocation entries from main binary by offset %x", main_reloc_table_size, mod_load_size)
        for entry_idx in range(main_reloc_table_size):
            target_addr = read_value_at_offset(load_size + entry_idx * 4, "<L")[0]
            target_value = read_value_at_offset(target_addr, "<L")[0]
            logger.debug("Main binary relocation table entry %d points to %x of value %x", entry_idx, target_addr, target_value)
            target_value += mod_load_size
            write_value_at_offset(target_addr, "<L", target_value)
            write_value_at_offset(load_size + entry_idx * 4, "<L", target_addr + mod_load_size)

        # Grab the code, and the relocation table
        bin_file.seek(STRUCT_SIZE_BYTES)
        main_binary = bin_file.read(load_size - STRUCT_SIZE_BYTES)
        main_reloc_table = bin_file.read()
        assert len(main_reloc_table) / 4 == main_reloc_table_size

        # Find jump_to_pbl_function in the main app
        jump_to_pbl_function_signature = unhexify("03 A3 18 68 08 44 02 68 94 46 0F BC 60 47 00 BF A8 A8 A8 A8")
        jump_to_pbl_function_addr = main_binary.index(jump_to_pbl_function_signature)
        assert jump_to_pbl_function_addr
        # Replace with something that still grabs reads the offset table addr, but immediately hands off the the address of the method we specify (the mod's proxy)
        mod_syscall_proxy_addr = get_symbol_addr(mod_binary_nm_output, "jump_to_pbl_function__proxy")
        mod_syscall_proxy_jmp_addr = mod_syscall_proxy_addr + 1 # +1 to indicate THUMB 16-bit instruction
        replacement_fcn = unhexify("03 A3 18 68 00 4A 10 47") + struct.pack("<L", mod_syscall_proxy_jmp_addr) + unhexify("00 BF 00 BF A8 A8 A8 A8")
        assert len(replacement_fcn) == len(jump_to_pbl_function_signature)
        main_binary = check_replace(main_binary, jump_to_pbl_function_signature, replacement_fcn)
        logger.info("Patching main binary jump routine at %x to use proxy at %x", jump_to_pbl_function_addr, mod_syscall_proxy_addr)

        # update the mod's binary with the (eventual) address of the jump table placeholder
        mod_jump_table_ptr_addr = mod_binary.index(unhexify("a8a8a8a8"))
        relocated_main_jump_table = jump_table + mod_load_size
        logger.info("Writing patch binary's jump indirection value at %x to %x", mod_jump_table_ptr_addr, relocated_main_jump_table)
        mod_binary = check_replace(mod_binary, unhexify("a8a8a8a8"), struct.pack("<L", relocated_main_jump_table))

        bin_file.seek(STRUCT_SIZE_BYTES)
        # Insert the mod binary
        bin_file.write(mod_binary)
        # then re-add their binary and relocation table
        bin_file.write(main_binary)
        bin_file.write(main_reloc_table)
        # and, finally, ours (plus the header since we don't compile that in)
        initial_added_reloc_entries_count = len(mod_reloc_entries)
        mod_reloc_entries.append(STRUCT_SIZE_BYTES + mod_load_size + jump_to_pbl_function_addr + 8) # For their jump to our proxy
        mod_reloc_entries.append(STRUCT_SIZE_BYTES + mod_jump_table_ptr_addr) # For our jump table ptr thing
        logger.info("Appending %d additional relocation entries, %d from patch binary", len(mod_reloc_entries), initial_added_reloc_entries_count)
        logger.debug("Additional relocation entries: %s" % mod_reloc_entries)
        for entry in mod_reloc_entries:
            bin_file.write(struct.pack('<L',entry))

        if bin_file.tell() > platform.max_binary_size:
            raise SizeLimitExceededError("Binary exceeds maximum size of %d bytes, is %d bytes" % (platform.max_binary_size, bin_file.tell()))

        # Update the header with the new values
        final_crc = crc32(mod_binary + main_binary)
        logger.debug("Final CRC: %d" % final_crc)
        write_value_at_offset(CRC_ADDR, "<L", final_crc)
        write_value_at_offset(NUM_RELOC_ENTRIES_ADDR, "<L", main_reloc_table_size + len(mod_reloc_entries))
        write_value_at_offset(OFFSET_ADDR, "<L", final_entrypoint)
        write_value_at_offset(VIRTUAL_SIZE_ADDR, "<H", final_virtual_size)
        write_value_at_offset(LOAD_SIZE_ADDR, "<H", final_load_size)
        write_value_at_offset(JUMP_TABLE_ADDR, "<L", final_jump_table)
        # If requested, rewrite UUID
        if new_uuid:
            bin_file.seek(UUID_ADDR)
            bin_file.write(new_uuid.bytes)

        assert final_entrypoint % 4 == 0, "Main entrypoint not byte-aligned"
        assert mod_syscall_proxy_addr % 4 == 0, "Mod code not byte-aligned, falls at %x" % (mod_syscall_proxy_addr + STRUCT_SIZE_BYTES)
        # assert (mod_binary.index(unhexify("044a8a42")) + STRUCT_SIZE_BYTES) == mod_syscall_proxy_addr, "Proxy address reality mismatch"

    def _update_manifest(self, app_dir):
        # Also ripped from the SDK
        def stm32crc(path):
            with open(path,'r+b')as f:
                binfile=f.read()
                return crc32(binfile)&0xFFFFFFFF

        manifest_obj = json.loads(open(os.path.join(app_dir, "manifest.json"), "r+").read())

        bin_crc = stm32crc(os.path.join(app_dir, "pebble-app.bin"))
        manifest_obj["application"]["crc"] = bin_crc
        manifest_obj["application"]["size"] = os.stat(os.path.join(app_dir, "pebble-app.bin")).st_size
        open(os.path.join(app_dir, "manifest.json"), "w").write(json.dumps(manifest_obj))

    def _update_appinfo(self, app_dir, new_uuid):
        appinfo_obj = json.loads(open(os.path.join(app_dir, "appinfo.json"), "r+").read())

        appinfo_obj["uuid"] = str(new_uuid)
        open(os.path.join(app_dir, "appinfo.json"), "w").write(json.dumps(appinfo_obj))

    def patch_pbw(self, pbw_path, pbw_out_path, c_sources=None, js_sources=None, cflags=None, new_uuid=None, ensure_basalt=False):
        pbw_tmp_dir = os.path.join(self._scratch_dir, "pbw")
        if os.path.exists(pbw_tmp_dir):
            shutil.rmtree(pbw_tmp_dir)
        os.mkdir(pbw_tmp_dir)

        with zipfile.ZipFile(pbw_path, "r") as z:
            z.extractall(pbw_tmp_dir)

        if new_uuid:
            self._update_appinfo(pbw_tmp_dir, new_uuid)

        if c_sources:
            # If they want a basalt binary, give them a basalt binary (that's really an Aplite binary)
            # We will probably end up using 3.x features in apps with a pruported SDK version of 1(??)/2 - but I don't think the firmware cares
            # (syscall changes are achieved by creating entirely new syscall indices, not checking the ver #)
            if ensure_basalt and not os.path.exists(os.path.join(pbw_tmp_dir, "basalt")):
                def copy_to_basalt(fn):
                    if os.path.exists(os.path.join(pbw_tmp_dir, fn)):
                        shutil.copy2(os.path.join(pbw_tmp_dir, fn), os.path.join(pbw_tmp_dir, "basalt", fn))
                os.mkdir(os.path.join(pbw_tmp_dir, "basalt"))
                copy_to_basalt("app_resources.pbpack")
                copy_to_basalt("manifest.json")
                copy_to_basalt("pebble-app.bin")

            if os.path.join(pbw_tmp_dir, "pebble-app.bin"):
                logger.info("Patching Aplite binary")
                self._patch_bin(c_sources, os.path.join(pbw_tmp_dir, "pebble-app.bin"), Patcher._platforms["aplite"], new_uuid, cflags=cflags)
                # Update CRC of binary
                self._update_manifest(pbw_tmp_dir)

            if os.path.exists(os.path.join(pbw_tmp_dir, "basalt")):
                logger.info("Patching Basalt binary")
                # Do the same for basalt
                self._patch_bin(c_sources, os.path.join(pbw_tmp_dir, "basalt", "pebble-app.bin"), Patcher._platforms["basalt"], new_uuid, cflags=cflags)
                self._update_manifest(os.path.join(pbw_tmp_dir, "basalt"))

        if js_sources:
            logger.info("Prepending JS sources")
            js_path = os.path.join(pbw_tmp_dir, "pebble-js-app.js")
            existing_js = None
            if os.path.exists(js_path):
                existing_js = open(js_path, "r").read()
            with open(js_path, "w") as js_hnd:
                for source in js_sources:
                    js_hnd.write(open(source, "r").read() + "\n")
                if existing_js:
                    js_hnd.write(existing_js)

        with zipfile.ZipFile(pbw_out_path, "w", zipfile.ZIP_DEFLATED) as z:
            for root, dirs, files in os.walk(pbw_tmp_dir):
                for file in files:
                    z.write(os.path.join(root, file), os.path.join(root, file).replace(pbw_tmp_dir, ""))
