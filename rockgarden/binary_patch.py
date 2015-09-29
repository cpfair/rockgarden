from rockgarden.exceptions import PatchException
from rockgarden.utils import unhexify, check_replace
from rockgarden.sdk import SDK
from .stm32_crc import crc32
import struct
import os
import subprocess
import logging
import re
logger = logging.getLogger(__name__)

# Taken from the SDK:
# Header offsets for the pebble executable format
STRUCT_VERSION_ADDR = 0x8
LOAD_SIZE_ADDR = 0xe
CRC_ADDR = 0x14
NUM_RELOC_ENTRIES_ADDR = 0x64
OFFSET_ADDR = 0x10
VIRTUAL_SIZE_ADDR = 0x80
STRUCT_SIZE_BYTES = 0x82
JUMP_TABLE_ADDR = 0x5c
UUID_ADDR = 0x68
FLAGS_ADDR = 0x60

# For FLAGS_ADDR
APP_INFO_WATCH_FACE = (1 << 0)
APP_INFO_ALLOW_JS = (1 << 3)


class SizeLimitExceededError(PatchException):
    pass


class CompilationError(PatchException):
    pass


class BinaryPatcher:
    # By the end of this, we should have (in no particular order)
    # - compiled the mod binary with the BSS located at the end of the main app's .bss
    # - have inserted the mod binary between the app header and the main body of the app code
    # - incremented the main app's relocation table entries, and their targets, by the size of the mod binary (so they properly relocate)
    # - incremented the main app's entrypoint similarly
    # - appended the mod's relocation table to the main one (offsetting to account for header, which isn't compiled as part of the mod, unlike a regular app where it's baked in)
    # - updated the app CRC
    # - updated the app UUID and other nonfunctional metadata if requested
    # - updated the virtual size and load_size (both incremented by size of mod's .data+.text+.bss)
    # - patched the main app's jump_to_pbl_function_addr to branch to our proxy (contained within the mod binary)
    # - patched the mod's jump_to_pbl_function_addr to use the main app's jump table address (this is partially achieved in patch_pebble_lib)
    # - increment the header's pointer to the main app's jump table addr placeholder
    # This is /not/ threadsafe

    class EmptyBinaryError(Exception):
        pass

    def __init__(self, pbw_file, platform, scratch_dir):
        self._bin_file = open(pbw_file, "r+b")
        self._platform = platform
        self._scratch_dir = scratch_dir

    def _write_value_at_offset(self, offset, format_str, value):
        self._bin_file.seek(offset)
        self._bin_file.write(struct.pack(format_str, value))

    def _read_value_at_offset(self, offset, format_str):
        self._bin_file.seek(offset)
        data = self._bin_file.read(struct.calcsize(format_str))
        return struct.unpack(format_str, data)

    def _compile(self, infiles, outfile, cflags=None, linkflags=None):
        if not hasattr(infiles, "__iter__"):
            infiles = [infiles]

        cflags = cflags if cflags else []
        linkflags = linkflags if linkflags else []

        if "-c" not in cflags: # To avoid the harmless warning
            infiles = infiles + [self._platform.lib]
        # Common flags
        cflags = [  "-mcpu=%s" % self._platform.arch,
                    "-mthumb",
                    "-fPIC",
                    "-fPIE",
                    "-ffunction-sections",
                    "-fdata-sections",
                    "-std=c99",
                    "-Os",
                    "-nostdlib"] + ["-I%s" % path for path in self._platform.includes] + cflags
        if self._platform.cflags:
            cflags = cflags + self._platform.cflags

        linkflags = ["-e_entry",
                     "--gc-sections"] + linkflags

        linkflags = ["-Wl,%s" % flag for flag in linkflags] # Since we're letting gcc link too
        cmd = [SDK.arm_tool("gcc")] + cflags + linkflags + ["-o", outfile] + infiles
        logger.debug("Compiling with %s" % cmd)
        compile_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        result, _ = compile_proc.communicate()
        if compile_proc.poll():
            raise CompilationError("Compilation failed:\n%s" % result)

    def _compile_mod_user_object(self, infiles, outfile, cflags=None):
        self._compile(infiles, outfile, cflags=["-c"] + (cflags if cflags else[]))

    def _compile_mod_bin(self, infiles, intermdiatefile, outfile, app_addr, bss_addr, bss_section="BSS", cflags=None):
        ldfile_template = open(os.path.join(os.path.dirname(__file__), "mods_layout.template.ld"), "r").read()
        ldfile_template = check_replace(ldfile_template, "@BSS@", hex(bss_addr)) # The end of their BSS, plus what we'll insert
        ldfile_template = check_replace(ldfile_template, "@BSS_SECTION@", bss_section) # Where to put it at all
        ldfile_template = check_replace(ldfile_template, "@APP@", hex(app_addr)) # Where the rest of the app will get mounted
        ldfile_out_path = os.path.join(self._scratch_dir, "mods.ld")
        map_out_path = os.path.join(self._scratch_dir, "mods.map")
        open(ldfile_out_path, "w").write(ldfile_template)
        self._compile(infiles, intermdiatefile, linkflags=["-T" + ldfile_out_path, "-Map,%s,--emit-relocs" % map_out_path], cflags=cflags)
        subprocess.check_call([SDK.arm_tool("objcopy"), "-S", "-R", ".stack", "-R", ".priv_bss", "-R", ".bss", "-O", "binary", intermdiatefile, outfile])

    def _get_nm_output(self, elf_file, raw=False):
        # This is from the SDK
        nm_process=subprocess.Popen([SDK.arm_tool("nm"),elf_file],stdout=subprocess.PIPE)
        nm_output=nm_process.communicate()[0]
        if not nm_output:
            raise BinaryPatcher.EmptyBinaryError()
        nm_output = nm_output.decode("utf-8")
        if raw:
            return nm_output
        nm_output=[line.split()for line in nm_output.splitlines()]
        return nm_output

    def _verify_header(self):
        # Make sure we know what we're dealing with - not that I think the executable header has ever changed
        self._bin_file.seek(0)
        assert self._bin_file.read(8) == b'PBLAPP\0\0', "Invalid main binary header"
        assert self._read_value_at_offset(STRUCT_VERSION_ADDR, "<H")[0] == 16, "Unknown main binary header format"

    def _update_header_extraneous_metadata(self, new_uuid=None, enable_js=None, new_app_type=None):
        # This is all the metadata that generally doesn't matter to actual execution
        if new_uuid:
            self._bin_file.seek(UUID_ADDR)
            self._bin_file.write(new_uuid.bytes)

        app_flags = self._read_value_at_offset(FLAGS_ADDR, "<L")[0]
        if enable_js is not None:
            if enable_js:
                app_flags = app_flags | APP_INFO_ALLOW_JS
            else:
                app_flags = app_flags & ~APP_INFO_ALLOW_JS

        if new_app_type is not None:
            if new_app_type == "watchface":
                app_flags = app_flags | APP_INFO_WATCH_FACE
            else:
                app_flags = app_flags & ~APP_INFO_WATCH_FACE
        self._write_value_at_offset(FLAGS_ADDR, "<L", app_flags)

    def _inspect_mod_proxied_syscalls(self, user_object):
        # Redefining a syscall fcn with __patch appended to the name will cause it to be overridden in the main app
        # This is where we scan for those __patch functions
        try:
            proxied_syscalls_list = re.findall(r"(\w+)__patch", self._get_nm_output(user_object, raw=True))
        except BinaryPatcher.EmptyBinaryError:
            return {}

        proxied_syscalls_map = {}
        for method in proxied_syscalls_list:
            try:
                proxied_syscalls_map[method] = self._platform.syscall_table[method]
            except KeyError:
                raise RuntimeError("__patch method defined for unknown syscall %s" % method)

        return proxied_syscalls_map

    def _inspect_called_syscall_indices(self):
        # Unlike _inspect_mod_proxied_syscalls, we can't just dump the symbols from the stripped binary
        # Instead, we scan for the syscall stubs in assembly
        # Which are of form...
        # 00000234 <window_stack_get_top_window>:
        #  234:   b40f        push    {r0, r1, r2, r3}
        #  236:   4901        ldr r1, [pc, #4]    ; (23c <window_stack_get_top_window+0x8>)
        #         @ The header for this opcode is just 0b11110 - so we don't attempt to match against it
        #  238:   f7ff bf3c   b.w b4 <jump_to_pbl_function>
        #  23c:   00000470    .word   0x00000470 @ This is the syscall index
        # It's not super critical if we "discover" some non-existent syscalls, but we should never under-report calls
        syscall_stub_pattern = unhexify("0fb4 0149")
        called_syscall_indices = set()
        # Can't use regex with a file stream :(
        self._bin_file.seek(0)
        bin_contents = self._bin_file.read()
        for stub_match in re.finditer(syscall_stub_pattern, bin_contents):
            called_syscall_idx = self._read_value_at_offset(stub_match.end() + 4, "<L")[0]
            called_syscall_indices.add(called_syscall_idx)
        return called_syscall_indices

    def _generate_proxy_asm(self, proxied_syscalls_map):
        # We unconditionally redirect all the app's syscalls to ourselves - but we only need to intercept a subset
        # So, we auto-generate some assembly to handle these incoming calls, intercepting some (proxied_syscalls_map)
        # ...while letting the rest pass through to the system unperturbed
        proxy_switch_body = []
        proxy_fcns_body = []
        # The matching is based on syscall index
        # Rather than LDR a fresh index for every check, we try to use ADD with an immediate value (where possible)
        last_idx = min(proxied_syscalls_map.values())
        written_base = False
        for method_name, method_idx in sorted(proxied_syscalls_map.items(), key=lambda tup: tup[1]):
            # First, we generate the switch that will branch to our proxy function
            if method_idx - last_idx > 255:
                written_base = False
                last_idx = method_idx
            if not written_base:
                written_base = True
                proxy_switch_body.append("    ldr r2, =%s" % hex(last_idx))
            if method_idx - last_idx:
                proxy_switch_body.append("    add r2, r2, #%s" % hex(method_idx - last_idx))
            last_idx = method_idx
            proxy_switch_body.append("    cmp r2, r1\n    beq %s @ syscall index %d" % (method_name + "__proxy", method_idx))
            # Then, the proxy routine itself - which simply branches to the mod's corresponding __patch C function
            proxy_fcns_body.append(".type %s function\n%s:\n    pop {r0, r1, r2, r3}\n    b %s" % (method_name + "__proxy", method_name + "__proxy", method_name + "__patch"))

        # These get dropped into a template
        proxy_asm = open(os.path.join(os.path.dirname(__file__), "mods_proxy.template.s"), "r").read()
        proxy_asm = check_replace(proxy_asm, "@PROXY_SWITCH_BODY@", "\n".join(proxy_switch_body))
        proxy_asm = check_replace(proxy_asm, "@PROXY_FCNS_BODY@", "\n".join(proxy_fcns_body))
        return proxy_asm

    def _offset_main_relocation_table(self, table_location, offset):
        # As part of the patch, we shift the app's code within the executable to make room for the mod's
        # So, we need to rewrite the app's relocation table to reflect this offset
        main_reloc_table_size = self._read_value_at_offset(NUM_RELOC_ENTRIES_ADDR, "<L")[0]
        logger.info("Rewriting %d relocation entries from main binary by offset %x", main_reloc_table_size, offset)
        for entry_idx in range(main_reloc_table_size):
            target_addr = self._read_value_at_offset(table_location + entry_idx * 4, "<L")[0]
            target_value = self._read_value_at_offset(target_addr, "<L")[0]
            target_value += offset
            self._write_value_at_offset(target_addr, "<L", target_value)
            self._write_value_at_offset(table_location + entry_idx * 4, "<L", target_addr + offset)

    def patch(self, mod_sources, new_uuid=None, new_app_type=None, enable_js=None, cflags=None):
        # Make sure the platform binaries are ready to go
        if not self._platform.patched:
            self._platform.patch(scratch_dir=self._scratch_dir)

        # The following functions are stolen from SDK:
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
        def get_symbol_addr(nm_output,symbol):
            for sym in nm_output:
                if symbol==sym[-1]and len(sym)==3:
                    return int(sym[0],16)
            raise Exception("Could not locate symbol <%s> in binary! Failed to inject app metadata"%(symbol))

        # Make sure this really is a Pebble binary, or at least claims to be
        self._verify_header()

        # Figure out the end of the .data+.text section (immediately before relocs) in the main app
        load_size = self._read_value_at_offset(LOAD_SIZE_ADDR, "<H")[0]
        # ...and the end of .data+.text+.bss (which includes the relocation table, which we will relocate to the end of the binary)
        virtual_size = self._read_value_at_offset(VIRTUAL_SIZE_ADDR, "<H")[0]
        main_entrypoint = self._read_value_at_offset(OFFSET_ADDR, "<L")[0]
        jump_table = self._read_value_at_offset(JUMP_TABLE_ADDR, "<L")[0]
        logger.info("Main binary:\n\tLoad size\t%x\n\tVirt size\t%x\n\tEntry pt\t%x\n\tJump tbl\t%x", load_size, virtual_size, main_entrypoint, jump_table)

        # We rewrite the UUID, etc. here since, if the patch binary is empty, we'll bail quite soon after this point
        self._update_header_extraneous_metadata(new_uuid=new_uuid, new_app_type=new_app_type, enable_js=enable_js)

        # Prep the mods by compiling the user code so we can see which functions they wish to patch (proxied_syscalls)
        mod_user_object_path = os.path.join(self._scratch_dir, "mods_user.o")
        self._compile_mod_user_object(mod_sources, mod_user_object_path, cflags=cflags)
        proxied_syscalls = self._inspect_mod_proxied_syscalls(mod_user_object_path)
        if not proxied_syscalls:
            logger.warning("Patch binary exports no __patch methods - nothing to do")
            return

        # We know which syscalls they want to patch - but which does the app actually use?
        # (we only want to include the intersection, for obvious reasons)
        called_syscall_indices = self._inspect_called_syscall_indices()
        applicable_proxied_syscalls = {}
        for method_name, method_idx in proxied_syscalls.items():
            if method_idx in called_syscall_indices:
                applicable_proxied_syscalls[method_name] = method_idx
            else:
                logger.debug("Discarding %s (%d) - not called by main app" % (method_name, method_idx))

        if not applicable_proxied_syscalls:
            logger.warning("All __patch functions in patch binary discarded - nothing to do")
            return

        # Now that we know which syscalls they will end up patching (applicable_proxied_syscalls), generate the assembly used to redirect those calls
        proxy_asm_path = os.path.join(self._scratch_dir, "mods_proxy.s")
        open(proxy_asm_path, "w").write(self._generate_proxy_asm(applicable_proxied_syscalls))

        # Compile the final binary once, since we need to know its dimensions to set the BSS section correctly the second time around
        mod_link_sources = [mod_user_object_path, proxy_asm_path]
        mods_final_intermediate_path = os.path.join(self._scratch_dir, "mods_final.o")
        mods_final_path = os.path.join(self._scratch_dir, "mods_final.bin")
        self._compile_mod_bin(mod_link_sources, mods_final_intermediate_path, mods_final_path, app_addr=0x00, bss_addr=0x00, bss_section="APP", cflags=cflags)

        # Then, compile it again with the BSS set to the end of the virtual_size (i.e. the eventual end of the main app's bss), now that we know it
        # This is a bit sketch since, in order to know the final virtual_size, we need to know the size of the mod's code and BSS
        # ...which requires compiling it
        # ...so I hope the size doesn't somehow change when we move the BSS (it shouldn't, it looks like all BSS stuff is ending up in the GOT)
        # We also need some word-alignment padding to make things work properly in ARM-land
        mod_true_load_size = os.stat(mods_final_path).st_size # Without the padding
        mod_pre_pad = 2
        mod_post_pad = (4 - (mod_true_load_size + mod_pre_pad) % 4) if (mod_true_load_size + mod_pre_pad) % 4 != 0 else 0
        mod_load_size = mod_true_load_size + mod_pre_pad + mod_post_pad # With the padding, which we actually insert at a later point
        mod_virtual_size = get_virtual_size(mods_final_intermediate_path) + mod_pre_pad + mod_post_pad
        logger.info("Patch binary:\n\tLoad size\t%x\n\tVirt size\t%x\n\tPrec Pad\t%x\n\tPost pad\t%x", mod_load_size, mod_virtual_size, mod_pre_pad, mod_post_pad)
        self._compile_mod_bin(mod_link_sources, mods_final_intermediate_path, mods_final_path, app_addr=STRUCT_SIZE_BYTES + mod_pre_pad, bss_addr=virtual_size + mod_load_size, cflags=cflags)
        # Load it in again, and check that the size didn't change on us
        mod_binary = open(mods_final_path, "rb").read()
        assert len(mod_binary) == mod_true_load_size, "Mod binary size changed after relocating BSS/APP sections"
        mod_binary = b'\0' * mod_pre_pad + mod_binary + b'\0' * mod_post_pad

        # Update their relocation table's entries and targets by the amount we're about to insert between the header and the main app
        self._offset_main_relocation_table(table_location=load_size, offset=mod_load_size)

        # Now that it's updated, grab the code and the relocation table separately as we're soon to overwrite both
        self._bin_file.seek(STRUCT_SIZE_BYTES)
        main_binary = self._bin_file.read(load_size - STRUCT_SIZE_BYTES)
        main_reloc_table = self._bin_file.read()

        # Find jump_to_pbl_function in the main app - this is what we modify to redirect the app's syscalls
        jump_to_pbl_function_signature = unhexify("03 A3 18 68 08 44 02 68 94 46 0F BC 60 47 00 BF A8 A8 A8 A8")
        jump_to_pbl_function_addr = main_binary.index(jump_to_pbl_function_signature)
        # Replace it with something that still reads the offset table addr (we want that), but immediately branches to the the address we specify (our jump_to_pbl_function__proxy)
        mod_binary_nm_output = self._get_nm_output(mods_final_intermediate_path)
        mod_syscall_proxy_addr = get_symbol_addr(mod_binary_nm_output, "jump_to_pbl_function__proxy")
        mod_syscall_proxy_jmp_addr = mod_syscall_proxy_addr + 1 # +1 to indicate THUMB 16-bit instruction
        replacement_fcn = unhexify("03 A3 18 68 00 4A 10 47") + struct.pack("<L", mod_syscall_proxy_jmp_addr) + unhexify("00 BF 00 BF A8 A8 A8 A8")
        main_binary = check_replace(main_binary, jump_to_pbl_function_signature, replacement_fcn)
        logger.info("Patching main binary jump routine at %x to use proxy at %x", jump_to_pbl_function_addr, mod_syscall_proxy_addr)

        # That's half of the job done - the app's syscalls now get sent to the mod - but where do the mod's syscalls go?
        # We need to update the mod's binary with the (eventual) address of the main app's jump table address placeholder
        # (in platforms.py we patched libpebble to follow this address to find the correct syscall destination)
        mod_jump_table_ptr_addr = None
        try:
            mod_jump_table_ptr_addr = mod_binary.index(unhexify("a8a8a8a8"))
        except ValueError:
            logger.info("Patch binary does not make any SDK calls, no need to patch its jump indirection value")
        else:
            relocated_main_jump_table = jump_table + mod_load_size
            logger.info("Writing patch binary's jump indirection value at %x to %x", mod_jump_table_ptr_addr, relocated_main_jump_table)
            mod_binary = check_replace(mod_binary, unhexify("a8a8a8a8"), struct.pack("<L", relocated_main_jump_table))


        # Now we can rewrite the entire binary from scratch (ish)
        self._bin_file.seek(STRUCT_SIZE_BYTES)
        # First, insert the mod binary
        self._bin_file.write(mod_binary)
        # Then their binary and relocation table
        self._bin_file.write(main_binary)
        self._bin_file.write(main_reloc_table)
        # And the mod's relocation table
        mod_reloc_entries = get_relocate_entries(mods_final_intermediate_path)
        logger.info("Appending %d relocation entries from patch binary", len(mod_reloc_entries))
        for entry in mod_reloc_entries:
            self._bin_file.write(struct.pack('<L',entry))

        # And finally, some predefined relocation entries for our proxy infrastructure
        # (we're adding STRUCT_SIZE_BYTES by hand since our mod binary doesn't include the header struct, while the final binary does)
        infr_reloc_entries = []
        infr_reloc_entries.append(STRUCT_SIZE_BYTES + mod_load_size + jump_to_pbl_function_addr + 8) # For their jump to our proxy
        if mod_jump_table_ptr_addr:
            infr_reloc_entries.append(STRUCT_SIZE_BYTES + mod_jump_table_ptr_addr) # For our jump table indirection ptr thing
        logger.debug("Appending %d infrastructure relocation entries" % len(infr_reloc_entries))
        for entry in mod_reloc_entries:
            self._bin_file.write(struct.pack('<L',entry))

        # Make sure we're not breaking the rules
        if self._bin_file.tell() > self._platform.max_binary_size:
            raise SizeLimitExceededError("Binary exceeds maximum size of %d bytes, is %d bytes" % (self._platform.max_binary_size, self._bin_file.tell()))

        # Update the executable header to reflect our changes
        final_entrypoint = main_entrypoint + mod_load_size
        final_jump_table = jump_table + mod_load_size
        final_virtual_size = virtual_size + mod_virtual_size
        final_load_size = load_size + mod_load_size
        logger.info("Final binary:\n\tLoad size\t%x\n\tVirt size\t%x\n\tEntry pt\t%x\n\tJump tbl\t%x", final_load_size, final_virtual_size, final_entrypoint, final_jump_table)
        if final_virtual_size > self._platform.max_memory_size:
            raise SizeLimitExceededError("App exceeds memory limit of %d bytes, is %d bytes" % (self._platform.max_memory_size, final_virtual_size))

        main_reloc_table_size = self._read_value_at_offset(NUM_RELOC_ENTRIES_ADDR, "<L")[0]
        final_crc = crc32(mod_binary + main_binary)
        logger.debug("Final CRC: %d" % final_crc)

        self._write_value_at_offset(CRC_ADDR, "<L", final_crc)
        self._write_value_at_offset(NUM_RELOC_ENTRIES_ADDR, "<L", main_reloc_table_size + len(mod_reloc_entries))
        self._write_value_at_offset(OFFSET_ADDR, "<L", final_entrypoint)
        self._write_value_at_offset(VIRTUAL_SIZE_ADDR, "<H", final_virtual_size)
        self._write_value_at_offset(LOAD_SIZE_ADDR, "<H", final_load_size)
        self._write_value_at_offset(JUMP_TABLE_ADDR, "<L", final_jump_table)

        assert mod_syscall_proxy_addr % 4 == 0, "Mod code not word-aligned, falls at %x" % (mod_syscall_proxy_addr + STRUCT_SIZE_BYTES)
