from rockgarden.utils import check_replace, unhexify
from rockgarden.sdk import SDK
import subprocess
import os
import logging
import re
logger = logging.getLogger(__name__)


class Platform:
    def __init__(self, name, arch, includes, lib, max_binary_size, max_memory_size, cflags=[]):
        self.name = name
        self.arch = arch
        self.includes = includes
        self.lib = lib
        self.max_binary_size = max_binary_size
        self.max_memory_size = max_memory_size
        self.cflags = cflags
        self._syscall_table = None # Lazy-loaded
        self._patched = False

    def patch(self, scratch_dir):
        def patch_pebble_header(src, dest):
            header = open(src, "r", encoding="utf-8").read()
            header = check_replace(header, '#include "src/resource_ids.auto.h"', '')
            open(dest, "w", encoding="utf-8").write(header)

        def patch_pebble_lib(src, dest):
            # We take advantage of a fortuitous nop at the end of this method to insert another LDR command
            # Thus adding another layer of indirection, such that we only need to swap the table address out with the address of the main app's placeholder, not the table itself
            pre  = "03 A3 18 68 08 44 02 68 94 46 0F BC 60 47 00 BF A8 A8 A8 A8"
            post = "03 A3 18 68 00 68 08 44 02 68 94 46 0F BC 60 47 A8 A8 A8 A8"
            pre, post = (unhexify(item) for item in (pre, post))
            bin_contents = open(src, "rb").read()
            bin_contents = check_replace(bin_contents, pre, post)
            open(dest, "wb").write(bin_contents)

        dest_dir = os.path.join(scratch_dir, self.name)
        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)

        new_header_path = os.path.join(dest_dir, "pebble.h")
        patch_pebble_header(os.path.join(self.includes[0], "pebble.h"), new_header_path)
        self.includes.insert(0, dest_dir) # So it gets picked first, falling back to the real dir otherwise

        new_lib_path = os.path.join(dest_dir, "libpebble.patched.a")
        patch_pebble_lib(self.lib, new_lib_path)
        self.lib = new_lib_path
        self._patched = True

    @property
    def patched(self):
        return self._patched

    @property
    def syscall_table(self):
        if not self._syscall_table:
            self._syscall_table = {}
            libpebble_dsm_output = subprocess.check_output([SDK.arm_tool("objdump"), "-d", self.lib]).decode("utf-8")
            for call_match in re.finditer(r"<(?P<fcn>[^>]+)>:(?:\n.+){4}8:\s*(?P<idx>[0-9a-f]{8})", libpebble_dsm_output):
                self._syscall_table[call_match.group("fcn")] = int(call_match.group("idx"), 16)
            logger.info("Read %d syscall table entries for %s", len(self.syscall_table.items()), self.name)
        return self._syscall_table


AplitePlatform = Platform(  "aplite", "cortex-m3",
                            includes=[os.path.join(SDK.path(), "Pebble", "aplite", "include")],
                            lib=os.path.join(SDK.path(), "Pebble", "aplite", "lib", "libpebble.a"),
                            max_memory_size=0x6000,
                            max_binary_size=0x10000,
                            cflags=["-DPBL_PLATFORM_APLITE", "-DPBL_BW"])
BasaltPlatform = Platform(  "basalt", "cortex-m4",
                            includes=[os.path.join(SDK.path(), "Pebble", "basalt", "include")],
                            lib=os.path.join(SDK.path(), "Pebble", "basalt", "lib", "libpebble.a"),
                            max_memory_size=0x10000,
                            max_binary_size=0x10000,
                            cflags=["-DPBL_PLATFORM_BASALT", "-DPBL_COLOR", "-D_TIME_H_"])
