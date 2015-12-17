import os
import subprocess
import re

# We assume it's on the PATH unless instructed otherwise
_pbl_tool_path = os.environ.get("PBL_TOOL_PATH", "pebble")


# For ye olde classic installs without automatic SDK management
class _SDK_Tool3:
    @classmethod
    def _path(cls):
        if not hasattr(cls, "_path"):
            # If they specified a valid path, use it instead of finding it our ourselves
            if os.path.exists(_pbl_tool_path):
                cls._path = os.path.dirname(os.path.dirname(_pbl_tool_path))
            else:
                cls._path = os.path.dirname(os.path.dirname(subprocess.check_output(["which", "pebble"]).decode("utf-8").strip()))
        return cls._path

    @classmethod
    def include_path(cls, platform_name):
        return os.path.join(cls._path(), "Pebble", platform_name, "include")

    @classmethod
    def lib_path(cls, platform_name):
        return os.path.join(cls._path(), "Pebble", platform_name, "lib")

    @classmethod
    def arm_tool(cls, tool):
        return os.path.join(cls._path(), "arm-cs-tools", "bin", "arm-none-eabi-%s" % tool)


# New pebble tool automatically manages SDKs and the ARM tools, making things harder to find
class _SDK_Tool4:
    _include_path_map = {}

    @classmethod
    def include_path(cls, platform_name):
        if platform_name not in cls._include_path_map:
            cls._include_path_map[platform_name] = subprocess.check_output([_pbl_tool_path, "sdk", "include-path", platform_name]).decode("utf-8").split('\n')[0]
        return cls._include_path_map[platform_name]

    @classmethod
    def lib_path(cls, platform_name):
        return os.path.join(os.path.dirname(cls.include_path(platform_name)), "lib")

    @classmethod
    def arm_tool(cls, tool):
        if not hasattr(cls, "_arm_tools_path"):
            # WHeee
            proc = subprocess.Popen([_pbl_tool_path, "analyze-size", "not-a-file"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate()

            cls._arm_tools_path = re.search(r"^(?P<tools_path>.+)arm-none-eabi-nm: '", stderr.decode("utf-8"), re.MULTILINE).group("tools_path")
        return os.path.join(cls._arm_tools_path, "arm-none-eabi-%s" % tool)


class SDK:
    @classmethod
    def _active_sdk(cls):
        if not hasattr(cls, "_sdk"):
            try:
                subprocess.check_output([_pbl_tool_path, "sdk", "list"])
            except subprocess.CalledProcessError as e:
                if e.returncode == 2:
                    # They're using tool 3.x, which doesn't have an "sdk" command
                    cls._sdk = _SDK_Tool3
                else:
                    # Something else is wrong, probably they're missing it
                    raise RuntimeError("pebble command-line tool not found in PATH or PBL_TOOL_PATH")
            else:
                # They're using tool 4.x
                cls._sdk = _SDK_Tool4
        return cls._sdk

    # I guess I could procedurally generate these stubs...
    @classmethod
    def include_path(cls, *args):
        return cls._active_sdk().include_path(*args)

    @classmethod
    def lib_path(cls, *args):
        return cls._active_sdk().lib_path(*args)

    @classmethod
    def arm_tool(cls, *args):
        return cls._active_sdk().arm_tool(*args)
