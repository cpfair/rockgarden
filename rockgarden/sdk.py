import os
import subprocess


class SDK:
    @classmethod
    def path(cls):
        if os.environ.get("PBL_SDK_DIR", None):
            return os.path.join(os.environ.get("PBL_SDK_DIR"))
        if not hasattr(cls, "_path"):
            try:
                cls._path = os.path.dirname(os.path.dirname(os.path.join(subprocess.check_output(["which", "pebble"]).decode("utf-8").strip())))
            except subprocess.CalledProcessError:
                raise RuntimeError("pebble command-line tool not found in PATH")
        return cls._path

    @classmethod
    def arm_tool(cls, tool):
        return os.path.join(cls.path(), "arm-cs-tools", "bin", "arm-none-eabi-%s" % tool)
