from rockgarden.binary_patch import BinaryPatcher
from rockgarden.platforms import AplitePlatform, BasaltPlatform
from .stm32_crc import crc32
import os
import shutil
import zipfile
import json
import logging
logger = logging.getLogger(__name__)


class Patcher:
    def __init__(self, scratch_dir=".pebble-patch-tmp"):
        # Set up the scratch directory
        self._scratch_dir = scratch_dir
        if not os.path.exists(self._scratch_dir):
            os.mkdir(self._scratch_dir)

    def _update_manifest(self, app_dir):
        # Ripped from the SDK
        def stm32crc(path):
            with open(path,'r+b')as f:
                binfile=f.read()
                return crc32(binfile)&0xFFFFFFFF

        manifest_obj = json.loads(open(os.path.join(app_dir, "manifest.json"), "r+").read())

        bin_crc = stm32crc(os.path.join(app_dir, "pebble-app.bin"))
        manifest_obj["application"]["crc"] = bin_crc
        manifest_obj["application"]["size"] = os.stat(os.path.join(app_dir, "pebble-app.bin")).st_size
        open(os.path.join(app_dir, "manifest.json"), "w").write(json.dumps(manifest_obj))

    def _update_appinfo(self, app_dir, new_uuid=None, new_app_type=None):
        appinfo_obj = json.loads(open(os.path.join(app_dir, "appinfo.json"), "r+").read())

        if new_uuid:
            appinfo_obj["uuid"] = str(new_uuid)

        if new_app_type:
            appinfo_obj.setdefault("watchapp", {})["watchface"] = new_app_type == "watchface"

        open(os.path.join(app_dir, "appinfo.json"), "w").write(json.dumps(appinfo_obj))

    def patch_pbw(self, pbw_path, pbw_out_path, c_sources=None, js_sources=None, cflags=None, new_uuid=None, new_app_type=None, ensure_platforms=()):
        pbw_tmp_dir = os.path.join(self._scratch_dir, "pbw")
        if os.path.exists(pbw_tmp_dir):
            shutil.rmtree(pbw_tmp_dir)
        os.mkdir(pbw_tmp_dir)

        assert new_app_type in (None, "watchapp", "watchface"), "new_app_type must be one of None, watchapp, or watchface"

        with zipfile.ZipFile(pbw_path, "r") as z:
            z.extractall(pbw_tmp_dir)

        if new_uuid or new_app_type:
            self._update_appinfo(pbw_tmp_dir, new_uuid, new_app_type)

        if c_sources:
            if os.path.exists(os.path.join(pbw_tmp_dir, "pebble-app.bin")):
                # If they want a basalt binary, give them a basalt binary (that's really an Aplite binary)
                # We will probably end up using 3.x features in apps with a pruported SDK version of 1(??)/2 - but I don't think the firmware cares
                # (syscall changes are achieved by creating entirely new syscall indices, not checking the ver #)
                if "basalt" in ensure_platforms and not os.path.exists(os.path.join(pbw_tmp_dir, "basalt")):
                    def copy_to_basalt(fn):
                        if os.path.exists(os.path.join(pbw_tmp_dir, fn)):
                            shutil.copy2(os.path.join(pbw_tmp_dir, fn), os.path.join(pbw_tmp_dir, "basalt", fn))
                    os.mkdir(os.path.join(pbw_tmp_dir, "basalt"))
                    copy_to_basalt("app_resources.pbpack")
                    copy_to_basalt("manifest.json")
                    copy_to_basalt("pebble-app.bin")

                logger.info("Patching Aplite binary")
                aplite_bin_patcher = BinaryPatcher(os.path.join(pbw_tmp_dir, "pebble-app.bin"), AplitePlatform, scratch_dir=self._scratch_dir)
                aplite_bin_patcher.patch(c_sources, new_uuid, new_app_type, enable_js=True if js_sources else None, cflags=cflags)
                # Update CRC of binary
                self._update_manifest(pbw_tmp_dir)

            if os.path.exists(os.path.join(pbw_tmp_dir, "basalt")):
                logger.info("Patching Basalt binary")
                # Do the same operations for basalt
                basalt_bin_patcher = BinaryPatcher(os.path.join(pbw_tmp_dir, "basalt", "pebble-app.bin"), BasaltPlatform, scratch_dir=self._scratch_dir)
                basalt_bin_patcher.patch(c_sources, new_uuid, new_app_type, enable_js=True if js_sources else None, cflags=cflags)
                # There are two manifests, one for each platform
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
