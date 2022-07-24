from rockgarden.binary_patch import BinaryPatcher
from rockgarden.platforms import AplitePlatform, BasaltPlatform, ChalkPlatform, DioritePlatform
from .stm32_crc import crc32
import os
import shutil
import zipfile
import json
import logging
logger = logging.getLogger(__name__)


class Patcher:
    _platforms = (AplitePlatform, BasaltPlatform, ChalkPlatform, DioritePlatform)

    def __init__(self, scratch_dir=".pebble-patch-tmp"):
        # Set up the scratch directory
        self._scratch_dir = scratch_dir
        if not os.path.exists(self._scratch_dir):
            os.mkdir(self._scratch_dir)

    def _update_manifest(self, platform_dir):
        # Ripped from the SDK
        def stm32crc(path):
            with open(path,'r+b')as f:
                binfile=f.read()
                return crc32(binfile)&0xFFFFFFFF

        manifest_path = os.path.join(platform_dir, "manifest.json")
        if not os.path.exists(manifest_path):
            return
        manifest_obj = json.loads(open(manifest_path, "r+").read())

        assets = (("application", "pebble-app.bin"), ("worker", "pebble-worker.bin"))
        for manifest_key, filename in assets:
            asset_path = os.path.join(platform_dir, filename)
            if os.path.exists(asset_path):
                bin_crc = stm32crc(asset_path)
                manifest_obj[manifest_key]["crc"] = bin_crc
                manifest_obj[manifest_key]["size"] = os.stat(asset_path).st_size
        open(os.path.join(platform_dir, "manifest.json"), "w").write(json.dumps(manifest_obj))

    def _update_appinfo(self, app_dir, new_uuid=None, new_app_type=None):
        appinfo_obj = json.loads(open(os.path.join(app_dir, "appinfo.json"), "r+").read())

        if new_uuid:
            appinfo_obj["uuid"] = str(new_uuid)

        if new_app_type:
            appinfo_obj.setdefault("watchapp", {})["watchface"] = new_app_type == "watchface"

        # Inspect which platforms we support automatically, and paste them in
        appinfo_obj["targetPlatforms"] = []
        for platform in Patcher._platforms:
            if os.path.exists(os.path.join(app_dir, platform.directory, "pebble-app.bin")):
                appinfo_obj["targetPlatforms"].append(platform.name)

        open(os.path.join(app_dir, "appinfo.json"), "w").write(json.dumps(appinfo_obj))

    def patch_pbw(self, pbw_path, pbw_out_path, c_sources=None, js_sources=None, cflags=None, new_uuid=None, new_app_type=None, ensure_platforms=()):
        pbw_tmp_dir = os.path.join(self._scratch_dir, "pbw")
        if os.path.exists(pbw_tmp_dir):
            shutil.rmtree(pbw_tmp_dir)
        os.mkdir(pbw_tmp_dir)

        assert new_app_type in (None, "watchapp", "watchface"), "new_app_type must be one of None, watchapp, or watchface"

        with zipfile.ZipFile(pbw_path, "r") as z:
            z.extractall(pbw_tmp_dir)

        platform_map = {x.name: x for x in Patcher._platforms}
        # Since we can shuffle around binaries, track where they came from
        binary_provenance = {x.name: x.name for x in Patcher._platforms}

        # Apply ensure_platform fallbacks
        # These are all the files that can ever be in a platform directory
        # If an ensured_platform is missing from the PBW, and one of its fallback_platforms is present, we'll copy these from the latter to the former
        fallback_copy_files = ("app_resources.pbpack", "manifest.json", "pebble-app.bin", "pebble-worker.bin", "layouts.json")
        for ensure_platform in (platform_map.get(platform_name) for platform_name in ensure_platforms):
            if not os.path.exists(os.path.join(pbw_tmp_dir, ensure_platform.directory, "pebble-app.bin")):
                # The PBW is missing this platform
                # Try to copy in one of the fallbacks
                for fallback_platform in (platform_map.get(platform_name) for platform_name in ensure_platform.fallback_platforms):
                    # We check for the primary binary's existence, since other files are optional-ish
                    if os.path.exists(os.path.join(pbw_tmp_dir, fallback_platform.directory, "pebble-app.bin")):
                        os.mkdir(os.path.join(pbw_tmp_dir, ensure_platform.directory))
                        for copy_fn in fallback_copy_files:
                            if os.path.exists(os.path.join(pbw_tmp_dir, fallback_platform.directory, copy_fn)):
                                shutil.copy2(os.path.join(pbw_tmp_dir, fallback_platform.directory, copy_fn), os.path.join(pbw_tmp_dir, ensure_platform.directory, copy_fn))
                        # Update provenance so the defines are correct
                        binary_provenance[ensure_platform.name] = binary_provenance[fallback_platform.name]
                        break

        if c_sources:
            # Actually patch the binaries
            for platform in Patcher._platforms:
                platform_cflags = (cflags if cflags else []) + ["-DRG_ORIGINAL_PLATFORM_%s" % binary_provenance[platform.name].upper()]
                if os.path.exists(os.path.join(pbw_tmp_dir, platform.directory, "pebble-app.bin")):
                    logger.info("Patching %s binary" % platform.name.title())
                    with BinaryPatcher(os.path.join(pbw_tmp_dir, platform.directory, "pebble-app.bin"), platform, scratch_dir=self._scratch_dir) as app_bin_patcher:
                        app_bin_patcher.patch(c_sources, new_uuid, new_app_type, enable_js=True if js_sources else None, cflags=platform_cflags)
                if os.path.exists(os.path.join(pbw_tmp_dir, platform.directory, "pebble-worker.bin")):
                    logger.info("Patching %s worker" % platform.name.title())
                    with BinaryPatcher(os.path.join(pbw_tmp_dir, platform.directory, "pebble-worker.bin"), platform, scratch_dir=self._scratch_dir) as worker_bin_patcher:
                        worker_bin_patcher.patch(c_sources, new_uuid, cflags=platform_cflags)
                # Update CRC of binary
                self._update_manifest(os.path.join(pbw_tmp_dir, platform.directory))

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

        self._update_appinfo(pbw_tmp_dir, new_uuid, new_app_type)

        with zipfile.ZipFile(pbw_out_path, "w", zipfile.ZIP_DEFLATED) as z:
            for root, dirs, files in os.walk(pbw_tmp_dir):
                for file in files:
                    z.write(os.path.join(root, file), os.path.join(root, file).replace(pbw_tmp_dir, ""))
