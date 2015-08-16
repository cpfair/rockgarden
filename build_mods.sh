cp /Volumes/MacintoshHD/Users/collinfair/pebble-dev/PebbleSDK-current/Pebble/aplite/lib/libpebble.a libpebble_patch.a
python patch_libpebble.py
rm mods.o
rm mods.d
rm mods.map
arm-none-eabi-gcc \
    -mcpu=cortex-m3 \
    -mthumb \
    -fPIC \
    -fPIE \
    -ffunction-sections \
    -fdata-sections \
    -std=c99 \
    -I/Volumes/MacintoshHD/Users/collinfair/pebble-dev/PebbleSDK-current/Pebble/aplite/include \
    -I./ \
    -I./src \
    -nostdlib \
    -Wl,-e_entry \
    -Wl,--gc-sections \
    -Wl,-Map,mods.map \
    -Wl,-Tmods_layout.ld \
    -o mods.o \
    src/mods.c \
    src/mods.s \
    libpebble_patch.a
arm-none-eabi-objdump -D mods.o > mods.d
arm-none-eabi-objcopy -S -R .stack -R .priv_bss -R .bss -O binary mods.o mods.bin