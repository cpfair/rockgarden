# We take advantage of a fortuitous nop at the end of this method to insert another LDR command
# Thus adding another layer of indirection, such that we only need to swap the table address out with the address of the main app's placeholder, not the table itself
pre  = "03 A3 18 68 08 44 02 68 94 46 0F BC 60 47 00 BF A8 A8 A8 A8"
post = "03 A3 18 68 00 68 08 44 02 68 94 46 0F BC 60 47 A8 A8 A8 A8"

pre, post = (item.replace(" ", "").decode("hex") for item in (pre, post))

libpebble_bin = open("libpebble_patch.a", "r+b")
bin_contents = libpebble_bin.read()
bin_contents = bin_contents.replace(pre, post)
libpebble_bin.seek(0)
libpebble_bin.write(bin_contents)