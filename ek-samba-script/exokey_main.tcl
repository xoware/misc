## Files to load
set bootstrapFile       "bootstrap.bin"
set ubootFile           "u-boot.bin"
set kernelFile          "linux.bin"
set rootfsFile          "rootfs.ubi"

## board variant
set boardFamily "sama5d3"
set board_suffix "ek"

## now call common script
source exokey_nandflash.tcl
