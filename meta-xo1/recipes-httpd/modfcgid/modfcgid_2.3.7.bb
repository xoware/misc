SECTION = "console/network"
DESCRIPTION = "A "
LICENSE = "Apache-2.0"
DEPENDS = "apache2-native apache2 zlib"
#INC_PR = "r1"

SRC_URI = "http://apache.rediris.es//httpd/mod_fcgid/mod_fcgid-${PV}.tar.bz2 \
"

SRC_URI[md5sum] = "5952c93dc16b42264a4bf2a54757fc08"
SRC_URI[sha256sum] = "4fcfadd2804734cc7a266d8c6044b34a21d5a4a1e2e0c1a882fc59a3e012eb80"


S = "${WORKDIR}/mod_fcgid-${PV}"

LIC_FILES_CHKSUM = "file://LICENSE-FCGID;md5=3b83ef96387f14655fc854ddc3c6bd57"


do_compile () {
        APXS=${STAGING_BINDIR_CROSS}/apxs ./configure.apxs || die "apxs configure failed!"
	replace "/usr/share/apache2/build/rules.mk" "/home/karl/Work/oe-core/build/tmp-eglibc/work/x86_64-linux/apr-util-native/1.5.1-r0/apr-util-1.5.1/build/rules.mk" -- Makefile
        make || die "make failed"
        ln -sf modules/fcgid/.libs .libs || die "symlink creation failed"
}
