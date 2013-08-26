SECTION = "console/network"
DESCRIPTION = "A "
LICENSE = "Apache-2.0"
DEPENDS = "apache2-native apache2 zlib python python-native"
#INC_PR = "r1"

SRC_URI = "https://modwsgi.googlecode.com/files/mod_wsgi-${PV}.tar.gz \
"

SRC_URI[md5sum] = "f42d69190ea0c337ef259cbe8d94d985"
SRC_URI[sha256sum] = "ae85c98e9e146840ab3c3e4490e6774f9bef0f99b9f679fca786b2adb5b4b6e8"


S = "${WORKDIR}/mod_wsgi-${PV}"

LIC_FILES_CHKSUM = "file://LICENCE;md5=3b83ef96387f14655fc854ddc3c6bd57"

inherit autotools



CFLAGS += " -g -I${STAGING_INCDIR}/apache2 -I${STAGING_INCDIR}/python${PYTHON_BASEVERSION}/"
LDFLAGS += " -lpython${PYTHON_BASEVERSION}"

EXTRA_OECONF = " --with-apxs=${STAGING_BINDIR_CROSS}/apxs \
  --with-python=${STAGING_BINDIR_NATIVE}/python-native/python \
  --disable-framework \
	"
#--with-python=${STAGING_BINDIR}/python 


do_configure_prepend () {
#    rm -f build/libtool.m4 ltmain.sh aclocal.m4
#    find . -name config.m4 | xargs -n1 sed -i 's!APXS_HTTPD=.*!APXS_HTTPD=${STAGING_BINDIR_NATIVE}/httpd!'
	autoreconf -Wcross --verbose --install --force 
}

#do_configure_append() {
#    # No libtool, we really don't want rpath set...
#    sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' ${HOST_SYS}-libtool
#    sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' ${HOST_SYS}-libtool
#}

