require openssl.inc

PR = "r6"
SRC_URI += "file://debian/ca.patch \
            file://debian/config-hurd.patch;apply=no \
            file://debian/debian-targets.patch;apply=no \
            file://debian/kfreebsd-pipe.patch;apply=no \
            file://debian/make-targets.patch \
            file://debian/man-dir.patch \
            file://debian/man-section.patch \
            file://debian/no-rpath.patch \
            file://debian/no-symbolic.patch \
            file://debian/pic.patch \
            file://debian/pkg-config.patch \
            file://debian/rc4-amd64.patch \
            file://debian/rehash-crt.patch \
            file://debian/rehash_pod.patch \
            file://debian/shared-lib-ext.patch \
            file://debian/stddef.patch \
            file://debian/version-script.patch \
            file://debian/perl-path.diff"

#   file://debian/engines-path.patch 


SRC_URI[md5sum] = "a5cb5f6c3d11affb387ecf7a997cac0c"
SRC_URI[sha256sum] = "7131242042dbd631fbd83436f42aea1775e7c32f587fa4ada5a01df4c3ae8e8b"
LIC_FILES_CHKSUM = "file://LICENSE;md5=83d26c69f6f0172ee7f795790424b453"



SRC_URI += "file://configure-targets.patch \
	    file://turbossl-0.9.8j.patch \
            file://shared-libs.patch"

#	    file://debug.patch
#	    file://cavium-headers.patch

BBCLASSEXTEND = "native nativesdk"

	