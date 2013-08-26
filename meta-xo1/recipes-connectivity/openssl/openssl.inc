SUMMARY = "Secure Socket Layer"
DESCRIPTION = "Secure Socket Layer (SSL) binary and related cryptographic tools."
HOMEPAGE = "http://www.openssl.org/"
BUGTRACKER = "http://www.openssl.org/news/vulnerabilities.html"
SECTION = "libs/network"

# "openssl | SSLeay" dual license
LICENSE = "openssl"


DEPENDS = "perl-native-runtime"

SRC_URI = "http://www.openssl.org/source/openssl-${PV}.tar.gz \
           file://parallel-make-fix.patch \
          "
S = "${WORKDIR}/openssl-${PV}"

AR_append = " r"
CFLAG = "${@base_conditional('SITEINFO_ENDIANNESS', 'le', '-DL_ENDIAN', '-DB_ENDIAN', d)} \
	-DTERMIO ${FULL_OPTIMIZATION} -Wall -DCAVIUM_SSL \
	-I/home/karl/Work/xoware/cns3xxx-sdk/apps-pool/nitrox-driver-cns3xxx-3.0-pre-release/software/api  \
	-I/home/karl/Work/xoware/cns3xxx-sdk/apps-pool/nitrox-driver-cns3xxx-3.0-pre-release/software/include"
#-DCAVIUM_ENGINE -DCAVIUM_SSL -DCAVIUM_CIPHERS 

#EXTRA_OECONF += "cavium"
EXTRA_OECONF += "-I/home/karl/Work/xoware/cns3xxx-sdk/apps-pool/nitrox-driver-cns3xxx-3.0-pre-release/software/include -DMC2 \
-DOPENSSL_NO_HW_4758_CCA -DOPENSSL_NO_HW_PADLOCK -DOPENSSL_NO_HW_NCIPHER -DOPENSSL_NO_HW_NURON -DOPENSSL_NO_HW_ATALLA -DOPENSSL_NO_HW_SUREWARE \
-DOPENSSL_NO_HW_UBSEC -DOPENSSL_NO_HW_AEP -DOPENSSL_NO_HW_CSWIFT "
	
# Avoid binaries being marked as requiring an executable stack (which causes 
# issues with SELinux on the host)
CFLAG_append_virtclass-native = " -Wa,--noexecstack"

# -02 does not work on mipsel: ssh hangs when it tries to read /dev/urandom
CFLAG_mtx-1 := "${@'${CFLAG}'.replace('-O2', '')}"
CFLAG_mtx-2 := "${@'${CFLAG}'.replace('-O2', '')}"

export DIRS = "crypto ssl apps"
export EX_LIBS = "-lgcc -ldl"
export AS = "${CC} -c"

APIDIR=/home/karl/Work/xoware/cns3xxx-sdk/apps-pool/nitrox-driver-cns3xxx-3.0-pre-release/software/api
export APIDIR

inherit pkgconfig siteinfo

PACKAGES =+ "libcrypto libssl"
FILES_libcrypto = "${libdir}/libcrypto.so.*"
FILES_libssl = "${libdir}/libssl.so.*"
FILES_${PN} =+ " ${libdir}/ssl/*"

do_configure () {
	cd util
	perl perlpath.pl ${STAGING_BINDIR_NATIVE}
	cd ..
	ln -sf apps/openssl.pod crypto/crypto.pod ssl/ssl.pod doc/

	os=${HOST_OS}
	if [ "x$os" = "xlinux-uclibc" ]; then
		os=linux
	fi
	target="$os-${HOST_ARCH}"
	case $target in
	linux-arm)
		target=linux-elf-arm
		;;
	linux-armeb)
		target=linux-elf-armeb
		;;
	linux-sh3)
		target=debian-sh3
		;;
	linux-sh4)
		target=debian-sh4
		;;
	linux-i486)
		target=debian-i386-i486
		;;
	linux-i586)
		target=debian-i386-i586
		;;
	linux-i686)
		target=debian-i386-i686/cmov
		;;
	linux-mips)
		target=debian-mips
		;;
	linux-mipsel)
		target=debian-mipsel
		;;
	linux-powerpc)
		target=linux-ppc
		;;
	linux-gnuspe-powerpc)
		target=linux-ppc
		;;
	linux-powerpc64)
		target=linux-ppc64
		;;
	linux-supersparc)
		target=linux-sparcv8
		;;
	linux-sparc)
		target=linux-sparcv8
		;;
	esac
	# inject machine-specific flags
	sed -i -e "s|^\(\"$target\",\s*\"[^:]\+\):\([^:]\+\)|\1:${CFLAG}|g" Configure
        useprefix=${prefix}
        if [ "x$useprefix" = "x" ]; then
                useprefix=/
        fi        

#	perl ./Configure ${EXTRA_OECONF} shared --prefix=$useprefix --openssldir=${libdir}/ssl $target
	perl ./Configure compiler:arm-poky-linux-gnueabi-gcc ${EXTRA_OECONF} shared enable-tlsext --prefix=$useprefix --openssldir=${libdir}/ssl cavium
	

}

do_compile () {
	touch include/app_defines.h
	ln -sf ../rsa_d/rsa_sign.c  crypto/rsa/rsa_sign.c
#	oe_runmake libssl.so libcrypto.so
	oe_runmake
}

do_install () {
#	install -m 0755 -d ${D}${libdir}/pkgconfig
	oe_runmake INSTALL_PREFIX="${D}" MANDIR="${mandir}" install_sw
#	chmod 644 ${D}${libdir}/pkgconfig/openssl.pc
	oe_libinstall -so libcrypto ${D}${libdir}
	oe_libinstall -so libssl ${D}${libdir}
}
