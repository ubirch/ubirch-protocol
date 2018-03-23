# HOWTO ADD TO BOSCH XDK:
#
# in SDK/xdk110/Common/application.mk:
# - add to lib dirs:
# 		UBIRCH_LIBRARY_DIR = $(BCDS_LIBRARIES_PATH)/ubirch-protocol
# - add to BCDS_XDK_EXT_INCLUDES
# 		-isystem $(UBIRCH_LIBRARY_DIR)/msgpack \
# 		-isystem $(UBIRCH_LIBRARY_DIR)/nacl \
# 		-isystem $(UBIRCH_LIBRARY_DIR) \
# in SDK/xdk110/Common/Libraries.mk
# - add to BCDS_THIRD_PARTY_LIBS
#		$(UBIRCH_LIBRARY_DIR)/ubirch_protocol.a

# msgpack dependencies and objects
MSGPACK_DEPS = msgpack/msgpack.h msgpack/msgpack/fbuffer.h msgpack/msgpack/object.h msgpack/msgpack/pack.h \
			   msgpack/msgpack/pack_define.h msgpack/msgpack/pack_template.h msgpack/msgpack/sbuffer.h \
			   msgpack/msgpack/sysdep.h msgpack/msgpack/unpack.h msgpack/msgpack/unpack_define.h \
		       msgpack/msgpack/unpack_template.h msgpack/msgpack/version.h msgpack/msgpack/vrefbuffer.h \
			   msgpack/msgpack/zbuffer.h msgpack/msgpack/zone.h
MSGPACK_OBJS = msgpack/objectc.o msgpack/unpack.o msgpack/version.o msgpack/vrefbuffer.o msgpack/zone.o

# NaCl dependencies and objects

NACL_DEPS= ubirch-mbed-nacl-cm0/source/nacl/crypto_sign/ge25519.h \
           ubirch-mbed-nacl-cm0/source/nacl/crypto_sign/ge25519_base.data \
           ubirch-mbed-nacl-cm0/source/nacl/crypto_sign/sc25519.h \
		   ubirch-mbed-nacl-cm0/source/nacl/include/bigint.h \
		   ubirch-mbed-nacl-cm0/source/nacl/include/fe25519.h \
		   ubirch-mbed-nacl-cm0/source/nacl/armnacl.h \
		   ubirch-mbed-nacl-cm0/source/randombytes/randombytes.h

NACL_OBJS = ubirch-mbed-nacl-cm0/source/nacl/crypto_hash/sha512.o \
			ubirch-mbed-nacl-cm0/source/nacl/crypto_hashblocks/sha512.o \
			ubirch-mbed-nacl-cm0/source/nacl/crypto_sign/ed25519.o \
			ubirch-mbed-nacl-cm0/source/nacl/crypto_sign/ge25519.o \
			ubirch-mbed-nacl-cm0/source/nacl/crypto_sign/sc25519.o \
			ubirch-mbed-nacl-cm0/source/nacl/crypto_verify/verify.o \
			ubirch-mbed-nacl-cm0/source/nacl/shared/bigint.o \
			ubirch-mbed-nacl-cm0/source/nacl/shared/consts.o \
			ubirch-mbed-nacl-cm0/source/nacl/shared/fe25519.o \
			ubirch-mbed-nacl-cm0/source/randombytes/randombytes.o
# ubirch-protocol dependencies and objects
UBIRCH_DEPS = ubirch/digest/sha512.h ubirch/digest/config.h \
			  ubirch/ubirch_protocol.h ubirch/ubirch_protocol_kex.h ubirch/ubirch_ed25519.h
UBIRCH_OBJS = ubirch/digest/sha512.o \
			  ubirch/ubirch_protocol_kex.o


DEPS = $(MSGPACK_DEPS) $(NACL_DEPS) $(UBIRCH_DEPS)
OBJS = $(MSGPACK_OBJS) $(NACL_OBJS) $(UBIRCH_OBJS)

CC=arm-none-eabi-gcc
AR=arm-none-eabi-ar
CFLAGS=-D__MBED__  -Wall -Wextra -mcpu=cortex-m3 -mthumb -Os -I. -Imsgpack -Iubirch-mbed-nacl-cm0/source

BUILD/xdk/%.o: %.c $(DEPS)
	@mkdir -p BUILD/xdk/$(patsubst %/,%,$(dir $(lastword $<)))
	$(CC) -c $(CFLAGS) -o $@ $<

BUILD/xdk/ubirch_protocol.a: $(addprefix BUILD/xdk/, $(OBJS))
	$(AR) -r $@ $^

.PHONY: clean dist

dist: BUILD/xdk/ubirch_protocol.a
	@mkdir -p BUILD/xdk/ubirch-protocol
	@cp -av ubirch BUILD/xdk/ubirch-protocol
	@cp -av msgpack BUILD/xdk/ubirch-protocol
	@cp -av ubirch-mbed-nacl-cm0/source/nacl BUILD/xdk/ubirch-protocol
	@cp BUILD/xdk/ubirch_protocol.a BUILD/xdk/ubirch-protocol

	

clean:
	rm -f $(addprefix BUILD/xdk/, $(OBJS)) BUILD/xdk/ubirch_protocol.a
	rm -fr BUILD/xdk
