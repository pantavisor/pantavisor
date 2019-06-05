LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_LIBRARIES := lxc

LOCAL_DESTDIR := ./lib/
LOCAL_MODULE := pv_lxc

LOCAL_CFLAGS := -g -Wno-format-nonliteral -Wno-format-contains-nul -fPIC
LOCAL_LDFLAGS := -Wl,--no-as-needed -lutil -Wl,--as-needed

LOCAL_SRC_FILES := plugins/pv_lxc.c

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_LIBRARIES := libthttp

LOCAL_DESTDIR := ./
LOCAL_MODULE := init

LOCAL_CFLAGS := -g -Wno-format-nonliteral -Wno-format-contains-nul -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS := -Wl,--no-as-needed -ldl -Wl,--as-needed -static-libgcc

PV_BUILD_DIR := $(call local-get-build-dir)
PV_VERSION_C := $(PV_BUILD_DIR)/version.c

$(PV_VERSION_C): .FORCE
	$(Q) $(PRIVATE_PATH)/gen_version.sh $(PRIVATE_PATH) $(PV_BUILD_DIR)

LOCAL_PREREQUISITES += \
	$(PV_VERSION_H)

LOCAL_SRC_FILES := init.c \
		   tsh.c \
	           loop.c \
	           log.c \
		   config.c \
		   pantavisor.c \
		   controller.c \
		   platforms.c \
		   addons.c \
		   utils.c \
		   volumes.c \
		   parser/parser.c \
		   parser/parser_multi1.c \
		   parser/parser_system1.c \
		   objects.c \
		   pantahub.c \
		   updater.c \
		   bootloader.c \
		   uboot.c \
		   grub.c \
		   storage.c \
		   cmd.c \
		   device.c \
		   wdt.c \
		   network.c

LOCAL_GENERATED_SRC_FILES := version.c

include $(BUILD_EXECUTABLE)
