LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

PV_PREFIX := /opt/pantavisor
PV_BINDIR := $(PV_PREFIX)/bin
PV_LIBDIR := $(PV_PREFIX)/lib
PV_DATADIR := $(PV_PREFIX)/share
PV_ETCDIR := $(PV_PREFIX)/etc
PV_VARDIR := $(PV_PREFIX)/var
PV_RUNDIR := $(PV_VARDIR)/pv

LOCAL_LIBRARIES := lxc libthttp
LOCAL_DESTDIR := .$(PV_LIBDIR)/plugins
LOCAL_MODULE := pv_lxc

LOCAL_CFLAGS := -g -Wno-format-nonliteral -Wno-format-contains-nul -fPIC -DPREFIX=$(PV_PREFIX)
LOCAL_LDFLAGS := -Wl,--no-as-needed -lutil -Wl,--as-needed

LOCAL_SRC_FILES := plugins/pv_lxc.c

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_LIBRARIES := libthttp libpvlogger mbedtls

LOCAL_DESTDIR := ./opt/pantavisor/bin
LOCAL_MODULE := pantavisor

LOCAL_CFLAGS := -g -Wno-format-nonliteral -Wno-format-contains-nul -D_FILE_OFFSET_BITS=64 -DPREFIX=\"$(PV_PREFIX)\" -DLIBDIR=\"$(PV_LIBDIR)\" -DDATADIR=\"$(PV_DATADIR)\" -DETCDIR=\"$(ETCDIR)\"

LOCAL_LDFLAGS := -Wl,--no-as-needed -ldl -Wl,--as-needed -static-libgcc

PV_BUILD_DIR := $(call local-get-build-dir)
PV_VERSION_C := $(PV_BUILD_DIR)/version.c

$(PV_VERSION_C): .FORCE
	$(Q) $(PRIVATE_PATH)/gen_version.sh $(PRIVATE_PATH) $(PV_BUILD_DIR) $(TARGET)

LOCAL_PREREQUISITES += \
	$(PV_VERSION_H)

ifeq ($(PANTAVISOR_DEBUG), yes)
LOCAL_CFLAGS += -DPANTAVISOR_DEBUG
LOCAL_DEPENDS_MODULES += dropbear-pv
endif

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
		   trestclient.c \
		   uboot.c \
		   grub.c \
		   storage.c \
		   cmd.c \
		   device.c \
		   wdt.c \
		   network.c \
		   pvlogger.c \
		   pvctl_utils.c \
		   mount.c \
		   revision.c \
		   skel.c \
		   ph_logger/ph_logger.c \
		   ph_logger/ph_logger_v1.c \
		   blkid.c

LOCAL_INSTALL_HEADERS := log.h
LOCAL_GENERATED_SRC_FILES := version.c

LOCAL_COPY_FILES := \
	defaults/pantahub.config:opt/pantavisor/share/pantahub.config \
	defaults/pantavisor.config:opt/pantavisor/share/pantavisor.config \
	$(NULL)

LOCAL_CREATE_LINKS := \
	init:opt/pantavisor/bin/pantavisor \
	$(NULL)

include $(BUILD_EXECUTABLE)

