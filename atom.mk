LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

PV_PREFIX := /opt/pantavisor
PV_BINDIR := $(PV_PREFIX)/bin
PV_LIBDIR := $(PV_PREFIX)/lib
PV_DATADIR := $(PV_PREFIX)/share
PV_ETCDIR := $(PV_PREFIX)/etc
PV_VARDIR := $(PV_PREFIX)/var
PV_RUNDIR := $(PV_VARDIR)/pv
PV_PLUGINSDIR := $(PV_PREFIX)/plugins

LOCAL_LIBRARIES := lxc libthttp
LOCAL_CONDITIONAL_LIBRARIES := OPTIONAL:libseccomp OPTIONAL:libcap OPTIONAL:apparmor
LOCAL_DESTDIR := .$(PV_PLUGINSDIR)/
LOCAL_MODULE := pv_lxc

LOCAL_CFLAGS := -g -Wno-format-nonliteral -Wno-format-contains-nul -fPIC -DPREFIX=$(PV_PREFIX)
LOCAL_LDFLAGS := -Wl,--no-as-needed -lutil -Wl,--as-needed

LOCAL_SRC_FILES := plugins/pv_lxc.c

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_LIBRARIES := libthttp libpvlogger mbedtls picohttpparser
LOCAL_CONDITIONAL_LIBRARIES := OPTIONAL:e2fsprogs

LOCAL_DESTDIR := .$(PV_PREFIX)/bin
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

LOCAL_C_INCLUDES := $(LOCAL_PATH)/utils/

LOCAL_SRC_FILES := init.c \
			loop.c \
			log.c \
			config_parser.c \
			config.c \
			pantavisor.c \
			state.c \
			group.c \
			condition.c \
			platforms.c \
			addons.c \
			volumes.c \
			signature.c \
			parser/parser.c \
			parser/parser_utils.c \
			parser/parser_multi1.c \
			parser/parser_system1.c \
			parser/parser_embed1.c \
			objects.c \
			utils/tsh.c \
			utils/fs.c \
			utils/system.c \
			utils/str.c \
			utils/strrep.c \
			utils/json.c \
			utils/file.c \
			utils/base64.c \
			utils/math.c \
			utils/timer.c \
			jsons.c \
			pantahub.c \
			updater.c \
			bootloader.c \
			trestclient.c \
			uboot.c \
			grub.c \
			storage.c \
			metadata.c \
			ctrl.c \
			wdt.c \
			network.c \
			pvlogger.c \
			pvctl_utils.c \
			mount.c \
			ph_logger/ph_logger.c \
			ph_logger/ph_logger_v1.c \
			buffer.c \
			blkid.c \
			skel.c \
			system.c

LOCAL_INSTALL_HEADERS := log.h
LOCAL_GENERATED_SRC_FILES := version.c

LOCAL_COPY_FILES := scripts/pv_e2fsgrow:lib/pv/pv_e2fsgrow \
	scripts/hooks_lxc-mount.d/export.sh:lib/pv/hooks_lxc-mount.d/export.sh \
	scripts/JSON.sh:lib/pv/JSON.sh \
	scripts/volmount/dm:lib/pv/volmount/dm \
	defaults/pantahub.config:opt/pantavisor/share/pantahub.config \
	defaults/pantavisor.config:opt/pantavisor/share/pantavisor.config \
	$(NULL)

LOCAL_CREATE_LINKS := \
	init:opt/pantavisor/bin/pantavisor \
	$(NULL)

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_DESTDIR := ./
LOCAL_MODULE := tsh_test

LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_SRC_FILES := utils/tsh.test.c \
			utils/tsh.c \
			utils/timer.c

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_DESTDIR := ./
LOCAL_MODULE := init-dm
LOCAL_LIBRARIES := cryptsetup

LOCAL_COPY_FILES := scripts/volmount/dm:lib/pv/volmount/dm

include $(BUILD_CUSTOM)

include $(CLEAR_VARS)

LOCAL_MODULE := init-crypt
LOCAL_LIBRARIES := cryptsetup
LOCAL_COPY_FILES := scripts/volmount/crypt:lib/pv/volmount/crypt

include $(BUILD_CUSTOM)
