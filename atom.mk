LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_LIBRARIES := lxc libthttp
LOCAL_CONDITIONAL_LIBRARIES := OPTIONAL:libseccomp OPTIONAL:libcap OPTIONAL:apparmor
LOCAL_DESTDIR := ./lib/
LOCAL_MODULE := pv_lxc

LOCAL_CFLAGS := -g -Wno-format-nonliteral -Wno-format-contains-nul -fPIC
LOCAL_LDFLAGS := -Wl,--no-as-needed -lutil -Wl,--as-needed

LOCAL_SRC_FILES := plugins/pv_lxc.c utils/fs.c utils/tsh.c utils/pvsignals.c

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_LIBRARIES := libthttp mbedtls picohttpparser
LOCAL_CONDITIONAL_LIBRARIES := OPTIONAL:e2fsprogs

LOCAL_DESTDIR := ./
LOCAL_MODULE := init

LOCAL_CFLAGS := -g -Wno-format-nonliteral -Wno-format-contains-nul -D_FILE_OFFSET_BITS=64 -Werror
LOCAL_LDFLAGS := -Wl,--no-as-needed -ldl -Wl,--as-needed

PV_BUILD_DIR := $(call local-get-build-dir)
PV_VERSION_C := $(PV_BUILD_DIR)/version.c

$(PV_VERSION_C): .FORCE
	$(Q) $(PRIVATE_PATH)/gen_version.sh PVALCHEMY $(PV_BUILD_DIR) $(TARGET)

LOCAL_PREREQUISITES += \
	$(PV_VERSION_H)

ifeq ($(PANTAVISOR_DEBUG), yes)
LOCAL_CFLAGS += -DPANTAVISOR_DEBUG
LOCAL_DEPENDS_MODULES += dropbear-pv
endif

LOCAL_CODECHECK_C := clang

LOCAL_C_INCLUDES := $(LOCAL_PATH)/utils/

LOCAL_SRC_FILES := debug.c \
			daemons.c \
			init.c \
			loop.c \
			logger.c \
			log.c \
			logserver/logserver_timestamp.c \
			logserver/logserver_utils.c \
			logserver/logserver_out.c \
			logserver/logserver_update.c \
			logserver/logserver_singlefile.c \
			logserver/logserver_filetree.c \
			logserver/logserver_null.c \
			logserver/logserver.c \
			config_parser.c \
			config.c \
			pantavisor.c \
			state.c \
			group.c \
			condition.c \
			platforms.c \
			addons.c \
			volumes.c \
			disk/disk.c \
			disk/disk_crypt.c \
			disk/disk_swap.c \
			disk/disk_volume.c \
			disk/disk_zram.c \
			disk/disk_utils.c \
			disk/disk_zram_utils.c \
			signature.c \
			parser/parser.c \
			parser/parser_multi1.c \
			parser/parser_system1.c \
			objects.c \
			utils/tsh.c \
			utils/system.c \
			utils/str.c \
			utils/strrep.c \
			utils/json.c \
			utils/base64.c \
			utils/math.c \
			utils/timer.c \
			utils/fs.c \
			utils/pvsignals.c \
			utils/socket.c \
			utils/pvsignals.c \
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
			ph_logger.c \
			buffer.c \
			blkid.c \
			paths.c \
			drivers.c \
			cgroup.c \
			apparmor.c

LOCAL_INSTALL_HEADERS := log.h
LOCAL_GENERATED_SRC_FILES := version.c

LOCAL_COPY_FILES := $(foreach a,$(shell cd $(LOCAL_PATH)/skel; find . -type f), skel/$(a):$(a)) \
	scripts/pv_e2fsgrow:lib/pv/pv_e2fsgrow \
	scripts/hooks_lxc-mount.d/export.sh:lib/pv/hooks_lxc-mount.d/export.sh \
	scripts/hooks_lxc-mount.d/mdev.sh:lib/pv/hooks_lxc-mount.d/mdev.sh \
	scripts/hooks_lxc-mount.d/remount.sh:lib/pv/hooks_lxc-mount.d/remount.sh \
	scripts/JSON.sh:lib/pv/JSON.sh \
	scripts/pvcrash:lib/pv/pvcrash \
	tools/pventer:usr/bin/pventer \
	tools/fallbear-cmd:usr/bin/fallbear-cmd \
	pvs/trust/ca-certificates.crt:etc/pantavisor/pvs/trust/ca-certificates.crt \
	pvs/trust/cacerts.default.pem:etc/pantavisor/pvs/trust/cacerts.default.pem \
	defaults/groups.json:etc/pantavisor/defaults/groups.json

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

LOCAL_LIBRARIES := libthttp

LOCAL_DESTDIR := ./
LOCAL_MODULE := json_test

LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_SRC_FILES := utils/json.test.c \
			utils/json.c

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_DESTDIR := ./
LOCAL_MODULE := init-dm
LOCAL_LIBRARIES := cryptsetup

LOCAL_COPY_FILES := scripts/volmount/verity/dm:lib/pv/volmount/verity/dm

include $(BUILD_CUSTOM)

include $(CLEAR_VARS)

LOCAL_MODULE := init-crypt
LOCAL_LIBRARIES := cryptsetup
LOCAL_COPY_FILES := scripts/volmount/crypt/crypt:lib/pv/volmount/crypt/crypt

include $(BUILD_CUSTOM)

include $(CLEAR_VARS)

LOCAL_DESTDIR := ./
LOCAL_MODULE := pvzram

LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_SRC_FILES := disk/disk_zram_utils.c \
		   utils/pv_zram.c

include $(BUILD_EXECUTABLE)
