LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_LIBRARIES := lxc libthttp
LOCAL_DESTDIR := ./lib/
LOCAL_MODULE := pv_lxc

LOCAL_CFLAGS := -g -Wno-format-nonliteral -Wno-format-contains-nul -fPIC
LOCAL_LDFLAGS := -Wl,--no-as-needed -lutil -Wl,--as-needed

LOCAL_SRC_FILES := plugins/pv_lxc.c

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_LIBRARIES := libthttp libpvlogger mbedtls
LOCAL_CONDITIONAL_LIBRARIES := OPTIONAL:e2fsprogs

LOCAL_DESTDIR := ./
LOCAL_MODULE := init

LOCAL_CFLAGS := -g -Wno-format-nonliteral -Wno-format-contains-nul -D_FILE_OFFSET_BITS=64
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
			config_parser.c \
			config.c \
			pantavisor.c \
			state.c \
			controller.c \
			platforms.c \
			addons.c \
			utils.c \
			volumes.c \
			parser/parser.c \
			parser/parser_multi1.c \
			parser/parser_system1.c \
			objects.c \
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
			revision.c \
			ph_logger/ph_logger.c \
			ph_logger/ph_logger_v1.c \
			blkid.c

LOCAL_INSTALL_HEADERS := log.h
LOCAL_GENERATED_SRC_FILES := version.c

LOCAL_COPY_FILES := scripts/pv_e2fsgrow:lib/pv/pv_e2fsgrow \
	scripts/hooks_lxc-mount.d/export.sh:lib/pv/hooks_lxc-mount.d/export.sh \
	scripts/JSON.sh:lib/pv/JSON.sh

include $(BUILD_EXECUTABLE)

