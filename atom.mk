LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := pv_lxc

include $(BUILD_CUSTOM)

include $(CLEAR_VARS)

LOCAL_MODULE := init
LOCAL_DESCRIPTION := zlib
LOCAL_LIBRARIES := libthttp mbedtls picohttpparser zlib lxc
LOCAL_CONDITIONAL_LIBRARIES := OPTIONAL:e2fsprogs
LOCAL_DESTDIR := ./

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

include $(BUILD_CMAKE)


include $(CLEAR_VARS)

LOCAL_DESTDIR := ./
LOCAL_MODULE := rpiab_test

LOCAL_C_INCLUDES := $(LOCAL_PATH)/utils/

LOCAL_LDFLAGS := -static

LOCAL_SRC_FILES := rpiab.test.c \
			utils/timer.c \
			utils/pvsignals.c \
			utils/tsh.c \
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

