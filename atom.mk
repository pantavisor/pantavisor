LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

## backward compatility modules (null op) to keep old global.config's happy
LOCAL_MODULE := pv_lxc

include $(BUILD_CUSTOM)

include $(CLEAR_VARS)

LOCAL_MODULE := init
LOCAL_DESCRIPTION := Pantavisor
LOCAL_LIBRARIES := libthttp mbedtls picohttpparser zlib lxc
LOCAL_CONDITIONAL_LIBRARIES := OPTIONAL:e2fsprogs OPTIONAL:dropbear-pv OPTIONAL:cryptsetup
LOCAL_CMAKE_CONFIGURE_ARGS += "-DPANTAVISOR_DM_VERITY=$(CONFIG_ALCHEMY_BUILD_INIT_DM)"
LOCAL_CMAKE_CONFIGURE_ARGS += "-DPANTAVISOR_DM_CRYPT=$(CONFIG_ALCHEMY_BUILD_INIT_CRYPT)"
LOCAL_CODECHECK_C := clang

ifeq ($(CONFIG_ALCHEMY_BUILD_PVZRAM), y)
LOCAL_CMAKE_CONFIGURE_ARGS += "-DPANTAVISOR_PVZRAM_TEST=ON"
endif

ifeq ($(PANTAVISOR_DEBUG), yes)
LOCAL_CMAKE_CONFIGURE_ARGS += "-DPANTAVISOR_DEBUG=ON"
else
LOCAL_CMAKE_CONFIGURE_ARGS += "-DPANTAVISOR_DEBUG=OFF"
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

# keep this as null-op target for backward compatibilityyy
LOCAL_MODULE := init-dm

include $(BUILD_CUSTOM)

include $(CLEAR_VARS)

# keep this as null-op target for backward compatibilityyy
LOCAL_MODULE := init-crypt

include $(BUILD_CUSTOM)

include $(CLEAR_VARS)

LOCAL_DESTDIR := ./
LOCAL_MODULE := pvtests
LOCAL_LIBRARIES += argp-standalone
LOCAL_CMAKE_CONFIGURE_ARGS += "-DPANTAVISOR_TESTS=ON"

include $(BUILD_CMAKE)

