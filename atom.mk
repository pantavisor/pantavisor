LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_LIBRARIES := lxc

LOCAL_DESTDIR := ./lib/
LOCAL_MODULE := pv_lxc

LOCAL_CFLAGS := -g -Wno-format-nonliteral -Wno-format-contains-nul -fPIC

LOCAL_SRC_FILES := plugins/pv_lxc.c

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_LIBRARIES := libthttp

LOCAL_DESTDIR := ./
LOCAL_MODULE := init

LOCAL_CFLAGS := -g -Wno-format-nonliteral -Wno-format-contains-nul -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS := -static-libgcc

LOCAL_SRC_FILES := init.c \
		   tsh.c \
	           loop.c \
	           log.c \
		   config.c \
		   pantavisor.c \
		   controller.c \
		   platforms.c \
		   utils.c \
		   volumes.c \
		   parser.c \
		   objects.c \
		   pantahub.c \
		   updater.c \
		   bootloader.c \
		   storage.c

include $(BUILD_EXECUTABLE)
