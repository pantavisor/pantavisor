LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_LIBRARIES := lxc libthttp

LOCAL_DESTDIR := ./
LOCAL_MODULE := init

LOCAL_CFLAGS := -g -Wno-format-nonliteral -Wno-format-contains-nul
LOCAL_LDFLAGS := -static

LOCAL_SRC_FILES := init.c \
		   tsh.c \
	           loop.c \
	           log.c \
	           lxc.c \
		   config.c \
		   systemc.c \
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

include $(CLEAR_VARS)

LOCAL_LIBRARIES := lxc libthttp

LOCAL_DESTDIR := ./
LOCAL_MODULE := systemc-debug

LOCAL_CFLAGS := -g -Wno-format-nonliteral -Wno-format-contains-nul
LOCAL_LDFLAGS := -static

LOCAL_SRC_FILES := loop.c \
	           log.c \
	           lxc.c \
		   config.c \
		   systemc_debug.c \
		   controller.c \
		   platforms.c \
		   utils.c \
		   volumes.c \
		   updater.c

include $(BUILD_EXECUTABLE)
