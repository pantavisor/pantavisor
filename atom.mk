LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_LIBRARIES := lxc libthttp

LOCAL_DESTDIR := ./
LOCAL_MODULE := init

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
		   updater.c

include $(BUILD_EXECUTABLE)
