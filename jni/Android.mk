LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CFLAGS := -std=c99
LOCAL_MODULE := wotw
LOCAL_LDLIBS := -llog
LOCAL_SRC_FILES := main.c QSEEComAPI.c vuln.c widevine_commands.c exploit_utilities.c kallsyms.c
include $(BUILD_EXECUTABLE)
