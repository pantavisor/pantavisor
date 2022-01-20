#ifndef PV_PATHS_H
#define PV_PATHS_H

#define PV_PATH					"/pv"
#define PLATFORM_PV_PATH			"/pantavisor"

#define LOG_CTRL_FNAME 				"pv-ctrl-log"
#define PV_LOG_CTRL_PATH 			PV_PATH"/"LOG_CTRL_FNAME
#define PLATFORM_LOG_CTRL_PATH 			PLATFORM_PV_PATH"/"LOG_CTRL_FNAME

#define LOG_DNAME				"logs"
#define PV_LOGS_PATH				PV_PATH"/"LOG_DNAME
#define PLATFORM_LOGS_PATH			PLATFORM_PV_PATH"/"LOG_DNAME

#define CTRL_SOCKET_FNAME			"pv-ctrl"
#define PV_CTRL_SOCKET_PATH			PV_PATH"/"CTRL_SOCKET_FNAME
#define PLATFORM_CTRL_SOCKET_PATH		PLATFORM_PV_PATH"/"CTRL_SOCKET_FNAME

#define USER_META_DNAME				"user-meta"
#define PV_USER_META_PATH			PV_PATH"/"USER_META_DNAME
#define PLATFORM_USER_META_PATH			PLATFORM_PV_PATH"/"USER_META_DNAME

#define CHALLENGE_FNAME				"challenge"
#define PV_CHALLENGE_PATH			PV_PATH"/"CHALLENGE_FNAME
#define PLATFORM_CHALLENGE_PATH			PLATFORM_PV_PATH"/"CHALLENGE_FNAME

#define DEVICE_ID_FNAME				"device-id"
#define PV_DEVICE_ID_PATH			PV_PATH"/"DEVICE_ID_FNAME
#define PLATFORM_DEVICE_ID_PATH			PLATFORM_PV_PATH"/"DEVICE_ID_FNAME

#define ONLINE_FNAME				"online"
#define PV_ONLINE_PATH				PV_PATH"/"ONLINE_FNAME
#define PLATFORM_ONLINE_PATH			PLATFORM_PV_PATH"/"ONLINE_FNAME

#define PV_USER_META_KEY_PATHF			PV_USER_META_PATH"/%s"
#define PV_USER_META_PLAT_PATHF			PV_USER_META_PATH".%s"
#define PV_USER_META_PLAT_KEY_PATHF		PV_USER_META_PATH".%s/%s"

#endif /* PATHS_H */
