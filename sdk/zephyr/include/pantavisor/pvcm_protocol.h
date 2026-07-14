/*
 * PVCM Protocol -- Pantavisor Container MCU
 *
 * Canonical wire format shared by all implementations:
 *   - pvcm-manager (Linux, A53)
 *   - U-Boot (board_late_init)
 *   - Zephyr SDK (M core / external MCU)
 *   - FreeRTOS SDK
 *
 * Frame format (UART and RPMsg):
 *   [ 0xAA | 0x55 | len 2B LE | payload | crc32 4B LE ]
 *
 * - sync: 0xAA 0x55
 * - len:  payload length in bytes (little-endian uint16)
 * - payload: starts with 1-byte opcode, followed by opcode-specific fields
 * - crc32: CRC32 of payload only (not sync bytes or length)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef PVCM_PROTOCOL_H
#define PVCM_PROTOCOL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Frame Constants --- */

#define PVCM_SYNC_BYTE_0        0xAA
#define PVCM_SYNC_BYTE_1        0x55
#define PVCM_MAGIC              0x5056434D  /* "PVCM" */
#define PVCM_PROTOCOL_VERSION   1
#define PVCM_DEFAULT_BAUDRATE   921600
/* Max data per HTTP_DATA/FW_DATA chunk.
 * Sized to fit in one RPMsg message: vring buffer (512) - RPMsg header (16)
 * - PVCM wire overhead (8) - DATA header (4) = 484. Round to 480. */
#define PVCM_MAX_CHUNK_SIZE     480

/* --- Opcodes --- */

typedef enum {
	/* Handshake */
	PVCM_OP_HELLO               = 0x01,  /* Linux -> MCU: probe */
	PVCM_OP_HELLO_RESP          = 0x02,  /* MCU -> Linux: identify */

	/* Boot State */
	PVCM_OP_QUERY_STATE         = 0x03,  /* Linux/U-Boot -> MCU */
	PVCM_OP_STATE_RESP          = 0x04,  /* MCU -> Linux/U-Boot */

	/* Revision Lifecycle */
	PVCM_OP_SET_TRYBOOT         = 0x05,  /* Linux -> MCU: stage tryboot */
	PVCM_OP_COMMIT              = 0x06,  /* Linux -> MCU: commit stable */
	PVCM_OP_ROLLBACK            = 0x07,  /* Linux -> MCU: explicit rollback */
	PVCM_OP_ACK                 = 0x08,  /* MCU -> Linux: accepted */
	PVCM_OP_NACK                = 0x09,  /* MCU -> Linux: rejected */

	/* Health Events (MCU -> Linux, unsolicited) */
	PVCM_EVT_HEARTBEAT          = 0x10,
	PVCM_EVT_BRIDGE_READY       = 0x11,
	PVCM_EVT_BRIDGE_LOST        = 0x12,
	PVCM_EVT_SERVICE_LIST       = 0x13,
	PVCM_EVT_REVISION_CHANGE    = 0x14,
	PVCM_OP_REQUEST_ROLLBACK    = 0x15,  /* MCU requests Linux rollback */

	/* Firmware Update (multiplexed, no special mode) */
	PVCM_OP_FW_UPDATE_START     = 0x20,
	PVCM_OP_FW_UPDATE_DATA      = 0x21,
	PVCM_OP_FW_UPDATE_END       = 0x22,
	PVCM_EVT_FW_PROGRESS        = 0x23,

	/* Log Stream */
	PVCM_OP_LOG                 = 0x28,

	/* MCU Detection */
	PVCM_OP_SMP_REJECT          = 0x29,

	/* HTTP Gateway -- chunked request/response (both directions)
	 * MCU as client: MCU sends HTTP_REQ, proxy forwards to Linux
	 * MCU as server: proxy sends HTTP_REQ, MCU handles and responds
	 * All bodies are chunked via HTTP_DATA frames */
	PVCM_OP_HTTP_REQ            = 0x30,  /* open request: method/status + path + headers */
	PVCM_OP_HTTP_DATA           = 0x31,  /* body chunk */
	PVCM_OP_HTTP_END            = 0x32,  /* transfer complete */

	/* DBus Gateway -- method calls, signal subscriptions, service exposure
	 * MCU as client: MCU sends DBUS_CALL, proxy forwards to Linux D-Bus
	 * MCU subscribes: MCU sends DBUS_SUBSCRIBE, proxy monitors signals
	 * MCU as server: MCU sends DBUS_EXPOSE, proxy registers on D-Bus
	 * All data fields use null-separated strings */
	PVCM_OP_DBUS_CALL           = 0x40,  /* MCU -> Linux: call method */
	PVCM_OP_DBUS_CALL_RESP      = 0x41,  /* Linux -> MCU: method reply */
	PVCM_OP_DBUS_SUBSCRIBE      = 0x42,  /* MCU -> Linux: subscribe signal */
	PVCM_OP_DBUS_UNSUBSCRIBE    = 0x43,  /* MCU -> Linux: unsubscribe */
	PVCM_OP_DBUS_SIGNAL         = 0x44,  /* Linux -> MCU: signal fired */
	PVCM_OP_DBUS_EXPOSE         = 0x45,  /* MCU -> Linux: register endpoint */
	PVCM_OP_DBUS_INVOKE         = 0x46,  /* Linux -> MCU: call MCU method */
	PVCM_OP_DBUS_INVOKE_RESP    = 0x47,  /* MCU -> Linux: MCU reply */
	PVCM_OP_DBUS_DATA           = 0x48,  /* either: data stream for D-Bus ops */

	/* Filesystem Gateway -- remote FS operations over RPMsg */
	PVCM_OP_FS_REQ              = 0x50,  /* MCU -> Linux: FS operation request */
	PVCM_OP_FS_RESP             = 0x51,  /* Linux -> MCU: operation result */
	PVCM_OP_FS_DATA             = 0x52,  /* either: data chunk (read/write) */
	PVCM_OP_FS_END              = 0x53,  /* either: transfer complete */

	/* Transport test — bidirectional echo for debugging */
	PVCM_OP_ECHO                = 0xE0,  /* either direction: echo back */
	PVCM_OP_ECHO_RESP           = 0xE1,  /* response to echo */
} pvcm_op_t;

/* --- Health Status --- */

#define PVCM_HEALTH_OK          0
#define PVCM_HEALTH_DEGRADED    1

/* --- HTTP Methods --- */

#define PVCM_HTTP_GET           0
#define PVCM_HTTP_POST          1
#define PVCM_HTTP_PUT           2
#define PVCM_HTTP_DELETE        3
#define PVCM_HTTP_HEAD          4
#define PVCM_HTTP_PATCH         5

/* --- HTTP Direction --- */

#define PVCM_HTTP_DIR_REQUEST   0  /* MCU → Linux (outbound) */
#define PVCM_HTTP_DIR_RESPONSE  1  /* Linux → MCU (response to outbound) */
#define PVCM_HTTP_DIR_INVOKE    2  /* Linux → MCU (inbound request) */
#define PVCM_HTTP_DIR_REPLY     3  /* MCU → Linux (response to inbound) */

/* --- Log Levels --- */

#define PVCM_LOG_ERR            0
#define PVCM_LOG_WRN            1
#define PVCM_LOG_INF            2
#define PVCM_LOG_DBG            3

/* --- NACK Error Codes --- */

#define PVCM_ERR_UNKNOWN        0
#define PVCM_ERR_NO_SLOT        1
#define PVCM_ERR_TOO_LARGE      2
#define PVCM_ERR_CHECKSUM       3
#define PVCM_ERR_BUSY           4
#define PVCM_ERR_INVALID_STATE  5

/* --- D-Bus Error Codes --- */

#define PVCM_DBUS_OK              0
#define PVCM_DBUS_ERR_NO_SERVICE  1  /* destination not on bus */
#define PVCM_DBUS_ERR_NO_METHOD   2  /* method/interface not found */
#define PVCM_DBUS_ERR_TIMEOUT     3  /* D-Bus call timed out */
#define PVCM_DBUS_ERR_FAILED      4  /* generic D-Bus error */
#define PVCM_DBUS_ERR_ARGS        5  /* argument marshalling error */
#define PVCM_DBUS_ERR_TRUNCATED   6  /* reply too large for frame */

/* --- Message Structs --- */

#ifndef __packed
#define __packed __attribute__((packed))
#endif

/* HELLO (Linux -> MCU): no payload beyond opcode */
typedef struct {
	uint8_t  op;
	uint32_t crc32;
} __packed pvcm_hello_t;

/* HELLO_RESP (MCU -> Linux) */
typedef struct {
	uint8_t  op;
	uint8_t  protocol_version;
	uint32_t baudrate;
	uint16_t max_msg_size;
	uint8_t  mcu_fw_version;
	uint32_t crc32;
} __packed pvcm_hello_resp_t;

/* QUERY_STATE (Linux/U-Boot -> MCU): no payload beyond opcode */
typedef struct {
	uint8_t  op;
	uint32_t crc32;
} __packed pvcm_query_state_t;

/* STATE_RESP (MCU -> Linux/U-Boot) */
typedef struct {
	uint8_t  op;
	uint8_t  status;
	uint8_t  stable_slot;       /* 0=A 1=B */
	uint8_t  tryboot_slot;
	uint8_t  tryboot_pending;
	uint8_t  tryboot_trying;
	uint32_t stable_rev;
	uint32_t tryboot_rev;
	uint8_t  mcu_fw_version;
	uint8_t  reserved[3];
	uint32_t crc32;
} __packed pvcm_state_resp_t;

/* ACK */
typedef struct {
	uint8_t  op;
	uint8_t  ref_op;            /* opcode being acknowledged */
	uint32_t crc32;
} __packed pvcm_ack_t;

/* NACK */
typedef struct {
	uint8_t  op;
	uint8_t  ref_op;
	uint8_t  error;             /* PVCM_ERR_* */
	uint32_t crc32;
} __packed pvcm_nack_t;

/* HEARTBEAT (MCU -> Linux, every 5s) */
typedef struct {
	uint8_t  op;
	uint8_t  status;            /* PVCM_HEALTH_OK / DEGRADED */
	uint16_t uptime_s;
	uint8_t  crash_count;
	uint8_t  reserved[3];
	uint32_t crc32;
} __packed pvcm_heartbeat_t;

/* LOG (MCU -> Linux -> PV log server) */
typedef struct {
	uint8_t  op;
	uint8_t  level;             /* PVCM_LOG_* */
	uint16_t msg_len;
	char     module[16];
	char     msg[224];
	uint32_t crc32;
} __packed pvcm_log_t;

/*
 * HTTP_REQ -- opens an HTTP exchange (metadata only)
 *
 * Path, headers, and body all flow as HTTP_DATA frames in order:
 *   first path_len bytes = path (e.g. "/sensor/config")
 *   next headers_len bytes = headers ("Key: Value\r\n" pairs)
 *   remaining bytes = body (total: body_len)
 *
 * HTTP_END marks the transfer complete.
 * No size limits on path, headers, or body — the transport
 * chunks them into DATA frames transparently.
 */
typedef struct {
	uint8_t  op;
	uint8_t  stream_id;         /* correlates REQ/DATA/END */
	uint8_t  direction;         /* PVCM_HTTP_DIR_* */
	uint8_t  method;            /* PVCM_HTTP_* (for requests) */
	uint16_t status_code;       /* HTTP status (for responses) */
	uint16_t path_len;          /* bytes of path in DATA stream */
	uint16_t headers_len;       /* bytes of headers in DATA stream */
	uint32_t body_len;          /* bytes of body in DATA stream */
	uint32_t crc32;
} __packed pvcm_http_req_t;

/* HTTP_DATA -- body chunk */
typedef struct {
	uint8_t  op;
	uint8_t  stream_id;
	uint16_t len;               /* bytes in this chunk */
	uint8_t  data[PVCM_MAX_CHUNK_SIZE];
	uint32_t crc32;
} __packed pvcm_http_data_t;

/* HTTP_END -- transfer complete */
typedef struct {
	uint8_t  op;
	uint8_t  stream_id;
	uint8_t  reserved[2];
	uint32_t crc32;
} __packed pvcm_http_end_t;

/*
 * D-Bus Gateway — streaming protocol
 *
 * All D-Bus operations use metadata-only headers followed by
 * DBUS_DATA frames carrying the actual payload. No size limits.
 *
 * Data is null-separated fields packed into the DBUS_DATA stream.
 * The metadata frame specifies field lengths so the receiver can
 * demux without buffering the entire payload.
 */

/*
 * DBUS_CALL (MCU -> Linux: call D-Bus method)
 *
 * Followed by DBUS_DATA frames carrying:
 *   dest + obj_path + interface + member + args_json
 *   (null-separated, lengths from metadata)
 */
typedef struct {
	uint8_t  op;
	uint8_t  req_id;            /* correlates with CALL_RESP */
	uint16_t data_len;          /* total bytes in DBUS_DATA stream */
	uint32_t crc32;
} __packed pvcm_dbus_call_t;

/*
 * DBUS_CALL_RESP (Linux -> MCU: method reply)
 *
 * Followed by DBUS_DATA frames carrying JSON result or error string.
 */
typedef struct {
	uint8_t  op;
	uint8_t  req_id;
	uint8_t  error;             /* PVCM_DBUS_OK or PVCM_DBUS_ERR_* */
	uint8_t  reserved;
	uint32_t data_len;          /* bytes in DBUS_DATA stream */
	uint32_t crc32;
} __packed pvcm_dbus_call_resp_t;

/*
 * DBUS_SUBSCRIBE (MCU -> Linux: subscribe to signal)
 *
 * Followed by DBUS_DATA frames carrying:
 *   sender\0obj_path\0interface\0signal_name
 */
typedef struct {
	uint8_t  op;
	uint8_t  sub_id;            /* assigned by MCU, used to unsubscribe */
	uint16_t data_len;          /* total bytes in DBUS_DATA stream */
	uint32_t crc32;
} __packed pvcm_dbus_sub_t;

/* DBUS_UNSUBSCRIBE (MCU -> Linux) — no data needed */
typedef struct {
	uint8_t  op;
	uint8_t  sub_id;
	uint8_t  reserved[2];
	uint32_t crc32;
} __packed pvcm_dbus_unsub_t;

/*
 * DBUS_SIGNAL (Linux -> MCU: signal fired)
 *
 * Followed by DBUS_DATA frames carrying:
 *   sender\0obj_path\0interface\0member\0args_json
 */
typedef struct {
	uint8_t  op;
	uint8_t  sub_id;
	uint16_t data_len;          /* total bytes in DBUS_DATA stream */
	uint32_t crc32;
} __packed pvcm_dbus_signal_t;

/*
 * DBUS_DATA — generic data frame for all D-Bus operations.
 * Correlated with the preceding metadata frame by context
 * (single-threaded dispatch, one pending operation per type).
 */
typedef struct {
	uint8_t  op;
	uint8_t  id;                /* req_id or sub_id from metadata */
	uint16_t len;               /* bytes in this chunk */
	uint8_t  data[PVCM_MAX_CHUNK_SIZE];
	uint32_t crc32;
} __packed pvcm_dbus_data_t;

/* DBUS_EXPOSE (MCU -> Linux: register D-Bus endpoint) -- future */
typedef struct {
	uint8_t  op;
	uint8_t  endpoint_id;
	uint16_t data_len;
	uint32_t crc32;
} __packed pvcm_dbus_expose_t;

/* DBUS_INVOKE (Linux -> MCU: call MCU endpoint) -- future */
typedef struct {
	uint8_t  op;
	uint8_t  invoke_id;
	uint8_t  endpoint_id;
	uint8_t  reserved;
	uint32_t data_len;
	uint32_t crc32;
} __packed pvcm_dbus_invoke_t;

/* DBUS_INVOKE_RESP (MCU -> Linux) -- future */
typedef struct {
	uint8_t  op;
	uint8_t  invoke_id;
	uint8_t  error;
	uint8_t  reserved;
	uint32_t data_len;
	uint32_t crc32;
} __packed pvcm_dbus_invoke_resp_t;

/* ---- Filesystem Gateway ---- */

/* FS sub-operations */
enum pvcm_fs_op {
	PVCM_FS_MOUNT     = 0x00,
	PVCM_FS_UNMOUNT   = 0x01,
	PVCM_FS_OPEN      = 0x02,
	PVCM_FS_CLOSE     = 0x03,
	PVCM_FS_READ      = 0x04,
	PVCM_FS_WRITE     = 0x05,
	PVCM_FS_LSEEK     = 0x06,
	PVCM_FS_TRUNCATE  = 0x07,
	PVCM_FS_SYNC      = 0x08,
	PVCM_FS_STAT      = 0x09,
	PVCM_FS_UNLINK    = 0x0A,
	PVCM_FS_RENAME    = 0x0B,
	PVCM_FS_MKDIR     = 0x0C,
	PVCM_FS_OPENDIR   = 0x0D,
	PVCM_FS_READDIR   = 0x0E,
	PVCM_FS_CLOSEDIR  = 0x0F,
	PVCM_FS_STATVFS   = 0x10,
};

/* FS_REQ (MCU -> Linux) */
typedef struct {
	uint8_t  op;            /* PVCM_OP_FS_REQ */
	uint8_t  req_id;
	uint8_t  fs_op;         /* PVCM_FS_OPEN, READ, etc. */
	uint8_t  fh;            /* file/dir handle (0 for open/mount) */
	uint32_t arg1;          /* flags, offset, whence, etc. */
	uint32_t arg2;          /* length, mode, etc. */
	uint16_t path_len;      /* bytes of path in FS_DATA stream */
	uint16_t reserved;
	uint32_t data_len;      /* total bytes of write data in FS_DATA */
	uint32_t crc32;
} __packed pvcm_fs_req_t;

/* FS_RESP (Linux -> MCU) */
typedef struct {
	uint8_t  op;            /* PVCM_OP_FS_RESP */
	uint8_t  req_id;
	uint8_t  fs_op;         /* echo back which operation */
	uint8_t  fh;            /* assigned handle (for open/opendir) */
	int32_t  result;        /* 0 success, negative errno */
	uint32_t data_len;      /* bytes of data in FS_DATA stream */
	uint32_t crc32;
} __packed pvcm_fs_resp_t;

/* FS_DATA (bidirectional: write MCU->Linux, read Linux->MCU) */
typedef struct {
	uint8_t  op;            /* PVCM_OP_FS_DATA */
	uint8_t  req_id;
	uint16_t len;
	uint8_t  data[PVCM_MAX_CHUNK_SIZE];
	uint32_t crc32;
} __packed pvcm_fs_data_t;

/* FS_END (bidirectional: marks data stream complete) */
typedef struct {
	uint8_t  op;            /* PVCM_OP_FS_END */
	uint8_t  req_id;
	uint8_t  reserved[2];
	uint32_t crc32;
} __packed pvcm_fs_end_t;

/* Serialized stat result in FS_DATA for STAT/READDIR responses */
struct pvcm_fs_stat {
	uint32_t type;          /* FS_DIR_ENTRY_FILE or FS_DIR_ENTRY_DIR */
	uint32_t size;          /* file size in bytes */
} __packed;

/* FW_UPDATE_START (Linux -> MCU) */
typedef struct {
	uint8_t  op;
	uint8_t  slot;
	uint32_t total_size;
	uint32_t chunk_size;
	uint8_t  sha256[32];
	uint32_t crc32;
} __packed pvcm_fw_start_t;

/* FW_UPDATE_DATA (Linux -> MCU) */
typedef struct {
	uint8_t  op;
	uint8_t  reserved;
	uint16_t seq;
	uint32_t offset;
	uint16_t len;
	uint8_t  data[PVCM_MAX_CHUNK_SIZE];
	uint32_t crc32;
} __packed pvcm_fw_data_t;

/* FW_UPDATE_END (Linux -> MCU) */
typedef struct {
	uint8_t  op;
	uint8_t  reserved[3];
	uint32_t crc32;
} __packed pvcm_fw_end_t;

/* EVT_FW_PROGRESS (MCU -> Linux) */
typedef struct {
	uint8_t  op;
	uint8_t  percent;
	uint32_t bytes_written;
	uint32_t total_bytes;
	uint32_t crc32;
} __packed pvcm_fw_progress_t;

/* ECHO / ECHO_RESP — transport test.
 * Send ECHO with N bytes of data; receiver sends ECHO_RESP with same data. */
typedef struct {
	uint8_t  op;
	uint8_t  seq;               /* sequence number for correlation */
	uint16_t reserved;
	uint32_t data_len;          /* total bytes requested (ping) or per-frame (echo) */
	uint8_t  data[500];         /* up to 500 bytes echo payload */
	uint32_t crc32;
} __packed pvcm_echo_t;

/* --- MCU Flash State --- */

typedef struct {
	uint32_t magic;             /* PVCM_MAGIC */
	uint32_t version;

	uint32_t stable_rev;
	uint8_t  stable_slot;       /* 0=A 1=B */
	uint32_t tryboot_rev;
	uint8_t  tryboot_slot;
	uint8_t  tryboot_pending;
	uint8_t  tryboot_trying;    /* set BEFORE jump, cleared on COMMIT */

	uint8_t  crash_count;
	uint8_t  crash_threshold;

	uint32_t crc32;
} pvcm_flash_state_t;

#ifdef __cplusplus
}
#endif

#endif /* PVCM_PROTOCOL_H */
