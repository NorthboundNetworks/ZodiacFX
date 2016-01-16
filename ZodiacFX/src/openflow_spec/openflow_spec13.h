/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

/* OpenFlow: protocol between controller and datapath. */


#ifndef OPENFLOW_13_H_
#define OPENFLOW_13_H_

/* Version number:
 * Non-experimental versions released: 0x01 = 1.0 ; 0x02 = 1.1 ; 0x03 = 1.2
 *     0x04 = 1.4
 * Experimental versions released: 0x81 -- 0x99
 */
/* The most significant bit being set in the version field indicates an
 * experimental OpenFlow version.
 */
#define OFP13_VERSION   0x04

#define OFP13_MAX_TABLE_NAME_LEN 32
#define OFP13_MAX_PORT_NAME_LEN  16

#define OFP13_TCP_PORT  6633
#define OFP13_SSL_PORT  6633

#define OFP13_ETH_ALEN 6          /* Bytes in an Ethernet address. */

enum ofp13_type {
	/* Immutable messages. */
	OFPT13_HELLO              = 0,  /* Symmetric message */
	OFPT13_ERROR              = 1,  /* Symmetric message */
	OFPT13_ECHO_REQUEST       = 2,  /* Symmetric message */
	OFPT13_ECHO_REPLY         = 3,  /* Symmetric message */
	OFPT13_EXPERIMENTER       = 4,  /* Symmetric message */

	/* Switch configuration messages. */
	OFPT13_FEATURES_REQUEST   = 5,  /* Controller/switch message */
	OFPT13_FEATURES_REPLY     = 6,  /* Controller/switch message */
	OFPT13_GET_CONFIG_REQUEST = 7,  /* Controller/switch message */
	OFPT13_GET_CONFIG_REPLY   = 8,  /* Controller/switch message */
	OFPT13_SET_CONFIG         = 9,  /* Controller/switch message */

	/* Asynchronous messages. */
	OFPT13_PACKET_IN          = 10, /* Async message */
	OFPT13_FLOW_REMOVED       = 11, /* Async message */
	OFPT13_PORT_STATUS        = 12, /* Async message */

	/* Controller command messages. */
	OFPT13_PACKET_OUT         = 13, /* Controller/switch message */
	OFPT13_FLOW_MOD           = 14, /* Controller/switch message */
	OFPT13_GROUP_MOD          = 15, /* Controller/switch message */
	OFPT13_PORT_MOD           = 16, /* Controller/switch message */
	OFPT13_TABLE_MOD          = 17, /* Controller/switch message */

	/* Multipart messages. */
	OFPT13_MULTIPART_REQUEST      = 18, /* Controller/switch message */
	OFPT13_MULTIPART_REPLY        = 19, /* Controller/switch message */

	/* Barrier messages. */
	OFPT13_BARRIER_REQUEST    = 20, /* Controller/switch message */
	OFPT13_BARRIER_REPLY      = 21, /* Controller/switch message */

	/* Queue Configuration messages. */
	OFPT13_QUEUE_GET_CONFIG_REQUEST = 22,  /* Controller/switch message */
	OFPT13_QUEUE_GET_CONFIG_REPLY   = 23,  /* Controller/switch message */

	/* Controller role change request messages. */
	OFPT13_ROLE_REQUEST       = 24, /* Controller/switch message */
	OFPT13_ROLE_REPLY         = 25, /* Controller/switch message */

	/* Asynchronous message configuration. */
	OFPT13_GET_ASYNC_REQUEST  = 26, /* Controller/switch message */
	OFPT13_GET_ASYNC_REPLY    = 27, /* Controller/switch message */
	OFPT13_SET_ASYNC          = 28, /* Controller/switch message */

	/* Meters and rate limiters configuration messages. */
	OFPT13_METER_MOD          = 29, /* Controller/switch message */
};

enum ofp13_multipart_types {
    /* Description of this OpenFlow switch.
     * The request body is empty.
     * The reply body is struct ofp_desc. */
    OFPMP13_DESC = 0,

    /* Individual flow statistics.
     * The request body is struct ofp_flow_stats_request.
     * The reply body is an array of struct ofp_flow_stats. */
    OFPMP13_FLOW = 1,

    /* Aggregate flow statistics.
     * The request body is struct ofp_aggregate_stats_request.
     * The reply body is struct ofp_aggregate_stats_reply. */
    OFPMP13_AGGREGATE = 2,

    /* Flow table statistics.
     * The request body is empty.
     * The reply body is an array of struct ofp_table_stats. */
    OFPMP13_TABLE = 3,

    /* Port statistics.
     * The request body is struct ofp_port_stats_request.
     * The reply body is an array of struct ofp_port_stats. */
    OFPMP13_PORT_STATS = 4,

    /* Queue statistics for a port
     * The request body is struct ofp_queue_stats_request.
     * The reply body is an array of struct ofp_queue_stats */
    OFPMP13_QUEUE = 5,

    /* Group counter statistics.
     * The request body is struct ofp_group_stats_request.
     * The reply is an array of struct ofp_group_stats. */
    OFPMP13_GROUP = 6,

    /* Group description.
     * The request body is empty.
     * The reply body is an array of struct ofp_group_desc_stats. */
    OFPMP13_GROUP_DESC = 7,

    /* Group features.
     * The request body is empty.
     * The reply body is struct ofp_group_features. */
    OFPMP13_GROUP_FEATURES = 8,

    /* Meter statistics.
     * The request body is struct ofp_meter_multipart_requests.
     * The reply body is an array of struct ofp_meter_stats. */
    OFPMP13_METER = 9,

    /* Meter configuration.
     * The request body is struct ofp_meter_multipart_requests.
     * The reply body is an array of struct ofp_meter_config. */
    OFPMP13_METER_CONFIG = 10,

    /* Meter features.
     * The request body is empty.
     * The reply body is struct ofp_meter_features. */
    OFPMP13_METER_FEATURES = 11,

    /* Table features.
     * The request body is either empty or contains an array of
     * struct ofp_table_features containing the controller's
     * desired view of the switch. If the switch is unable to
     * set the specified view an error is returned.
     * The reply body is an array of struct ofp_table_features. */
    OFPMP13_TABLE_FEATURES = 12,

    /* Port description.
     * The request body is empty.
     * The reply body is an array of struct ofp_port. */
    OFPMP13_PORT_DESC = 13,

    /* Experimenter extension.
     * The request and reply bodies begin with
     * struct ofp_experimenter_multipart_header.
     * The request and reply bodies are otherwise experimenter-defined. */
    OFPMP13_EXPERIMENTER = 0xffff
};

enum ofp13_multipart_request_flags {
    OFPMPF13_REQ_MORE  = 1 << 0  /* More requests to follow. */
};

struct ofp13_multipart_request {
    struct ofp_header header;
    uint16_t type;              /* One of the OFPMP_* constants. */
    uint16_t flags;             /* OFPMPF_REQ_* flags. */
    uint8_t pad[4];
    uint8_t body[0];            /* Body of the request. */
};

enum ofp13_multipart_reply_flags {
    OFPMPF13_REPLY_MORE  = 1 << 0  /* More replies to follow. */
};

struct ofp13_multipart_reply {
    struct ofp_header header;
    uint16_t type;              /* One of the OFPMP_* constants. */
    uint16_t flags;             /* OFPMPF_REPLY_* flags. */
    uint8_t pad[4];
    uint8_t body[0];            /* Body of the reply. */
};

#define DESC_STR_LEN   256
#define SERIAL_NUM_LEN 32

struct ofp13_desc {
	char mfr_desc[DESC_STR_LEN];       /* Manufacturer description. */
	char hw_desc[DESC_STR_LEN];        /* Hardware description. */
	char sw_desc[DESC_STR_LEN];        /* Software description. */
	char serial_num[SERIAL_NUM_LEN];   /* Serial number. */
	char dp_desc[DESC_STR_LEN];        /* Human readable description of datapath. */
};

/* Switch features. */
struct ofp13_switch_features {
    struct ofp_header header;
    uint64_t datapath_id;   /* Datapath unique ID.  The lower 48-bits are for
                               a MAC address, while the upper 16-bits are
                               implementer-defined. */

    uint32_t n_buffers;     /* Max packets buffered at once. */

    uint8_t n_tables;       /* Number of tables supported by datapath. */
    uint8_t auxiliary_id;   /* Identify auxiliary connections */
    uint8_t pad[2];         /* Align to 64-bits. */

    /* Features. */
    uint32_t capabilities;  /* Bitmap of support "ofp_capabilities". */
    uint32_t reserved;
};


/* Description of a port */
struct ofp13_port {
    uint32_t port_no;
    uint8_t pad[4];
    uint8_t hw_addr[OFP13_ETH_ALEN];
    uint8_t pad2[2];                  /* Align to 64 bits. */
    char name[OFP13_MAX_PORT_NAME_LEN]; /* Null-terminated */

    uint32_t config;        /* Bitmap of OFPPC_* flags. */
    uint32_t state;         /* Bitmap of OFPPS_* flags. */

    /* Bitmaps of OFPPF_* that describe features.  All bits zeroed if
     * unsupported or unavailable. */
    uint32_t curr;          /* Current features. */
    uint32_t advertised;    /* Features being advertised by the port. */
    uint32_t supported;     /* Features supported by the port. */
    uint32_t peer;          /* Features advertised by peer. */

    uint32_t curr_speed;    /* Current port bitrate in kbps. */
    uint32_t max_speed;     /* Max port bitrate in kbps */
};

/* Body for ofp_multipart_request of type OFPMP_PORT. */
struct ofp13_port_stats_request {
    uint32_t port_no;        /* OFPMP_PORT message must request statistics
                              * either for a single port (specified in
                              * port_no) or for all ports (if port_no ==
                              * OFPP_ANY). */
    uint8_t pad[4];
};

/* Body of reply to OFPMP_PORT request. If a counter is unsupported, set
 * the field to all ones. */
struct ofp13_port_stats {
    uint32_t port_no;
    uint8_t pad[4];          /* Align to 64-bits. */
    uint64_t rx_packets;     /* Number of received packets. */
    uint64_t tx_packets;     /* Number of transmitted packets. */
    uint64_t rx_bytes;       /* Number of received bytes. */
    uint64_t tx_bytes;       /* Number of transmitted bytes. */
    uint64_t rx_dropped;     /* Number of packets dropped by RX. */
    uint64_t tx_dropped;     /* Number of packets dropped by TX. */
    uint64_t rx_errors;      /* Number of receive errors.  This is a super-set
                                of more specific receive errors and should be
                                greater than or equal to the sum of all
                                rx_*_err values. */
    uint64_t tx_errors;      /* Number of transmit errors.  This is a super-set
                                of more specific transmit errors and should be
                                greater than or equal to the sum of all
                                tx_*_err values (none currently defined.) */
    uint64_t rx_frame_err;   /* Number of frame alignment errors. */
    uint64_t rx_over_err;    /* Number of packets with RX overrun. */
    uint64_t rx_crc_err;     /* Number of CRC errors. */
    uint64_t collisions;     /* Number of collisions. */
    uint32_t duration_sec;   /* Time port has been alive in seconds. */
    uint32_t duration_nsec;  /* Time port has been alive in nanoseconds beyond
                                duration_sec. */
};

/* Current state of the physical port.  These are not configurable from
 * the controller.
 */
enum ofp13_port_state {
    OFPPS13_LINK_DOWN    = 1 << 0,  /* No physical link present. */
    OFPPS13_BLOCKED      = 1 << 1,  /* Port is blocked */
    OFPPS13_LIVE         = 1 << 2,  /* Live for Fast Failover Group. */
};

/* Features of ports available in a datapath. */
enum ofp13_port_features {
	OFPPF13_10MB_HD    = 1 << 0,  /* 10 Mb half-duplex rate support. */
	OFPPF13_10MB_FD    = 1 << 1,  /* 10 Mb full-duplex rate support. */
	OFPPF13_100MB_HD   = 1 << 2,  /* 100 Mb half-duplex rate support. */
	OFPPF13_100MB_FD   = 1 << 3,  /* 100 Mb full-duplex rate support. */
	OFPPF13_1GB_HD     = 1 << 4,  /* 1 Gb half-duplex rate support. */
	OFPPF13_1GB_FD     = 1 << 5,  /* 1 Gb full-duplex rate support. */
	OFPPF13_10GB_FD    = 1 << 6,  /* 10 Gb full-duplex rate support. */
	OFPPF13_40GB_FD    = 1 << 7,  /* 40 Gb full-duplex rate support. */
	OFPPF13_100GB_FD   = 1 << 8,  /* 100 Gb full-duplex rate support. */
	OFPPF13_1TB_FD     = 1 << 9,  /* 1 Tb full-duplex rate support. */
	OFPPF13_OTHER      = 1 << 10, /* Other rate, not in the list. */

	OFPPF13_COPPER     = 1 << 11, /* Copper medium. */
	OFPPF13_FIBER      = 1 << 12, /* Fiber medium. */
	OFPPF13_AUTONEG    = 1 << 13, /* Auto-negotiation. */
	OFPPF13_PAUSE      = 1 << 14, /* Pause. */
	OFPPF13_PAUSE_ASYM = 1 << 15  /* Asymmetric pause. */
};

/* Capabilities supported by the datapath. */
enum ofp13_capabilities {
	OFPC13_FLOW_STATS     = 1 << 0,  /* Flow statistics. */
	OFPC13_TABLE_STATS    = 1 << 1,  /* Table statistics. */
	OFPC13_PORT_STATS     = 1 << 2,  /* Port statistics. */
	OFPC13_GROUP_STATS    = 1 << 3,  /* Group statistics. */
	OFPC13_IP_REASM       = 1 << 5,  /* Can reassemble IP fragments. */
	OFPC13_QUEUE_STATS    = 1 << 6,  /* Queue statistics. */
	OFPC13_PORT_BLOCKED   = 1 << 8   /* Switch will block looping ports. */
};

enum ofp13_error_type {
	OFPET13_HELLO_FAILED         = 0,  /* Hello protocol failed. */
	OFPET13_BAD_REQUEST          = 1,  /* Request was not understood. */
	OFPET13_BAD_ACTION           = 2,  /* Error in action description. */
	OFPET13_BAD_INSTRUCTION      = 3,  /* Error in instruction list. */
	OFPET13_BAD_MATCH            = 4,  /* Error in match. */
	OFPET13_FLOW_MOD_FAILED      = 5,  /* Problem modifying flow entry. */
	OFPET13_GROUP_MOD_FAILED     = 6,  /* Problem modifying group entry. */
	OFPET13_PORT_MOD_FAILED      = 7,  /* Port mod request failed. */
	OFPET13_TABLE_MOD_FAILED     = 8,  /* Table mod request failed. */
	OFPET13_QUEUE_OP_FAILED      = 9,  /* Queue operation failed. */
	OFPET13_SWITCH_CONFIG_FAILED = 10, /* Switch config request failed. */
	OFPET13_ROLE_REQUEST_FAILED  = 11, /* Controller Role request failed. */
	OFPET13_METER_MOD_FAILED     = 12, /* Error in meter. */
	OFPET13_TABLE_FEATURES_FAILED = 13, /* Setting table features failed. */
	OFPET13_EXPERIMENTER = 0xffff      /* Experimenter error messages. */
};

/* ofp_error_msg 'code' values for OFPET_FLOW_MOD_FAILED.  'data' contains
 * at least the first 64 bytes of the failed request. */
enum ofp13_flow_mod_failed_code {
    OFPFMFC13_UNKNOWN      = 0,   /* Unspecified error. */
    OFPFMFC13_TABLE_FULL   = 1,   /* Flow not added because table was full. */
    OFPFMFC13_BAD_TABLE_ID = 2,   /* Table does not exist */
    OFPFMFC13_OVERLAP      = 3,   /* Attempted to add overlapping flow with
                                   CHECK_OVERLAP flag set. */
    OFPFMFC13_EPERM        = 4,   /* Permissions error. */
    OFPFMFC13_BAD_TIMEOUT  = 5,   /* Flow not added because of unsupported
                                   idle/hard timeout. */
    OFPFMFC13_BAD_COMMAND  = 6,   /* Unsupported or unknown command. */
    OFPFMFC13_BAD_FLAGS    = 7,   /* Unsupported or unknown flags. */
};

/* ## ----------------- ## */
/* ## OpenFlow Actions. ## */
/* ## ----------------- ## */

enum ofp13_action_type {
    OFPAT_OUTPUT       = 0,  /* Output to switch port. */
    OFPAT_COPY_TTL_OUT = 11, /* Copy TTL "outwards" -- from next-to-outermost
                                to outermost */
    OFPAT_COPY_TTL_IN  = 12, /* Copy TTL "inwards" -- from outermost to
                               next-to-outermost */
    OFPAT_SET_MPLS_TTL = 15, /* MPLS TTL */
    OFPAT_DEC_MPLS_TTL = 16, /* Decrement MPLS TTL */

    OFPAT_PUSH_VLAN    = 17, /* Push a new VLAN tag */
    OFPAT_POP_VLAN     = 18, /* Pop the outer VLAN tag */
    OFPAT_PUSH_MPLS    = 19, /* Push a new MPLS tag */
    OFPAT_POP_MPLS     = 20, /* Pop the outer MPLS tag */
    OFPAT_SET_QUEUE    = 21, /* Set queue id when outputting to a port */
    OFPAT_GROUP        = 22, /* Apply group. */
    OFPAT_SET_NW_TTL   = 23, /* IP TTL. */
    OFPAT_DEC_NW_TTL   = 24, /* Decrement IP TTL. */
    OFPAT_SET_FIELD    = 25, /* Set a header field using OXM TLV format. */
    OFPAT_PUSH_PBB     = 26, /* Push a new PBB service tag (I-TAG) */
    OFPAT_POP_PBB      = 27, /* Pop the outer PBB service tag (I-TAG) */
    OFPAT_EXPERIMENTER = 0xffff
};

/* Action header that is common to all actions.  The length includes the
 * header and any padding used to make the action 64-bit aligned.
 * NB: The length of an action *must* always be a multiple of eight. */
struct ofp13_action_header {
    uint16_t type;                  /* One of OFPAT_*. */
    uint16_t len;                   /* Length of action, including this
                                       header.  This is the length of action,
                                       including any padding to make it
                                       64-bit aligned. */
    uint8_t pad[4];
};

enum ofp13_controller_max_len {
	OFPCML_MAX       = 0xffe5, /* maximum max_len value which can be used
	                              to request a specific byte length. */
	OFPCML_NO_BUFFER = 0xffff  /* indicates that no buffering should be
	                              applied and the whole packet is to be
	                              sent to the controller. */
};

/* Action structure for OFPAT_OUTPUT, which sends packets out 'port'.
 * When the 'port' is the OFPP_CONTROLLER, 'max_len' indicates the max
 * number of bytes to send.  A 'max_len' of zero means no bytes of the
 * packet should be sent. A 'max_len' of OFPCML_NO_BUFFER means that
 * the packet is not buffered and the complete packet is to be sent to
 * the controller. */
struct ofp13_action_output {
    uint16_t type;                  /* OFPAT_OUTPUT. */
    uint16_t len;                   /* Length is 16. */
    uint32_t port;                  /* Output port. */
    uint16_t max_len;               /* Max length to send to controller. */
    uint8_t pad[6];                 /* Pad to 64 bits. */
};

/* Action structure for OFPAT_SET_MPLS_TTL. */
struct ofp13_action_mpls_ttl {
    uint16_t type;                  /* OFPAT_SET_MPLS_TTL. */
    uint16_t len;                   /* Length is 8. */
    uint8_t mpls_ttl;               /* MPLS TTL */
    uint8_t pad[3];
};

/* Action structure for OFPAT_PUSH_VLAN/MPLS/PBB. */
struct ofp13_action_push {
    uint16_t type;                  /* OFPAT_PUSH_VLAN/MPLS/PBB. */
    uint16_t len;                   /* Length is 8. */
    uint16_t ethertype;             /* Ethertype */
    uint8_t pad[2];
};

/* Action structure for OFPAT_POP_MPLS. */
struct ofp13_action_pop_mpls {
    uint16_t type;                  /* OFPAT_POP_MPLS. */
    uint16_t len;                   /* Length is 8. */
    uint16_t ethertype;             /* Ethertype */
    uint8_t pad[2];
};

/* Action structure for OFPAT_GROUP. */
struct ofp13_action_group {
    uint16_t type;                  /* OFPAT_GROUP. */
    uint16_t len;                   /* Length is 8. */
    uint32_t group_id;              /* Group identifier. */
};

/* Action structure for OFPAT_SET_NW_TTL. */
struct ofp13_action_nw_ttl {
    uint16_t type;                  /* OFPAT_SET_NW_TTL. */
    uint16_t len;                   /* Length is 8. */
    uint8_t nw_ttl;                 /* IP TTL */
    uint8_t pad[3];
};

/* Action structure for OFPAT_SET_FIELD. */
struct ofp13_action_set_field {
    uint16_t type;                  /* OFPAT_SET_FIELD. */
    uint16_t len;                   /* Length is padded to 64 bits. */
    /* Followed by:
     *   - Exactly oxm_len bytes containing a single OXM TLV, then
     *   - Exactly ((oxm_len + 4) + 7)/8*8 - (oxm_len + 4) (between 0 and 7)
     *     bytes of all-zero bytes
     */
    uint8_t field[4];               /* OXM TLV - Make compiler happy */
};

/* Action header for OFPAT_EXPERIMENTER.
 * The rest of the body is experimenter-defined. */
struct ofp13_action_experimenter_header {
    uint16_t type;                  /* OFPAT_EXPERIMENTER. */
    uint16_t len;                   /* Length is a multiple of 8. */
    uint32_t experimenter;          /* Experimenter ID which takes the same
                                       form as in struct
                                       ofp_experimenter_header. */
};

/* ## ---------------------- ## */
/* ## OpenFlow Instructions. ## */
/* ## ---------------------- ## */

enum ofp13_instruction_type {
    OFPIT_GOTO_TABLE = 1,       /* Setup the next table in the lookup
                                   pipeline */
    OFPIT_WRITE_METADATA = 2,   /* Setup the metadata field for use later in
                                   pipeline */
    OFPIT_WRITE_ACTIONS = 3,    /* Write the action(s) onto the datapath action
                                   set */
    OFPIT_APPLY_ACTIONS = 4,    /* Applies the action(s) immediately */
    OFPIT_CLEAR_ACTIONS = 5,    /* Clears all actions from the datapath
                                   action set */
    OFPIT_METER = 6,            /* Apply meter (rate limiter) */

    OFPIT_EXPERIMENTER = 0xFFFF  /* Experimenter instruction */
};

/* Generic ofp_instruction structure */
struct ofp13_instruction {
    uint16_t type;                /* Instruction type */
    uint16_t len;                 /* Length of this struct in bytes. */
};

/* Instruction structure for OFPIT_GOTO_TABLE */
struct ofp13_instruction_goto_table {
    uint16_t type;                /* OFPIT_GOTO_TABLE */
    uint16_t len;                 /* Length of this struct in bytes. */
    uint8_t table_id;             /* Set next table in the lookup pipeline */
    uint8_t pad[3];               /* Pad to 64 bits. */
};

/* Instruction structure for OFPIT_WRITE_METADATA */
struct ofp13_instruction_write_metadata {
    uint16_t type;                /* OFPIT_WRITE_METADATA */
    uint16_t len;                 /* Length of this struct in bytes. */
    uint8_t pad[4];               /* Align to 64-bits */
    uint64_t metadata;            /* Metadata value to write */
    uint64_t metadata_mask;       /* Metadata write bitmask */
};

/* Instruction structure for OFPIT_WRITE/APPLY/CLEAR_ACTIONS */
struct ofp13_instruction_actions {
    uint16_t type;              /* One of OFPIT_*_ACTIONS */
    uint16_t len;               /* Length of this struct in bytes. */
    uint8_t pad[4];             /* Align to 64-bits */
    struct ofp13_action_header actions[0];  /* Actions associated with
                                             OFPIT_WRITE_ACTIONS and
                                             OFPIT_APPLY_ACTIONS */
};

/* Instruction structure for OFPIT_METER */
struct ofp13_instruction_meter {
    uint16_t type;                /* OFPIT_METER */
    uint16_t len;                 /* Length is 8. */
    uint32_t meter_id;            /* Meter instance. */
};

/* Instruction structure for experimental instructions */
struct ofp13_instruction_experimenter {
    uint16_t type;		/* OFPIT_EXPERIMENTER */
    uint16_t len;               /* Length of this struct in bytes */
    uint32_t experimenter;      /* Experimenter ID which takes the same form
                                   as in struct ofp_experimenter_header. */
    /* Experimenter-defined arbitrary additional data. */
};

/* Table Feature property types.
 * Low order bit cleared indicates a property for a regular Flow Entry.
 * Low order bit set indicates a property for the Table-Miss Flow Entry.
 */
enum ofp13_table_feature_prop_type {
    OFPTFPT_INSTRUCTIONS           = 0,  /* Instructions property. */
    OFPTFPT_INSTRUCTIONS_MISS      = 1,  /* Instructions for table-miss. */
    OFPTFPT_NEXT_TABLES            = 2,  /* Next Table property. */
    OFPTFPT_NEXT_TABLES_MISS       = 3,  /* Next Table for table-miss. */
    OFPTFPT_WRITE_ACTIONS          = 4,  /* Write Actions property. */
    OFPTFPT_WRITE_ACTIONS_MISS     = 5,  /* Write Actions for table-miss. */
    OFPTFPT_APPLY_ACTIONS          = 6,  /* Apply Actions property. */
    OFPTFPT_APPLY_ACTIONS_MISS     = 7,  /* Apply Actions for table-miss. */
    OFPTFPT_MATCH                  = 8,  /* Match property. */
    OFPTFPT_WILDCARDS              = 10, /* Wildcards property. */
    OFPTFPT_WRITE_SETFIELD         = 12, /* Write Set-Field property. */
    OFPTFPT_WRITE_SETFIELD_MISS    = 13, /* Write Set-Field for table-miss. */
    OFPTFPT_APPLY_SETFIELD         = 14, /* Apply Set-Field property. */
    OFPTFPT_APPLY_SETFIELD_MISS    = 15, /* Apply Set-Field for table-miss. */
    OFPTFPT_EXPERIMENTER           = 0xFFFE, /* Experimenter property. */
    OFPTFPT_EXPERIMENTER_MISS      = 0xFFFF, /* Experimenter for table-miss. */
};

/* Common header for all Table Feature Properties */
struct ofp13_table_feature_prop_header {
    uint16_t         type;    /* One of OFPTFPT_*. */
    uint16_t         length;  /* Length in bytes of this property. */
};

/* Instructions property */
struct ofp13_table_feature_prop_instructions {
    uint16_t         type;    /* One of OFPTFPT_INSTRUCTIONS,
                                 OFPTFPT_INSTRUCTIONS_MISS. */
    uint16_t         length;  /* Length in bytes of this property. */
    /* Followed by:
     *   - Exactly (length - 4) bytes containing the instruction ids, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
    struct ofp13_instruction   instruction_ids[0];   /* List of instructions */
};

/* Next Tables property */
struct ofp13_table_feature_prop_next_tables {
    uint16_t         type;    /* One of OFPTFPT_NEXT_TABLES,
                                 OFPTFPT_NEXT_TABLES_MISS. */
    uint16_t         length;  /* Length in bytes of this property. */
    /* Followed by:
     *   - Exactly (length - 4) bytes containing the table_ids, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
    uint8_t          next_table_ids[0];
};

/* Actions property */
struct ofp13_table_feature_prop_actions {
    uint16_t         type;    /* One of OFPTFPT_WRITE_ACTIONS,
                                 OFPTFPT_WRITE_ACTIONS_MISS,
                                 OFPTFPT_APPLY_ACTIONS,
                                 OFPTFPT_APPLY_ACTIONS_MISS. */
    uint16_t         length;  /* Length in bytes of this property. */
    /* Followed by:
     *   - Exactly (length - 4) bytes containing the action_ids, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
    struct ofp_action_header  action_ids[0];      /* List of actions */
};

/* Match, Wildcard or Set-Field property */
struct ofp13_table_feature_prop_oxm {
    uint16_t         type;    /* One of OFPTFPT_MATCH,
                                 OFPTFPT_WILDCARDS,
                                 OFPTFPT_WRITE_SETFIELD,
                                 OFPTFPT_WRITE_SETFIELD_MISS,
                                 OFPTFPT_APPLY_SETFIELD,
                                 OFPTFPT_APPLY_SETFIELD_MISS. */
    uint16_t         length;  /* Length in bytes of this property. */
    /* Followed by:
     *   - Exactly (length - 4) bytes containing the oxm_ids, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
    uint32_t         oxm_ids[0];   /* Array of OXM headers */
};

/* Experimenter table feature property */
struct ofp13_table_feature_prop_experimenter {
    uint16_t         type;    /* One of OFPTFPT_EXPERIMENTER,
                                 OFPTFPT_EXPERIMENTER_MISS. */
    uint16_t         length;  /* Length in bytes of this property. */
    uint32_t         experimenter;  /* Experimenter ID which takes the same
                                       form as in struct
                                       ofp_experimenter_header. */
    uint32_t         exp_type;      /* Experimenter defined. */
    /* Followed by:
     *   - Exactly (length - 12) bytes containing the experimenter data, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
    uint32_t         experimenter_data[0];
};

/* Body for ofp_multipart_request of type OFPMP_TABLE_FEATURES./
 * Body of reply to OFPMP_TABLE_FEATURES request. */
struct ofp13_table_features {
    uint16_t length;         /* Length is padded to 64 bits. */
    uint8_t table_id;        /* Identifier of table.  Lower numbered tables
                                are consulted first. */
    uint8_t pad[5];          /* Align to 64-bits. */
    char name[OFP13_MAX_TABLE_NAME_LEN];
    uint64_t metadata_match; /* Bits of metadata table can match. */
    uint64_t metadata_write; /* Bits of metadata table can write. */
    uint32_t config;         /* Bitmap of OFPTC_* values */
    uint32_t max_entries;    /* Max number of entries supported. */

    /* Table Feature Property list */
    struct ofp13_table_feature_prop_header properties[0];
};

/* Body of reply to OFPMP_TABLE request. */
struct ofp13_table_stats {
    uint8_t table_id;        /* Identifier of table.  Lower numbered tables
                                are consulted first. */
    uint8_t pad[3];          /* Align to 32-bits. */
    uint32_t active_count;   /* Number of active entries. */
    uint64_t lookup_count;   /* Number of packets looked up in table. */
    uint64_t matched_count;  /* Number of packets that hit table. */
};

/* ## -------------------------- ## */
/* ## OpenFlow Extensible Match. ## */
/* ## -------------------------- ## */

/* The match type indicates the match structure (set of fields that compose the
 * match) in use. The match type is placed in the type field at the beginning
 * of all match structures. The "OpenFlow Extensible Match" type corresponds
 * to OXM TLV format described below and must be supported by all OpenFlow
 * switches. Extensions that define other match types may be published on the
 * ONF wiki. Support for extensions is optional.
 */
enum ofp_match_type {
    OFPMT13_STANDARD = 0,       /* Deprecated. */
    OFPMT13_OXM      = 1,       /* OpenFlow Extensible Match */
};

/* Fields to match against flows */
struct ofp13_match {
    uint16_t type;             /* One of OFPMT_* */
    uint16_t length;           /* Length of ofp_match (excluding padding) */
    /* Followed by:
     *   - Exactly (length - 4) (possibly 0) bytes containing OXM TLVs, then
     *   - Exactly ((length + 7)/8*8 - length) (between 0 and 7) bytes of
     *     all-zero bytes
     * In summary, ofp_match is padded as needed, to make its overall size
     * a multiple of 8, to preserve alignement in structures using it.
     */
    uint8_t oxm_fields[4];     /* OXMs start here - Make compiler happy */
};

/* Why is this packet being sent to the controller? */
enum ofp13_packet_in_reason {
	OFPR13_NO_MATCH    = 0,   /* No matching flow (table-miss flow entry). */
	OFPR13_ACTION      = 1,   /* Action explicitly output to controller. */
	OFPR13_INVALID_TTL = 2,   /* Packet has invalid TTL */
};

/* ## --------------------------- ## */
/* ## OpenFlow Flow Modification. ## */
/* ## --------------------------- ## */

enum ofp13_flow_mod_command {
    OFPFC13_ADD           = 0, /* New flow. */
    OFPFC13_MODIFY        = 1, /* Modify all matching flows. */
    OFPFC13_MODIFY_STRICT = 2, /* Modify entry strictly matching wildcards and
                                priority. */
    OFPFC13_DELETE        = 3, /* Delete all matching flows. */
    OFPFC13_DELETE_STRICT = 4, /* Delete entry strictly matching wildcards and
                                priority. */
};

/* Flow setup and teardown (controller -> datapath). */
struct ofp13_flow_mod {
    struct ofp_header header;
    uint64_t cookie;             /* Opaque controller-issued identifier. */
    uint64_t cookie_mask;        /* Mask used to restrict the cookie bits
                                    that must match when the command is
                                    OFPFC_MODIFY* or OFPFC_DELETE*. A value
                                    of 0 indicates no restriction. */

    /* Flow actions. */
    uint8_t table_id;             /* ID of the table to put the flow in.
                                     For OFPFC_DELETE_* commands, OFPTT_ALL
                                     can also be used to delete matching
                                     flows from all tables. */
    uint8_t command;              /* One of OFPFC_*. */
    uint16_t idle_timeout;        /* Idle time before discarding (seconds). */
    uint16_t hard_timeout;        /* Max time before discarding (seconds). */
    uint16_t priority;            /* Priority level of flow entry. */
    uint32_t buffer_id;           /* Buffered packet to apply to, or
                                     OFP_NO_BUFFER.
                                     Not meaningful for OFPFC_DELETE*. */
    uint32_t out_port;            /* For OFPFC_DELETE* commands, require
                                     matching entries to include this as an
                                     output port.  A value of OFPP_ANY
                                     indicates no restriction. */
    uint32_t out_group;           /* For OFPFC_DELETE* commands, require
                                     matching entries to include this as an
                                     output group.  A value of OFPG_ANY
                                     indicates no restriction. */
    uint16_t flags;               /* One of OFPFF_*. */
    uint8_t pad[2];
    struct ofp13_match match;       /* Fields to match. Variable size. */
    //struct ofp_instruction instructions[0]; /* Instruction set */
};

/* Send packet (controller -> datapath). */
struct ofp13_packet_out {
    struct ofp_header header;
    uint32_t buffer_id;           /* ID assigned by datapath (OFP_NO_BUFFER
                                     if none). */
    uint32_t in_port;             /* Packet's input port or OFPP_CONTROLLER. */
    uint16_t actions_len;         /* Size of action array in bytes. */
    uint8_t pad[6];
    struct ofp_action_header actions[0]; /* Action list. */
    /* uint8_t data[0]; */        /* Packet data.  The length is inferred
                                     from the length field in the header.
                                     (Only meaningful if buffer_id == -1.) */
};

/* Packet received on port (datapath -> controller). */
struct ofp13_packet_in {
    struct ofp_header header;
    uint32_t buffer_id;     /* ID assigned by datapath. */
    uint16_t total_len;     /* Full length of frame. */
    uint8_t reason;         /* Reason packet is being sent (one of OFPR_*) */
    uint8_t table_id;       /* ID of the table that was looked up */
    uint64_t cookie;        /* Cookie of the flow entry that was looked up. */
    struct ofp13_match match; /* Packet metadata. Variable size. */
    /* Followed by:
     *   - Exactly 2 all-zero padding bytes, then
     *   - An Ethernet frame whose length is inferred from header.length.
     * The padding bytes preceding the Ethernet frame ensure that the IP
     * header (if any) following the Ethernet header is 32-bit aligned.
     */
    uint8_t pad[2];       /* Align to 64 bit + 16 bit */
    uint8_t data[0];      /* Ethernet frame */
};

#endif /* OPENFLOW_13_H_ */