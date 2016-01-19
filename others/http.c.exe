/*
 * HTTP Decoder, Copyright by Palo Alto Networks, 2006
 *
 * Info sources:
 * 1. HTTP RFC
 * 2. MSIE vulnerabilities ;-)
 */

#define HTTP 1
#define ENABLE_DLP 1

/*******************************************************
 * Note: All file format related states need to be added
 *       in avinclude.sml, and any enums in panav.sml
 ******************************************************/
#include "version.h"
unsigned packet_status:8;
#include "avinclude.h"
#include "predict.h"
#include "att.h"
#include "http_common_hit.h"

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,0,0,0)))
#include "gnu-httptunnel.h"
#endif

/*********************
 * Global Defs       *
 ********************/

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    unsigned host4bytes:32;
    unsigned freegate:8;
    unsigned cgiproxy:8;
    unsigned pktnum:8;
    unsigned used_as_flag:8;
#endif

/*zealot add*/
    unsigned charset:32;
    unsigned convert_count:8;


#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,0,0,0)))
    unsigned rsp_code:16;
    unsigned ntlm_ssp_flag:8;   /*highest bit for ftp/ftp-data bug 58677*/
#else
    unsigned rsp_code:8;
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,0,0,15)))
    unsigned http_proxy:8;
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    unsigned simple_request:8;
    unsigned switch_reason:8;
    unsigned p2p:8;
    unsigned evasive:8; /* bit 0: for real evasive case; bit 1 and bit 2 for scotty detection.*/
    unsigned rsp_pktnum:8;
    unsigned loic_count:8;
#endif

/*
 * evasive_app is used for some apps which only have a valid short HTTP header in the first req packet
 * We mark this flag in request and check whether need to setapp in the evasive state
 * So if it is valid HTTP session, evasive_app could be re-used for other purpose.
 * */
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    unsigned evasive_app:16;
#endif

unsigned http_method:8;
unsigned proto:8;
//add var below for zealot secondary module check
unsigned field_req_uri_path_is_begin:8;
unsigned field_req_params_is_begin:8;
unsigned field_host_header_is_begin:8;
unsigned field_full_cookie_is_begin:8;
unsigned field_auth_user_is_begin:8;
unsigned field_post_message_body_is_begin:8;
unsigned field_cdn_src_ip_is_begin:8;
unsigned field_http_req_x_forwarded_for_is_begin:8;
unsigned skip_search_engine:8;
unsigned flash_search_engine:8;         //added by wangshiyou for flash 0day, 2015.07.09

unsigned isRspSuspend:32 ;
#include "http_p2p.h"

#define MAX_URL_LEN 18000
#define MAX_HEADER_LEN 25000
#define MAX_METHOD_LEN 64
/* for method */
enum {
  UNKNOWN_METHOD,
  GET,
  POST,
  PUT,
  SEARCH,
  SUBSCRIBE,
  UNSUBSCRIBE,
  PROPFIND,
  PROPPATCH,
  MKCOL,
  COPY,
  MOVE,
  LOCK,
  UNLOCK,
  NOTIFY,
  POLL,
  BCOPY,
  BDELETE,
  BMOVE,
  BPROPFIND,
  BPROPPATCH,
  LINK,
  UNLINK,
  OPTIONS,
  HEAD,
  DELETE,
  TRACE,
  TRACK,
  CONNECT,
  RPC_CONNECT,
  PROXY_SUCCESS,
  SOURCE,
  BITS_POST,
  CCM_POST,
  SMS_POST,
  RPC_IN_DATA,
  RPC_OUT_DATA,
  RPC_ECHO_DATA,
  DVRPOST,
};

/* for header */

enum {
  ASP = 1,
  HTR = 2,
  PHP = 3,
  PLCGI = 4,
  THEME = 5,
  ASA = 6,
};

enum {
  NO_RETADDR,
  EDIR_IMONITOR,
  MINISHARE_RETADDR,
  NAVICOPA_RETADDR,
  BIGANT_RETADDR,
  HP_POWER_MGR_RETADDR,
  BLUECOAT_PROXY_RETADDR,
  WINGATE_PROXY_RETADDR,
  DOMINO_ACCLANG_RETADDR,
  INTERSYS_CACHE_RETADDR,
  OVJAVALOCALE_RETADDR,
  VERMEER_URLENCODED,
  MICROSOFT_RICHUPLOAD,
};

enum
{
    NOREASON,
    REQ_FIRST_METHOD_OFFSET_ABNORMAL1,
    REQ_FIRST_METHOD_OFFSET_ABNORMAL2,
    REQ_FIRST_METHOD_OFFSET_ABNORMAL3,
    REQ_LONG_HEADER,
    REQ_LONG_URL,
    REQ_LONG_UNKNOWN_METHOD,
    REQ_BINARY_UNKNOWN_METHOD,
    REQ_BINARY_4_URLBYTES,
    REQ_NO_METHOD_IN_64_BYTES,
    REQ_SIMPLE_REQUEST_NOT_GET_METHOD,
    REQ_RTMP_MATCHED,
    REQ_RTMPE_MATCHED,
    REQ_MULTIPLE_SIMPLE_REQUEST,
    REQ_SIMPLE_REQUEST_IN_MULTIPLE_PACKET,
    REQ_2_CRLF_IN_SIMPLE_REQUEST,
    REQ_HTTP_VERSION_ERROR,
    REQ_HTTP_VERSION_DONT_SEE_CRLF_AFTER_8_BYTES,
    REQ_NOT_GET_ON_SIMPLE_REQUEST,
    REQ_CRLF_FOUND_BEFORE_VERSIONSTRING,
    REQ_ZERO_START_METHOD,
    RSP_RSPLEN_GREATER_10,
    RSP_VERSION_ERROR,
    RSP_NOT_FOUND_HTTP_IN_10_BYTES,
    RSP_NOT_FOUND_RSP_CODE_START_SPACE_IN_10_BYTES,
    RSP_CODE_NOT_FINISH_IN_4_BYTES,
    RSP_NO_DIGITAL_RSP_CODE,
    RSP_TOO_LONG_REASON,
    RSP_LONG_HEADER,
};

enum
{
    HTTP_REQ_INIT_STATUS,
    HTTP_REQ_METHOD_STATUS,
    HTTP_REQ_URL_STATUS,
    HTTP_REQ_PARAMS_STATUS,
    HTTP_REQ_VERSION_STATUS,
    HTTP_REQ_HEADERS_STATUS,
    HTTP_REQ_BODY_STATUS,
};

enum {
  UNKNOWN_PROTO,
};

#define FIELD_BEGIN_IGNORE_CASE(a) field_begin(a, ignore_case)

#define SEARCH_HEADER_END_FLAG(dirn, field_val, limit, flag)    \
  field_flag(flag);                             \
  SEARCH_HEADER_END(dirn, field_val, limit)

#define SEARCH_FLD_END(limit, delim)            \
    found_f_end = FALSE;                        \
    skip(limit,delim);                          \
    found_f_end = $?;

#define SEARCH_HEADER_END(dirn, field_val, limit)       \
  dirn ## _hdr_init(field_val);                         \
  skip(limit, "\x 0a \x");                              \
  found_hdr_end = $?;                                   \
  dirn ## _hdr_end();

/*############################################################*/
/* zealot add
 * 原xcode中没有对charset的详细处理为了能将http中不同不同
 * 字符集的数据转换为同一的字符集编码特此添加这部分代码
 curr_dir ##  ".*;charset=" ignore_case :\
 */
/*############################################################*/
#define FIELD_CHARSET \
stc  ".*; charset=" ignore_case :\
    {\
        charset_offset = $;\
        skip(15,"\x0d 0a\x");\
        if($?){\
            if(($ - charset_offset-2) == 3){\
                if((*($ - 5):24 == 0x67626b) || (*($ - 5):24 == 0x47424b)){\
                    charset = GBK;\
                }\
            }\
            else if(($ - charset_offset-2) == 5){\
                if(((*($ - 7):32 == 0x7574662d)||(*($ - 7):32 == 0x5554462d)) && (*($ - 3):8 == 0x38)){\
                    charset = UTF8;\
                }\
                else if(((*($ - 7):32 == 0x7574662d)||(*($ - 7):32 == 0x5554462d)) && (*($ - 3):8 == 0x37)){\
                    charset = UTF7;\
                }\
\
            }\
            else if(($ - charset_offset-2) == 6){\
                if(((*($ - 8):32 == 0x7574662d)||(*($ - 8):32 == 0x5554462d)) && (*($ - 4):16 == 0x3136)){\
                    charset = UTF16;\
                }\
                else if(((*($ - 8):32 == 0x7574662d)||(*($ - 8):32 == 0x5554462d))&&(*($ - 4):16 == 0x3332)) {\
                    charset = UTF32;\
                }\
                else if(((*($ - 8):16 == 0x6762)||(*($ - 8):16 == 0x4742)) && (*($ - 6):32 == 0x32333132)){\
                    charset = GB2312;\
                }\
                /*else if(((*($ - 8):32 == 0x62617365)||(*($ - 8):32 == 0x42415345))&&(*($ - 4):16 == 0x3634)){\
                    charset = BASE64;\
                }*/\
            }\
            else if(($ - charset_offset-2) == 8){\
                if(((*($ - 10):32 == 0x7574662d)||(*($ - 10):32 == 0x5554462d)) && (*($ - 6):16 == 0x3136)){\
                    if((*($ - 4):16 == 0x6265) || (*($ - 4):16 == 0x4245)){\
                        charset = UTF16BE;\
                    }\
                    else if((*($ - 4):16 == 0x6c65) || (*($ - 4):16 == 0x4c45)){\
                        charset = UTF16LE;\
                    }\
                }\
                else if(((*($ - 10):32 == 0x7574662d)||(*($ - 10):32 == 0x5554462d)) && (*($ - 6):16 == 0x3332)) {\
                    if((*($ - 4):16 == 0x6265) || (*($ - 4):16 == 0x4245)){\
                        charset = UTF32BE;\
                    }\
                    else if((*($ - 4):16 == 0x6c65) || (*($ - 4):16 == 0x4c45)){\
                        charset = UTF32LE;\
                    }\
                }\
            }\
            else if(($ - charset_offset-2) == 10){\
                if(((*($ - 12):32 == 0x69736f2d) || (*($ - 12):32 == 0x49534f2d)) && \
                        (*($ - 8):32 == 0x38383539) && (*($ - 4):16 == 0x2d31)){\
                    charset = ISO_8859_1;\
                } \
            }\
        }\
    }

#define SWITCH_STATE(dirn, currstate)           \
  unsigned next_state:32;            \
                        \
  dirn start : {                 \
    next_state = restore_state;             \
    restore_state = &currstate;                  \
    goto *next_state;                 \
  }

//add marco define below for zealot secondary module check
#define BRUT_FORCE_ATTACK_FUNC_ID 22
#define BRUT_FORCE_ATTACK_CHECK(a) callback(a,BRUT_FORCE_ATTACK_FUNC_ID)

#define HTTP_METHOD_PROCESS_FUNC_ID 23
#define HTTP_METHOD_PROCESS_FUNC(a) callback(a,HTTP_METHOD_PROCESS_FUNC_ID)

#define HTTP_URI_PROCESS_FUNC_ID 24
//#define HTTP_URI_PROCESS_FUNC(a,b) callback(a,b,HTTP_URI_PROCESS_FUNC_ID)

#define HTTP_HOST_PROCESS_FUNC_ID 25
#define HTTP_HOST_PROCESS_FUNC(a) callback(a,HTTP_HOST_PROCESS_FUNC_ID)

#define HTTP_COOKIE_PROCESS_FUNC_ID 26
#define HTTP_POST_BODY_PROCESS_FUNC_ID 27

#define HTTP_CDN_IP_PROCESS_FUNC_ID 29
#define HTTP_CDN_IP_PROCESS_FUNC(a) callback(a,HTTP_CDN_IP_PROCESS_FUNC_ID)

#define HTTP_X_FORWARDED_FOR_PROCESS_FUNC_ID 30
#define HTTP_X_FORWARDED_FOR_PROCESS_FUNC(a) callback(a,HTTP_X_FORWARDED_FOR_PROCESS_FUNC_ID)


#define HTTP_FILE_NAME_FUNC_ID 97
#define HTTP_FILE_INFO_FUNC_ID 98
#define HTTP_FILE_INFO_FUNC(a) callback(a,HTTP_FILE_INFO_FUNC_ID)
#define HTTP_FILE_CONTENT_TYPE_FUNC_ID 99

#define HTTP_REQ_USER_AGENT_PROCESS_ID  101
#define HTTP_REQ_USER_AGENT_PROCESS_FUNC(a) callback(a,HTTP_REQ_USER_AGENT_PROCESS_ID)

// http rsp 检测开关
#define HTTP_RSP_SUSPEND 13501


sub end_req_message_body() {
  printf(&"[HTTP] End of request message body\n");
  //validation_flag &= 0xfd;
  goto request_body_end; /* Go back to first request state */
}

sub end_rsp_message_body() {
  printf(&"[HTTP] End of response message body\n");
  field_end();
  http_method = UNKNOWN_METHOD;
  goto rsp_init; /* Go back to first response state */
}

sub encoding_init() {
  panav_trans_encoding = LENGTH;
  panav_body_encoding = UNKNOWN_ENCODING;
  return 0;
}
/************************
 *      STATES          *
 ***********************/

state init {

	isRspSuspend = get_env_var( HTTP_RSP_SUSPEND ) ;

	cts start:
	{
		/** zealot add */
		evasive = 0;
		http_method = UNKNOWN_METHOD;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,0,0,15)))
		http_proxy = 0;
#endif
		/* In case the traffic is through http-proxy app override, hash the destination ip and port.*/
		if ($appid == 62)
		{
			printf(&"[http-proxy]Hash the destination ip and port if it is from http-proxy\n");
			hash_add( $daddr , $dport , HTTPPROXY , 1800 );
		}

		if( 0 < isRspSuspend )
		{
			suspend( RSP );
			restore_state = &init;
		}else
		{
			restore_state = &rsp_init;
		}
		/*zealot add*/
		stored_state = &req_init;
		restore_state = &rsp_init;

		/* Adding this field for eval */
		field_begin("http-req-before-start",ignore_case);
//here I changed ,but I don't know where it will change
//        eval("http-rsp-file-info-reset", 1);
//        HTTP_FILE_INFO_FUNC("http-rsp-file-info-reset");
		goto req_init;
	}

	stc start:
	{
		if( 0 < isRspSuspend )
		{
			suspend( RSP );
			printf(&"[HTTP] rsp need to suspend\n");
		}else
		{
			evasive = 0;				/*zealot*/
			stored_state = &rsp_init;	/*zealot*/
			restore_state = &req_init;	/*zealot*/
			goto rsp_init;
		}
	}
}

/*************************************************
 * If http validation failes,
 * 1. setapp to be unknown-tcp.
 * 2. Go to evasive states for certain detection.
 ************************************************/
#define SWITCH_FROM_HTTP                        \
    printf(&"[HTTP] Does not look like HTTP traffic. Lets switch to unknown\n");\
    hash_add($daddr, $dport, SWITCHFROMHTTP);   \
    goto initiate_http_unknown_state;

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
#define REQ_METHOD(method)                      \
    MREQ_METHOD(.*method(\x20\x|\x00\x|\x09\x), method)
#else
#define REQ_METHOD(method)                      \
    MREQ_METHOD(.*method(\x20\x|\x00\x|\x09\x|\x0a\x|\x0d\x), method)
#endif

#define MREQ_METHOD(methodstr, method)          \
  cts #methodstr ignore_case : {                \
    init_method(method);                        \
  }

state req_init {

  unsigned reqlen:32;
  unsigned reqstart:32;
  unsigned before_method_len:32;
  unsigned tmp:8;
  unsigned tmp2:8;
    unsigned first_byte:8;

    scope_end(PDU);
    field_begin("http-req-before-start2",ignore_case);
    eval("http-rsp-file-info-reset", 1);
    HTTP_FILE_INFO_FUNC("http-rsp-file-info-reset");
    if($dport != 80)
    {
        if((used_as_flag & 0x20) == 0)
        {
            eval("http-req-dst-port",$dport);
            used_as_flag |= 0x20;
        }
    }
    field_end();
    first_byte = 0;
    tmp2 = 0;
    if(*($):8 == 0x0d)
    {
        if(($ + 5)< $+)
        {
            while(tmp2 < 5)
            {
                tmp = *($ + tmp2):8;
                tmp2++;
                if((tmp == 0x0d) || (tmp == 0x0a))
                {
                    continue;
                }
                else
                {
                    first_byte = tmp;
                    break;
                }
            }
        }
    }

  if (evasive == 1) {
      pktnum = 0;
      goto http_evasive_req_state;
  }

if ((validation_flag & 0x82) == 0) {
    if(pktnum == 0) {
    /* If the first byte is 0x03 or 0x06, let's go to unknown-tcp directly, in case it is RTMP.*/
        if ($ < $+){
          if (*($):8 == 3){
            printf(&"[rtmp] rtmp may be now!\n");
            switch_reason = REQ_RTMP_MATCHED;
            SWITCH_FROM_HTTP
          }
          if (*($):8 == 6){
            printf(&"[rtmpe] rtmpe may be now!\n");
            switch_reason = REQ_RTMPE_MATCHED;
            SWITCH_FROM_HTTP
          }
          if($pktlen == 1)
          {
              if(($ == 0) && (*($):8 == 0))
              {
                  if ($dport == 80)
                  {
                      switch_reason = REQ_ZERO_START_METHOD;
                      SWITCH_FROM_HTTP
                  }
              }
          }
        }
        if(($+ - $)> 3)
        {
            if(*($):32 & 0x80808080)
            {
                switch_reason = REQ_BINARY_UNKNOWN_METHOD;
                SWITCH_FROM_HTTP
            }
        }
    }
}

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
  if (simple_request != 0) { /* only one simple request is allowed per session */
    switch_reason = REQ_MULTIPLE_SIMPLE_REQUEST;
      SWITCH_FROM_HTTP
  }
#endif


#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    MIME_Boundry_Last4bytes = 0;
    proto = UNKNOWN_PROTO; /* No change for this part since more http validation could rely on this.*/

    //used_as_flag &= 0xfe; /* zero the first bit */
  /* In case it is SSL traffic from citrix (bug 14362), switch into ssl */
  cts "(\x16 03 01 00\x|\x16 03 02 00\x|\x16 03 03 00\x)" :
  {
  		skip(3);
		if (*($ - 2):16 == 0x100) {
			switch "ssl";
			exit();
		}
  }
#endif

  cts end : {
    if ($ > reqstart) {
      reqlen += $ - reqstart;
    }
    if (proto == UNKNOWN_PROTO) {
     if ($ > before_method_len) {
        eval("http-req-before-method-len", $ - before_method_len);
        if ($ - before_method_len > 0x10000)
        {
            if((first_byte == 0x20) || (first_byte == 0x09))
            {
                eval("http-req-before-method-abnormal", 1);
            }
        }
      }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
        if ((validation_flag & 0x82) == 0) {
            if (reqlen  >= MAX_METHOD_LEN) {      /* no known methd or SP where found yet */
                switch_reason = REQ_NO_METHOD_IN_64_BYTES;
                SWITCH_FROM_HTTP
            }
        }
#else
        if (reqlen > 1024) {
            SWITCH_FROM_HTTP
        }
#endif

        reqstart = $;
	} else {
     	/* bug 43229: If seeing "SSH-1." or 'SSH-2.' in the first 6 bytes after normal http transaction, exit to unknown-tcp.*/
		if ($pktlen > 6) {
			if (*($-):32 == 0x5353482d){
				if (*($- + 4):16  == 0x322e || *($- + 4):16  == 0x312e){
					setapp "unknown-tcp";
					exit();
				}
			 }
		 }
    }



#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    /* For certain freegate fg684p traffic, the first req and rsp are normal http but all the others are not normal http.
	 * The 2nd request is normally between 200 and 600 byte
	 * The dport is not standard port. We will use p2p value 66 to remember it.
	 * The 2nd response is normally large than 1000 byte
	 * With these conditions, we will then check the IP range.
	 *************************************************************/
	if ($dport != 80 && $dport != 443){
		if ($dport != 8080 && $dport != 8000){
			if (reqlen > 150 && reqlen < 600){
				if ((packet_status&1) == 1){
					p2p = 66;
				}
			}
		}
	}
#endif
  }

  panav_content_len = 0;
  post_content_type = UNKNOWN_REQ_CONTENT;
  reqlen = 0;
  reqstart = $;
  before_method_len = $;
  used_as_flag |= 2;
  used_as_flag &= 0x22; /* clear other flag and remain 2 and 6*/


  FIELD_BEGIN_IGNORE_CASE("http-req-before-method");



    if ((validation_flag & 0x82) == 0) {
        skip(MAX_METHOD_LEN, "\x09 20 00\x");
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
		if (($appid != 1532) || ($ignore_s2c != 1)){
			if( 0 == isRspSuspend )
			{
				resume(RSP);
			}
		}
#endif
        if ($? == 1 && http_method == UNKNOWN_METHOD) {
            /* Check the previous 2 bytes, which shouldn't be binary.*/
            if(($ - before_method_len) > 2)
            {
                tmp = *($ - 2):8;
                if (tmp< 0x30 ||( tmp > 0x39 && tmp < 0x41) || ( tmp > 0x5A && tmp < 0x61) || tmp > 0x7A){
                    switch_reason = REQ_BINARY_UNKNOWN_METHOD;
                    SWITCH_FROM_HTTP
                }
                tmp = *($ - 3):8;
                if (tmp < 0x30 ||( tmp > 0x39 && tmp < 0x41) || ( tmp > 0x5A && tmp < 0x61) || tmp > 0x7A){
                    switch_reason = REQ_BINARY_UNKNOWN_METHOD;
                    SWITCH_FROM_HTTP
                }
            }
            if(($+ - $)> 3)
            {
                if(*($):32 & 0x80808080)
                {
                    switch_reason = REQ_BINARY_4_URLBYTES;
                    SWITCH_FROM_HTTP
                }
            }
            if ($ > before_method_len) {
                /* we did not match any known method
                   so assume it is a valid unknown method and continue
                */
                field_end();
               	proto = HTTP;
                goto req_uri_state;
            }
        } else {
            if ($ > before_method_len)
            {
                eval("http-req-before-method-len", $ - before_method_len);
            }
            switch_reason = REQ_LONG_UNKNOWN_METHOD;
            SWITCH_FROM_HTTP
        }
    }

  REQ_METHOD(GET)
  REQ_METHOD(HEAD)
  REQ_METHOD(DELETE)
  REQ_METHOD(PUT)
  REQ_METHOD(TRACE)
  REQ_METHOD(TRACK)
  REQ_METHOD(CONNECT)
  REQ_METHOD(RPC_CONNECT)
  REQ_METHOD(SEARCH)
  REQ_METHOD(OPTIONS)
  REQ_METHOD(PROPFIND)
  REQ_METHOD(PROPPATCH)
  REQ_METHOD(MKCOL)
  REQ_METHOD(COPY)
  REQ_METHOD(MOVE)
  REQ_METHOD(LOCK)
  REQ_METHOD(UNLOCK)
  REQ_METHOD(NOTIFY)
  REQ_METHOD(POLL)
  REQ_METHOD(BCOPY)
  REQ_METHOD(BDELETE)
  REQ_METHOD(BMOVE)
  REQ_METHOD(BPROPFIND)
  REQ_METHOD(BPROPPATCH)
  REQ_METHOD(SUBSCRIBE)
  REQ_METHOD(UNSUBSCRIBE)
  REQ_METHOD(LINK)
  REQ_METHOD(UNLINK)
  REQ_METHOD(SOURCE)
  REQ_METHOD(BITS_POST)
  REQ_METHOD(CCM_POST)
  REQ_METHOD(SMS_POST)
  REQ_METHOD(DVRPOST)
  REQ_METHOD(RPC_IN_DATA)
  REQ_METHOD(RPC_OUT_DATA)
  REQ_METHOD(RPC_ECHO_DATA)

  cts ".*POST " ignore_case : {
    http_method = POST;
    post_content_type = UNKNOWN_REQ_CONTENT;
    panav_content_len = 0;
    eval("http-req-method", http_method);
    printf(&"[HTTP] Request method POST seen\n");
    field_end();
    //add zealot code below for transfer http method to the outside
    HTTP_METHOD_PROCESS_FUNC("http-req-method");

   	proto = HTTP;
    goto req_uri_state;
  }

  sub init_method(method) {
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    if (($appid != 1532) || ($ignore_s2c != 1)){
		if( 0 == isRspSuspend )
		{
			resume(RSP);
		}
    }
#endif

    http_method = method;
    eval("http-req-method", http_method);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,5)))
    set_http_method(http_method);
#endif
    field_end();
    //add zealot code below for transfer http method to the outside
    HTTP_METHOD_PROCESS_FUNC("http-req-method");

   	proto = HTTP;
    goto req_uri_state;
  }
}

state req_uri_state {

  unsigned req_uri_path:32;
  unsigned easerver_query_len:32;
  unsigned req_uri_start:32;
  unsigned ldap_uri_found:8;
  unsigned ldap_uri_qcount:8;
  unsigned slash_found:8;
  unsigned forward_slash:8;
  unsigned tmp8:8;
  unsigned long_utf8_count:8;
  unsigned easerver_query_start:8;
  unsigned uri_count:8;
  unsigned firstbyte:8;
  unsigned find3f:8; /* change to use bit. */
  unsigned version_found:8;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,5)))
  unsigned offset:32;
  unsigned http_port:32;
  flash_search_engine = 0;
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
  unsigned number_of_tilde_found:8;
  unsigned ipv6_host:8;
#endif
  SWITCH_STATE(stc, req_uri_state)

  /* Add some validation for the http method from 1st request.
   * In the http requst format like: "abcdefGET http...."
   * where we see ".*GET" matching for http method but want to do something for validation.
   * We will check GET/HEAD/CONNECT.  The Live traffic shows POST could be complicated to have some random bytes before the method. so we don't check POST now.
   */
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
  if (rsp_pktnum == 0 && evasive == 0){
    if (http_method == GET) {
        if ($ > 4 && $ < 18){
            switch_reason = REQ_FIRST_METHOD_OFFSET_ABNORMAL1;
            eval("http-req-switch-reason", switch_reason);
            SWITCH_FROM_HTTP
        }
    } else	if (http_method == HEAD) {
        if ($ > 5 && $ < 19){
            switch_reason = REQ_FIRST_METHOD_OFFSET_ABNORMAL2;
            eval("http-req-switch-reason", switch_reason);
            SWITCH_FROM_HTTP
        }
    } else if (http_method == CONNECT){
        if ($ > 8 && $ < 22){
            switch_reason = REQ_FIRST_METHOD_OFFSET_ABNORMAL3;
            eval("http-req-switch-reason", switch_reason);
            SWITCH_FROM_HTTP
        }
    }
 }
#endif

  /*Check common path in http_host_com.h */
  CHECK_COMMON_URI_PATH()

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
  find3f = 0;
  pktnum++ ;
  cgiproxy=0;
    if(http_method > PUT)
    {
        if(http_method < CONNECT)
        {
            if(http_method != HEAD)
            {
                if(http_method != OPTIONS)
                {
                    eval("http-req-webdav-request-found",TRUE);
                }
            }
        }
    }

#endif

  printf(&"[HTTP] Begin request URI path\n");
  FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-uri-path", http_method, ANY);

  /** zealot add */
  //field_flag(DATA_CACHE);
  field_bind(HTTP_URI_PROCESS_FUNC_ID);
  field_bind(HTTP_FILE_NAME_FUNC_ID);
  field_req_uri_path_is_begin = 1;


  req_uri_path = $;
  slash_found = FALSE;
  ldap_uri_found = FALSE;
  easerver_query_start = FALSE;
  ldap_uri_qcount = 0;
  long_utf8_count = 0;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    validation_flag |= 0x40; //bit 7
    number_of_tilde_found = 0;
#endif
  tmp8 = 0;
    http_used_as_flag &= 0x10; /* make sure not to set the bit for implicit app policy lookup check.*/
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,0,0,15)))
    if (http_method == CONNECT) {
        set_http_proxy();
        http_proxy = 1;
        FIELD_BEGIN_IGNORE_CASE("http-req-uri-proxy-host");
        eval("http-req-proxy-found",TRUE);
        field_flag(URL_FILTER_HOST);
        forward_slash = FALSE;
        easerver_query_len = $;
        tmp8 = 0;
        if( *($):8 >= 0x30 && *($):8 <= 0x39 ){
            while ( *($):8 != 0x2e && tmp8 <= 4){
                   skip(1);
                   tmp8 ++ ;
            }
            if (tmp8 <= 3) {
                   tmp8= atoi (easerver_query_len, 10);
                   if (tmp8 <= 254 && tmp8 >= 1){
                      host4bytes = tmp8;
                      skip(1);
                   }
             }
        }
        if(tmp8 == host4bytes){
			do{
			  easerver_query_len = $;
			  skip(1);
			  tmp8 = 0;
			  while ( *($ - 1):8 != 0x2e && *($ - 1):8 != 0x3a  && *($ - 1):8 != 0x20 ){
					skip(1);
					tmp8++;
			  }
			  if(tmp8 > 3 && ((used_as_flag & 0x40) == 0)){
					break;
			  }
			  else{
					easerver_query_len = atoi(easerver_query_len,10);
					tmp8= easerver_query_len;
			  }
			 if(tmp8 > 256 && ((used_as_flag & 0x40) == 0)){
					break;
			 }
			  if ((used_as_flag & 0x40) == 0) {
					host4bytes = host4bytes << 8;
					host4bytes += tmp8;
			  }
			  if( *($ - 1):8 == 0x3a ){
				used_as_flag |= 0x40;
			  }
			}while ( *($ - 1):8 != 0x20);

			if (http_proxy == 1 && easerver_query_len != 80 && easerver_query_len!=8080 && easerver_query_len!=8081){
				hash_add($saddr,$sport+3,BITTORRENT,10);
			}
			/* For the detection of ultrasurf10.6 going through http proxy, it is needed to check
			 * the port 25101 as well as the well known IP range first 65.49.*.*
			 */
			if (easerver_query_len == 25101 && http_method == CONNECT){
				hash_find($saddr,FIRST_ULTRASURF, ldap_uri_found,forward_slash);
				if (ldap_uri_found == FIRST_ULTRASURF ){
					setapp "ultrasurf";
					exit();
				}
				forward_slash = FALSE;
				ldap_uri_found  = FALSE;
			}
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
			/* For the detection of freegate7.34 going through http proxy,
			 * It should go through icmp ping to 65.55.27.219.
			 * Within seconds, it connects to google.cn at IP: 203.208.46.2 (3419418112) to fool people.
			 * Then hash the value FREEGATE731 for further freegate detection within 5 mins.
			 */
			if (http_method == CONNECT){
				/* For freegate, after sending icmp to 65.55.*.* networks, it will connect with google.cn as the next step.*/
				if (host4bytes - 3419418110 < 10) {
          /*hash($saddr,FREEGATE,ldap_uri_found,forward_slash);应该是hash_add, zealot modify*/
          hash_add($saddr,FREEGATE,ldap_uri_found,forward_slash);
					if (ldap_uri_found == FIRST_FREEGATE){
						hash_add($saddr,FREEGATE,FREEGATE731,300);
						exit();
					}
					forward_slash = FALSE;
					ldap_uri_found  = FALSE;
				}
				/* Hash the host IP for further ultrasurf check. */
				rsp_code = $sport&0xff<<8 +$sport&0xff00>>8 ;
				hash_add($daddr,rsp_code + 1,host4bytes,10);
				hash_add($daddr,rsp_code + 2,host4bytes >> 16,10);
				rsp_code = 0; /*set back to 0.*/
			}
#endif
        }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,5)))
        if(used_as_flag & 0x40){
           if( *($ - 1):8 == 0x20 && easerver_query_len!= 21){
                predict_check("ftp-data", TCP, $saddr, host4bytes, easerver_query_len);
                if( $? == 1 ){
                    ntlm_ssp_flag |=0x80;
                    setapp "ftp";
                    goto ftp_proxy_state;
                }
          }
        }
	if( *($ - 1):8 == 0x20 ){
            forward_slash = TRUE;
        }
#endif
        if(forward_slash == FALSE){
           do {
            skip(1);
            tmp8 = *($ - 1):8;
            if (tmp8 == 0x20) {
                forward_slash = TRUE;
            }
          } while(forward_slash == FALSE);
        }
        field_end();
        tmp8 = 0;
    }

#endif

  FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-uri-path", http_method, ANY);
  skip(1);
  firstbyte = *($ - 1):8;
    if((firstbyte == 0x0d) || (firstbyte == 0x0a))
    {
        if($ < 8)
        {
            eval("http-req-invalid-end-line-found",TRUE);
        }
    }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
	if( (firstbyte == 0x40) || ( *($ - 1):16 == 0x3a40))
	{
		eval("http-req-uri-cve-2011-3368",1);
	}
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
      version_found = 0;
      req_uri_start = $;
      if (http_method == GET) { /* assume it is simple until we see the version */
        simple_request = 1;
      } else {
          simple_request = 0;
     }
#endif
/*
added by wangshiyou for flash 0day, 2015.07.09
*/
  cts ".*\.swf" : {
      flash_search_engine = 1;
  }


  cts ".* /a/" : {
       eval("http-req-google-enterprise",TRUE);
   }
  cts ".* /adver" : {
       used_as_flag |= 0x10;
   }

    /* ppstream http client*/
    cts ".* /ugc/" : {
    if ($ + 5 < $+) {
        if (*($ + 1):8 == 0x2f && *($ + 4):8 == 0x2f) {
           eval("http-req-ppstream-ugc", TRUE);
        }
    }
    }

    /* ms-echange-admin-center http client*/
    cts ".* /ecp/" : {
       eval("http-req-ms-exchange-admin-center", TRUE);
    }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    cts ".*((~)|(%7e)|(%u003a)|(%u0589)|(%u2236)|(%u007e)|(%u0303)|(%u223c)|(%uff5e))" ignore_case:
    {
        number_of_tilde_found++;
        eval("http-req-uri-tilde-count-num",number_of_tilde_found,http_method);
    }
#endif

/*this part looks for glype uri format which is b= or bit= a one or two digit number*/
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
  cts ".*/b" : {
    if($ + 1 < $+){
        if((*$:8 > 0x2f) && (*$:8 < 0x3a )){
           if((*($ + 1):8 == 0x20) || (*($ + 1):8 == 0x26)){
              eval("http-req-glype-found",1);
           }else if($ + 2 < $+ ){
               if((*($ + 2):8 == 0x20) || (*($ + 2):8 == 0x26)){
                  eval("http-req-glype-found",1);
               }
           }
        }
    }
  }
#endif

  cts ".*%" : {
    field_flag(URI_DECODE);
    if(*($ - 2):8 == 0x2f)
    {
        eval("http-req-error-code", MAXDB_PERCENTILE_FOUND);
    }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    if($ <= 6)
    {
        skip(260,"\x2e 2f 20\x");
        if($? == 0)
        {
            if((find3f & 2) == 0)
            {
                eval("http-req-CVE-2005-0684-found",1);
            }
        }
    }
    else
    {
        find3f |= 2;
    }
#endif
  }
  /*.*%f[0-4]%8.%*/
  cts ".*%f[0-4]%8" : {
	 if ($+ > $ + 1){
	   skip(2);
       if (*($ - 1):8 == 0x25){
      	long_utf8_count ++;
        if (long_utf8_count == 40) {
          eval("http-req-overly-long-utf8", TRUE);
          long_utf8_count = 0;
        }
	  }
    }
  }

  cts ".*\.(/|\\)" : {
    eval("http-req-possible-dir-traversal", TRUE);
    field_flag(URI_DECODE);
  }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    cts ".*/CommunityCBR/CC\." ignore_case:
    {
        if(http_method == POST)
        {
            skip(64,"\x20 2f 0a\x");
            if($? == 0)
            {
                eval("http-req-lotus-long-url-bof",TRUE);
            }
        }
    }

  cts ".*\.\." : {
    eval("http-req-possible-dir-traversal", TRUE);
  }
  cts ".*\.%252f" : {
    eval("http-req-possible-dir-traversal", TRUE);
  }
#endif

  cts ".*:80" : {
    eval("http-req-uri-proxy-port-found", TRUE);
  }

  cts ".*:443 " : {
      if (http_method == CONNECT){
    printf(&"[connect] Seeing connect on IP:443\n");
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
        if ((*($ - 6):8) >= 0x30 && (*($ - 6):8 <= 0x39)){
            if (*($ - 7):8 >= 0x2e && *($ - 7):8 <= 0x39){
                hash_add($saddr+$sport,$sport,CONNECT443,10);
            }
        }
    //for cve-2005-2830
    if($dport == 3128 && *($ - 9):32 == 0x2e636f6d){
       eval("http-req-CVE-2005-2830-found", 1);
    }
#endif
    }
  }

  /* In ultrasurf proxy case, we'd better remember the first IP range for ultrasurf to go */
  cts ".* 65\.49\.2\.":{
      if (http_method == CONNECT){
		if (*($ + 3):8 == 0x3a) { /*# if there is 3rd digit, it normally goes to freegate.*/
			hash_add($saddr,$daddr,FIRST_FREEGATE,600);
		} else if (*($):8 == 0x39) {
			hash_add($saddr,$daddr,FIRST_FREEGATE,600);
		} else {
			hash_add($saddr,FIRST_ULTRASURF,FIRST_ULTRASURF,600);
        	hash_add($saddr,$daddr,FIRST_ULTRASURF,600);
		}
    }
  }
  cts ".* 65\.49\.14\.":{
      if (http_method == CONNECT){
	    hash_add($saddr,FIRST_ULTRASURF,FIRST_ULTRASURF,600);
        hash_add($saddr,$daddr,FIRST_ULTRASURF,600);
    }
  }
  cts ".*\x32 19 99 01\x" : {
    eval("http-req-retaddr", WINGATE_PROXY_RETADDR);
  }


    /* For URL filter to check the http proxy */
    cts ".*( http://| ftp://| https://)" ignore_case :
    {
        eval("http-req-proxy-found",TRUE);
        hash_add($daddr,$dport,HTTPPROXY,3600);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,0,0,15)))
        set_http_proxy();
        http_proxy = 1;
#endif
    field_end();
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    /* bug 31317: ipv6url: http://[2001:cdba:0000:0000:0000:0000:3257:9652]/1x1.png?u1308559211447s1094604913.v6lit
	 * In IPV6 case, so far we only consider the forward byte is always available case.*/
    if ($ < $+) {
		if (*($):8 == 0x5b){
			printf(&"[IPV6 notation in http url]\n");
			FIELD_BEGIN_IGNORE_CASE("http-req-uri-proxy-host");
			field_flag(URL_FILTER_HOST);
			skip(41,"\x5d\x"); /* skip between "[" and "]" for ipv6 url notation case .*/
			if (*($ -1):8 == 0x5d) {
				 ipv6_host = 1;
				 tmp8 = *($):8;
			}
		}
	}
	if (ipv6_host == 0) {
#endif
		FIELD_BEGIN_IGNORE_CASE("http-req-uri-proxy-host");
		field_flag(URL_FILTER_HOST);
		forward_slash = FALSE;
		tmp8 = 0;
		  do {
			  /*
			   * For most of the case, it is within one packet, then
			   * we will check the forward byte to avoid bug 20285
			   */
			  if ( $ < $+ ) {
				tmp8 = *($):8;
				if (tmp8 == 0x3a || tmp8 == 0x2f || tmp8 == 0x20) {
					forward_slash = TRUE;
	#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,5)))
					offset = $ + 1;
	#endif
				} else {
					skip(1);
				}
			  } else {
				skip(1);
				tmp8 = *($ - 1):8;
				if (tmp8 == 0x3a || tmp8 == 0x2f || tmp8 == 0x20) {
					forward_slash = TRUE;
	#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,5)))
					offset = $;
	#endif
				}
			  }
		  } while(forward_slash == FALSE);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
	  }
#endif
    field_end();

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    if ((forward_slash == TRUE || ipv6_host == 1) && (tmp8 == 0x3a)) {
#else
    if (forward_slash == TRUE && tmp8 == 0x3a) {
#endif
        FIELD_BEGIN_IGNORE_CASE("http-req-uri-proxy-host");
        /* looking for the slash or space  */
        skip(8, "\x2f 20\x");
        /* get the port here */
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,5)))
        if ($? == 1) {
            http_port = atoi(offset, 10);
            set_http_port(http_port);
        }
#endif
    }

    tmp8 = 0;

    if($ >  req_uri_path)
    {
        eval("http-req-host-in-url-length",$ -  req_uri_path);
    }

    FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-uri-path", http_method, ANY);
    req_uri_path = $ ;
  }
  cts ".*://" : {
    if(firstbyte != 0x2f){
      uri_count = 4;
      tmp8 = *( $ - uri_count ):8;
      while ( (tmp8 < 0x39 && tmp8 > 0x30) ||(tmp8 > 0x61 && tmp8 < 0x7a) || (tmp8 > 0x41 && tmp8 < 0x5a ))
      {
        if ( uri_count >= 13 && ($ - uri_count < 6)) {
            eval("http-req-uri-protocol-too-long", TRUE );
            break;
        }
        uri_count++;
        tmp8 = *( $ - uri_count ):8;
      }
    }
  }

  cts ".*\?" : {
    freegate=0x0f;
    if (req_uri_path <= $) {
      req_uri_path = $ - req_uri_path;
      // modify by sunon.zealot in 14/7/9, /1234567890123?a=a&b=124 uri-path-length should be 15, but it's 16
      // origin version is EVAL_QUALIFIER("http-req-uri-path-length", (req_uri_path -1), http_method, ANY, ANY, ANY);
      EVAL_QUALIFIER("http-req-uri-path-length", (req_uri_path -1), http_method, ANY, ANY, ANY);

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
      if (req_uri_path == 2) {
	if (*($ - 2):8 == 0x2f) {
	  if ($+ > $ + 1) {
	    if (*($):8 == 0x2b || *($):8 == 0x25) {
	      eval("http-req-no-path-nextchar-suspicious", 1);
	    }
	  }
	}
      }
#endif

      if ($dport == 7144) {
    if (http_method == SOURCE) {
      if (req_uri_path > 164) {
        eval("http-req-peercast-overlong-source-uri", TRUE);
      }
    }
      }
	  /* For bittorrent traffic, there should be no . in the end of url-path.*/
	  if (*($ - 6):8 != 0x2e && *($ - 5):8 != 0x2e) {
	      http_used_as_flag |= 8;
	  }

        /* ppstream http client*/
        if (*($ - 5):32 == 0x2e706676) {
            eval("http-req-ppstream-pfv",TRUE);
        }
    }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,4)))
    field_flag(FILENAME);
      print("-->http 6\n");
#endif

    field_flag(URL_FILTER_URL);
    field_end();
    goto req_uri_params;
  }

  cts ".*\.jsp;" : {
    easerver_query_start = TRUE;
    easerver_query_len = $;
  }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
  ".*\.mp3(\x20\x|\x00\x|\x09\x)" ignore_case : {
    eval("http-req-mp3-ext-found", 1);
  }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
  ".*\.bat(\x20\x|\x00\x|\x09\x)" ignore_case : {
    eval("http-req-bat-ext-found", 1);
  }
  ".*\.hta(\x20\x|\x00\x|\x09\x)" ignore_case : {
    eval("http-req-hta-ext-found", 1);
  }
  ".*\.dws " ignore_case : {
    panav_file_type = DWS;
  }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
  ".*\.cmd(\x20\x|\x00\x|\x09\x)" ignore_case : {
      eval("http-req-cmd-ext-found", 1);
  }
#endif
  /* for filename */
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,0,11,4)))
    ".*\.doc(x|m) " ignore_case : {
        panav_file_type = DOCX;
    }
    ".*\.ppt(x|m) " ignore_case : {
        panav_file_type = PPTX;
    }
    ".*\.xls(x|m) " ignore_case : {
        panav_file_type = XLSX;
    }
    ".*\.doc " ignore_case : {
        panav_file_type = DOC;
    }
    ".*\.ppt " ignore_case : {
        panav_file_type = PPT;
    }
    ".*\.xls " ignore_case : {
        panav_file_type = XLS;
    }
    ".*\.apk" ignore_case : {
        panav_file_type = APK;
    }
    ".*\.jar" ignore_case : {
        panav_file_type = JAR;
    }
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
  cts start: {
        /* we should not see any bytes after simple_request */
        if (simple_request == 2) {
            switch_reason = REQ_SIMPLE_REQUEST_IN_MULTIPLE_PACKET;
            SWITCH_FROM_HTTP
        }
  }
#endif
  cts end : {

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    if (*($ - 1):8 == 0xa) {
        /* end of the packet is also end of the command
                                      and we did not see the version string or \r\n \n\n
                                     it can only be true for simple request, if
                                     it is set the end of simple_request, if not
                                     it is not http.
                                     */
          if (simple_request == 1) {
            simple_request = 2;
        }else {
            if ((validation_flag & 0x82) == 0) {
                switch_reason = REQ_2_CRLF_IN_SIMPLE_REQUEST;
                SWITCH_FROM_HTTP
            }
        }
    }
#endif

    if (req_uri_path <= $) {
      EVAL_QUALIFIER("http-req-uri-path-length", $ - req_uri_path, http_method, ANY, ANY, ANY);
    }
    if ($dport == 7144) {
      if (http_method == SOURCE) {
    if ($ - req_uri_path > 164) {
      eval("http-req-peercast-overlong-source-uri", TRUE);
    }
      }
    }
    if (easerver_query_start == TRUE) {
      if ($ > easerver_query_len) {
        easerver_query_len = $ - easerver_query_len;
        eval("http-req-easerver-query-len", easerver_query_len);
      }
    }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    /* if we got here and still have not found CTLF exit */
    if (req_uri_start < $) {
        if (($ - req_uri_start) >= MAX_URL_LEN) {
            switch_reason = REQ_LONG_URL;
            SWITCH_FROM_HTTP
        }
    }
#endif
  }

  cts ".*ldap(:|%3a)" ignore_case : {
    ldap_uri_found = TRUE;
  }
  cts ".*/post( |\?)" ignore_case : {
    eval("http-req-post-uri", 1);
  }

/*
    The following 4 checks are used for cgiproxy check.
*/
  cts ".*/twig/" : {
          eval("http-req-seen-twig", 1);
  }

  cts ".*/[0|1]?[0|1][0|1][0|1][0|1][0|1][0|1]A" : {
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
  cgiproxy = 1;
#endif
    eval ("http-req-cgiproxy-digit", 1);
  }

  cts ".*\.cgi/[0|1]?[0|1][0|1][0|1][0|1][0|1][0|1]A/http/" : {
    eval ("http-req-cgiproxy-digit-new", 1);
  }

  cts ".*/\.php" : {
                  eval("http-req-seen-camo-proxy", 1);
  }

  cts ".*/\.i/" : {
                  eval("http-req-camo-proxy-uri", 1);
  }

  cts ".*%3f" ignore_case : {
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    if ( *($ - 4):8 == 0x2f && *($ - 5):8 == 0x20 ) {
      find3f |= 1;
    }
    else if ($ < $+)
    {
        if(*($):8 == 0x2f)
        {
            find3f |= 1;
        }
    }
#endif
    if (ldap_uri_found == TRUE) {
      ldap_uri_qcount++;
      if (ldap_uri_qcount > 4) {
    eval ("http-req-ldap-uri-qcount", ldap_uri_qcount);
      }
    }
  }

  cts ".*(\\|%5c)" ignore_case : {
    slash_found = TRUE;
  }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
  cts ".*\.\.%5c" : {
      eval("http-req-possible-dir-traversal-inuri", TRUE);
  }
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
  cts ".*\.theme" : {
      eval("http-req-uri-file-ext", THEME);
  }
  cts ".*%1b(%5b|%5d|\[|\])" ignore_case : {
    eval("http-req-possible-terminal-esc-inject-inuri", 1);
  }
  cts ".*/parsequery\?" ignore_case:
    {
      if ($ + 4 < $+) {
	if (*($):32 != 0x73657276) {
	  /* As per oracle doc, parsequery usage is :
	     /reports/rwservlet/parsequery[?][server=server_name][&authid=username/password]
	     (http://docs.oracle.com/cd/E16764_01/bi.1111/b32121/pbr_cla007.htm#i640592)
	     Hence we will treat req not in this format as suspicious
	  */
	  eval("http-req-suspicious-parsequery", 1);
	}
      }
    }
#endif

  cts ".* /(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]|CLOCK\$) " ignore_case : {
    eval("http-req-dos-device-found", TRUE);
  }

  cts ".*\.id[aq]" : {
    eval("http-req-error-code", CODERED_FILE_IN_URL);
    if ((*($):8) == 0x3f) { // 0x3f == '?'
      eval("http-req-question-mark-after-codered", 1);
    }
  }
  cts ".*\.plx?[\x20 3f\x]" ignore_case:
  {
    eval("http-req-uri-file-ext", PLCGI);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    search_back(4, 360, "\x2f 20 25\x", easerver_query_len);
    if ($? == 0) {
      eval("http-req-long-plcgi-filename", 1);
    }
#endif
  }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
  cts ".*\.ppt" ignore_case :
  {
    search_back(4, 200, "\x2f 20 25\x", easerver_query_len);
    if ($? == 0) {
      eval("http-req-long-ppt-filename", 1);
    }
  }
#endif
  cts ".*\.htr" : {
    eval("http-req-uri-file-ext", HTR);
  }
  cts ".*\.php" ignore_case: {
    eval("http-req-uri-file-ext", PHP);
  }
  cts ".*\.asa" ignore_case: {
    eval("http-req-uri-file-ext", ASA);
  }

  cts ".*\.asp" : {
    eval("http-req-uri-file-ext", ASP);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    skip(2);
    if((*($ - 2):16 == 0x7825) || (*($ - 2):16 == 0x5825))//.aspx%
    {
        skip(2);
        if(atoi($ - 2,16) > 0)
        {
            eval("http-req-error-code", MS09_036_CVE_2009_1536);
        }
    }
#endif
  }

  cts ".*%2bhtr" : {
    if(*($ - 10):32 == 0x2e617370 || *($ - 10):32 == 0x2e617361)
      eval("http-req-htr-source-disclosure", TRUE);
  }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    cts ".*\.(asp|php);" ignore_case:
    {
        tmp8 = 0x40;
        while(tmp8 > 0)
        {
            skip(1);
            ipv6_host = *($ - 1):8;
            if(ipv6_host < 0x30) break;
            if((ipv6_host > 0x39) && (ipv6_host < 0x41)) break;
            ipv6_host |= 0x20; //convert to lowercase
            if(ipv6_host > 0x7a) break;
            if(ipv6_host < 61) break;
        }
        if(*($ - 1):8 == 0x2e)
        {
            skip(3);
            if(((*($ - 3):24 | 0x20) == 0x6A7067) || ((*($ - 3):24 | 0x20) == 0x676966))
            {
                eval("http-req-iis-script-jpg-file-found",TRUE);
            }
        }
    }
#endif

  cts ".*\.aspx" : {
    used_as_flag |= 1;
    if (slash_found == TRUE) {
      eval("http-req-error-code", MS05_004_IIS_ASP_ERROR);
    }
  }

  cts ".*\.rtf%0a" : {
    eval("http-req-error-code", MS05_005_OFFICE_XP_URL_PARSING_ERROR);
  }

  cts ".*%00" : {
    if((*($ - 7):32 == 0x2E706466) /* .pdf */ || (*($ - 7):32 == 0x2E786664) /* .xfd */ || (*($ - 7):32 == 0x2E666466) /* .fdf */ || (*($ - 7):32 == 0x2E786470) /* .xdp */)
    {
        eval("http-req-pdf-percent", 1);
    }
    else if(*($ - 7):32 == 0x78666466)
    {
        if(*($ - 8):8 == 0x2e) /* .xfdf */
        {
            eval("http-req-pdf-percent", 1);
        }
    }
    else if(*($ - 7):32 == 0x2E646F63)
    {
        eval("http-req-error-code", MS05_005_OFFICE_XP_URL_PARSING_ERROR);
    }
  }

  cts ".*%c1(%1c|%9c|%8s|%pc)" : {
    eval("http-req-codeblue-in-uri", 1);
  }

  cts ".*%c0(%cc|%25|%2e|%a5|%ae|%5c|%af|%2f|%be|%qf|%9v)" : {
    eval("http-req-codeblue-in-uri", 1);
  }

  cts ".*(%d0%af|%d1%9c)" : {
    eval("http-req-codeblue-in-uri", 1);
  }
  /* Remove for now..shall add in case of FPs
     cts ".*\x15 1f 50 63\x" : {
     eval("http-req-retaddr", EDIR_IMONITOR);
     }
  */

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
  cts ".*(\x6f c4 02 10\x|\xff b4 09 10\x)" : {
    if ($ == 0xec || $ == 0xeb) {
      eval("http-req-retaddr", NAVICOPA_RETADDR);
    }
  }

  cts ".*\xeb 06 1a 79 f2 6f\x" : {
    if ($dport == 57772) {
      eval("http-req-uri-retaddr", INTERSYS_CACHE_RETADDR);
    }
  }
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
  cts ".*(\xad 32 aa 71\x|\xc4 2a 02 75\x|\x6a 19 9a 0f\x)" : {
    eval("http-req-retaddr", BIGANT_RETADDR);
    if ($ - req_uri_path > 900) {
      if ($dport == 6080 || $dport == 6660) {
	eval("http-req-bigant-uri-overflow", 1);
      }
    }
  }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
  cts ".*(\x67 42 a7 71\x|\xf7 56 44 7e\x)" : {
      if ($ == 784) {
          if ($ - req_uri_path > 700) {
              if ($dport == 8080) {
                  eval("http-req-codesys-uri-overflow", 1);
              }
          }
      }
  }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
  cts ".*\x2f 2e 2e 2f 2e 2e 2f\x" : {
    eval("http-req-directory-traversal", TRUE);
  }
#endif


#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,0,0,0)))
  cts ".*ssp/admin/_layouts" ignore_case : {
    ntlm_ssp_flag |= 2;
  }
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,0,11,4)))
  cts ".*(\xab a3 54 77\x|\x63 f1 17 75\x|\x54 1d ab 71\x|\x72 93 ab 71\x|\x4d 3c c0 71\x)" : {
    if ($ == 1795) {
      eval("http-req-retaddr", MINISHARE_RETADDR);
    }
  }
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
  cts ".*setup/setup-/\.\./" ignore_case : {
    if ($dport == 9090 || $dport == 9091) {
      eval("http-req-jive-dir-traversal", 1);
    }
  }
    cts ".*%252f%252e%252e%252f":
    {
        eval("http-req-double-encoding-url-request",TRUE);
    }
    cts ".*%([2-7])([0-9]|[a-f])%2500[a-z]" ignore_case:
    {
        eval("http-req-double-encoding-url-request",TRUE);
    }
#endif

  cts ".* RTSP/1\.0\r\n" ignore_case : {
         switch "rtsp";
          exit();
  }


  cts ".*[\x00 09 20\x]HTTP/" ignore_case : {
    /** zealot add */
    if(1 == field_req_params_is_begin || 1 == field_req_uri_path_is_begin)
    {
      //the last field req params is not end
      field_end();
      field_req_params_is_begin = 0;
      field_req_uri_path_is_begin = 0;
      //add code below for transfer http uri to the outside
      //HTTP_URI_PROCESS_FUNC("http-req-uri-path","http-req-params");
      //field_cache_clear("http-req-uri-path","http-req-params");
    }

    if($ > 600)
    {
        if(*($ - 26):32 == 0x41414141)
        {
            if(*($ - 22):32 == 0x41414141)
            {
                if(*($ - 18):32 == 0x41414141)
                {
                    if((*($ - 10):32 == 0x41253543) || (*($ - 10):32 == 0x4141412f))
                    {
                        eval("http-req-test-long-url-found",TRUE);
                    }
                }
            }
        }
    }
    if((*($ - 7):8 == 0x0d) || (*($ - 7):8 == 0x0a) || (*($ - 8):8 == 0x0a) || (*($ - 8):8 == 0x0a))
    {
        eval("http-req-invalid-end-line-found",TRUE);
    }
    if((*($ - 9):8 == 0x0d) || (*($ - 9):8 == 0x0a) || (*($ - 10):8 == 0x0a) || (*($ - 10):8 == 0x0a))
    {
        eval("http-req-invalid-end-line-found",TRUE);
    }
    if(*($ - 10):32 == 0x2f2e2e2f) /* /../ */
    {
        eval("http-req-directory-traversal-attempt",1);
    }

    /* ppstream http client*/
    if (*($ - 10):32 == 0x2e706676) {
        eval("http-req-ppstream-pfv", TRUE);
    }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    if (*($ - 7):8 == 0x7c || *($ - 9):24 == 0x253763) {
      eval("http-req-pipe-char-end-of-uri", 1);
    }
#endif
    if (req_uri_path <= $) {
      req_uri_path = $ - req_uri_path;
      /** to reduce the length of 6 bytes of string " HTTP/" for req_uri_path**/
      /** add by sunon.zealot in 3/31/2014 **/
      if( 6 <= req_uri_path )
      {
        EVAL_QUALIFIER("http-req-uri-path-length", (req_uri_path - 6), http_method, ANY, ANY, ANY);
      }
      else
      {
        EVAL_QUALIFIER("http-req-uri-path-length", req_uri_path, http_method, ANY, ANY, ANY);
      }
      if ($dport == 7144) {
        if (http_method == SOURCE) {
          if (req_uri_path > 164) {
            eval("http-req-peercast-overlong-source-uri", TRUE);
          }
        }
      }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,0,0,14)))
    if((*($ - 10):32 == 0x2e62696e) || (*($ - 10):32 == 0x2E636667) || (*($ - 10):32 == 0x2E63706D))
    {
        if(http_method == GET)/*get xyz.bin*/
        {
            http_used_as_flag |= 1;
        }
    }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
	/********************************************************************************
	 * How to identify the scotty proxy?
	 * 1. Request like : "POST / HTTP/1.0" ==>set evasive bit 1;
	 * 2. Content-Length is an even number.
	 * 3. At the 345 offset place after body starts, we will see "==|"; ==> set evasive bit 2;
	 * 4. 345 bytes after seeing the first "==|", we will see the 2nd "==|", then setapp.
	 * 5. For the http req message body part, the bytes are always ascii ones.
	 *******************************************************************************/
	if ($ == 12){
		if (http_method == POST) {
			if (pktnum == 1) {
				evasive |= 2;
			} else {
				evasive = 0;
			}
		}
	}
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    else if((*($ - 10):32 | 0x20202020) == 0x61737078)//aspx
    {
        if((find3f & 1 ) && (*($ - 11):8 == 0x2e))
        {
            eval("http-req-error-code", MS09_036_CVE_2009_1536);
        }
    }
#endif
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
      if(*($ - 9):32 == 0x25356320)
      {
        if (*($ - 13):32 == 0x2e617370) {
            eval("http-req-iis-unc-mapping-disclosure", TRUE);
        }
      }
#endif
	  /* For bittorrent traffic, there should be no . in the end of url-path.*/
	  if (*($ - 10):8 != 0x2e &&*($ - 11):8 != 0x2e) {
	      http_used_as_flag |= 8;
	  }
      if (*($ - 10):32 == 0x2e676966) { /* .gif */
        if (req_uri_path > 1024) {
          eval("http-req-long-gif-request", TRUE);
        }
        if (*($ - 14):32 == 0x07070707) {
          if (req_uri_path > 800) {
            eval("http-req-unreal-hellbell-attack", TRUE);
          }
        }
        if (pktnum == 1 && freegate !=0xf) {
            if (req_uri_path > 26) {
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
			   /* The freegate on http normally comes from 65.49.2.* network. The traffic pattern is as following:
			    * .gif HTTP/1.1\r\nHost:
				*/
			   if ($+ > $ + 12) {
			   	 if (*($ + 5):32 == 0x486f7374){
				 	if (($daddr&0xffffff00) ==  0x41310200){
						setapp "freegate";
						exit();
					}
				 }
			   }
#endif
                freegate |= 0x80;
            }
         } else if (pktnum == 2) {
            if ((freegate & 0xa0) != 0xa0) {
                freegate = 0;
            }
        }
      } else {
        	freegate=0;
    	}
    }
    /* To fix FP caused by GET / HTTP/ */
    if (req_uri_path >= 8) {

        field_flag(URL_FILTER_URL);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,4)))
    field_flag(FILENAME);
      print("-->http 7\n");
#endif

      eval("http-req-uri-path-last-byte", *($ - 7):8);
    }
    if (easerver_query_start == TRUE) {
      if ($ > easerver_query_len) {
    easerver_query_len = $ - easerver_query_len;
    eval("http-req-easerver-query-len", easerver_query_len);
      }
      easerver_query_start = FALSE;
    }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    version_found = 1;
    simple_request = 0;
    FIELD_BEGIN_IGNORE_CASE("http-req-version-string");
    if ((validation_flag & 0x82) == 0) {
        skip(3);

        if ((*($ - 3):8 < 0x30) || (*($ - 3):8 > 0x39)) {
            eval("http-req-version-invalid", 1);
            switch_reason = REQ_HTTP_VERSION_ERROR;
            SWITCH_FROM_HTTP
        }

        if (*($ - 2):8 != 0x2e) {
            eval("http-req-version-invalid", 1);
            switch_reason = REQ_HTTP_VERSION_ERROR;
            SWITCH_FROM_HTTP
        }

        if ((*($ - 1):8 < 0x30) || (*($ - 1):8 > 0x39)) {
            eval("http-req-version-invalid", 1);
            switch_reason = REQ_HTTP_VERSION_ERROR;
            SWITCH_FROM_HTTP
        }

        skip(1);
        tmp8 = *($ - 1):8;
        if ((tmp8 != 0x09) && (tmp8 != 0x20) && (tmp8 != 0) &&
            (tmp8 != 0xd) && (tmp8 != 0xa)) {
            eval("http-req-version-invalid", 1);
            switch_reason = REQ_HTTP_VERSION_ERROR;
            SWITCH_FROM_HTTP
        }

        if (tmp8 != 0xa && (*($):8 != 0xa)) {
            skip(4, "\x0a 00\x");
            if ($? == 0)  {
                eval("http-req-version-invalid", 1);
                switch_reason = REQ_HTTP_VERSION_DONT_SEE_CRLF_AFTER_8_BYTES;
                SWITCH_FROM_HTTP
            }
        }
    }
       field_end();
       encoding_init();
       goto req_headers_state;

#else
    field_end();
    encoding_init();
    goto req_headers_state;
#endif
  }
  cts ".*( \r\n| \n\n|\n\r\n)" : {

    if (req_uri_path <= $) {
      req_uri_path = $ - req_uri_path;
      EVAL_QUALIFIER("http-req-uri-path-length", req_uri_path, http_method, ANY, ANY, ANY);
      if ($dport == 7144) {
        if (http_method == SOURCE) {
          if (req_uri_path > 164) {
            eval("http-req-peercast-overlong-source-uri", TRUE);
          }
        }
      }
    }
    if (easerver_query_start == TRUE) {
      if ($ > easerver_query_len) {
        easerver_query_len = $ - easerver_query_len;
        eval("http-req-easerver-query-len", easerver_query_len);
      }
      easerver_query_start = FALSE;
    }
    field_flag(URL_FILTER_URL);
    field_end();

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    if (version_found == 0) {
        if (http_method != GET) {
            eval("http-req-error-code", SIMPLE_REQUEST_NOT_GET_METHOD);
            if ((validation_flag & 0x82) == 0) {
                switch_reason = REQ_NOT_GET_ON_SIMPLE_REQUEST;
                SWITCH_FROM_HTTP
            }
        }
    }
    encoding_init();
#else
    if (http_method != GET) {
          eval("http-req-error-code", SIMPLE_REQUEST_NOT_GET_METHOD);
    }
#endif

    goto req_headers_state;
  }
}

state req_uri_params {
    unsigned http_req_param_len:32;
    unsigned http_req_ind_param_len:32;
    unsigned http_req_param_start:32;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    unsigned tmp2_dword:32;
    unsigned tmp3_dword:32;
    unsigned last_param_offset:32;
#endif
    unsigned tmp:32;
    unsigned offset:32;
    unsigned field_cycle_count:16;
    unsigned from_cgi_seen:8;
    unsigned long_utf8_count:8;
    unsigned title_flag:8;
    unsigned for_looking_id:8;
    unsigned version_found:8;
    skip_search_engine = 0;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    unsigned net_hash_count:8;
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(6,0,0,0)))
    unsigned yahoo_n:8;
	yahoo_n = 0;
#endif

    http_req_param_start = $;
    version_found = 0;
    /*
       unsigned is_bit:8;
       unsigned sport:16;
       unsigned tmp:32;
       */

  /** zealot add */
  SWITCH_STATE(stc,req_uri_params)

  if(post_content_type == URI_PARAMS)
  {
    field_begin("http-req-post-message-body");
      //add code below for transfer http post message body to the outside
    field_bind(HTTP_POST_BODY_PROCESS_FUNC_ID);
    field_post_message_body_is_begin = 1;
  }
  /** zealot end */

    printf(&"[HTTP] Begin request parameters\n");
    FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-params", http_method, ANY);



    /** zealot add */
    if(post_content_type != URI_PARAMS)
    {
      //field_flag(DATA_CACHE);
        field_bind(HTTP_URI_PROCESS_FUNC_ID);
    }

    field_req_params_is_begin = 1;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    net_hash_count = 0;
    last_param_offset = 0;
#endif
    for_looking_id = 0;
    field_flag(DLP);
    if(post_content_type != URI_PARAMS)
    {
        field_flag(URL_FILTER_URL); //this flag won't be set on post uri
    }

    /* FIXME: Remove the URI parameter field_end, field_begin parsing for now */
    http_req_param_len = $;
    http_req_ind_param_len = $;
    from_cgi_seen = 0;
    long_utf8_count = 0;
    field_cycle_count = 0;

    title_flag = 0;
    if (post_content_type == URI_PARAMS) {
        /* in HTTP 1.0, it allow post something without a length */
        if(panav_trans_encoding == LENGTH)
        {
            if(panav_content_len == 0)
            {
                panav_content_len = 0x7fffffff;
                validation_flag |= 0x80; //don't do validation on this case
            }
        }
        /* TODO: If content-len is 0 and is not chunk-encoded, suspicious. Shall check in signature */
        /* Use skip instead of ignore so we can still parse the uri parameters
           hxie, for post content length > 10K, we will just look for first 3K and then ignore the rest to gain speed
           */
        if (panav_content_len > 10000) {
            skip(3000);
            panav_content_len -= 3000;
            ignore(panav_content_len);
        } else {
            skip(panav_content_len);
        }
        if(for_looking_id == 0xc1)
        {
            eval("http-req-black-energy-found",TRUE);
        }
        /* To calculate last param length */
        if ($ >= http_req_param_len) {
            http_req_param_len = $ - http_req_param_len;
        }
        else {
            http_req_param_len = 0;
        }
        eval("http-req-param-length", http_req_param_len);

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
	if (field_cycle_count > 230) {
	    search_back(1, 20, "\x5b\x", offset);
	    if ($?) {
		if (*($ - offset):16 == 0x5d3d) {
		    if (panav_content_len > 12000) {
			eval("http-req-cve20120830-large-param-count", 1);
		    }
		}
	    }
	}
#endif
        end_req_message_body();
    }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    else
    {
        if(*($ - 1):8 == 0x3f) //'?'
        {
            tmp2_dword = *($ - 5):32;
            skip(10,"\x5b 3d 26\x"); //'[' '=' '&'
            if(*($ - 1):8 == 0x5b)
            {
                tmp3_dword = $;
		skip(10,"\x5b 3d 5d\x"); //'[' '=' '&'
                if(*($ - 1):8 == 0x5b)
                {
		    if(($ - tmp3_dword) > 1)
		    {
                        eval("http-req-ror-cve-2012-2695",1);
 		    }
                }
            }
        }
    }
#endif

    cts ".*%" : {
        if($ + 2 < $+)
        {
            if(*($):16 == 0x3030)
            {
                if(used_as_flag & 1)
                {
                    eval("http-req-dot-net-null-injection",TRUE);
                }
            }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
	    if (field_cycle_count < 5) {
		if (*($):16 == 0x3236) {
		    if (post_content_type == URI_PARAMS) {
			eval("http-req-sql-inject-26-post-content", 1);
		    }
		}
	    }
#endif
        }
        field_flag(URI_DECODE);
    }

    cts ".*\.(/|\\)" :
    {
        field_flag(URI_DECODE);
    }
    cts ".*\x26 56 61 72 3d\x":
    {
        if( *($ - 8):8 == 0x2d )
        {
            if (*($ - 11):8 == 0x2d)
            {
                if(*($ - 14):8 == 0x2d)
                {
                    if(*($ - 17):8 == 0x2d)
                    {
                        if(*($ - 20):8 == 0x2d)
                        {
                            if(*($ - 23):8 == 0x5f)
                            {
                                if(*($ - 28):32 == 0x26666e3d)
                                {
                                    eval("http-req-backdoor-bmw-found", TRUE);
                                }
                                else if (*($ - 29):32 == 0x26666e3d)
                                {
                                    eval("http-req-backdoor-bmw-found", TRUE);
                                }
                                else if (*($ - 30):32 == 0x26666e3d)
                                {
                                    eval("http-req-backdoor-bmw-found", TRUE);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
  cts ".*\.swf\?jsModuleId=%ED%A0%80\x5c 22 29 29 7d 63 61 74 63 68 28\x" ignore_case : { /*\"))}catch(*/
      eval("http-req-cve-2014-0509-found", 1);
  }
#endif

    cts ".*src=file&service=myp_" ignore_case:
    {
        if(http_method == POST){
            post_content_type = APP_STREAM;
        }
    }


    cts ".*tool=sfsync" ignore_case:
    {
        if(http_method == POST && $appid == 1035){
            post_content_type = APP_STREAM;
        }
    }
    cts ".*fname=" ignore_case:
    {
        if(http_method == POST && $appid == 1772){
            post_content_type = APP_STREAM;
        }
    }
    cts ".*filename=" ignore_case:
    {
        if(http_method == POST && $appid == 668){
            post_content_type = APP_STREAM;
        }
    }


    cts ".*=%25[sn]%" :
    {
        if (post_content_type == URI_PARAMS) {
            eval("http-req-cve-2006-4154", TRUE);
        }
    }
    cts ".*%20%60" : {
        eval("http-req-possible-cmd-injection", TRUE);
    }
    cts ".*title=" ignore_case:
    {
        title_flag |= 1;
    }
    cts ".*((%250d%250a)|(%0d%0a))":
    {
        if(title_flag & 1)
        {
            eval("http-req-possible-title-csrf",TRUE);
        }
    }
    cts ".*(%20-s|%09-s|%2d-s|--s|%2ds|-%73|%2d%73)" ignore_case :
    {
        if (field_cycle_count == 0) {
            eval("http-req-possible-phpcgi-disclosure", 1);
        }
    }
    cts ".*\x2f 2e 2e 2f 2e 2e 2f\x" : {
        eval("http-req-directory-traversal", TRUE);
    }


    /*for labnol-proxy*/
    /*  /?url= */
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    cts ".*(\x20 2f 3f 75 72 6c 3d\x|\x6d 2f 3f 75 72 6c 3d\x)": {
        eval("http-req-labnol-value", TRUE);
    }
#endif


#if (PAN_ENGINE_VERSION >= (PAN_VERSION(6,0,0,0)))
    cts ".*(&vm=p&|&vm=i&)" ignore_case:
    {
        yahoo_n = 1;
    }
#endif


    cts ".*id=":
    {
        if($ == (http_req_param_len + 3))
        {
            for_looking_id |= 0x80;
        }
    }
    cts ".*&build_id=":
    {
        for_looking_id |= 0x40;
    }
    cts ".*URL=" ignore_case:{
        cgiproxy+=4;
        if ((cgiproxy & 1) == 1) {
            /* to make sure we have seen the (010101)A before */
            if (http_method == POST) {
                setapp "cgiproxy";
            }
        }

        if (cgiproxy == 7) {
            setapp "cgiproxy";
        }
    }
    cts ".*rs=" :{
        cgiproxy+=2;
        if (cgiproxy == 7) {
            setapp "cgiproxy";
        }
    }
    cts ".*\.\.%5c" : {
        eval("http-req-possible-dir-traversal-inparam", TRUE);
    }

    cts ".*%f[0-4]%8" : {
     if ($+ > $ + 1){
       skip(2);
       if (*($ - 1):8 == 0x25){
        long_utf8_count ++;
        if (long_utf8_count == 40) {
            eval("http-req-overly-long-utf8", TRUE);
            long_utf8_count = 0;
        }
       }
     }
    }

    cts ".*CONVERT\(" ignore_case: {
        tmp = 0;
        offset = $;
        do {
            skip(1);
            if ( *($ - 1):8 == 0x2c ) { tmp++; offset = $; }
        } while ( *($ - 1):8 != 0x29 );
        if ( tmp == 2 ) {
            tmp = atoi(offset, 10);
            if ( tmp > 131 ) {
                eval("http-req-convert-milformed", TRUE);
            }
        }
        if(post_content_type == URI_PARAMS)
        {
            if(panav_content_len > 10000)
            {
                if(($ - http_req_param_start) >= 3000)
                {
                    ignore(panav_content_len - ($ - http_req_param_start));
                }
                else
                {
                    skip(3000 - ($ - http_req_param_start));
                    ignore(panav_content_len - 3000);
                }
            }
            else
            {
                skip(panav_content_len - ($ - http_req_param_start));
            }
            field_end();
            end_req_message_body();

        }
    }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    cts ".*txt_user_name_p=" ignore_case:
    {
        skip(256,"\x26 3d 0a\x"); //& = \n
        if($? == 0)
        {
            eval("http-req-CVE-2010-1223-find",1);
        }
        if(post_content_type == URI_PARAMS)
        {
            if(panav_content_len > 10000)
            {
                if(($ - http_req_param_start) >= 3000)
                {
                    ignore(panav_content_len - ($ - http_req_param_start));
                }
                else
                {
                    skip(3000 - ($ - http_req_param_start));
                    ignore(panav_content_len - 3000);
                }
            }
            else
            {
                skip(panav_content_len - ($ - http_req_param_start));
            }
            field_end();
            end_req_message_body();
        }

    }
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
    cts ".*%271%27=%271" ignore_case:
    {	eval("http-req-SQLInjectionAttempt-found", 1);}

    cts ".*%27a%27%3D%27a" ignore_case:
    {   eval("http-req-SQLInjectionAttempt-found", 1);}

    cts ".*%22a%22%3D%22a" ignore_case:
    {   eval("http-req-SQLInjectionAttempt-found", 1);}

    cts ".*%221%22%3D%221" ignore_case:
    {   eval("http-req-SQLInjectionAttempt-found", 1);}
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
    cts ".*&tree=" ignore_case:
	{
	    if (post_content_type != URI_PARAMS) {
		skip (200, "\x26 20\x");
		if ($? == 0) {
		    eval("http-req-long-tree-param", 1);
		}
	    }
	}
    cts ".*&arg=-" ignore_case:
        {
            if (post_content_type != URI_PARAMS) {
                skip (512, "\x26 20\x");
                if ($? == 0) {
                    eval("http-req-long-malform-arg-param", 1);
                }
            }
        }
    cts ".*(\?|&)host=" ignore_case:
        {
            if (post_content_type != URI_PARAMS) {
                skip (200, "\x26 20\x");
                if ($? == 0) {
                    eval("http-req-long-host-param", 1);
                }
            }
        }
#endif
    cts ".*from=" ignore_case: {
        from_cgi_seen = 1;
    }

    cts ".*\.fmx" ignore_case: {
        eval("http-req-oracle-form-in-params", TRUE);
    }

    cts ".*&" : {
        if ($ >= http_req_param_len) {
            http_req_param_len = $ - http_req_param_len;
        }
        else {
            http_req_param_len = 0;
        }
        title_flag &= 0xfe;
        if((for_looking_id & 0x3f) > 0x3e) {for_looking_id = 0;}
        for_looking_id++;
        // modify by sunon.zealot in 14/7/9. http_req_param_len will not contain the len of char '&'
        eval("http-req-param-length", (http_req_param_len - 1));
        http_req_param_len = $;
        if (from_cgi_seen) {
            if (($ > http_req_ind_param_len) &&
                    (($ - http_req_ind_param_len) > 153)) {
                eval("http-req-error-code", OVERLONG_FROM_PARAM);
            }
        }
        from_cgi_seen = 0;
        http_req_ind_param_len = $;
        if(field_cycle_count < 10)
        {
            field_end();
            FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-params", http_method, ANY);
            /** zealot add */
            if(post_content_type != URI_PARAMS)
            {
              //field_flag(DATA_CACHE);
                field_bind(HTTP_URI_PROCESS_FUNC_ID);
            }
            field_req_params_is_begin = 1;
            /** zealot end */

            field_flag(DLP);
            if(post_content_type != URI_PARAMS)
            {
                field_flag(URL_FILTER_URL);
            }
        }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
        if (field_cycle_count == 300) {
            eval("http-req-uri-params-high-count", 1);
        }
        if(*($ - 2):8 == 0x3d) //'='
        {
            if(last_param_offset != 0xffffffff)
            {
                if(last_param_offset)
                {
                    if(($ - last_param_offset) < 40)
                    {
                        if((*($ - 3):8 > 0x39) || (*($ - 3):8 < 0x30))
                        {
                            net_hash_count++;
                        }
                        else if(*($ - 5):8 == 0x25) /* '%' */
                        {
                            net_hash_count++;
                        }

                        if(net_hash_count > 0x50)
                        {
                            eval("http-req-CVE-2011-4858-found",1);
                            net_hash_count = 0;
                        }
                    }
                }
                last_param_offset = $;
            }
        }
        else
        {
            last_param_offset = 0xffffffff;
        }

#endif
        if(field_cycle_count > 300) /* why 600? in POST, we only do skip on first 1000 byte */
        {
            if((post_content_type == URI_PARAMS) && (panav_content_len > 100000))
            {
                eval("http-req-CVE-2010-1899-found",TRUE);
            }
        }
        else
        {
            field_cycle_count++;
        }
    }
    cts ".*('|%27)":
    {
        eval("http-req-found-sqlinjection-in-param",TRUE);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
	if (for_looking_id & 0x80) {
	    eval("http-req-sqlinject-in-id-param", 1);
	}
#endif
    }
    /*more way of URL encoding "'" for sql-in-jection*/
    cts ".*%2527":
    {
        eval("http-req-found-sqlinjection-in-param",TRUE);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
        if (for_looking_id & 0x80) {
            eval("http-req-sqlinject-in-id-param", 1);
        }
#endif
    }
    cts ".*%%327":
    {
        eval("http-req-found-sqlinjection-in-param",TRUE);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
        if (for_looking_id & 0x80) {
            eval("http-req-sqlinject-in-id-param", 1);
        }
#endif
    }
    cts ".*%25%327":
    {
        eval("http-req-found-sqlinjection-in-param",TRUE);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
        if (for_looking_id & 0x80) {
            eval("http-req-sqlinject-in-id-param", 1);
        }
#endif
    }
    cts ".*%2%37":
    {
        eval("http-req-found-sqlinjection-in-param",TRUE);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
        if (for_looking_id & 0x80) {
            eval("http-req-sqlinject-in-id-param", 1);
        }
#endif
    }
    cts ".*%252%37":
    {
        eval("http-req-found-sqlinjection-in-param",TRUE);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
        if (for_looking_id & 0x80) {
            eval("http-req-sqlinject-in-id-param", 1);
        }
#endif
    }
    cts ".*%%32%37":
    {
        eval("http-req-found-sqlinjection-in-param",TRUE);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
        if (for_looking_id & 0x80) {
            eval("http-req-sqlinject-in-id-param", 1);
        }
#endif
    }
    cts ".*%25%32%37":
    {
        eval("http-req-found-sqlinjection-in-param",TRUE);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
        if (for_looking_id & 0x80) {
            eval("http-req-sqlinject-in-id-param", 1);
        }
#endif
    }

    cts ".*%0a" ignore_case:
    {
        eval("http-req-found-0x0a-in-param",TRUE);
    }

    cts ".*(\||%7c)" : {
        eval("http-req-params-meta-char", TRUE);
        if (*($ - 7):32 == 0x6964323d) {
            eval("http-req-omnipcx-id2-meta-char", TRUE);
        }
        else if (*($ - 9):32 == 0x6964323d) {
            eval("http-req-omnipcx-id2-meta-char", TRUE);
        }
        else if (*($ - 8):32 == 0x6964323d) {
            eval("http-req-omnipcx-id2-meta-char", TRUE);
        }
        else if (*($ - 10):32 == 0x6964323d) {
            eval("http-req-omnipcx-id2-meta-char", TRUE);
        }
    }

    cts ".*\.xls":
    {
        eval("http-req-found-xls-in-param",TRUE);
    }

    /* This is used to identify gnu-httptunnel
     *index.html?crap=1276308281
     */
    cts ".*crap=":
    {
        GNU_HTTPTUNNEL_APPID()
    }

    cts start: {
        /* we should not see any bytes after simple_request */
        if (simple_request == 2) {
            switch_reason = REQ_SIMPLE_REQUEST_IN_MULTIPLE_PACKET;
            SWITCH_FROM_HTTP
        }
    }

    cts end : {

        if (simple_request == 1) {
            if (*($ - 1):8 == 0xa) {  /* end of the packet is also end of the command
                                         and we did not see the version string or \r\n \n\n
                                         this is a real simple_request remain in this state
                                         since we should not see more requests.
                                         */
                simple_request = 2;
            }
        }
        if ($ >= http_req_param_len) {
            eval("http-req-param-length", $ - http_req_param_len);
        }

        if (post_content_type != URI_PARAMS) {

            /* if we got here before seeing the CTLF of the request-line, exit */

            if ((validation_flag & 0x82) == 0) {
                if (($ - http_req_param_start) > MAX_URL_LEN) {
                    switch_reason = REQ_LONG_URL;
                    SWITCH_FROM_HTTP
                }
            }
        }
    }

    cts ".*[\x00 09 20\x]HTTP/" ignore_case : {
      /** zealot add */
      if(1 == field_req_params_is_begin || 1 == field_req_uri_path_is_begin)
      {
        //the last field req params is not end
        field_end();
        field_req_params_is_begin = 0;
        field_req_uri_path_is_begin = 0;
        //add code below for transfer http uri to the outside
        //HTTP_URI_PROCESS_FUNC("http-req-uri-path","http-req-params");
        //field_cache_clear("http-req-uri-path","http-req-params");
      }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(6,0,0,0)))
		    eval("http-req-yahoo-2", yahoo_n);
#endif
        if((*($ - 7):8 == 0x0d) || (*($ - 7):8 == 0x0a) || (*($ - 8):8 == 0x0d) || (*($ - 8):8 == 0x0a))
        {
            eval("http-req-invalid-end-line-found",TRUE);
        }
        if((*($ - 9):8 == 0x0d) || (*($ - 9):8 == 0x0a) || (*($ - 10):8 == 0x0d) || (*($ - 10):8 == 0x0a))
        {
            eval("http-req-invalid-end-line-found",TRUE);
        }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
        if(*($ - 10):32 == 0x2532356e)
        {
            eval("http-req-fmt-string-found",TRUE);
        }
	search_back(1, 20, "\x3d\x", tmp2_dword);
	if ($?) {
	    if (*($ - tmp2_dword - 5):32 == 0x26746964) {
		eval("http-req-tid-last-param", 1);
	    }
	}
#endif

        if(post_content_type != URI_PARAMS)
        {
            if (http_method != POST) {
                printf(&"[HTTP] End request parameters\n");

                if ($ >= http_req_param_len) {
                    http_req_param_len = $ - http_req_param_len;
                }
                else {
                    http_req_param_len = 0;
                }
                /** to reduce the length of 6 bytes of string " HTTP/" for http_req_param_len**/
                /** add by sunon.zealot in 3/31/2014 **/
                if(6 <= http_req_param_len)
                {
                    eval("http-req-param-length", (http_req_param_len - 6));
                }
                else
                {
                    eval("http-req-param-length", http_req_param_len);
                }
            }
            if (from_cgi_seen) {
                if (($ > http_req_ind_param_len) &&
                        (($ - http_req_ind_param_len) > 153)) {
                    eval("http-req-error-code", OVERLONG_FROM_PARAM);
                }
            }
            /* For CVE-2000-0984 cisco IOS dos */
            if(*($ - 8):16 == 0x3f2f) /* ?/ */
            {
                eval("http-req-uri-cisco-ios-dos",TRUE);
            }
            field_flag(URL_FILTER_URL);
            version_found = 1;
            simple_request = 0;
            FIELD_BEGIN_IGNORE_CASE("http-req-version-string");
            if ((validation_flag & 0x82) == 0) {
                skip(3);
                if ((*($ - 3):8 < 0x30) || (*($ - 3):8 > 0x39)) {
                    eval("http-req-version-invalid", 1);
                    switch_reason = REQ_HTTP_VERSION_ERROR;
                    SWITCH_FROM_HTTP
                }

                if (*($ - 2):8 != 0x2e) {
                    eval("http-req-version-invalid", 1);
                    SWITCH_FROM_HTTP
                }

                if ((*($ - 1):8 < 0x30) || (*($ - 1):8 > 0x39)) {
                    switch_reason = REQ_HTTP_VERSION_ERROR;
                    eval("http-req-version-invalid", 1);
                    SWITCH_FROM_HTTP
                }

                skip(1);
                tmp = *($ - 1):8;
                if ((tmp != 0x09) && (tmp != 0x20) && (tmp != 0) &&
                        (tmp != 0xd) && (tmp != 0xa)) {
                    eval("http-req-version-invalid", 1);
                    switch_reason = REQ_HTTP_VERSION_ERROR;
                    SWITCH_FROM_HTTP
                }

                if ((tmp != 0xa) &&  (*($):8 != 0xa)) {
                    skip(4, "\x0a 00\x");
                    if ($? == 0) {
                        eval("http-req-version-invalid", 1);
                        switch_reason = REQ_HTTP_VERSION_DONT_SEE_CRLF_AFTER_8_BYTES;
                        SWITCH_FROM_HTTP
                    }
                }
            }
            field_end();
            encoding_init();
            goto req_headers_state;
        }
    }

    cts ".*mode=ssp" ignore_case : {
        if ((ntlm_ssp_flag & 2) != 2) {
            eval("http-req-ms08-077-found", 1);
        }
    }

    cts ".*=%udffe%udffe" ignore_case : {
        if(http_method == POST){
            eval("http-req-CVE-2008-0075-found", 1);
        }
    }

    cts ".*((\x2F 63 68 61 72 49 6D 67 2E 61 78 64 3F 69 3D 5C 2E 2E 5C\x)|(\x2F 63 68 61 72 49 6D 67 2E 61 78 64 3F 69 3D 2F 2E 2E 2F\x))" ignore_case:
    {
        eval("http-req-cve-2011-1977-found",1);
    }
    /*this part looks for glype uri format which is b= or bit= a one or two digit number*/
    cts ".*(&b=|&bit=)" : {
        if($ + 1 < $+){
            if((*$:8 > 0x2f) && (*$:8 < 0x3a )){
                if((*($ + 1):8 == 0x20) || (*($ + 1):8 == 0x26)){
                    eval("http-req-glype-found",1);
                }else if($ + 2 < $+ ){
                    if((*($ + 2):8 == 0x20) || (*($ + 2):8 == 0x26)){
                        eval("http-req-glype-found",1);
                    }
                }
            }
        }
    }


    cts ".*ReturnURL=http" : {
        skip(50, "\x5c 0a 26\x");
        if ($? == 1)
        {
            if( *($ - 1):8 == 0x5c )
            {
                if(used_as_flag & 1)
                {
                    eval("http-req-cve-2011-3415",1);
                }
            }
        }
    }

    CHECK_COMMON_URI_PARAMS_APPS
        CHECK_COMMON_URI_PARAMS
        cts ".*( \r\n| \n\n|\n\r\n)" : {

            if (post_content_type != URI_PARAMS) {   /* this means we are still in the request line */
                if (version_found == 0) {
                    if (http_method == GET) {
                        simple_request = 1;
                    } else {
                        if ((validation_flag & 0x82) == 0) {
                            switch_reason = REQ_CRLF_FOUND_BEFORE_VERSIONSTRING;
                            SWITCH_FROM_HTTP
                        }
                    }
                }
            }
            else
            {
                if(panav_content_len > 10000)
                {
                    if(($ - http_req_param_start) >= 3000)
                    {
                        ignore(panav_content_len - ($ - http_req_param_start));
                    }
                    else
                    {
                        skip(3000 - ($ - http_req_param_start));
                        ignore(panav_content_len - 3000);
                    }
                }
                else
                {
                    if(panav_content_len > ($ - http_req_param_start))
                    {
                        skip(panav_content_len - ($ - http_req_param_start));
                    }
                }
                end_req_message_body();
            }
            encoding_init();

            if (http_method != POST) {
                printf(&"[HTTP] End request parameters\n");

                if ($ >= http_req_param_len) {
                    http_req_param_len = $ - http_req_param_len;
                } else {
                    http_req_param_len = 0;
                }
                eval("http-req-param-length", http_req_param_len);
            }
            field_flag(URL_FILTER_URL);
            field_end();
            goto req_headers_state;
        }
   cts ".*(.baidu.com|.bing.com|.sogou.com|.soso.com|.so.com|.360.cn|afs.googlesyndication.com|.yahoo.com)" : {
	skip_search_engine = 1;
   }
}

state req_headers_state {
  unsigned req_hdr_len:32;
  unsigned offset:32;
  unsigned other_hdrs_len:32;
  unsigned req_hdrs_start:32;
  unsigned content_len:32;
  unsigned req_hdr_type:8; /* !!! Don't change the position of req_hdr_type !!! */
  unsigned found_hdr_end:8;
  unsigned found_host:8;
  unsigned hdr_char:8;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
  unsigned lastSkipStart:32;
  unsigned noNewLine:8;
  unsigned noDot:8;
#endif
  unsigned found_content_len:8;
  unsigned tmp:8;
  unsigned panid:32;
  unsigned deviceid:32;
  unsigned tmp2:32;
  /*
   * flag field use to check header info
   * bit 0: use for check flash header
   * bit 1: use for "silverlightdownload: false" header
   * bit 2: use for navermail html5 upload
   * bit 3: use for "application/octet-stream" encountered during content post
   */
  unsigned flag:8;

  /** zealot add */
  SWITCH_STATE(stc,req_headers_state)

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
  unsigned auth_offset:32;
  unsigned eencoding:8;
  eencoding = 0;
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(6,0,0,0)))
	/*variables used for safe search feature - YZ*/
  unsigned google_p:8;
  unsigned google_n:8;
  unsigned bing_p:8;
  unsigned bing_n:8;
  unsigned yahoo_p:8;
  unsigned youtube_p:8;

  google_p = 0;
  google_n = 0;
  bing_p = 0;
  bing_n = 0;
  yahoo_p = 0;
  youtube_p = 0;
#endif

printf(&"ABCDEFG123=======\n%x",*$:32);

  printf(&"[HTTP] Begin request headers\n");
  FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-headers", http_method, req_hdr_type);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,4)))
    field_flag(DLP);
#endif
/*
added by wangshiyou for flash 0day, 2015.07.09
*/
   cts ".*Host:[^\n]*(12306|baidu|google|sina|tencent|qq|sohu|163|126|yahoo|cctv|xinhuanet|people|youku|tudou|taobao|jd|icbc|dangdang|bankofbeijing|ccb|boc)" ignore_case : {
	flash_search_engine = 0;
   }
/*
added by wangshiyou for Trojan.Kazy.290327 malicious communication, 2015.12.16
*/
   cts ".*Host:[^\n]*www\.gov\.toh\.info" ignore_case : {
           eval("http-req-toh-host-found",1);
   }

/*
added by wangshiyou for Apache HTTP server does not complete Request Denial of Service Vulnerability,2015.12.31 
*/
   cts ".*Content-Length:[^\n]*42\r\nX-a:[^\n]*\r\n" ignore_case : {
           eval("http-req-apache-denial-found",1);
   }

  cts ".*\nHost: server-[0-9a-fA-F]{4,8}" :
  {
    /* This is for zealot bps'cps test , the signature is generated by bps automaticly */
    printf("[HTTP] Hit bps cps'signature which is generated by bps automaticly , will exit current micro thread\n") ;
    exit( 0 ) ;
  }

/* At the beginning of headers, if seeing rpc_over_http, exit here!*/
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
   if (http_method == RPC_OUT_DATA || http_method == RPC_IN_DATA ||http_method == RPC_ECHO_DATA||http_method == RPC_CONNECT) {
           eval("http-req-rpc-method-used",TRUE);
        if ($appid != 792) {
               setapp "rpc-over-http";
        }

   }


#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))

    /*; authchallenge=87959309aac5a7bab5519fdb2d784134; .ASPXAUTH=*/
    cts ".*; authchallenge=":{
        auth_offset = $;
    }
    cts ".*; \.ASPXAUTH=":{
        if (auth_offset > 0) {
            if ($ - auth_offset == 44){
                eval("http-req-cookie-bit9-found",TRUE);
                setapp "bit9-parity";
            }
        }
    }
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(6,0,0,0)))
    /*variables used for safe search feature - YZ*/
    cts ".*FF=1" ignore_case:
    {
        google_p |= 0x01;
    }

    cts ".*NID=" ignore_case:
    {
        google_n |= 0x01;
    }

    cts ".*ADLT=STRICT" ignore_case:
    {
        bing_p |= 0x01;
    }

    cts ".*SRCHD=" ignore_case:
    {
        bing_n |= 0x01;
    }

    cts ".*vm=r" ignore_case:
    {
        yahoo_p |= 0x01;
    }

    cts ".*sBL=1" ignore_case:
    {
        yahoo_p |= 0x01;
    }
    cts ".*\x66 32 3d 38 30 30 30  30 30 30\x" ignore_case:
    {
        youtube_p |= 0x01;
    }
#endif


    cts ".*\nConnection: close" ignore_case:
    {
        if($appid != 62)
        {
            http_connection_closed=1;
        }
    }


  cts ".*\x04 ba 20 60\x" : {
    eval("http-req-retaddr", BLUECOAT_PROXY_RETADDR);
  }

  cts ".*(\x2e 07 c6 62\x|\x1e 07 91 63\x)\xeb ba\x" : {
    eval("http-req-retaddr", DOMINO_ACCLANG_RETADDR);
  }
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
  cts ".*(\x4a 2a 21 5a\x|\x67 2b c0 71\x|\x2c 78 c0 71\x)" : {
    eval("http-req-retaddr", OVJAVALOCALE_RETADDR);
  }
#endif
/*
 * for drive by download cookie in 4.0
 */
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,2)))
    cts ".*PANID" : {
        offset = $ ;
        skip(16, "\x3d\x");
        found_hdr_end = $?;
        if (found_hdr_end == TRUE) {
           deviceid= atoi(offset, 10);
           offset = $ ;
           skip(16, "\x3b 0d 0a\x");
           found_hdr_end = $?;
           if (found_hdr_end == TRUE) {
              panid = atoi(offset, 10);
              set_pan_cookie(deviceid, panid);
           }
        }
    }
#endif


#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
#define val content_len
  cts ".*\nSource=" : {
    if ($ + 100 <= $+) {
      val = *($ + 96):32;
      if (val == 0xb5410760 || val == 0xdadb1e60 || val == 0x42424242 || val ==0x58416e37 ) {
    eval("http-req-mfe-source-overflow", 1);
      }
      if (val == 0xce111160) // for core impact exploit
      {
          eval("http-req-mfe-source-overflow", 1);
      }
    }
    skip(90, "\x0a\x");
    if ($? == 0)
    {
       eval("http-req-mfe-source-overflow", 1);
    }
  }
#undef val
#endif
  found_host = 0;
  found_content_len = 0;
  panav_content_len = 0;
  req_hdr_type = UNKNOWN_HDR;
  other_hdrs_len = $;
  req_hdrs_start = $;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))//
  lastSkipStart = 0;
  noNewLine = 0;
  noDot = 0;
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
  flag = 0;
#endif

#define cnt found_content_len
  /* Count number of whitespace for CVE-2004-0942 */
  /* Skip the version of HTTP */
    if (*($ - 1):8 != 0x0a)
    {
        skip(10,"\x0a\x");
    }
    if (*($ - 1):8 == 0x0a)
    {
        skip(10);
        if(*($ - 10):32 == 0x20202020)
        {

            if(*($ - 6):32 == 0x20202020)
            {
                if(*($ - 2):16== 0x2020)
                {
                    eval("http-req-header-too-many-space", TRUE);
                }
            }
        }
    }
#undef cnt

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    found_content_len = 0;
#endif
  cts ".*\nContent-Length:" ignore_case : {
    used_as_flag &= 0xfd;
    get_other_hdrs_len();
    SEARCH_HEADER_END(req, CONTENT_LENGTH, 14)
    if (found_hdr_end == TRUE) {
      content_len = atoi(offset, 10);
      if(content_len == 0) {eval("http-req-zero-content-length-found",1);}
      if (content_len == 1073741824 ){
        if ($appid == 792) {
             printf(&"[RPCRPC] Back to appid now!\n");
               goto backto_appid_state;
              exit();
         }
      }

	 /* Add the code to check kugoo through http.*/
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    if ($ == 80) {
        if (http_method == POST){
			if (content_len > 40 && content_len < 100){
            	rsp_code = 2;
			}
        }
    }
#endif


#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
	  /* In the case of scott proxy, the content length should be even all the time.*/
	  if ((evasive&2) == 2) {
	  	if (panav_content_len % 2 == 1){
			evasive = 0;
		}
	  }
#endif
      if (found_content_len) {
        if(content_len == 0)
        {
            /* we are seeing double content-length. It is an anomaly */
            eval("http-req-double-content-length-found",TRUE);
        }

    /* Take the larger value as content length */
        if (content_len > panav_content_len) {
            panav_content_len = content_len;
        }
      }
      else {
        panav_content_len = content_len;
      }
      found_content_len = 1;
      eval("http-req-content-length", panav_content_len);
      printf(&"[HTTP] Content length = %d(0x%x)\n", panav_content_len, panav_content_len);
    }
  }

  cts ".*\nContent-Type:" ignore_case : {
    get_other_hdrs_len();
    SEARCH_HEADER_END(req, CONTENT_TYPE, 128)
  }

  cts ".*\nAuthorization:" ignore_case : {
	eval("http-req-authorization", TRUE);
  }



#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
  cts ".*\nRange:" ignore_case : {
    get_other_hdrs_len();
    SEARCH_HEADER_END(req, RANGE, 1024)
  }
  cts ".*bytes=" ignore_case : {
      if (req_hdr_type == RANGE)
      {
#define range_cnt hdr_char
#define range_val1 panid
#define range_val2 deviceid

	range_cnt = 0;
	range_val1 = 0;
	range_val2 = 0;
	offset = $;
	do {
	  skip (8, "\x0a 2c 2d\x");
	  if ($? == 0) {
	    break;
	  }
	  tmp = *($ - 1):8;
	  if (tmp == 0x2d) { /* Hyphen - */
	    /* Check for overlapping ranges */
	    tmp2 = atoi (offset, 10);
	    if (range_cnt > 0) {
	      if (tmp2 == range_val2 || tmp2 == range_val1) { /* Ex: 5-6, 5-7 */
		eval("http-req-overlapping-range-values", 1);
		break;
	      }
	      else if (tmp2 < range_val2) { /* Ex: 1-9,7-10 */
		if (tmp2 > range_val1) {
		  eval("http-req-overlapping-range-values", 1);
		  break;
		}
	      }
	    }
            range_val1 = tmp2;
	    offset = $;
	  }
          else if (tmp == 0x2c || tmp == 0x0a) { /* indicates end of one range */
	    tmp2 = atoi (offset, 10);
	    if (range_cnt > 0) {
	      if (tmp2 == range_val2) { /*Ex: 7-12, 6-12 */
		eval("http-req-overlapping-range-values", 1);
		break;
	      }
	      else if (range_val1 < range_val2) { /* Ex: 7-11, 6-12 */
		if (tmp2 > range_val2) {
		  eval("http-req-overlapping-range-values", 1);
		  break;
		}
	      }
	    }
	    if ($ == offset + 1) { /* Ex: 0- : No end value, assign end of file */
	      range_val2 = 0xffffffff;
	    }
	    else {
	      range_val2 = tmp2;
	    }
            if (range_val1 > range_val2) {
              eval("http-req-negative-range-values", 1);
              break;
            }
            range_cnt ++;
            offset = $;
          }
	} while (tmp != 0x0a && range_cnt < 5);
#undef range_cnt
#undef range_val1
#undef range_val2
	if (tmp == 0x0a) {
	  found_hdr_end = TRUE;
	  req_hdr_end();
	}
	else {
	  SEARCH_HEADER_END(req, RANGE, 1024)
	}
	if (found_hdr_end != TRUE)
	  {
	    eval("http-req-long-range-bytes-header", 1);
	  }
      }
  }
  cts ".*Content-Disposition:" ignore_case : {
    get_other_hdrs_len();
    SEARCH_HEADER_END(req, CONTENT_DISPOSITION, 256)
  }
  cts ".*filename=" ignore_case : {
    if(req_hdr_type == CONTENT_DISPOSITION) {
      field_end();
      field_begin("http-req-header-filename",ignore_case);
      eval("http-req-file-upload-all", TRUE);
      skip(1);
      if(*($ - 1):8 == 0x22) {
	skip(256, "\x0a 3b 22\x");
      }
      else {
	skip(256, "\x0a 3b\x");
      }
      if ($?) {
	field_flag(FILENAME);
      print("-->http 8\n");
	field_end();
        post_content_type = APP_STREAM;
	FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-headers", http_method, req_hdr_type);
      }
      else {
	eval("http-req-error-code", OVERLONG_mime_filename);
      }
    }
  }

  cts ".*\.mp3" ignore_case : {
    if(req_hdr_type == CONTENT_DISPOSITION) {
      eval("http-req-mp3-ext-found", 1);
    }
  }
  CHECK_COMMON_HEADERS_APPS
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
 cts ".*\.bat" ignore_case : {
    if(req_hdr_type == CONTENT_DISPOSITION) {
      eval("http-req-bat-ext-found", 1);
    }
  }
 cts ".*\.hta" ignore_case : {
    if(req_hdr_type == CONTENT_DISPOSITION) {
      eval("http-req-hta-ext-found", 1);
    }
  }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
 cts ".*\.cmd" ignore_case : {
     if(req_hdr_type == CONTENT_DISPOSITION) {
	 eval("http-req-cmd-ext-found", 1);
     }
 }
#endif
  cts ".*\nCookie: "ignore_case : {

       field_begin("http-req-full-cookie");
       //add zealot code below for transfer http cookie to the outside
       field_bind(HTTP_COOKIE_PROCESS_FUNC_ID);
       field_full_cookie_is_begin = 1;

  	   host4bytes = $;
       validation_flag |= 0x80; /* Release the header length check after seeing Cookie */
  	   skip(5,"\x3d\x");
	   if ($? != 0){
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
	     if ($ - host4bytes == 1) {
	       if ($ + 1 < $+) {
		 if (*($):8 == 0x0d || *($):8 == 0x0a) {
		   eval("http-req-null-cookie", 1);
		 }
	       }
	     }
#endif
	   		if ($ - host4bytes == 5) {
				skip(38,"\x0d\x");
				if (*($ - 1):8 == 0x0d) {
					eval("http-req-btlike-cookie",TRUE);
					if ($? != 0){
						if ((http_used_as_flag&12) == 12) {
							http_used_as_flag |= 2;
						}
					}
				}
			}
	   } else {
	   	  /* Process the dostupest cookie like: "Cookie: 245d7e7a=1pijdsug52sfoukj7pkbdoidg5;"*/
		   skip(4,"\x3d\x");
		   if ($? != 0){
		   		if ($ - host4bytes == 9) {
					skip(27,"\x0d 3b\x");
					if ($? != 0){
						if ($ - host4bytes == 36){
							if (*($ - 1):8 == 0x3b || *($ - 1):8 == 0x0d){
								eval("http-req-dostupest-cookie",TRUE);
							}
						}
					}
              }
           }
	   }
	   host4bytes = 0; /* set it back for normal use late on */
  }


#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
  /*this code looks for glype cookie that is s=xxxx which is 32 or 26 bytes length*/
  cts ".*(;|Cookie:) s=" :{
     tmp2 = $;
     if($ + 27 < $+){
	     skip (27,"\x0d 0a 3b\x");
         if($? == 1){
             tmp2 = $ - tmp2;
             if(tmp2 == 27){
                 eval("http-req-glype-cookie-found",1);
             }
         }else{
             if($ + 6 < $+){
                 skip(6, "\x0d 0a 3b\x");
                 tmp2 = $ - tmp2;
                 if($? == 1){
                     if(tmp2 == 33){
                         eval("http-req-glype-cookie-found",1);
                     }
                 }
             }
         }
     }
  }
#endif

    cts ".*(\nx-droplr-filename:|\ndroplr-date:)" ignore_case:
    {
        if(http_method == POST){
            post_content_type = APP_STREAM;
        }
    }


#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
  cts ".*\nAuthorization: " ignore_case : {
    if ($+ - $ > 4) {
      if (*($):32 == 0x41414141) {
	    eval("http-req-authorization-hdr-dos", 1);
      }
	  else if (*($):32 == 0x42656172){   //Authorization: Bearer
		 if(http_method == POST && $appid == 1800){
          post_content_type = APP_STREAM;
		 }

     /** zealot add */
     field_begin("http-req-auth-user");
     field_flag(DATA_CACHE);
     field_auth_user_is_begin = 1;

	  }
    }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    skip(4);
    tmp2 = *($ - 4):32 | 0x20202020; //low case
    get_other_hdrs_len();
    if(tmp2 == 0x6E65676F)//negotiate
    {
        SEARCH_HEADER_END(req, AUTHORIZATION, 256)
        if (found_hdr_end != TRUE)
        {
            eval("http-req-error-code", OVERLY_LONG_AUTH_NEGOTIATE_HEADER);
        }
    }
    else if(tmp2 == 0x62617369) //basic
    {
        /*  added by sunon.zealot for basic authorization in 2014/3/5  **/
         skip(2,"\x20\x");
         field_flag(BASE64);
        /*  end  **/

        SEARCH_HEADER_END(req, AUTHORIZATION, 450)
        if (found_hdr_end != TRUE)
        {
            eval("http-req-error-code", OVERLY_LONG_AUTH_HEADER);
        }
    }
    else if(tmp2 == 0x64696765) //digest
    {
        SEARCH_HEADER_END(req, AUTHORIZATION, 512)
        if (found_hdr_end != TRUE)
        {
            eval("http-req-error-code", OVERLY_LONG_AUTH_DIGEST_HEADER);
        }
    }
#endif
  }

    cts ".*((\nTranslate: f)|(\nLock-Token: <)|(\nif: ))" ignore_case:
    {
      eval("http-req-webdav-request-found",TRUE);
    }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
  cts ".*\nsilverlightupload: " ignore_case : {
    skip(4);
    if (*($ - 4):32 == 0x74727565) { /* 'true' */
      post_content_type = APP_STREAM;
    }
    else if (*($ - 4):32 == 0x66616c73) { /* 'false' */
      flag |= 0x02; // set "silverlightdownload: false" header flag
      if (flag & 0x08) { // if we have already encountered "application/octet-stream" during content post
          post_content_type = APP_STREAM;
      }
    }
  }
#endif
  cts ".*\nTransfer-Encoding:" ignore_case : {
    get_other_hdrs_len();
    SEARCH_HEADER_END(req, TRANSFER_ENCODING, 25)
  }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
  cts ".*\nAccept-Encoding:" ignore_case : {
      if(($ + 1) < $+)
      {
          if(*($):16 == 0x0d0a)
          {
              if(eencoding == 1)
              {
                  eval("http-req-cve-2013-1305",TRUE);
              }
          }
      }
      eencoding = 1;
  }
#endif

  cts ".*User-Agent: MSRPC" ignore_case : {
        if ($appid != 792) {
               setapp "rpc-over-http";
        }
   }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    cts ".*\nCookie: OvJavaLocale=" ignore_case:
    {
        skip(5000,"\x0a 3b 3d\x");
        if($? == 0)
        {
            eval("http-req-hp-openview-long-javalocalecookien",TRUE);
        }

    }
    cts ".*\nMime-Version:"ignore_case:
    {
        skip(250,"\x0d 0a 3a\x");
        if($? == 0)
        {
            eval("http-req-mime-long-mime-version",TRUE);
        }
    }
#endif

  cts ".*pdbox\.co\.kr" :{
      if((used_as_flag & 0x10) || (*($ - 15):32 == 0x6164762e )){
        eval("http-req-pdbox-adv",FALSE);
      }
      else{
        eval("http-req-pdbox-adv",TRUE);
      }
  }


  cts ".*:80\r" : {
	/**********************************************
	 * For xunlei it will be something like:
	 * POST / HTTP/1.1\r\nHost: 123.129.242.xxx:80
	 * POST / HTTP/1.1\r\nHost: 58.254.134.xxx:80
	 * POST / HTTP/1.1\r\nHost: 61.147.81.58:80
	 *********************************************/
	 if (req_hdr_type == HOST) {
		 if (rsp_code == 1){
			if ($pktlen < 350) {
				hash_find($saddr,XUNLEI,tmp,tmp2);
				if (tmp == XUNLEI){
					setapp "xunlei";
					exit();
				}
			}
		}
	}
  }


  cts ".*Host:" ignore_case : {
    /******************************************************************
    * add by sunon.zealot in 3/27/2014
    * char "\n" in pattern ".*\nHost:" may be absorbed by last state, then this condition will be false.
    * change ".*\nHost:" to ".*Host:" and add another condition (*($ - 7):16 ==0x0d0a)
    ********************************************************************/
    if (*($ - 7):16 ==0x0d0a)
    {
    /* Add the code to check xunlei through http.*/
    if ($ == 22) {
		if (http_method == POST){
			rsp_code = 1;
		}
    }


       /*add for netflix-streaming traffic
       * Range: bytes=5064259-
       * Host: 37.77.191.130
       */

       if (*($ - 8):16 == 0x2d0d){
	       eval("http-req-netflixstreaming", 1);
       }


    get_other_hdrs_len();

    /*
     * special case for host-header, will remove it later for 2.0 when everyone using qualifier
     */
    FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-host-header", http_method, ANY);


   if (skip_search_engine != 1) {
	eval("http-req-host-header-xss", 1);
   }

    /** zealot add */
    field_flag(DATA_CACHE);
    field_host_header_is_begin = 1;

    if (pktnum == 1) {
	    /* check if host name is IP based: checks if first five bytes are in  *
         * range 0x20 - 0x3F. It includes hyphen(-), but it is good enough.   */
	    while ( *($):8 == 0x20){
		    skip(1);
	    }
        if ( ($ + 5) <= $+ ) {
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    if(http_method == OPTIONS)
    {
        if(*($):32 == 0x3137322e) //172.
        {
            if(($daddr >> 24) != 172)
            {
                eval("http-req-suspicious-webdav-options-request",1);
            }
        }
    }
#endif
	        if(( *($):8 ^ 0x30)  <= 9) {
    		    if (( *($ + 1):32 & 0xC0C0C0C0) == 0) {
	    	        http_used_as_flag |= 4;  //use the 3rd bit of http_used_as_flag to mark IP based host name.
		        }
            }
        }
    }
    /* for < engine version < 2.0 */
    #if (PAN_ENGINE_VERSION <= (PAN_VERSION(2,0,11,7)))
      skip(1);
      while (*($ - 1):8 == 0x20) {
        FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-host-header", http_method, ANY);
        /** zealot add */
        field_flag(DATA_CACHE);
        field_host_header_is_begin = 1;

        skip(1);
      }
    #endif
    field_flag(URL_FILTER_HOST);
    req_hdr_init(HOST);
    tmp2 = $;
	tmp = 0;
	if( $+ >= $ + 1){
		tmp = *$:8;
	}
    #if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,1,0,0)))
	if ($ipv6 == 1 && tmp && tmp != 0x5b) {
		while (*($):8 != 0x3a && (*($):8 != 0x0a)){
			if ($ - tmp2 >= 80) {
				break;
			}
			skip(1);
			if($+ <= $){
				break;
			}
		}
		if ($+ > $) {
			if (*($):8 == 0x3a){
				field_end();
				FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-host-header", http_method, ANY);
			}else if((*($ - 1):8 != 0xa)){
				if ($ - tmp2 >= 80) {
					eval("http-req-error-code", OVERLY_LONG_HOST_HEADER);
					skip(175, "\x0a\x");
					if($? == 0)
					{
						eval("http-req-cve-2008-4562", TRUE);
					}
				}else{
					skip((80-($ - tmp2)), "\x 0a \x");
					if($? == 0)
					{
						eval("http-req-error-code", OVERLY_LONG_HOST_HEADER);
						skip(175, "\x0a\x");
						if($? == 0)
						{
							eval("http-req-cve-2008-4562", TRUE);
						}
					}
				}
			}
		}
	} else {
    #endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
        lastSkipStart = $;
        skip(80, "\x 2e 0a\x");
            if($? == 0)
            {
                noNewLine = 1;
                noDot = 1;
            }
            else
            {
                if(*($ - 1):8 == 0xa)
                {
                    noDot =1;
                }
                else
                {
                    skip((80 - ($ - lastSkipStart)), "\x 0a \x");
                        if($? == 0)
                        {
                            noNewLine = 1;
                        }
                }
            }
            if(noDot == 1)
            {
                eval("http-req-header-no-dot-in-hostname", 1);
                noDot = 0;
            }
            if(noNewLine == 1)
            {
                eval("http-req-error-code", OVERLY_LONG_HOST_HEADER);
                skip(175, "\x0a\x");
                    if($? == 0)
                    {
                        eval("http-req-cve-2008-4562", TRUE);
                    }
                noNewLine = 0;
            }
#else
        skip(80, "\x 0a \x");
               if($? == 0)
               {
                       eval("http-req-error-code", OVERLY_LONG_HOST_HEADER);
                       skip(175, "\x0a\x");
                       if($? == 0)
                       {
                               eval("http-req-cve-2008-4562", TRUE);
                       }
               }
#endif
    #if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,1,0,0)))
	}
    #endif
    found_hdr_end = TRUE;
    req_hdr_end();
    //SEARCH_HEADER_END_FLAG(req, HOST, 80, URL_FILTER_HOST)
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    if (pktnum == 1) {
        host4bytes = *($ - 8):32;
    }

    found_host = 1;
#endif
  } // zealot end cts ".*Host:"
}

#define h1 host4bytes
#define h2 other_hdrs_len
  CHECK_COMMON_SHORT_HOST()
#undef h1
#undef h2

    cts ".*\nUser-Agent: " ignore_case :
	{
        field_begin("http-req-user-agent");
        field_flag(DATA_CACHE);
		skip(4,"\x0a 0d\x");
		if($?)
		{
			eval("http-req-user-agent-first-4bytes",*($ - 5):32);
		}
		else
		{
			eval("http-req-user-agent-first-4bytes",*($ - 4):32);

                        /*detect Java Client, if user-agent is Java, set the bit 3 of 'used_for_zip_threat2' to 1.*/
                        if (*($ - 4):32 == 0x4a617661)
                        {
                            used_for_zip_threat2 |= 8;
                        }
                        else if (*($ - 4):32 == 0x75436c6f)
                        {
                            flag |= 0x01;
                        }
                }
        skip(136, "\x0a 0d\x");
        field_end();
        HTTP_REQ_USER_AGENT_PROCESS_FUNC("http-req-user-agent");
  }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(6,0,0,1)))
   cts ".*\nOrigin:" ignore_case: {
      printf(&"[HTTP] Translation Filtering chrome Origin type hit\n");
      field_end();
      FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-headers", http_method, req_hdr_type);
      field_flag(GRP_HTTP_ORIGIN);
      skip(255,"\x0a\x");
      field_end();
      FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-headers", http_method, req_hdr_type);
   }
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
  cts ".*\x20 09 09\xUser-Agent:" ignore_case: {
  	hash_find($saddr+$sport,$sport,tmp,tmp2);
	if (tmp == CONNECT443){
		setapp "ultrasurf";
		exit();
	}
  }
#endif

  /* This is a special case header, as we want to check not only
     end of header, but also if comma and semi-colon characters
     are not found. Hence we shall not use the template */

  cts ".*\nAccept-Language:" ignore_case : {
    get_other_hdrs_len();
    req_hdr_init(ACCEPT_LANGUAGE);

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
#define comma_cnt tmp
    comma_cnt = 0;
    do {
      skip(50,"\x0a 2c\x");
      found_hdr_end = $?;
      if (found_hdr_end) {
    if (*($ - 1):8 == 0x0a) {
      break;
    }
    else {
      comma_cnt ++;
      eval("http-req-accept-language-comma-cnt", comma_cnt);
    }
    found_hdr_end = FALSE;
      }
      else {
    if (comma_cnt == 0) {
      break;
    }
      }
    } while (found_hdr_end == FALSE);
#undef comma_cnt
#elif (PAN_ENGINE_VERSION >= (PAN_VERSION(2,0,11,4)) && PAN_ENGINE_VERSION < (PAN_VERSION(2,1,0,8)))
    skip(50, "\x0a 2c\x");
    found_hdr_end = $?;
#else
    do {
      skip(1);
      hdr_char = *($ - 1):8;
      if (hdr_char == 0x0a || hdr_char == 0x2c) {
    found_hdr_end = TRUE;
    break;
      }
    } while($ - req_hdr_len <= 50);
#endif

    if (found_hdr_end == FALSE) {
      eval("http-req-hdr-accept-Language-too-long", TRUE);
    }
    req_hdr_type = UNKNOWN_HDR;
    req_hdr_len = 0;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    /* Fixed a potential False Positive here, because we need set other_hdrs_len to current offset */
    other_hdrs_len = $;
#endif
  }

  cts ".*\n(NT|SID|CALLBACK|TIMEOUT):" ignore_case : {
    get_other_hdrs_len();
    SEARCH_HEADER_END(req, SUBSCRIBE_HDR, 128)
  }

  cts ".*\nIf-Modified-Since:" ignore_case : {
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    get_other_hdrs_len();
    req_hdr_init(IF_MOD_SINCE);
    skip(196,"\x0a\x");
    found_hdr_end = $?;
    if (found_hdr_end) {
      if ($ - req_hdr_len < 84) {
	if (*($ - 4):32 & 0x80808080 || *($ - 8):32 & 0x80808080) {
	  if ($ + 4 <= $+) {
	    if (*($):32 == 0x436f6e6e) {
	      eval("http-req-hdr-CVE-2007-5067-found", TRUE);
	    }
	  }
	}
      }
    }
    req_hdr_end();
#else
    get_other_hdrs_len();
    SEARCH_HEADER_END(req, IF_MOD_SINCE, 196)
#endif
  }
    cts ".*\nReferer: " ignore_case :
    {
        get_other_hdrs_len();
#if (PAN_ENGINE_VERSION < (PAN_VERSION(4,0,0,0)))
        SEARCH_HEADER_END(req, REFERER, 128)
#else
        req_hdr_init(REFERER);
        tmp2 = 0;
        do
        {
            skip(1);
            hdr_char = *($ - 1):8;
            if(hdr_char == 0x0a)
            {
                 break;
            }
            else if(hdr_char == 0x2c) //',' Referer: ver=1,p=2,a=1
            {
                break;
            }
            else if(hdr_char == 0x2e) //'.' qzoneclientphoto.qq.com
            {
                break;
            }
            else if(hdr_char == 0x2f) //'/' http://www.google.com
            {
                break;
            }
            else if(hdr_char == 0x20) //' '
            {
                break;
            }
            else if(hdr_char == 0x09) //'\t'
            {
                break;
            }
            else if(hdr_char == 0x3a) //':' about:blank
            {
                break;
            }
            tmp2++;
        } while(tmp2 < 20);

        if((hdr_char == 0x0a) || (tmp2 == 20))
        {
            eval("http-req-dirt-jumper-dos-non-standard-ref-hdr",1);
            found_hdr_end = 1;
        }
        else
        {
            if((hdr_char == 0x20) || (hdr_char == 0x09))
            {
                if(tmp2 > 2)
                {
                    eval("http-req-dirt-jumper-dos-non-standard-ref-hdr",1);
                }
            }
            skip(108, "\x 0a \x");
            found_hdr_end = $?;
        }
        req_hdr_end();
#endif
    }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,0,0,4)))
  cts ".*\nX-Forwarded-For:" ignore_case : {
    get_other_hdrs_len();
    req_hdr_init(X_FORWARD_FOR);
    /** zealot add */
    field_begin("http-req-x-forwarded-for");
    field_flag(DATA_CACHE);
    field_http_req_x_forwarded_for_is_begin = 1;
      //field_flag(URL_X_FORWARD);

    /* looking for \n or "," */
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    skip(128, "\x 0a\x");
#else
    skip(128, "\x 0a 2c \x");
#endif
    found_hdr_end = $?;
    req_hdr_end();
  }
#endif


#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,0,0,0)))
  cts ".*\nProxy-Authorization: " ignore_case : {
    if (ntlm_ssp_flag & 1) {
      if (*($):32 == 0x4e544c6d) {
    eval("http-req-squid-proxy-auth-dos", TRUE);
      }
    }
    else {
      if (*($):32 == 0x4e544c4d) {
    ntlm_ssp_flag |= 1;
      }
    }
  }
#endif

  /*
  cts ".*\nx-Spirent-Id:" : {
        setapp "spirent";
      //suspend(RSP);
  }
  */
  cts ".*chunked" ignore_case : {
    if (req_hdr_type == TRANSFER_ENCODING) {
      panav_trans_encoding = CHUNKED;
      eval("http-req-transfer-encoding", CHUNKED);
      if (post_content_type == URI_PARAMS) {
	eval("http-req-chunked-uri-params", 1);
      }
    }
  }

  cts ".*x-www-form-urlencoded" ignore_case : {
    if (req_hdr_type == CONTENT_TYPE) {
      if (http_method == POST) {
    post_content_type = URI_PARAMS;
    eval("http-req-post-content-type", URI_PARAMS);
      }
    }
  }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
  cts ".*x-flash-version: " ignore_case : {
    flag |= 0x01;
  }

  cts ".*filehash: " ignore_case : {
    flag |= 0x01;
  }

/*Bug 59617 for dropbox in Chrome*/
  cts ".*Origin: https://www\.dropbox\.com" ignore_case : {
    flag |= 0x01;
    if(flag & 0x08)
    {
        post_content_type = APP_STREAM;
    }
  }

    cts ".*Wlc-Offset: 0\r\n" ignore_case:
    {
        flag |= 0x01;
        post_content_type = APP_STREAM;
    }
  cts ".*Box-Obj-Filename: " ignore_case : {
  	  req_hdr_type = UNKNOWN_HDR;
	  FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-headers", http_method, req_hdr_type);
      skip(128,"\x0a 0d\x");
      field_flag(FILENAME);
      print("-->http 9\n");
      field_end();
	  FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-headers", http_method, req_hdr_type);
      flag |= 0x01;
      post_content_type = APP_STREAM;
  }

  cts ".*((\nx-file-name: )|(\nx-filename: ))" ignore_case:{
  	  req_hdr_type = UNKNOWN_HDR;
	  FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-headers", http_method, req_hdr_type);
      skip(128,"\x0a 0d\x");
      field_flag(FILENAME);
      print("-->http 10\n");
      field_end();
	  FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-headers", http_method, req_hdr_type);
      flag |= 0x01;
      post_content_type = APP_STREAM;
  }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
  cts ".*\nfileName: " : {
    req_hdr_type = UNKNOWN_HDR;
    FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-headers", http_method, req_hdr_type);
    skip(128,"\x0a 0d\x");
    field_flag(FILENAME);
      print("-->http 11\n");
    field_end();
    FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-headers", http_method, req_hdr_type);
    if (flag & 0x04) {
      post_content_type = APP_STREAM;
    }
    else {
      flag |= 0x04;
    }
  }
#endif

  cts ".*(\nX-RequestStats: upType=h5|\nX-RequestStats: upType=sl)" ignore_case :{
      post_content_type = APP_STREAM;
  }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
  cts ".*\nfileSize: " ignore_case : {
    if (http_method == POST) {
      if (flag & 0x04) {
	post_content_type = APP_STREAM;
      }
      else {
	flag |= 0x04;
      }
    }
  }
#endif

    cts ".*application/octet-stream" ignore_case :
    {
        if (req_hdr_type == CONTENT_TYPE)
        {
            if (http_method == POST)
            {
                flag |= 0x08; // set application/octet-stream encontered during content post flag
                if ((flag & 0x01) || (flag & 0x02))
                {
                    post_content_type = APP_STREAM;
                }
            }
        }
    }
#endif

    cts ".*\.projectplace\.com" ignore_case:
    {
        if(req_hdr_type == HOST)
        {
            flag |= 1;
        }
    }
    cts ".*\nContent-Encoding:" ignore_case :
    {
        get_other_hdrs_len();
        SEARCH_HEADER_END(req, CONTENT_ENCODING, 25)
    }
    cts ".*gzip" ignore_case :
    {
        if (req_hdr_type == CONTENT_ENCODING)
        {
            panav_body_encoding = GZIP_ENCODING;
        }
    }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    cts ".*\nX-HTTP-Method-Override: " ignore_case :
    {
        skip(3,"\x0a\x");
        if(*($ - 3):24 == 0x505554)
        {
            http_method=PUT;
        }
    }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
  cts ".*x-vermeer-urlencoded" ignore_case : {
      if (req_hdr_type == CONTENT_TYPE) {
        if (http_method == POST) {
            post_content_type = VERMEER_URLENCODED;
        }
       }
  }

  cts ".*User-Agent: Microsoft\.Live\.SkyDrive\.RichUpload" : {
    if (http_method == POST) {
        /* no content type is present in this format */
           post_content_type = APP_STREAM;
    }
  }

	cts ".*NMCanaveral":
	{
		hash_add($saddr,$daddr,PROPALMS,600);
		printf(&"propalms' hash found");
		setapp "propalms";

	}

    cts ".*boundary=" ignore_case:
    {
        if(post_content_type == MIME)
        {
	  skip (1);
	  if (*($ - 1):8 == 0x22) {
	    skip (1);
	  }
	  if (*($ - 1):8 == 0x2d) {
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
	    tmp2 = $;
#endif
	    skip(70,"\x0d 0a 22\x"); /* This would overwrite prev trigger of content-type */
	    if($?)
	      {
		MIME_Boundry_Last4bytes = *($ - 5):32;
	      }
	    skip(4010, "\x0a\x"); /* This would overwrite the content-type skip */
	    if ($? == 0) {
	      eval("http-req-large-formdata-boundary", 1);
	    }
	  }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
	  else {
            tmp2 = $;
	    skip(4080, "\x0a\x"); /* This would overwrite the content-type skip */
	    if ($? == 0) {
	      eval("http-req-large-formdata-boundary", 1);
	    }
	  }
	  if ($ - tmp2 < 128) {
	    skip(128 - ($ - tmp2), "\x0a\x"); /* The search limit is 128 for content-type header */
	  }
	  found_hdr_end = $?;
	  req_hdr_end();
#endif
        }
    }
#endif


  cts ".*((part/form-data)|(part/Related))" ignore_case : {
    if (req_hdr_type == CONTENT_TYPE) {
      if (http_method == POST) {
        post_content_type = MIME;
    field_begin("http-rsp-body-start");
    eval("http-req-mime-start-location", 1);
    HTTP_FILE_INFO_FUNC("http-req-mime-start-location");
    field_end();
      }
    }
  }

  cts ".*/vnd\.wap\.mms-message" ignore_case : {
    if (req_hdr_type == CONTENT_TYPE) {
      if (http_method == POST) {
        post_content_type = MMS;
      }
    }
  }

  cts ".*\x30 3a 20 76 76 76 76 0d 0a 41 41 41\x" : {
     if(content_len == 21212)
     {
       eval("http-req-coreimpact-CVE-2007-4727", 1);
     }
  }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    cts ".*nection:%" ignore_case:
    {
        skip(50,"\x0a 0d\x");
        if($?)
        {
            if(*($ - 4):24 == 0x24686e)
            {
                eval("http-req-breakpoint-CVE-2007-6682", 1);
            }
        }
    }
#endif

/** zealot add */
  cts ".*cdn-src-ip:" ignore_case:
  {
    field_begin("http-req-cdn-src-ip");
    field_flag(DATA_CACHE);
    field_cdn_src_ip_is_begin = 1;
  }

  cts ".*\n" ignore_case:
  {
    //add if below for sql injection check
    if(1 == field_full_cookie_is_begin)
    {
      field_end();
      field_full_cookie_is_begin = 0;
    }

    //add if below for brut-force attack check
    if(1 == field_auth_user_is_begin)
    {
      field_end();
      field_auth_user_is_begin = 0;
      BRUT_FORCE_ATTACK_CHECK("http-req-auth-user");
    }

    if(1 == field_cdn_src_ip_is_begin)
    {
      field_end();
      field_cdn_src_ip_is_begin = 0;
      HTTP_CDN_IP_PROCESS_FUNC("http-req-cdn-src-ip");
    }

    if (1 == field_http_req_x_forwarded_for_is_begin)
    {
      field_end();
      field_http_req_x_forwarded_for_is_begin = 0;
      HTTP_X_FORWARDED_FOR_PROCESS_FUNC("http-req-x-forwarded-for");
    }
  }
/** zealot end */


  cts ".*(\r\n\r\n|\n\n)" : {
/* Identify app psiphon*/
    if ($ == 19 && http_method == POST) {
        if (pktnum == 1 && $dport != 80 && $dport != 8080 && $pktlen > 31) {
            if (*$:32 & 0x80808080 != 0 || *($ + 4):32 & 0x80808080 != 0 || *($ + 8):32 & 0x80808080 != 0) {
                setapp "psiphon";
                exit();
            }
        }
    }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(6,0,0,0)))
    /*variables used for safe search feature - YZ*/
	if (google_p > 1){
     eval("http-req-google-1", google_p);
     eval("http-req-google-2", google_n);
	}
    else if (bing_p > 1){

    printf(&"[YANG] EVL BING\n");
     eval("http-req-bing-1", bing_p);
     eval("http-req-bing-2", bing_n);
	}
    else if (yahoo_p > 1){
	 eval("http-req-yahoo-1", yahoo_p);
    }
	else if (youtube_p > 1){
	 eval("http-req-youtube-1", youtube_p);
    }
#endif


#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    if(*($ - 4):32 == 0x0d0a0d0a){
      if(($ + 6) < $+) {
	 	if (*$:16 == 0x0100){
          if (rsp_code == 2){
            if ($pktlen < 250) {
               if ((*($ + 2):32) & 0x00ffffff == 0){
                   hash_find($saddr,KUGOO,tmp,tmp2);
                   if (tmp == KUGOO){
                        setapp "kugoo";
                        exit();
                    }
                }
             }
          }
	    }
     }
   }
#endif


    get_other_hdrs_len();
    printf(&"[HTTP] End request headers\n");
    if(validation_flag & 1)
    {
        validation_flag |= 0x80;
    }
    else
    {
        validation_flag |= 0x2;
    }
    if (http_method == POST) {
      if (found_content_len == FALSE) {
    eval("http-req-error-code", POST_CONTENT_LENGTH_NOT_FOUND);
      }
    }
    if(found_content_len == FALSE && panav_trans_encoding == CHUNKED){
      if(http_method == GET){
         eval("http-req-CVE-2002-0386-found", 1);
      }
    }
    field_end();
    /* a fake field to mark the URL filter ended */
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,0,0,15)))
    if (found_host == 0 && http_proxy == 0)
#else
    if (found_host == 0 )
#endif
    {
        FIELD_BEGIN_IGNORE_CASE("http-req-uri-filter-end");
        eval("http-req-no-host-in-header",TRUE);
        field_flag(URL_FILTER_HOST);
        field_end();
    }
    goto req_message_body;
  }
  if(http_method == PROPFIND || http_method == PROPPATCH){
  	cts ".*loot SYSTEM .file:" : {
		eval("http-req-cve-2015-1833",1);
	}
  }
  cts end: {
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    if(*($ - 1):8 == 0x0a)
    {
        if(found_content_len == 1)
        {
            if(panav_content_len > 0)
            {
                eval("http-req-no-terminate-str-after-content-length",TRUE);
            }
        }
    }
#endif
    eval( "http-req-header-too-long", $ - req_hdrs_start);

    if ((validation_flag & 0x81) == 0) {
        if ($ - req_hdrs_start > MAX_HEADER_LEN) {
            switch_reason = REQ_LONG_HEADER;
            SWITCH_FROM_HTTP
        }
      }
  }

  sub req_hdr_init (field_val) {
    req_hdr_len = $;
    printf(&"[HTTP] Header len %d\n", req_hdr_len);
    req_hdr_type = field_val;
    eval("http-req-header-type", req_hdr_type);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,0,11,4)))
    if (field_val != HOST) {
      FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-headers", http_method, req_hdr_type);
    }
#endif
    found_hdr_end = FALSE;
    offset = $;
    return 0;
  }

  sub req_hdr_end() {
      if (found_hdr_end == TRUE) {
          if (req_hdr_len <= $) {
              req_hdr_len = $ - req_hdr_len;
          }
      EVAL_QUALIFIER("http-req-header-length", req_hdr_len, http_method, req_hdr_type, ANY, ANY );
          printf(&"[HTTP] Header length = %d(0x%x)\n", req_hdr_len, req_hdr_len);
      }
      else {
          printf(&"[HTTP] Could not find end of header within given limit\n");
          eval("http-req-error-code", MALFORMED_HEADER_VALUE);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
          EVAL_QUALIFIER("http-req-error-code2", MALFORMED_HEADER_VALUE,req_hdr_type,ANY,ANY,ANY);
#endif
      }
      /*  added by sunon.zealot for host length althougth you can use http-req-header-length with qualifier  **/
      /*  but there is no qualifier in web site now in 2014/3/5                                       **/
      if(1 == field_host_header_is_begin )
      {
        eval("http-req-host-header-length", (req_hdr_len - 1 -1));
      }
      /*  end**/
      req_hdr_len = 0;
      other_hdrs_len = $;
      field_end();

      if(1 == field_host_header_is_begin)
      {
        //add zealot code below for transfer http host to the outside
        HTTP_HOST_PROCESS_FUNC("http-req-host-header");
        field_host_header_is_begin = 0;
      }

      req_hdr_type = UNKNOWN_HDR;
      FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-headers", http_method, req_hdr_type);
      return 0;
  }

  sub get_other_hdrs_len() {
    if ($ >= other_hdrs_len) {
      other_hdrs_len = $ - other_hdrs_len;
      printf(&"[HTTP] Other unparsed headers total length is %d\n", other_hdrs_len);
      eval("http-req-other-headers-total-length", other_hdrs_len);
    }
    return 0;
  }
}

/*
 *    Request message body
 *
 */
state req_message_body
{
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    unsigned last_param_offset:32;
#endif
    unsigned tmp:16;
    unsigned tmp2:16;

    SWITCH_STATE(stc, req_message_body) ;

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    unsigned offset:16;
    unsigned net_hash_count:16;
    unsigned iis_repeat_count:8;
    /* The first 4 bytes of message should not be binary.*/
    offset = $;
    if ((evasive&2) == 2) {
        if (*($):32&0x80808080) {
            evasive = 0;
        }
    }
    net_hash_count = 0;
    last_param_offset = 0;
    iis_repeat_count = 0;
#endif
/*
added by wangshiyou for flash 0day, 2015.07.09
*/
   if(flash_search_engine == 1){
      eval("http-req-flash-0day",1);
   }

  printf(&"[HTTP] Begin request message body\n");

  if (panav_trans_encoding == CHUNKED) {
    FIELD_BEGIN_IGNORE_CASE("http-req-chunk-body");
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    if ((post_content_type == URI_PARAMS) || (post_content_type == MIME))
    {
        validation_flag |= 0x80; /* set this flag, then on http side it will not do validation */
        field_flag(CHUNK);
        field_end();
        panav_content_len = 0x7fffffff;
        save_state(http_init);
        panav_trans_encoding = LENGTH;
        if(post_content_type == URI_PARAMS)
        {
            jump req_uri_params;
        }
        else
        {
            jump req_mime_body;
        }
    }
#endif
    goto panav_init_state;
  }

  if (post_content_type == URI_PARAMS) {
    if(((used_as_flag & 2) == 2) || (panav_content_len > 0)){ /* the second bit of used_as_flag will be removed when found "content-length" */
        if(panav_body_encoding == GZIP_ENCODING)
        {
            if((panav_content_len > 3) && ($ + 3 < $+))
            {
                if((*($):32 & 0xfffffff0) != 0x1f8b0800)
                {
                    eval("http-req-non-valid-gzipi-encoding-data",1);
                }
            }
        }
    goto req_uri_params;
    }
  }

  if (post_content_type == MIME) {
    goto req_mime_body;
  }

  if (post_content_type == VERMEER_URLENCODED) {
          goto req_vermeer_body;
  }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
  if ((post_content_type == APP_STREAM) && (panav_content_len > 8)) {
        goto panav_init_state;
  }
  //zealot修改，20131112
  //修改原因：由于yahoo message 传输文件，无法通过请求头部识别post_content_type
  //所以无法对req_message_body进行识别，无法跳转到panav_init_state中执行，
  //因此添加下面代码进行修改
  if ((post_content_type == UNKNOWN_REQ_CONTENT) && (panav_content_len > 8)) {
        goto panav_init_state;
  }

#endif
  cts ".*\xc4 2a 02 75\x" : {
    if(*($ - 6):16 == 0xeb18) {
      eval("http-req-retaddr", HP_POWER_MGR_RETADDR);
    }
  }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
	/* There are at least 2  "==|" happened in the response body.
	 * the offset gap between them is always 345.
	 * We also check the 4 bytes before it are ascii ones.
	 */
	cts ".*\x3d 3d 7c\x":
	{
    /** zealot modify */
		if (((*($ - 7):32) & 0x80808080) == 0){
			if ((evasive&6) == 6){
				if ($ - offset == 345) {
					setapp "scotty";
					exit();
				}
			}else if ((evasive&2) == 2) {
				if ($ - offset == 345){
					offset = $;
					evasive |= 4;
				}
			}
		}
	}
	cts ".*sel=" : {
	    skip(50, "\x25 26\x");
	    if ($?) {
		if (*($ - 1):8 == 0x25) {
		    if ($+ > $ + 1) {
			if (*($):8 == 0x6e) {
			    eval("http-req-sel-param-format-string", 1);
			}
		    }
		}
	    }
	    else {
		skip(512, "\x26 0a\x");
		if ($? == 0) {
		    eval("http-req-sel-param-overflow", 1);
		}
	    }
	    if ($ > offset) {
		if (panav_content_len > $ - offset) {
		    ignore (panav_content_len - ($ - offset));
		}
	    }
	}

    cts ".*&":
    {
        if(*($ - 5):8 == 0x26)
        {
            if(http_method == HEAD)
            {
                iis_repeat_count++;
                if(iis_repeat_count > 0x60)
                {
                    eval("http-req-CVE-2010-1899",1);
                    iis_repeat_count = 0;
                }
            }
        }

        if(*($ - 2):8 == 0x3d) //'='
        {
            if(last_param_offset != 0xffffffff)
            {
                if(last_param_offset)
                {
                    if(($ - last_param_offset) < 40)
                    {
                        net_hash_count++;
                        if(net_hash_count > 0x50)
                        {
                            eval("http-req-CVE-2011-4858-found",1);
                            net_hash_count = 0;
                        }
                    }
                }
                last_param_offset = $;
            }
        }
        else
        {
            last_param_offset = 0xffffffff;
        }

    }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
    cts ".*&tree=" ignore_case:
	{
	    skip (200, "\x26 0a\x");
	    if ($? == 0) {
		eval("http-req-long-tree-param-in-msgbody", 1);
	    }
	    if ($ > offset) {
                if (panav_content_len > $ - offset) {
                    ignore (panav_content_len - ($ - offset));
		}
            }
	}
    cts ".*(&|\n)Login=" ignore_case:
        {
            skip (200, "\x26 0a\x");
            if ($? == 0) {
                eval("http-req-long-login-param-in-msgbody", 1);
            }
            if ($ > offset) {
                if (panav_content_len > $ - offset) {
                    ignore (panav_content_len - ($ - offset));
                }
            }
        }
#endif

  if (post_content_type == MMS) {
    FIELD_BEGIN_IGNORE_CASE("http-req-mms-message-body");
  }
  else {
    FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-message-body", http_method, ANY);
  }
  if ((http_method == PUT) && (panav_content_len > 8))
  {
    goto panav_init_state;
  }
  if ( panav_content_len == 31){
      if ((*($):32 == 0x4a4e5450) && (*($ + 6):16) == 0){
          eval("http-req-jntp-seen", 1);
      }
  }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,0,0,14)))
  if( (http_method == POST) && (post_content_type == UNKNOWN_REQ_CONTENT))
  {
     if ($ + 10 < $+)
     {
        if (*($ + 2):32 != 0)
        {
            hash_find($saddr, *($ + 3):32, tmp, tmp2);
            if($? == 1 && (*($ + 9):16 != 0))
            {
                if(tmp == *($ + 9):16)
                    eval("http-req-zbot-found", 1);
            }
        }
     }
     if($ + 0x48 < $+ )
     {
        if(*($ + 16):32 == 0x636f7265)
        {
            if(*($ + 20):32 == 0x5f636861 && *($ + 24):32 == 0x6e6e656c && *($ + 28):32 == 0x5f777269)
            {
                if(*($ + 56):32 == 0x6963726f && *($ + 60):32 == 0x736f6674 && *($ + 64):32 == 0x2057696e)
                    eval("http-req-found-shell-access-command", 1);
            }
        }
     }
  }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
  if ($dport == 808) {
    if (http_method == GET) {
      if (*($):32 == 0x45494450) {
	if ($ + 24 < $+) {
	  if (*($ + 20):32:swap > 0x7fffffff) {
	    eval("http-req-scada-progea-overflow", 1);
	  }
	}
      }
    }
  }
  if (panav_content_len > 3000) {
      skip (3000);
      ignore(panav_content_len - 3000);
  }
  else {
      skip(panav_content_len);
  }
#else
  /** zealot modify: ignore(0) will lead engine to hang up, need to justify it*/
  if(panav_content_len > 0)
  {
    ignore(panav_content_len);
  }
#endif
    eval("http-req-content-length",panav_content_len);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,4)))
    field_flag(DLP);
#endif
  // end_req_message_body();
  //validation_flag &= 0xfd;
  /** zealot modify */
  goto init;
}


#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
state req_vermeer_body {

  unsigned req_vermeer_start:32;
  unsigned tmp:8;
  unsigned found:8;


  printf(&"[HTTP] Begin request message VERMEER body\n");

  req_vermeer_start = $;

  cts ".*document=%5bdocument%5fname%3d" : {
    field_begin("http-req-vermeer-file",ignore_case);
    field_flag(FILENAME);
      print("-->http 12\n");

    found = 0;

    do {
        skip(1);
        tmp = *($):8;
        if (tmp == 0x25) {
            skip(1);
            tmp = *($):8;
            if (tmp == 0x33) {
                skip(1);
                tmp = *($):8;
                if (tmp == 0x62) {
                    field_end();
                    found = 1;
                }
            }
        }
      } while ((found == 0) && (tmp != 0x0a));

      if (tmp != 0x0a) {
            skip(panav_content_len, "\x0a\x");
    }

      if ((tmp == 0x0a) || ($? == 1)) {
        if (found == 0) {
            field_end();
        }
        panav_content_len -= ($ - req_vermeer_start);
        field_begin("http-req-vermeer-body",ignore_case);
        goto panav_init_state;
      } else {

          skip(panav_content_len);
          end_req_message_body();
      }
  }
}
#endif

state req_mime_body
{
  unsigned http_meet_content_dispositon:8;
  unsigned http_phpddos_counter:32;
  unsigned fld_len:32;
  unsigned req_mime_start:32;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    unsigned variable_count:16;
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    unsigned form_data_indicator:8;
#endif
  unsigned mime_header_type:8;
  unsigned found_f_end:8;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    unsigned need_parse:8;
    unsigned detect_file_type:8;
#endif

  printf(&"[HTTP] Begin request message MIME body\n");

  req_mime_start = $;
  //panav_not_ignore = FALSE;
  mime_header_type = UNKNOWN;
  panav_content_type = UNKNOWN;

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    variable_count = 0;
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    need_parse = 0;
    detect_file_type = 0;
    panav_file_type = UNKNOWN;
#endif
  /* This is to distinguish when this state is entered after parsing
     some file format or after first time this state is entered */
    field_begin("http-req-mime-form-data");
    /* in HTTP 1.0, it allow post something without a length */
    if(panav_trans_encoding == LENGTH)
    {
        if((panav_content_len == 0) && (http_connection_closed == 1))
        {
            panav_content_len = 0x7fffffff;
            validation_flag |= 0x80; //don't do validation on this case
        }
    }

  if (panav_content_len != 0) {
    skip(panav_content_len);
  }
  end_req_message_body();
  cts ".*Content-Disposition: " ignore_case : {
    field_end();
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    need_parse = 0;
    detect_file_type = 0;
    panav_file_type = UNKNOWN;
#endif
    printf(&"[HTTP] End of form MIME field data\n");
    mime_header_type = CONTENT_DISPOSITION;
    field_begin("http-req-mime-form-data");
    http_meet_content_dispositon = 1;
  }
    // php multiple/form-data dos, added by wangshiyou
    cts ".*[^:]*\n|.*\n[ \t\v\f]" : {
	if (http_meet_content_dispositon == 1) {
		http_phpddos_counter++;
	}
	if ( http_phpddos_counter >= 10000) {
                eval("http-req-formdata-php-dos",1);
	}
    }
    cts ".*\n\n|.*\n\r\n" : {
	if ( http_meet_content_dispositon ==1) {
		http_phpddos_counter = 0;
	}
    }


  cts ".*\nContent-Type: " ignore_case : {
    if (mime_header_type == CONTENT_DISPOSITION) {
      field_end();
      mime_header_type = CONTENT_TYPE;
      field_begin("http-req-mime-content-type");
    }
  }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    cts ".*\nMime-Version:"ignore_case:
    {
        skip(250,"\x0d 0a 3a\x");
        if($? == 0)
        {
            eval("http-req-mime-long-mime-version",TRUE);
        }
    }
#endif
  cts ".* name=" ignore_case: {
      if (mime_header_type == CONTENT_DISPOSITION) {
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
          form_data_indicator = 0;
          if(*($ - 16):32 == 0x666F726D) //form-data;
          {
              if(*($ - 12):32 == 0x2D646174)
              {
                  if(*($ - 8):16 == 0x613b)
                  {
                      form_data_indicator = 1;
                  }
              }
          }
#endif
          fld_len = $;
#if (PAN_ENGINE_VERSION < (PAN_VERSION(2,1,0,8)))
          SEARCH_FLD_END(180, ';')
#else
          SEARCH_FLD_END(180, "\x0a 3b\x")
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
          if(form_data_indicator == 1 && *($ - 1):8 == 0x0a)
          {
              if($ + 5 <= $+)
              {
                  if(*$:32 == 0x0d0a0d0a) //Add count only if no data
                  {
                      if(*($ + 4):16 == 0x2d2d)
                      {
                          variable_count++;
                          if(variable_count >= 0x700)
                          {
                              eval("http-req-CVE-2011-3414-found",1);
                              variable_count = 0;
                          }
                      }
                  }
              }
          }
#endif
#endif
          if (found_f_end == FALSE) {
              eval("http-req-error-code", OVERLONG_mime_name);
          }
            if (panav_content_len > ($ - req_mime_start))
            {
                skip(panav_content_len - ($ - req_mime_start));
            }
            end_req_message_body();
      }

  }
  cts ".*(;| )filename=" ignore_case: {
      if (mime_header_type == CONTENT_DISPOSITION) {
         eval("http-req-file-upload-all", TRUE);
         printf(&"[HTTP] mime filename");
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,4)))
        field_end();
        field_begin("http-req-mime-form-data");
#endif
          fld_len = $;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
          need_parse = 1;
#endif
#if (PAN_ENGINE_VERSION < (PAN_VERSION(2,1,0,8)))
          SEARCH_FLD_END(250, ';')
#else
          detect_file_type = 1;
          skip(1);
          if(*($ - 1):8 == 0x22)
          {
            SEARCH_FLD_END(250, "\x0a 3b 22\x")
          }
          else
          {
            SEARCH_FLD_END(250, "\x0a 3b\x")
          }
          detect_file_type = 0;
#endif
          if (found_f_end == FALSE) {
              eval("http-req-error-code", OVERLONG_mime_filename);
          }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
          if((*($ - 1):8 == 0x22) || (*($ - 1):8 == 0x0a))
          {
              if(($ - fld_len) == 1) /* that means null file name */
              {
                  need_parse = 0;
              }
          }
          if(need_parse) {
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,4)))
    field_flag(FILENAME);
      print("-->http 13\n");
    field_end();
    field_begin("http-req-mime-form-data");
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
        }
        if (panav_content_len > ($ - req_mime_start))
        {
            skip(panav_content_len - ($ - req_mime_start));
        }
        end_req_message_body();
#endif
      }
  }
/*
 *  Looking for file type
 */

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    OFFICE_FILE_MATCH_DEFINE
#elif (PAN_ENGINE_VERSION >= (PAN_VERSION(2,0,11,4)))
    ".*\.doc(x|m)" ignore_case : {
      if (mime_header_type == CONTENT_DISPOSITION) {
        panav_file_type = DOCX;
      }
    }
    ".*\.ppt(x|m)" ignore_case : {
      if (mime_header_type == CONTENT_DISPOSITION) {
        panav_file_type = PPTX;
      }
    }
    ".*\.xls(x|m)" ignore_case : {
      if (mime_header_type == CONTENT_DISPOSITION) {
        panav_file_type = XLSX;
      }
    }
    ".*\.doc" ignore_case : {
      if (mime_header_type == CONTENT_DISPOSITION) {
        panav_file_type = DOC;
      }
    }
    ".*\.ppt" ignore_case : {
      if (mime_header_type == CONTENT_DISPOSITION) {
        panav_file_type = PPT;
      }
    }
    ".*\.xls" ignore_case : {
      if (mime_header_type == CONTENT_DISPOSITION) {
        panav_file_type = XLS;
      }
    }
    ".*\.apk" ignore_case : {
      if (mime_header_type == CONTENT_DISPOSITION) {
        panav_file_type = APK;
      }
    }
    ".*\.jar" ignore_case : {
      if (mime_header_type == CONTENT_DISPOSITION) {
        panav_file_type = JAR;
      }
    }
#endif
#if (PAN_ENGINE_VERSION < (PAN_VERSION(2,1,0,8)))
  /* .doc" */
  cts ".*\x 2e 64 6f 63\x" ignore_case : {
      if (mime_header_type == CONTENT_DISPOSITION) {
            eval("http-req-doc-file", 1);
      }
  }
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
  cts ".*\.mp3" ignore_case : {
    if(mime_header_type == CONTENT_DISPOSITION) {
      eval("http-req-mp3-ext-found", 1);
    }
  }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
  cts ".*\.bat" ignore_case : {
    if(mime_header_type == CONTENT_DISPOSITION) {
      eval("http-req-bat-ext-found", 1);
    }
  }
  cts ".*\.hta" ignore_case : {
    if(mime_header_type == CONTENT_DISPOSITION) {
      eval("http-req-hta-ext-found", 1);
    }
  }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
  cts ".*\.cmd" ignore_case : {
      if(mime_header_type == CONTENT_DISPOSITION) {
	  eval("http-req-cmd-ext-found", 1);
      }
  }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
  cts ".*\.php" ignore_case : {
      if(mime_header_type == CONTENT_DISPOSITION) {
          eval("http-req-php-ext-found", 1);
      }
  }
#endif
  cts ".*((\r\n\r\n)|(\n\n))" : {
    if (mime_header_type == CONTENT_TYPE) {
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    if(need_parse) {
#endif
        if (panav_content_len > ($ - req_mime_start))
        {
            panav_content_len -= $ - req_mime_start;
        }
      goto panav_init_state;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    }
#endif
    }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    need_parse = 0;
#endif
    DLP_MIME_FIELD_BEGIN
    if (panav_content_len > ($ - req_mime_start))
    {
        skip(panav_content_len - ($ - req_mime_start));
    }
     end_req_message_body();
    /* defiend in avinclude.h */
  }

  /* End of MIME form data
     FIXME: In some case, multiple files might be uploaded.
     In this case, there might be multiple such patterns.
     We need to appropriately do a field end */

  cts ".*\x2d 2d\x\r\n" : {
    field_end();
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    if($ ==  $+)
    {
        if(panav_content_len == ($ - req_mime_start))
        {
            goto init;
        }
    }
#endif
  }
}

state request_body_end
{
    field_end();

    /** zealot modify */
    if(post_content_type == URI_PARAMS && 1 == field_post_message_body_is_begin )
    {
      field_end();
      field_post_message_body_is_begin = 0;
    }
    goto init;
}

/****************************
 *      Response States     *
 ***************************/

state rsp_init
{
  unsigned rspstart:32;
  unsigned rsplen:32;
  unsigned tmp:8;
  unsigned tmp2:8;

  /*zealot add*/
  convert_count = 0;

  packet_status &= 0xd; // clear HTTP 206 GET flag


#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
  if($appid == 1532){
    if($ignore_s2c == 1){
      suspend(RSP);
      goto init;
    }
  }
#endif

  SWITCH_STATE(cts, rsp_init)
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    validation_flag &= 0xbf; //clear 7th bit
#endif
  if (evasive == 1) {
      rsp_pktnum = 0;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
      loic_count |= 0x80; /* set flag on highest bit */
#endif
      goto http_evasive_rsp_state;
  }

/* if previous response code was not 200
       we need to relax the validations */
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
   if ((validation_flag & 0x04) != 0) {
           validation_flag &= 0xfb;
        validation_flag |= 1;
    }
#endif


  stc end : {
    if ($ > rspstart) {
          rsplen += $ - rspstart;
        rspstart = $;

          if (rsplen > 1024) {
              if (*($ - 4):32 == 0x41414141) {
                  if (*($ - 8):32 == 0x41414141) {
                    eval("http-rsp-before-code-possible-dos", 1);
                  }
            }
        }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
        if (rsplen > 10) {
            if ((validation_flag & 0x81) == 0) {
                if (simple_request == 0) {
                    switch_reason = RSP_RSPLEN_GREATER_10;
                    SWITCH_FROM_HTTP
                   }
            }
          }
#endif
    }

#if (PAN_ENGINE_VERSION < (PAN_VERSION(2,1,0,8)))
    if (proto == UNKNOWN_PROTO) {
      if (rsplen > 128) {
        printf(&"[HTTP] Does not look like HTTP traffic. Lets switch to unknown\n");
        hash_add($saddr, $sport, SWITCHFROMHTTP);
        setapp "unknown-tcp";
        /* Set the pktnum and rsp_pktnum before moving to evasive states. */
        pktnum = 1;
        goto http_evasive_rsp_state;
        exit();
      }
    }
#endif

    rspstart = $;
 } /* End of stc end check*/


  printf(&"[HTTP] Begin response\n");
  rsplen = 0;
  rspstart = $;
  rsp_pktnum++;

  stored_state = &rsp_init; // add for zealot

  field_begin("http-rsp-before-code"); //Add this field to capture some wierd http traffic


  stc "ICY" ignore_case :{
      setapp "shoutcast";
      exit();
  }

  stc "Happens " ignore_case :{
  	  if (rsp_pktnum == 1) {
		  setapp "xunlei";
		  exit();
	  }
  }

  stc ".*(x-flash-video|x-shockwave-flash|video/x-flv)" ignore_case :{
  	http_used_as_flag |= 0x40; /*Mark for flash detection together in avinclude.*/
  }

	stc "\x 00 14 00 01 00 00\x":{
		hash_find($daddr,BITTORRENT,tmp,tmp2);
		if (tmp == BITTORRENT){
			setapp "bittorrent";
			exit();
		}
	}

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
	stc "hrive" :
	{
		if( $pktlen == 5)
		{
			eval("http-rsp-trojan-spook-found",TRUE);
		}
	}
#endif

  stc "JEDI " ignore_case :{
      validation_flag |= 0x80;
      eval("http-rsp-jedi-response",TRUE);
      exit();
  }

#if 0
 /* bug 32099:
  * How to avoid the traffic going to http through appid cache?
  * Based on the obvious keyword in the first rsp packet, switch to unknown-tcp.
  * 1. In the case where rsp packet is the first one.
  * 2. In the case where there is no unknown and seeing the keyword in the first 50 bytes.
  * Currently we consider the obvious protocols like: smtp/sip/ssh/ftp/imap etc.
  * We could add more more keywords there if needed.
  */
  stc ".*(SMTP|SSH-|FTP|SIP/|imap)" ignore_case :{
  	if (pktnum == 0) {
		switch "unknown-tcp";
		exit();
	} else if (rsp_pktnum == 1){
		if (http_method == UNKNOWN_METHOD) {
			if ($ <= 50){
				switch "unknown-tcp";
				exit();
			}
		}
    }
  }
#endif

  stc ".*HTTP/" ignore_case : {
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))

          rsplen += $ - rspstart;

        if ((validation_flag & 0x81) == 0)  {

            if (rsplen >= 15) {
                printf(&"Version found too deep \n");
                SWITCH_FROM_HTTP
            }

            skip(3);
            if((*($ - 1):8 == 0x30) && (*($ - 2):8 == 0x2e) && (*($ - 3):8 == 0x31))
            {
               used_as_flag |= 4; //this is 1.0 response message
            }
            if ((*($ - 3):8 < 0x30) || (*($ - 3):8 > 0x39)) {
                switch_reason = RSP_VERSION_ERROR;
                SWITCH_FROM_HTTP
            }

            if (*($ - 2):8 != 0x2e) {
                switch_reason = RSP_VERSION_ERROR;
                SWITCH_FROM_HTTP
            }

               if ((*($ - 1):8 < 0x30) || (*($ - 1):8 > 0x39)) {
                   switch_reason = RSP_VERSION_ERROR;
                SWITCH_FROM_HTTP
            }
        }
#endif
    field_end();
    proto = HTTP;
    encoding_init();
    panav_content_type = CONTENT_TYPE_NOT_EXIST;
    goto response_code;
  }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))

    skip(10, "\x0a\x");

    if ($? == 1) {

        if ((validation_flag & 0x81) == 0)  {

               if ($ > rspstart) {
                /* the line ends before we saw version string */
                if (simple_request == 0) {
                    switch_reason = RSP_NOT_FOUND_HTTP_IN_10_BYTES;
                    SWITCH_FROM_HTTP
                }
               }
        }
    }
#endif
}

state response_code
{
  unsigned offset:32;
  unsigned count:8;
  unsigned tmp:8;
  unsigned tmp2:8;

  SWITCH_STATE(cts, response_code)

  field_begin("http-rsp-code-field");

#if (PAN_ENGINE_VERSION < (PAN_VERSION(2,0,11,4)))
    /* Look for begin of response code */
    do {
      skip (1);
      tmp = *($ - 1):8;
    } while(tmp != 0x20);
#else
  skip(10, "\x20\x");

  if ($? == 0) {
    eval("http-rsp-code-error", 1);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    if ((validation_flag & 0x81) == 0)  {
        switch_reason = RSP_NOT_FOUND_RSP_CODE_START_SPACE_IN_10_BYTES;
        SWITCH_FROM_HTTP
    }
#endif
    exit();
  }
#endif


  offset = $;
#if (PAN_ENGINE_VERSION < (PAN_VERSION(2,0,11,4)))
  count = 0;

  /* Look for end of response code */
  do {
    skip (1);
    tmp = *($ - 1):8;
    count ++;
    if (count > 4) {
      eval("http-rsp-error-code", MALFORMED_HTTP_RSP_CODE);
      break;
    }
    if ( tmp == 0x0d || tmp == 0x0a ) {
        break;
    }
  } while(tmp != 0x20);

  /* FIXME: Currently, register space is limited. Hence, used
     8 bit register for rsp_code. So MAX value is 255. Should
     suffice for now as we just want to check 200 rsp code
  */

  if (count < 5) {
    rsp_code = atoi(offset, 10);
    eval("http-rsp-code", rsp_code);
  }
#else
    //skip(4, "\x20 0d 0a\x");
    skip(4,"\x20\x");  // zealot modify only should be xxxspace rfc

  if ($? == 0) {
       eval("http-rsp-error-code", MALFORMED_HTTP_RSP_CODE);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
       if ((validation_flag & 0x81) == 0)  {
            switch_reason = RSP_CODE_NOT_FINISH_IN_4_BYTES;
           SWITCH_FROM_HTTP
       }
#endif
  } else {

    rsp_code = atoi(offset, 10);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))

        if (rsp_code == 0)  { /* check if atoi failed or response code is zero */

            if ((validation_flag & 0x81) == 0)  {
                tmp = *($ - 2):8;

                if ((tmp < 0x30) || (tmp > 0x39)) {
                    switch_reason = RSP_NO_DIGITAL_RSP_CODE;
                    SWITCH_FROM_HTTP
                }
                tmp = *($ - 3):8;
                if ((tmp < 0x30) || (tmp > 0x39)) {
                    switch_reason = RSP_NO_DIGITAL_RSP_CODE;
                    SWITCH_FROM_HTTP
                }
                tmp = *($ - 4):8;
                if ((tmp < 0x30) || (tmp > 0x39)) {
                    switch_reason = RSP_NO_DIGITAL_RSP_CODE;
                    SWITCH_FROM_HTTP
                }
            }
        }

        if (rsp_code != 200) {
            validation_flag  |= 0x04;
        }

#endif
    eval("http-rsp-code", rsp_code);
  }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,0,0,0)))
  packet_status |= 1; /* use the 1st bit to remember the rsp packets looks normal. Freegate detection will use this logic.*/
 if (rsp_code == 206 || rsp_code == 503) {
	  if (http_used_as_flag&14 == 14) {
		hash_find($saddr,$sport,tmp,count);
		if (tmp == HTTPPROXY) {
				hash_find($daddr,$dport + 3, tmp,count);
				if (tmp == BITTORRENT) {
					hash_add($daddr,BITTORRENT,BITTORRENT);
					setapp "bittorrent";
					exit();
				}
			} else {
				if ($sport != 80 && $sport!= 8080 && $sport != 8000){
					hash_find($daddr,BITTORRENT,tmp,count);
					if (tmp == BITTORRENT){
						hash_add($daddr,BITTORRENT,BITTORRENT);
						setapp "bittorrent";
						exit();
					}
				}
				if ($sport > 5000) {
				    CHECK_PROXY_USED($saddr,$sport,tmp,count,tmp2)
					if (tmp2 == 0) {
						setapp "bittorrent";
						exit();
					}
				}
			}
	  }
  }
#endif
  tmp = *($ - 1):8;

#endif
  /* if ended with 0x0d, means no response reason string
   * so go to next state response_header
   */
  if ( tmp == 0x0d || tmp == 0x0a ) {
    eval("http-rsp-reason-len", 0);
    field_end();
    goto response_header;
  }
  field_end();
  goto response_reason;
}

state response_reason
{
    unsigned reason_len:32;
    unsigned offset:32;
    unsigned byte_value:8;

    SWITCH_STATE(cts, response_reason)

    field_begin("http-rsp-reason");
    offset = $;

    reason_len = 0;
#if (PAN_ENGINE_VERSION < (PAN_VERSION(2,0,11,4)))
    do
    {
        skip(1);
        byte_value = *($ - 1):8;
        reason_len++;
    } while((byte_value != 0) && (byte_value != 0x0a) && (reason_len < 0x100));
    if(reason_len == 0x100)
    {
        eval("http-rsp-long-reaslon-len",TRUE);
    }
#else
      //    skip(0x100, "\x00 0a\x"); zealot modify
      skip(0x100, "\x0d\x");

    if($? == 0)
    {
        eval("http-rsp-long-reaslon-len",TRUE);

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
        if ((validation_flag & 0x81) == 0)
        {
            switch_reason = RSP_TOO_LONG_REASON;
            SWITCH_FROM_HTTP
        }
#endif

    }
    reason_len = $ - offset;
#endif
    reason_len -= 1;
    /* if(*($ - 2):8 == 0x0d) zealot modify*/
    if(*($ - 1):8 == 0x0d)
    {
       reason_len = reason_len - 1;
    }
    eval("http-rsp-reason-len",reason_len);
    field_end();
    goto response_header;
}

state response_header
{
  unsigned rsp_hdr_len:32;
  unsigned offset:32;
  unsigned headers_len:32;
  unsigned saved_content_len:32;
  unsigned range_start_offset:32;
  unsigned end_offset:32;
  unsigned rsp_hdr_type:8;
  unsigned found_hdr_end:8;
  unsigned found_content_len:8;
  unsigned connection_is_close:8;
  unsigned tmp:8;
  unsigned tmp2:8;

    /** zealot add **/
  unsigned charset_offset:32;

  SWITCH_STATE(cts, response_header)

  printf(&"[HTTP] Begin response headers\n");
  field_begin("http-rsp-headers");
  headers_len = $;
  found_content_len = FALSE;
  connection_is_close = TRUE;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    saved_content_len = panav_content_len;
#endif
    panav_content_len = 0; /* Just assign to a large number to avoid evasion */

    /* Reset hdr type to avoid FPs*/
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    rsp_hdr_type = UNKNOWN_HDR;
#endif

  stc ".*\nContent-Length:" ignore_case : {
    found_content_len = TRUE;
    if (panav_trans_encoding == CHUNKED) {
      eval("http-rsp-multiple-trans-encoding-evasion", 1);
    }
    panav_trans_encoding = LENGTH;
    SEARCH_HEADER_END(rsp, CONTENT_LENGTH, 256)
    if (found_hdr_end == TRUE) {
      panav_content_len = atoi(offset, 10);
      eval("http-rsp-content-length", panav_content_len);
	  HTTP_FILE_INFO_FUNC("http-rsp-content-length");
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
      if (panav_content_len > 0x7fffffff) {
        panav_content_len = 0x7fffffff;
      }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
      if (panav_content_len == 1073741824 ){
        if ($appid == 792) {
             printf(&"[RPCRPC] Back to appid now!\n");
               goto backto_appid_state;
              exit();
         }
      }
    if((saved_content_len > 0) && (panav_content_len > 0))
    {
         validation_flag |= 0x80;
    }
#endif
      printf(&"[HTTP] Content length = %d(0x%x)\n", panav_content_len, panav_content_len);
    }
  }
  stc ".*\nTransfer-Encoding:" ignore_case : {
    SEARCH_HEADER_END(rsp, TRANSFER_ENCODING, 25)
  }

  stc ".*chunked" ignore_case : {
    if (rsp_hdr_type == TRANSFER_ENCODING) {
      if (found_content_len == 1) {
	eval("http-rsp-multiple-trans-encoding-evasion", 1);
      }
      panav_trans_encoding = CHUNKED;
      eval("http-rsp-transfer-encoding", CHUNKED);
	  HTTP_FILE_INFO_FUNC("http-rsp-transfer-encoding");
      panav_content_len = 0;
    }
  }

  /* Process the dostupest cookie like: "Set-Cookie: 8160faa4=0js0lb4lbd20t0r83hnev1pk71;"*/
  stc ".*\nSet-Cookie: "ignore_case : {
  	   host4bytes = $;
  	   skip(9,"\x3d\x");
	   if ($? != 0){
	   		skip(27,"\x3b\x");
	   		if ($? != 0){
				if ( $ - host4bytes == 36){
					if (*($ - 1): 8 == 0x3b){
						eval("http-rsp-dostupest-cookie",TRUE);
					}
				}
			}
		}
   }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
  stc ".*/[0|1]?[0|1][0|1][0|1][0|1][0|1][0|1]A" : {
      if ((cgiproxy & 1) == 1) {
          setapp "cgiproxy";
      }
  }
#endif

  stc ".*\nContent-Encoding:" ignore_case : {
    SEARCH_HEADER_END(rsp, CONTENT_ENCODING, 25)
  }

  /* To get the filename out */

  stc ".*\nContent-Disposition:" ignore_case : {
      rsp_hdr_type = CONTENT_DISPOSITION;
  }
  stc ".*filename=" ignore_case : {
      print("-->http 1\n");
#define filename_offset range_start_offset
      print("-->http 2\n");
      if(rsp_hdr_type == CONTENT_DISPOSITION) {
      print("-->http 3\n");
      eval("http-rsp-file-download", TRUE);
      filename_offset = $;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,4)))
      print("-->http 4\n");
    field_end();
    field_begin("http-rsp-headers");
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
	field_begin("http-rsp-filename");
      print("-->http 5\n");
    field_flag(DATA_CACHE);
	field_bind(HTTP_FILE_NAME_FUNC_ID);
    skip(1);
    if(*($ - 1):8 == 0x22)
    {
        skip(256, "\x0a 3b 22\x");
    }
    else
    {

#endif
    skip(256, "\x0a 3b\x");
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    }
#endif
    if($?)
    {
        if(*($ - 6):32 == 0x68746D6C)
        {
            if(*($ - 8):16 == 0x2e6d)
            {
                eval("http-rsp-potential-threat-attachment-found",TRUE);
            }
        }
        else if((*($ - 1):8 == 0x22) || (*($ - 1):8 == 0x3b)) {
	  if (*($ - 5):32 == 0x2E737667) {
            eval("http-rsp-potential-threat-attachment-found",TRUE);
	  }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,1,0,0)))
	  else if (*($ - 5):32 == 0x2E707074) { /* .ppt */
	    search_back(5, 20, "\x25 20 3d\x", end_offset);
	    if ($? == 0) {
	      if ($ - filename_offset > 200) {
		eval("http-rsp-long-ppt-filename-in-disposition", TRUE);
	      }
	    }
	  }
#endif
	}
        else if((*($ - 1):8 == 0x0a)) {
	  if (*($ - 6):32 == 0x2E737667) {
	    eval("http-rsp-potential-threat-attachment-found",TRUE);
	  }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,1,0,0)))
	  else if (*($ - 6):32 == 0x2E707074) { /* .ppt */
            search_back(6, 20, "\x25 20 3d\x", end_offset);
	    if ($? == 0) {
	      if ($ - filename_offset > 200) {
		eval("http-rsp-long-ppt-filename-in-disposition", TRUE);
	      }
	    }
	  }
#endif
	}
    }
    field_flag(FILENAME);
      print("-->http 14\n");
	field_end();
    field_end();
      field_begin("http-rsp-headers");
#endif
    }
  }
#undef filename_offset
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,4)))
    ".*\.doc(x|m)" ignore_case : {
      if (rsp_hdr_type== CONTENT_DISPOSITION) {
        panav_file_type = DOCX;
      }
    }
    ".*\.ppt(x|m)" ignore_case : {
      if (rsp_hdr_type == CONTENT_DISPOSITION) {
        panav_file_type = PPTX;
      }
    }
    ".*\.xls(x|m)" ignore_case : {
      if (rsp_hdr_type == CONTENT_DISPOSITION) {
        panav_file_type = XLSX;
      }
    }
    ".*\.doc" ignore_case : {
      if (rsp_hdr_type== CONTENT_DISPOSITION) {
        panav_file_type = DOC;
      }
    }
    ".*\.ppt" ignore_case : {
      if (rsp_hdr_type == CONTENT_DISPOSITION) {
        panav_file_type = PPT;
      }
    }
    ".*\.xls" ignore_case : {
      if (rsp_hdr_type == CONTENT_DISPOSITION) {
        panav_file_type = XLS;
      }
    }
    ".*\.apk" ignore_case : {
      if (rsp_hdr_type == CONTENT_DISPOSITION) {
        panav_file_type = APK;
      }
    }
    ".*\.jar" ignore_case : {
      if (rsp_hdr_type == CONTENT_DISPOSITION) {
        panav_file_type = JAR;
      }
    }
#endif
    /* mp3 download */
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    stc ".*\.mp3" ignore_case : {
      if (rsp_hdr_type == CONTENT_DISPOSITION) {
	eval("http-rsp-mp3-ext-found", 1);
      }
    }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    stc ".*\.bat" ignore_case : {
      if (rsp_hdr_type == CONTENT_DISPOSITION) {
        eval("http-rsp-bat-ext-found", 1);
      }
    }
    stc ".*\.hta" ignore_case : {
      if (rsp_hdr_type == CONTENT_DISPOSITION) {
        eval("http-rsp-hta-ext-found", 1);
      }
    }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
    stc ".*\.cmd" ignore_case : {
	if (rsp_hdr_type == CONTENT_DISPOSITION) {
	    eval("http-rsp-cmd-ext-found", 1);
	}
    }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
    stc ".*\.php" ignore_case : {
        if (rsp_hdr_type == CONTENT_DISPOSITION) {
            eval("http-rsp-php-ext-found", 1);
        }
    }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,0,0,0)))
  stc ".*\nWWW-Authenticate:" ignore_case:
  {
    if(rsp_code == 401)
    {
        eval("http-rsp-authentication-failed",TRUE);
    }
  }
#endif

  stc ".*gzip" ignore_case : {
    if (rsp_hdr_type == CONTENT_ENCODING) {
      panav_body_encoding = GZIP_ENCODING;
        //suspend(RSP);
    }
  }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,0,0,0)))
    stc ".*deflate" ignore_case :
    {
        if (rsp_hdr_type == CONTENT_ENCODING)
        {
            panav_body_encoding = DEFLATE_ENCODING;
        }
    }
#endif
  stc ".*\nContent-Type:" ignore_case : {

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,2)))
    field_begin("http-rsp-headers");
    field_flag(PANCONTENT_TYPE);
#endif

    field_bind(HTTP_FILE_CONTENT_TYPE_FUNC_ID);
    panav_content_type = UNKNOWN;
      rsp_hdr_type = CONTENT_TYPE;
      SEARCH_HEADER_END(rsp, CONTENT_TYPE, 512)
      printf(&"[HTTP] Content-Type length = %d\n", $ - offset);
    eval("http-rsp-content-type-len",$ - offset);
	HTTP_FILE_INFO_FUNC("http-rsp-content-type-len");
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,2)))
    field_end();
    field_begin("http-rsp-headers");
#endif
  }

  /** 添加字符集的处理,目前只处理回应的字符集编码 zealot add**/
  FIELD_CHARSET
  /************************************************************/

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
  stc ".*application/vnd\.android\.package-archive" ignore_case : {
    panav_file_type = APK;
  }
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
  stc ".*\nCSEC:" ignore_case : {
    SEARCH_HEADER_END(rsp, CSEC, 256)
  }
  stc ".*eepa_0_" ignore_case : {
    if (rsp_hdr_type == CSEC) {
      SEARCH_HEADER_END(rsp, CSEC, 256)
      if (found_hdr_end != TRUE) {
	eval("http-rsp-long-csec-eepa-header", 1);
      }
    }
  }
  CHECK_MEDIATYPE
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
  stc ".*epas" ignore_case : {
    if (rsp_hdr_type == CSEC) {
      SEARCH_HEADER_END(rsp, CSEC, 256)
      if (found_hdr_end != TRUE) {
	eval("http-rsp-long-csec-epas-header", 1);
      }
    }
  }
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
  stc ".*: (Apache\r\n|LiteSpeed\r\n)" ignore_case : {
      if (rsp_code == 200 && pktnum == 1){
        if ((freegate&0x80) == 0x80){
            freegate |= 0x20;
        }
        hash_find($saddr,$sport,tmp, tmp2);
        if (tmp == HTTPPROXY ) {
			if ((freegate&0xa0) == 0xa0){
           	 	freegate |= 0x40;
			}
		}
    }
  }

    stc ".*/x-msn-messenger" ignore_case :
    {
        if (rsp_hdr_type == CONTENT_TYPE)
        {
            switch "msn";
            exit();
        }
    }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,1,0,0)))
    /* DON'T Modified the Tokens! */
    stc ".*\nAccept-Ranges: bytes" ignore_case :
    {
        set_http_range();
    }
#endif
    stc ".*\nContent-Range:" ignore_case:
    {
        //unsigned range_start_offset:32;
        //unsigned end_offset:32;
        end_offset = 0;
        range_start_offset = $;
        skip(20,"\x2d 0a\x");
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,1,0,0)))
        set_http_range();
#endif
        if($? == 1)
        {
            if(*($ - 1):8 == 0x2d)
            {
                //search back found the start offset after SP
                end_offset = $;
                do
                {
                    end_offset--;
                    if((*(end_offset - 1):8 == 0x20) || (*(end_offset - 1):8 == 0x09))
                    {
                        break;
                    }
                } while(end_offset > range_start_offset);
                if(end_offset > range_start_offset)
                {
                    range_start_offset = atoi(end_offset,10);
                    if(range_start_offset == 0)
                    {
                        if(rsp_code == 206)
                        {
                            packet_status |= 2;
                            /* use it to remember the rsp_code is 0 and start_offset is 0 */

                            rsp_code = 200;
                        }
                    }
                }
            }
        }
    }
#endif

  stc ".*text/" ignore_case: {
      if (rsp_hdr_type == CONTENT_TYPE) {
        panav_content_type = TXT;
    }
  }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    stc ".*\x3b 20 63 68 61 72  73 65 74 3d 75 74 66 2d\x(7|16|32)" ignore_case : {
        if (rsp_hdr_type == CONTENT_TYPE)
        {
            http_used_as_flag |= 0x20;
        }
    }
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
  stc ".*x-vermeer-rpc" ignore_case: {
    if (rsp_hdr_type == CONTENT_TYPE) {
        panav_content_type = VERMEER_RPC;
    }
  }
#endif


#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,7)))
  stc ".*x-javascript" ignore_case: {
      if (rsp_hdr_type == CONTENT_TYPE) {
        panav_content_type = TXT;
    }
  }
  stc ".*image/" ignore_case: {
      freegate = 0;
      if (rsp_hdr_type == CONTENT_TYPE) {
        panav_content_type = TXT;
    }
  }
#endif
  /* looking  for keep-alive */
  stc ".*(\nConnection: keep|\nProxy-Connection: keep)" ignore_case : {
/*
 * if the connect is close set in request, we will make it true here
 */
      if (http_connection_closed == 0) {
      connection_is_close = FALSE;
        http_connection_closed = 0;
      }
    }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    stc ".*\nConnection: close" ignore_case:
    {
        if($appid != 62)
        {
            http_connection_closed=1;
        }
    }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    stc ".*\nLocation: " : {
	if (rsp_hdr_type == LOCATION) {
	    eval("http-rsp-multiple-location-hdrs-found", 1);
	}
	else {
	    rsp_hdr_type = LOCATION;
	}
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
	skip (20, "\x3f 0a\x");
	if ($?) {
	    if (*($ - 1):8 == 0x3f) {
		if (*($ - 5):32 == 0x2e706466) {
		    skip (1024, "\x0a\x");
		    if ($? == 0) {
			eval("http-rsp-foxit-long-pdf-url-in-location", 1);
		    }
		}
	    }
	}
#endif
    }
#endif
  stc ".*location: ftp://" : {
          if ($appid == 1015) {
            predict("bigupload", TCP, $daddr, 0, $saddr, 21, 0x0f, 10);
        }
  }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
  stc ".*Location: http://[a-zA-Z0-9]+\r\n":{
        if(rsp_code == 301){
            eval("http-rsp-301-invalid-address", 1);
        }
  }
#endif

  stc ".*(\r\n\r\n|\n\n)" : {
  	if (rsp_code == 0){
		if (host4bytes == 0){
			validation_flag &= 0x7f;    /* Unset the highest bit so the validation will continue.*/
		}
	}
    printf(&"[HTTP] End response headers\n");
    if(validation_flag & 2)
    {
        validation_flag |= 0x80;
    }
    else
    {
        validation_flag |= 0x1;
    }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,0,0,15)))
    if (http_proxy == 1) {
        reset_http_proxy_app_stat();
    }
#endif

    if ($ > headers_len) {
      headers_len = $ - headers_len;
      eval("http-rsp-total-headers-len", headers_len);
    }
    field_end();
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,2)))
    /* if not content type found, set the content type to 0 */
    if (panav_content_type == CONTENT_TYPE_NOT_EXIST) {
        field_begin("http-rsp-not-content-type");
        field_flag(PANCONTENT_TYPE);
        field_end();
    }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    if((http_method != GET) && (saved_content_len > 0))
    {
        if((rsp_code < 200) || (rsp_code >= 300))
        {
            panav_content_len = saved_content_len; //restore it back
        }
    }
#endif
    if (connection_is_close == TRUE) {
        if (found_content_len == FALSE) {
            if(rsp_code == 200)
            {
                /* assign a big value */
                panav_content_len = 0xffffff;
            }
        }
    }
    if(used_as_flag & 4) /* http response 1.0 */
    {
        if(found_content_len == FALSE)
        {

            if(rsp_code == 200)
            {
                panav_content_len = 0xffffff;
                panav_trans_encoding = LENGTH;
            }
        }
        used_as_flag &= 0xfb; /* reset 3th bit */
    }
    goto response_body;
  }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    stc end : {
        if (headers_len > MAX_HEADER_LEN) {
            if ((validation_flag & 0x81) == 0) {
                switch_reason = RSP_LONG_HEADER;
                SWITCH_FROM_HTTP
            }
        }
    }
#endif


  sub rsp_hdr_init (field_val) {
    rsp_hdr_len = $;
    printf(&"[HTTP] Header len %d\n", rsp_hdr_len);
    rsp_hdr_type = field_val;
    eval("http-rsp-header-type", rsp_hdr_type);
    found_hdr_end = FALSE;
    offset = $;
    return 0;
  }

  sub rsp_hdr_end() {
    if (found_hdr_end == TRUE) {
      if (rsp_hdr_len <= $) {
    rsp_hdr_len = $ - rsp_hdr_len;
      }
      eval("http-rsp-header-length", rsp_hdr_len);
      printf(&"[HTTP] Header length = %d(0x%x)\n", rsp_hdr_len, rsp_hdr_len);
    }
    else {
      printf(&"[HTTP] Could not find end of header within given limit\n");
      eval("http-rsp-error-code", MALFORMED_HEADER_VALUE);
    }
    rsp_hdr_type = UNKNOWN_HDR;
    rsp_hdr_len = 0;
    return 0;
  }
}

state response_body
{
  unsigned tmp:32;
  unsigned total:32;
  unsigned cnt:8;
  unsigned temp_byte:8;
  unsigned normal:8;


#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
/* We are foring a policy lookup. This is needed for making sure implicitely
 * allowed web-browsing won't be allowed forever.
 */
  if ((http_used_as_flag & 0x10) == 0){
  	do_policy_lookup();
  }
  http_used_as_flag |= 0x10; /*Mark the 5th bit of http_used_as_flag so next time no policy_lookup.*/
#endif

  SWITCH_STATE(cts, response_body)

  printf(&"[HTTP] Begin response message body\n");

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
if (panav_content_len == 4)
{
    if (*($):32 == 0x536d6b30)
    {
        eval("http-rsp-trojan-smoke-found",1);
    }
}
#endif
    //validation_flag = validation_flag & 0xfe;
  if (panav_content_type == VERMEER_RPC) {
    goto rsp_vermeer_body;
  }

  /* CONNECT and RPC_CONNECT tunneling needs to go back to appid.
     This is because the next traffic is some tunneled traffic
     and not HTTP. TO identify this we need to go back to appid.
     Even for RPC_CONNECT, we cannot just use switch since the offset
     needs to be from current offset and not from beginning of flow.
  */

  if (http_method == CONNECT) {
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    if (($appid != 800) && ($appid != 536)) {
#endif
        if  (rsp_code == 200) {
             printf(&"[HTTP] HTTP Tunneling detected. Need to go back to appid for app detection..Adding soon. For now, just exit decoder\n");
            /* set the http_proxy bit for later used by the song's ssl proxy */

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,5)))
	    if ($appid == 27) {
          if ((ntlm_ssp_flag & 0x80) == 0x80){
			used_as_flag |= 0x80;
			goto ftp_proxy_state;
		  }
	    }
#endif
            goto backto_appid_state;
              exit();
            }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    }
#endif
  }

  if (http_method == RPC_CONNECT) {
    if (rsp_code == 200) {
      printf(&"[HTTP] HTTP RPC Tunneling detected. Need to go back to appid for app detection..Adding soon. For now, just exit decoder\n");
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,0,0,0)))
        goto backto_appid_state;
#endif
      exit();
    }
  }
  if(panav_trans_encoding == LENGTH) {
    if((panav_content_len < 8) || (((rsp_code < 200) || (rsp_code > 299))
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,0,0,0)))
    && (rsp_code != 406) && (rsp_code != 207)
#endif
    )) {

      field_begin("http-rsp-forbiden-payload", ignore_case);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
      validation_flag |= 1;
      if(rsp_code != 100) {
#endif
      skip(panav_content_len);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
    }
#endif
      scope_end(PDU);
      field_end();
      goto rsp_init;
    }
  }
  /* For HEAD method, there should be no message body,
     even if there is a content-length header in response
  */
  if (http_method != HEAD) {
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,0,0,0)))
    if(panav_trans_encoding == CHUNKED)
    {
        if($ < $+)
        {
            total = $+ - $;
            normal = 1;
            cnt = 0;
            if(total > 4)
            {
                total = 4;
            }
            while(cnt < total)
            {
                //0x30-0x39, 0x61-0x66, 0x41-0x46
                temp_byte = *($ + cnt):8;
                if((temp_byte == 0x0d) || (temp_byte == 0x0a))
                {
                    break;
                }
                if((temp_byte > 0x2f) && (temp_byte < 0x3a))
                {
                    cnt++;
                }
                else if((temp_byte > 0x60) && (temp_byte < 0x67))
                {
                    cnt++;
                }
                else if((temp_byte > 0x40) && (temp_byte < 0x47))
                {
                    cnt++;
                }
                else if((temp_byte == 0x20) || (temp_byte == 0x09))
                {
                    cnt++;
                }
                else
                {
                    normal = 0;
                    break;
                }
            }
            if(normal == 0)
            {
                exit(); //don't know how to continue;
            }
        }
    }
#endif
    field_begin("http-rsp-body-start");
    eval("http-rsp-file-start-location", 1);
    HTTP_FILE_INFO_FUNC("http-rsp-file-start-location");
    field_end();
    goto panav_init_state;
  }
  scope_end(PDU);
  goto rsp_init;
}


#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
state rsp_vermeer_body {
  unsigned offset:32;
  unsigned tmp:32;

  printf(&"[HTTP] Begin response message VERMEER body\n");

  stc ".*document_name=" : {
    field_begin("http-rsp-vermeer-file");
    field_flag(FILENAME);
      print("-->http 15\n");
    skip(30, "\x0a\x");
      if ($? == 1) {
        field_end();
    }
  }

  stc ".*\x3c 6c 69 3e 76 74 69 5f 66 69 6c 65 73 69 7a 65 0a 3c 6c 69 3e 49 52\x" : {
    field_end();
    /* read the file size */

    offset = $;
     do {
       skip(1);
       tmp = *($ - 1):8;
    } while (tmp != 0x0a);

    panav_content_len = atoi(offset, 10);
  }

  stc ".*\x3c 2f 68 74 6d 6c 3e 0a\x" : {
       field_begin("http-rsp-vermeer-body");
       goto panav_init_state;
  }
  scope_end(PDU);
}
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,0,0,0)))
state http_init
{
    // zealot donot need to patch for chunk decoder
    //skip(2,"\x0a\x"); //for chunk only, software side didn't eat it
    goto init;
}
#endif


state backto_appid_state
{
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,0,0,0)))
    if ($dir == 0){
       hash_add($saddr, $sport, HTTPPROXY,1800);
    } else {
       hash_add($daddr, $dport, HTTPPROXY,1800);
    }
      backto_appid (NEXT);
      exit();
#endif
}

/* The following states handle the evasive traffic on port 80. Mainly used for p2p detection. */

state http_req_switch_back_state {
    goto http_evasive_req_state;
}

state http_rsp_switch_back_state {
    goto http_evasive_rsp_state;

}
/* we are rich for global variable here:

unsigned panav_content_len:32;
unsigned chunk_body_len:32;
unsigned restore_state:32;
unsigned pe_start_offset:32;
#if defined (HTTP) && (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
unsigned MIME_Boundry_Last4bytes:32;
#endif
*/

/*
{
    NOREASON,
    REQ_LONG_HEADER,
    REQ_LONG_URL,
    REQ_LONG_UNKNOWN_METHOD,
    REQ_BINARY_UNKNOWN_METHOD,
    REQ_NO_METHOD_IN_64_BYTES,
    REQ_SIMPLE_REQUEST_NOT_GET_METHOD,
    REQ_RTMP_MATCHED,
    REQ_MULTIPLE_SIMPLE_REQUEST,
    REQ_SIMPLE_REQUEST_IN_MULTIPLE_PACKET,
    REQ_2_CRLF_IN_SIMPLE_REQUEST,
    REQ_HTTP_VERSION_ERROR,
    REQ_HTTP_VERSION_DONT_SEE_CRLF_AFTER_8_BYTES,
    REQ_NOT_GET_ON_SIMPLE_REQUEST,
    REQ_CRLF_FOUND_BEFORE_VERSIONSTRING,
    RSP_RSPLEN_GREATER_10,
    RSP_VERSION_ERROR,
    RSP_NOT_FOUND_HTTP_IN_10_BYTES,
    RSP_NOT_FOUND_RSP_CODE_START_SPACE_IN_10_BYTES,
    RSP_CODE_NOT_FINISH_IN_4_BYTES,
    RSP_NO_DIGITAL_RSP_CODE,
    RSP_TOO_LONG_REASON,
    RSP_LONG_HEADER,
};*/

state http_evasive_req_state
{
    /* ATTENSION, please don't change order of these variables.You can use it free, but cannot add or remove variable before req_hdr_type */
    unsigned start_offset_this_state:32;
    unsigned already_skipped:32;
    unsigned unknown_dword1:32;
    unsigned unknown_dword2:32;
    unsigned unknown_word1:16;
    unsigned tmp:8;
      unsigned tmp2:8;
      unsigned req_hdr_type:8;
      /* You can add your new variable here */

    /** zealot add */
    unsigned qq_num:32;

#define req_total_len chunk_body_len
#define req_current_state_status used_as_flag
    cts start: {
        req_total_len += $pktlen;
        rsp_code += $pktlen;
        goto http_req_switch_back_state;
    }

    /* if qq-base tcp on port 80, switch to unknown-tcp*/
    if ($dport == 80 && $pktlen >= 7 && *($-):16 == $pktlen && *($- + 2):8 == 0x02 && *($+ - 1):8 == 0x03) {
        switch "unknown-tcp";
        exit();
    }

    start_offset_this_state = $;
    /*
    else if((switch_reason = REQ_LONG_UNKNOWN_METHOD) || (switch_reason == REQ_NO_METHOD_IN_64_BYTES))
    {
        req_total_len += MAX_METHOD_LEN;
    }
    */
    evasive = 1;
    req_hdr_type = 0;
    if(req_current_state_status == HTTP_REQ_URL_STATUS)
    {
        FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-uri-path", http_method, ANY);
        field_flag(URI_DECODE);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
        if ( $pktlen < 5 && ((loic_count & 0x80) != 0x80))
        {
            if (loic_count == 30 )
            {
                eval("http-req-loic-ddos", TRUE);
            }
            loic_count++;
        }
        else
        {
            loic_count |= 0x80;
        }
#endif
    }
    else if(req_current_state_status == HTTP_REQ_PARAMS_STATUS)
    {
        FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-params", http_method, ANY);
    }
    else if(req_current_state_status == HTTP_REQ_HEADERS_STATUS)
    {
        FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-headers", http_method, req_hdr_type);
    }
    else if(req_current_state_status == HTTP_REQ_METHOD_STATUS)
    {
        FIELD_BEGIN_IGNORE_CASE("http-req-before-method");
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,1,0,8)))
        if ( $pktlen < 5 )
        {
            if (loic_count == 30 && ((loic_count & 0x80) != 0x80))
            {
                eval("http-req-loic-ddos", TRUE);
            }
            loic_count++;
        }
#endif
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
        skip($+ - $, "\x09 20 00 \x");
        if($? == 0)
        {
            if(req_current_state_status == HTTP_REQ_METHOD_STATUS)
            {
                eval("http-req-before-method-len", req_total_len);
            }
        }
        else
        {
            if(req_total_len > ($+ - $))
            {
                eval("http-req-before-method-len", req_total_len - ($+ - $));
            }
            req_current_state_status = HTTP_REQ_URL_STATUS;
            FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-uri-path", http_method, ANY);
            field_flag(URI_DECODE);
            req_total_len = $+ - $;
        }
#endif
    }
    else if(req_current_state_status == HTTP_REQ_VERSION_STATUS)
    {
        FIELD_BEGIN_IGNORE_CASE("http-req-version-string");
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
        skip(10,"\x0a\x");
        if($?)
        {
            req_current_state_status = HTTP_REQ_HEADERS_STATUS;
            FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-headers", http_method, req_hdr_type);
            req_total_len = $+ - $;
        }
#endif
    }
    else
    {
        FIELD_BEGIN_IGNORE_CASE("http-req-unknown-data");
    }
    if($ > 4)
    {
        if(*($ - 4):32 == 0x0d0a0d0a)
        {
            if(($ + 2) < $+)
            {
                if(*($ + 1):16 == 0x3a5c)
                {
                    eval("http-req-found-driveprompt",TRUE);
                }
            }
        }
    }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
    if($+ < 6)
    {
        if(switch_reason ==  REQ_NOT_GET_ON_SIMPLE_REQUEST)
        {
            if(*($ - 2):16 == 0x0d0a)
            {
                if((*(0):24 == 0x202020) || (*(0):24 == 0x20200d) || (*(0):24 == 0x200d0a))
                {
                    eval("http-req-apache-mod-proxy-ajp-dos",TRUE);
                }

            }
        }
    }
#endif
    pktnum++;

    /*****************************************************************
     * To make the code clean and use less registers, we will use one
     * variable for all the p2p tracking--- p2p;
     * 1-15: used for xunlei detection.
     * 16-31: used for skype detection.
     * 32-47: used for emule detection.
	 * 48-52: used for qvod
	 * 64-68: used for freegate
     *****************************************************************/

    if (pktnum == 1 && http_method == UNKNOWN_METHOD){
        rsp_code = $pktlen; /* rsp_code will be reused to accumlate the req length now. */
        if ($pktlen >= 151 && $pktlen <=156) {
            p2p = 1;
        }
        if ($pktlen < 30 && rsp_pktnum == 0) {
            p2p |= 0x20;
        }
		if ($pktlen >= 85 && $pktlen <= 100) {
			p2p |= 0x30;
		}
		if ($pktlen >= 160 && $pktlen <=600){
			p2p |= 0x40;
		}
		if ($daddr == 0x413102bf){
			setapp "freegate";
			exit();
		}
        if($pktlen == 256){
            freegate = 0xf0; //used as pi-rat flag
         }
    }

    if (switch_reason == REQ_RTMP_MATCHED || switch_reason == REQ_RTMPE_MATCHED) {
		if (rsp_code == 1537 && rsp_pktnum <= 1) {
			if (switch_reason == REQ_RTMP_MATCHED) {
				switch "rtmp";
				exit();
			} else {
				 hash_find($saddr,1935,tmp,tmp2);
					if(tmp == TV4PLAY){
							predict("tv4play", TCP, 0, 0, $daddr, 1935, 0x2d, 10);
							setapp "tv4play";
							exit();
					}else if (tmp == RDIORTMPE){
                    		setapp "rdio";
                    		exit();
					}else {
							predict("rtmpe", TCP, 0, 0, $daddr, 1935, 0x2d, 60);
							setapp "rtmpe";
							exit();
					}
			}
            /* Handshake packet is 1537, which normally comes in two pieces
             * (since default mtu = 1500). For a little flexibility, we wait
             * until second part arrives. */
		} else if (rsp_code > 1537 || rsp_pktnum != 0) {
			setapp "unknown-tcp";
		}
	}

	if(IS_PRIV($daddr) == 0 || IS_PRIV($saddr) == 0){
		if (http_method == UNKNOWN_METHOD) {
    		http_p2p_guessing(tmp, tmp2);
		}
    }


    /* bug 46767: For certain oracle traffic, it might hit non-standard port 80, we need cover it in this evasive state.
	*/
	cts ".*(@insert into|@update |create table|select |delete from)" : {
		if (*($-):16 == $pktlen && (*($- + 2): 32)&0xfffff8ff == 0){
			if ($ > 110 && $ < 125) {
				  switch "oracle";
				  exit();
			}
		}
	}

    /* define your DFA pattern here: */
    cts ".* HTTP/" ignore_case:
    {
        if((req_current_state_status == HTTP_REQ_URL_STATUS) || (req_current_state_status == HTTP_REQ_PARAMS_STATUS))
        {
            already_skipped = $ - start_offset_this_state;
            if($pktlen > already_skipped)
            {
                req_total_len -= $pktlen -already_skipped;
                if(req_current_state_status == HTTP_REQ_PARAMS_STATUS)
                {
                    eval("http-req-param-length", req_total_len);
                }
                else
                {
                    EVAL_QUALIFIER("http-req-uri-path-length", req_total_len, http_method, ANY, ANY, ANY);
                }
            }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
            skip(10,"\x0a\x");
#endif
            field_end();
            FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-headers", http_method, req_hdr_type);
            req_current_state_status = HTTP_REQ_HEADERS_STATUS;
            req_total_len = $+ - $;
        }
    }

    cts ".*\nHost:" ignore_case :
    {
        if(req_current_state_status == HTTP_REQ_HEADERS_STATUS)
        {
            if(req_total_len > ($+ - $))
            {
                eval("http-req-other-headers-total-length", req_total_len - ($+ - $));
            }
            FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-host-header", http_method, ANY);
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
            req_hdr_type = HOST;
            skip(80,"\x0a\x");
            if ($? == 0)
            {
                eval("http-req-error-code", OVERLY_LONG_HOST_HEADER);
            }
            field_end();
            req_hdr_type = UNKNOWN_HDR;
            FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-headers", http_method, req_hdr_type);
#endif
        }
    }

    cts ".*NMCanaveral":
	{
		hash_add($saddr,$daddr,PROPALMS,600);

	}

	cts ".*\x00 00 00 30 30\x":{
		if ((*($ - 9):32 == 0x0110 && *($ - 11):32 == 0) ||(*($ - 10):24 == 0 && *($ - 6):8 > 0)) {
			hash_find($saddr,XUNLEI,tmp,tmp2);
			if (tmp == XUNLEI){
				hash_add($saddr,XUNLEI,XUNLEI,3600);
			}
			setapp "xunlei";
			exit();
		}
	}


 /* 00.0c 00..00 00 01 00 00 00 */
    cts ".*\x00 00 01 00 00 00\x":{
		if ( $ == 12){
			if ((*($ - 12):32) & 0xff00ffff == 0x0c00){
      			if ($pktlen == 16 || $pktlen == 64){
            		setapp "guildwars";
            		exit();
				}
			}
		}
	}




	cts ".*\?":
    {
        if(req_current_state_status == HTTP_REQ_URL_STATUS)
        {
            already_skipped = $ - start_offset_this_state;
            if($pktlen > already_skipped)
            {
                req_total_len -= $pktlen - already_skipped;
                EVAL_QUALIFIER("http-req-uri-path-length", req_total_len, http_method, ANY, ANY, ANY);
            }
            req_total_len = $+ - $;
            req_current_state_status = HTTP_REQ_PARAMS_STATUS;
            FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-params", http_method, ANY);
        }
    }
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,0,0,0)))
    cts ".*\nTransfer-Encoding: chunked" ignore_case:
    {
        panav_trans_encoding = CHUNKED;
	if (tmp == 2) {
	  eval("http-req-chunked-uri-params", 1);
	}
    }
    cts ".*x-www-form-urlencoded" ignore_case : {
      if(req_current_state_status == HTTP_REQ_HEADERS_STATUS) {
	tmp = 2;
      }
    }
	cts ".*Client: mTrader\r\nProtocol"  ignore_case : {
		setapp "infront";
		exit();
	}
#endif
    cts ".*(\r\n\r\n|\n\n)" :
    {
        if(*($ - 4):32 == 0x0d0a0d0a)
        {
            if(($ + 2) < $+)
            {
                if(*($ + 1):16 == 0x3a5c)
                {
                    eval("http-req-found-driveprompt",TRUE);
                }
            }
        }
        if(req_current_state_status == HTTP_REQ_HEADERS_STATUS)
        {
            if(req_total_len > ($+ - $))
            {
                eval("http-req-other-headers-total-length", req_total_len - ($+ - $));
            }
            field_end();
            req_current_state_status = HTTP_REQ_BODY_STATUS;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,0,0,0)))
            if(panav_trans_encoding == CHUNKED)
            {
                    field_begin("http-req-start-of-chunk");
                    field_flag(CHUNK);
                    field_end();
                    save_state(http_req_switch_back_state);
                    panav_trans_encoding = LENGTH;
                    jump panav_init_proxy_state;
            }
#endif
        }
        panav_trans_encoding = 0;
    }
    cts ".*GET ":
    {
        if(req_current_state_status == HTTP_REQ_METHOD_STATUS)
        {
            req_total_len = $+ - $;
            req_current_state_status = HTTP_REQ_URL_STATUS;
            http_method = GET;
            FIELD_BEGIN_IGNORE_CASE_QUALIFIER("http-req-uri-path", http_method, ANY);
        }
    }
    cts end:
    {
        if(req_current_state_status == HTTP_REQ_URL_STATUS)
        {
            EVAL_QUALIFIER("http-req-uri-path-length", req_total_len, http_method, ANY, ANY, ANY);
        }
        /*******************************************************
        * for qq number in HTTP protocol add by sunon.zealot in 4/07/2014
        * 00000000  00 95 02 35 0b 08 25 5b  3f 3f 70 23 90 03 00 00 ...5..%[ ??p#....
        * 00000010  00 01 01 01 00 00 66 d5  00 00 00 00 d5 d4 fe 7b ......f. .......{
        * ...
        * 000001AA  8a 71 8a 18 2a 62 ba b1  8a 00 e1 7c 19 b1 b5 5e .q..*b.. ...|...^
        * 000001BA  86 e6 55 b1 03                                   ..U..
        * from client to server the packet's dport is 80 , and payload length is 149 with
        * fixed string \x00 95\x.{146}\x03\x
        * certainly, the qq number is cts data, because of the eval type user rsp field without any influence
        *********************************************************/
        //printf(&"pkt_len %d dir %d dport %d end %x\n", $pktlen, $dir, $dport , *($ - 1):8);
        if($pktlen == 149 && $dir == 1 && $dport == 80 && *($ - 1):8 == 0x03)
        {
          //printf(&"pkt_len %d dir %d dport %d start %x\n", $pktlen, $dir, $dport , *($-):16);
            if(*($-):16 == 0x0095)
            {
                qq_num = *($- + 9):32;
                eval("qq-rsp-qq-number", qq_num);
                setapp "qq";
                exit();
            }
        }
        //[[[add by luoyuanhai.zealot for QQTalk 20140516
        //the first 2 bytes is payload length(0x009d) , dport is 80, and end with byte \x03
        if($pktlen == 157 && $dir == 1 && $dport == 80 && *($ - 1):8 == 0x03)
        {
            if(*($-):16 == 0x009d)
            {
                setapp "QQTalk";
                exit();
            }
        }
        //]]]
    }

#undef req_total_len
#undef req_current_state_status
}

state http_evasive_rsp_state {
    unsigned tmp:8;
      unsigned tmp2:8;

    stc start: {
        goto http_rsp_switch_back_state;
    }

    evasive = 1;
    FIELD_BEGIN_IGNORE_CASE("http-rsp-unknown-data");
    rsp_pktnum++;

	if(IS_PRIV($daddr) == 0 || IS_PRIV($saddr) == 0){
		if (http_method == UNKNOWN_METHOD) {
    		http_p2p_guessing(tmp, tmp2);
		}
	}

    if(freegate == 0xf0)
    {
       if(rsp_pktnum == 1 && $pktlen == 256)
       {
           eval("http-rsp-poisonive-rat-found", 1);
       }
       freegate = 0;
    }

    if( $pktlen == 0x410 )
    {
        if(*($):32 == 0x2c010000)
        {
            eval("http-rsp-macontrol-found", 1);
        }
    }

    stc ".*\r\n\r\n[C-Z]:\\" ignore_case:
    {
        eval("http-rsp-found-driveprompt",TRUE);
    }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(3,1,0,0)))
    stc "\x03 00 00\x":
    {
        if(BOCH_RCP_P == evasive_app){
            setapp "bosch-rcp-plus";
            exit();
        }
    }
#endif
}

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,5)))
state ftp_proxy_state {
  cts start : {
      if($appid == 27){
        if(used_as_flag & 0x80){
          if (ntlm_ssp_flag & 0x80){
            setdecoder "ftp-data";
            exit();
          }
        }
      }
  }
  stc start : {
      if($appid == 27){
        if(used_as_flag & 0x80){
          if (ntlm_ssp_flag & 0x80){
            setdecoder "ftp-data";
            exit();
		  }
        }
      }
  }
}
#endif

state initiate_http_unknown_state
{
    chunk_body_len = 0;
#define req_current_state_status used_as_flag
    req_current_state_status = HTTP_REQ_INIT_STATUS;
    if ($dir == 1)
    {
        pktnum = 0;
		if (switch_reason != REQ_RTMP_MATCHED && switch_reason != REQ_RTMPE_MATCHED) { /* In case it is rtmp related, don't set unknown-tcp now.*/
        	setapp "unknown-tcp";
		}
		if (switch_reason == REQ_ZERO_START_METHOD){
			switch "unknown-tcp";
			exit();
		}
        chunk_body_len = $pktlen; /* rsp_code will be reused to accumlate the req length now. */

        if(switch_reason == REQ_LONG_HEADER)
        {
            chunk_body_len += MAX_HEADER_LEN;
            req_current_state_status = HTTP_REQ_HEADERS_STATUS;
        }
        else if(switch_reason == REQ_LONG_URL)
        {
            chunk_body_len += MAX_URL_LEN;
            req_current_state_status = HTTP_REQ_URL_STATUS;
        }
        else if(switch_reason == REQ_BINARY_4_URLBYTES)
        {
            req_current_state_status = HTTP_REQ_URL_STATUS;
        }
        else if((switch_reason == REQ_HTTP_VERSION_ERROR) || (switch_reason == REQ_HTTP_VERSION_DONT_SEE_CRLF_AFTER_8_BYTES))
        {
            req_current_state_status = HTTP_REQ_VERSION_STATUS;
        }
        else if((switch_reason == REQ_NO_METHOD_IN_64_BYTES) || (switch_reason == REQ_BINARY_UNKNOWN_METHOD) || (switch_reason == REQ_LONG_UNKNOWN_METHOD))
        {
            req_current_state_status = HTTP_REQ_METHOD_STATUS;
        }
        field_begin("http-req-switch-reson-field");
        eval("http-req-switch-reason",switch_reason);
        field_end();
        goto http_evasive_req_state;
    }
    else
    {
        field_begin("http-rsp-switch-reson-field");
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,0)))
        /* Checking for headerless HTTP 0.9 - 1.0 response */
        if($- == 0) {
            if(*($-):32 == 0x3c68746d || *($-):32 == 0x3c48544d || *($-):32 == 0x3c21646f || *($-):32 == 0x3c21444f) {
                /* We've founda headerless HTTP response */
                switch_reason = switch_reason;
            }
            else {
                eval("http-rsp-found-none-standard-response",TRUE);
            }
        }
        else {
            eval("http-rsp-found-none-standard-response",TRUE);
        }
#endif
        setapp "unknown-tcp";
        eval("http-rsp-switch-reason",switch_reason);
        field_end();
        goto http_evasive_rsp_state;
    }
#undef req_current_state_status
}
