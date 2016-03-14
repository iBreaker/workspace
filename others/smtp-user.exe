#define SMTPCODE
#define REQ_FILE_DATA_ONLY
#include "emailav.h"
#include "version.h"

unsigned xlink_total_chunk_len:32;
unsigned rsp_code:32;
unsigned unknown_cmd_len:32;
unsigned smtp_bdat_chunk_size:32;
unsigned xlink_found_first_chunk:8;
unsigned smtp_command:8;
unsigned seen_percent_s:8;
unsigned proven_smtp:8;
unsigned ftp_command:8;
unsigned need_skip_lines:8;
unsigned auth_subcmd:8;
unsigned rsp_pktnum:8;
unsigned no_smtp_check:8;
unsigned multiple_line_parse:8;
unsigned auth_state:8;
unsigned seen_esmtp:8;
unsigned seen_postfix:8;
unsigned pktnum:8;
unsigned bp_auth_gssapi_attack:8;
unsigned passid:8;
unsigned userid:8;

enum {
  UNKNOWN_CMD,
  EHLO , 
  HELO ,
  MAIL , 
  SEND ,
  SOML ,
  SAML ,
  RCPT , 
  DATA , 
  AUTH ,
  VRFY ,
  QUIT , 
  RSET ,
  XEXCH50,
  XLINK2STATE,
  USER,
  XTELLMAIL,
  BDAT,
  XEXPS,
  STARTTLS,
  EXPN,
};
enum
{
    UNKNOWN_SUB_AUTHCMD,
    NTLM,
    CRAMMD5,
    DIGESTMD5,
    GSSAPI,
};

enum {
    UNKNOWN_AUTH_TYPE,
    TLS_START,
    TLS_OKAY,
};
enum {
  NO_ERROR,
  XEXCH50_NEGATIVE_LENGTH_ERROR,
  RCPT_CVE_2006_4379_FORMAT_OVERLONG,
  SMTP_UNKNOWN_CMD_SPACE_FIRST_CHAR,
  WMAIL_RETADDR_FOUND, 
  NJSTAR_RETADDR_FOUND,
  SMTP_FORMAT_STRING_ERROR,
  BDAT_OVERLONG_DATALEN,
  INVALID_MAIL_ADDRESS,
  INVALID_CHAR_IN_HELO,
};
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(1,2,0,0)))
    #define FIELD_BEGIN_IGNORE_CASE(a) field_begin(a, ignore_case)
#else
    #define FIELD_BEGIN_IGNORE_CASE(a) field_begin(a)
#endif

#define DEF_STR_REF(str) #str
/* #define SET_CMD_PARSE(cmdstr,cmd)   cts DEF_STR_REF(((cmdstr)|(.*\n##cmdstr))) ignore_case:{COMMAND_PARSING(cmd)} */
#define SET_CMD_PARSE(cmdstr,cmd)   \
    cts DEF_STR_REF(.*\n##cmdstr) ignore_case:{COMMAND_PARSING(cmd)} \
    cts DEF_STR_REF(cmdstr) ignore_case:{COMMAND_PARSING(cmd)}

#define COMMAND_PARSING(cmd)				\
  field_end();						        \
  if ($ >= unknown_cmd_start) {				\
    unknown_cmd_len = $ - unknown_cmd_start;	    	\
  }							                \
  eval("smtp-req-unknown-cmd-length", unknown_cmd_len);	\
  seen_percent_s = 0;						\
  smtp_command = cmd;			        	\
  eval("smtp-req-command", smtp_command);	\
  goto argument_state;

#define VALID_RSPCODE(rsp_code) 														\
   if (rsp_code < 100 || rsp_code >= 600) {												\
		printf(&"[smtp valication] This rsp code may not be a real smtp one!\n");		\
		switch "unknown-tcp";															\
		exit();																			\
	}

/** zealot add */
#define WEAK_PASSWD_CHECK_FUNC_ID 19
#define WEAK_PASSWD_CHECK(a,b) callback(a,b,WEAK_PASSWD_CHECK_FUNC_ID)
#define BRUT_FORCE_ATTACK_FUNC_ID 22
#define BRUT_FORCE_ATTACK_CHECK(a) callback(a,BRUT_FORCE_ATTACK_FUNC_ID)

state init {
  
  xlink_total_chunk_len = 0;
  xlink_found_first_chunk = FALSE;
  //auth_subcmd = 0;

  cts start: {
    goto command_state;
  }
  
  stc start : {
    goto response_state;
  }
}

state command_state
{
    unsigned tmp:32;
    unsigned unknown_cmd_start:32;
    
    cts start : 
    {
        if(need_skip_lines > 0)
        {
            if(rsp_code < 400)
            {
                 goto cycle_lines_state;
            }
        }
    }
    stc start :
    {
        goto response_state;		
    }
	if (passid == 5){
	    userid = 0;
	    field_begin("smtp-req-passwd");
	    field_flag(DATA_CACHE);
	}
	if (userid == 5){
	    passid = 5;
	    userid = 6;
	}
	
    smtp_command = UNKNOWN_CMD;
	pktnum++;
	/* After 1st request, we need check all the response code afterwards until seeing DATA and STARTTLS key command.*/
	if (pktnum == 1) {
		if (no_smtp_check == 1) {
			no_smtp_check = 0;
		}
        if(($+ - $)> 3)
        {
            if(*($):32 & 0x80808080 && rsp_pktnum == 0){
				switch "unknown-tcp";
				exit();
			}
		}	

    }

    cts end : 
    { 
        /* Can move this check once we have cts end flow/stc end flow */
        /** zealot add*/
        if (rsp_code == 334)
        {
            if(passid == 5 && userid ==6)
            {
                field_end();
                field_end();
                print("-->%d %x \n", $, *($):32) ;
            }

	    if (passid == 5 && userid == 0){
		passid = 0;
		WEAK_PASSWD_CHECK("smtp-req-user","smtp-req-passwd");
	    	field_end();
	    }
		
            goto response_state;
        }
        if (smtp_command == UNKNOWN_CMD) 
        {
            if ($ >= unknown_cmd_start) 
            {
                unknown_cmd_len += $ - unknown_cmd_start;
            }
            eval("smtp-req-unknown-cmd-length", unknown_cmd_len);
			/*
			 * For any randomly typed smtp request commant, let's wait for the smtp response code before doing validation.
			 * But if the 1st response does not have any "SMTP" key words, exit to unknown-tcp.
			 */
			if (unknown_cmd_len > 15 && (rsp_code == 0 || rsp_code > 600) && seen_esmtp == 0 && no_smtp_check == 0){
				if (*($ - 1):8 == 0x0a || rsp_pktnum > 0){
					switch "unknown-tcp";
					exit();
				}
			}
            unknown_cmd_start = $;
        }
    }
    need_skip_lines = 0;
    ftp_command = 0;
    smtp_bdat_chunk_size = 0;
    smtp_command = UNKNOWN_CMD;
    unknown_cmd_len = 0;
    unknown_cmd_start = $;
   if(rsp_code == 334 && passid == 5 && userid ==6)
    {
        field_begin("icmp-req-header");
        print("-->%d %x \n", $, *($):32 );
    }
 FIELD_BEGIN_IGNORE_CASE("smtp-req-unknown-command");

    

    cts ".*AUTH" :
    {
	userid = 5;
    }
    
    /* This check is for CVE-2005-2287 */
    skip(1);
    if (*($ - 1):8 == 0x20) 
    {
        eval("smtp-req-error-code", SMTP_UNKNOWN_CMD_SPACE_FIRST_CHAR);
    }
    if(auth_state == TLS_OKAY)
    {
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,0,0,0)))
            setdecoder "ssl";
            auth_state = UNKNOWN_AUTH_TYPE;
            goto init;
#else
            exit();
#endif        
    }
    if(auth_state == TLS_START) 
    {
        auth_state = UNKNOWN_AUTH_TYPE;
    }
    
    cts ".*(\x99 17 6a 77\x|\xc4 2a 02 75\x|\xad 32 aa 71\x)" : 
    {
        if (smtp_command == UNKNOWN_CMD) 
        {
            eval("smtp-req-error-code", WMAIL_RETADDR_FOUND);
        }
    }
    cts ".*(\x59 54 c3 77\x|\x38 07 d2 77\x|\x65 22 be 77\x)" : 
    {
        if (smtp_command == UNKNOWN_CMD)
	{
	  if ($ + 22 < $+) {
	    if (*($ + 18):32 == 0x77303074) {
	      eval("smtp-req-error-code", NJSTAR_RETADDR_FOUND);
	    }
	  }
	}
    }
    
    /*
    cts ".*MAIL FROM"   ignore_case: { if(($ == 9) || (*($ - 10):8 == 0x0a)){ COMMAND_PARSING(MAIL) } }
    cts ".*RCPT TO"     ignore_case: { if(($ == 7) || (*($ - 8):8 == 0x0a)){ COMMAND_PARSING(RCPT) } }
    cts ".*SAML "       ignore_case: { if(($ == 5) || (*($ - 6):8 == 0x0a)){ COMMAND_PARSING(SAML) } }
    cts ".*SOML "       ignore_case: { if(($ == 5) || (*($ - 6):8 == 0x0a)){ COMMAND_PARSING(SOML) } }
    cts ".*EHLO "       ignore_case: { if(($ == 5) || (*($ - 6):8 == 0x0a)){ COMMAND_PARSING(EHLO) } }
    cts ".*HELO "       ignore_case: { if(($ == 5) || (*($ - 6):8 == 0x0a)){ COMMAND_PARSING(HELO) } }
    cts ".*DATA"        ignore_case: { if(($ == 4) || (*($ - 5):8 == 0x0a)){ COMMAND_PARSING(DATA) } }
    cts ".*AUTH "       ignore_case: { if(($ == 5) || (*($ - 6):8 == 0x0a)){ COMMAND_PARSING(AUTH) } }
    cts ".*RSET"        ignore_case: { if(($ == 4) || (*($ - 5):8 == 0x0a)){ COMMAND_PARSING(RSET) } }
    cts ".*QUIT"        ignore_case: { if(($ == 4) || (*($ - 5):8 == 0x0a)){ COMMAND_PARSING(QUIT) } }
    cts ".*xtellmail"   ignore_case: { if(($ == 9) || (*($ - 10):8 == 0x0a)){ COMMAND_PARSING(XTELLMAIL) } }
    cts ".*X-EXPS"      ignore_case: { if(($ == 6) || (*($ - 7):8 == 0x0a)){ COMMAND_PARSING(XEXPS) } }
    cts ".*XEXCH50"     ignore_case: { if(($ == 7) || (*($ - 8):8 == 0x0a)){ COMMAND_PARSING(XEXCH50) } }
    cts ".*X-LINK2STATE" ignore_case: {if(($ == 12) || (*($ - 13):8 == 0x0a)){ COMMAND_PARSING(XLINK2STATE) } }
    */
    
    SET_CMD_PARSE(MAIL FROM,MAIL)
    SET_CMD_PARSE(RCPT TO,RCPT)
    SET_CMD_PARSE(SAML\x20\x,SAML)
    SET_CMD_PARSE(SOML\x20\x,SOML)
    SET_CMD_PARSE(EHLO,EHLO)
    SET_CMD_PARSE(HELO,HELO)
    SET_CMD_PARSE(DATA\x20\x?\r?\n,DATA)
    SET_CMD_PARSE(AUTH\x20\x,AUTH)
    SET_CMD_PARSE(RSET\r?\n,RSET)
    SET_CMD_PARSE(QUIT\r?\n,QUIT)
    SET_CMD_PARSE(xtellmail\x20\x,XTELLMAIL)
    SET_CMD_PARSE(X-EXPS\x20\x,XEXPS)
    SET_CMD_PARSE(XEXCH50\x20\x,XEXCH50)
    SET_CMD_PARSE(X-LINK2STATE\x20\x,XLINK2STATE)
    SET_CMD_PARSE(STARTTLS,STARTTLS)
    /** zealot add */
    SET_CMD_PARSE(VRFY,VRFY)
    SET_CMD_PARSE(EXPN,EXPN)
    cts ".*BDAT"        ignore_case: { COMMAND_PARSING(BDAT) }
    cts ".*USER" ignore_case: { ftp_command = 1; }
}

state argument_state 
{
    unsigned smtp_req_arg_len: 32;
    unsigned offset:32;
    unsigned xexch_len:32;
    unsigned ignore_data_length:32;
    unsigned xlink_chunk_found:8;
    unsigned rcpt_addr_amp_found:8;
    unsigned char_byte:8;

    /** zealot add */
    unsigned vrfy_expn_is_cached:8;
    
    
    //FIELD_BEGIN_IGNORE_CASE("smtp-req-argument");
    FIELD_BEGIN_IGNORE_CASE_QUALIFIER("smtp-req-argument",smtp_command,ANY);
    ignore_data_length = 0;

	if (smtp_command != UNKNOWN_CMD && seen_esmtp == 1){
		no_smtp_check = 1;
	}

    //add if below for brut-force attack by cuichen.zealot
    if(smtp_command == VRFY || smtp_command == EXPN)
    {
        field_flag(DATA_CACHE);
        vrfy_expn_is_cached = 1;
    }

    /* we should skip to ':' for MAIL and RCPT command */
    if((smtp_command == MAIL) || (smtp_command == RCPT))
    {
        char_byte = 0;
		if (smtp_command == RCPT && rsp_pktnum >= 3) { no_smtp_check = 1;}
        do
        {
            if(char_byte > 10)
            {
                /** zealot modify */
                char_byte = 0x0a; /* we should eval an error and quit */
                break;
            }
            skip(1);
            char_byte++;
        } while(*($ - 1):8 == 0x20);
        smtp_req_arg_len = $;
        if(*($ - 1):8 != 0x3a) /* : */
        {
            eval("smtp-req-error-code",INVALID_MAIL_ADDRESS);
            scope_end(PDU);
            goto init;
        }
    }
    else if(smtp_command == HELO)
    {
        bp_auth_gssapi_attack |= 1;
        do
        {
            skip(1);
            char_byte = *($ - 1):8;
        } while((char_byte == 0x20) || (char_byte == 0x09));
        smtp_req_arg_len = $;
        if((char_byte < 0x20) || (char_byte > 0x7e)) //invalid char
        {
            if((char_byte != 0x0d) && (char_byte != 0x0a))
            {
                skip(1);
                char_byte = *($ - 1):8;
                if((char_byte == 0x0d) || (char_byte == 0x0a))
                {
                    eval("smtp-req-error-code", INVALID_CHAR_IN_HELO);
                    exit();
                }    
            }
        }
    }
    else if(smtp_command == BDAT)
    {
		no_smtp_check = 1;
        //caculate the length BDAT NNNNNNN [AAAA]
        do
        {
            skip(1);
            char_byte = *($ - 1):8;
        } while(char_byte == 0x20);
        smtp_req_arg_len = $ - 1;
        xexch_len = 0;
        while((char_byte < 0x39) && (char_byte > 0x2f))
        {
            skip(1);
            char_byte = *($ - 1):8;
            xexch_len ++;
            if(xexch_len > 0x20)
            {
                eval("smtp-req-error-code", BDAT_OVERLONG_DATALEN);
                exit();
            }
        }
        smtp_bdat_chunk_size = atoi(smtp_req_arg_len,10);
    }
    else
    {
        smtp_req_arg_len = $;
        if(smtp_command == EHLO)
        {
            bp_auth_gssapi_attack &= 0xfe;
        }
    }
    xlink_chunk_found = FALSE;
    rcpt_addr_amp_found = FALSE;

    /* Bug 34792: 
	 * In the case of AUTH LOGIN, the coming requests could be treated as unknown command, we should bypass this.
	 * Ref: http://www.fehcom.de/qmail/smtpauth.html 
	 * In this case, normally server should response 220 or 250 before this request.
	 */
    if (smtp_command == AUTH)
    {
		if (rsp_code == 250 || rsp_code == 220) {
			no_smtp_check = 3;
		}	
    }
    else if(smtp_command == DATA)  /* WHY WE put this in? we have a bug in software, because of a DFA pattern '\n'
                                    in this state, it will be confilic with .*\nDATA\n. There is a software bug
                                    which will stop the .*\n matches. Then we need execute the right command here rather
                                    than waiting for line end. */ 
    {
        no_smtp_check = 1;
        goto data_state;
    } 
    else if((smtp_command == RSET) || (smtp_command == QUIT))
    {
        scope_end(PDU);
        goto command_state;
    }
    else if (smtp_command == XEXCH50) 
    {
		no_smtp_check = 1;
        do 
        {
            skip (1);
        } while (*($ - 1):8 == 0x20);
        offset = $ - 1;
        /* Check MS03-026 error when length is negative */
        if (*($ - 1):8 == 0x2d) 
        {
            eval("smtp-req-error-code", XEXCH50_NEGATIVE_LENGTH_ERROR);
        }
        else 
        {
            /* Check MS03-026 error when length is a large value */
            xexch_len = 1;
            do 
            {
                skip (1);
                xexch_len ++;
                if (xexch_len > 10) 
                {
                    break;
                }
            } while (*($ - 1):8 != 0x20);
            
            xexch_len = atoi(offset, 10);
            ignore_data_length = xexch_len;
            eval("smtp-req-xexch50-length", xexch_len);
        }
    }

    cts ".*\(\) \{" : {
	if(smtp_command == MAIL || smtp_command == RCPT) {
	    eval("smtp-req-cve-2014-6271",1);
	}
    }
    
    cts ".*FIRST CHUNK" ignore_case: 
    {
        if (smtp_command == XLINK2STATE) 
        {
            xlink_found_first_chunk = TRUE;
        }
    }
    
    cts ".*CHUNK=" ignore_case: 
    {
        xlink_chunk_found = TRUE;
    }
    
    /* This is for checking the vulnerable condition related to CVE-2006-4379 */
    
    cts ".*\x20 3c 40\x" : 
    {
        if (smtp_command == RCPT) 
        {
            skip(5);
            if (*($ - 1):8 == 0x3a) 
            { /* Colon(:) character */
                rcpt_addr_amp_found = TRUE;
            }
        }
    }
    cts ".*%[0-9\.]+$hn" :
    {
        fmt_count();
    }
    cts ".*%[ns]":
    {
        fmt_count();
    }
    cts ".*GSSAPI" ignore_case:
    {
        if((smtp_command == XEXPS) || (smtp_command == AUTH))
        {
            need_skip_lines = 1;
            if(smtp_command == AUTH)
            {
                if(rsp_code >= 500)
                {
                   if(auth_subcmd != 0 && auth_subcmd != GSSAPI) eval("smtp-req-CVE-2011-1720-found", 1);
                }
                if((bp_auth_gssapi_attack & 3) == 1)
                {
                    bp_auth_gssapi_attack |= 4;
                }
            }
            auth_subcmd = GSSAPI;
        }
    }
    cts ".*cram-md5" ignore_case:
    {
        if(smtp_command == AUTH)
        {
            need_skip_lines = 1;
            if(rsp_code >= 500)
            {
               if(auth_subcmd != 0 && auth_subcmd != CRAMMD5) eval("smtp-req-CVE-2011-1720-found", 1);
            }
            auth_subcmd = CRAMMD5;
        }
    }
    cts ".*digest-md5" ignore_case:
    {
        if(smtp_command == AUTH)
        {
            need_skip_lines = 1;
            if(rsp_code >= 500)
            {
               if(auth_subcmd != 0 && auth_subcmd != DIGESTMD5) eval("smtp-req-CVE-2011-1720-found", 1);
            }
            auth_subcmd = DIGESTMD5;
        }
    }
    cts ".*ntlm" ignore_case:
    {
        if(smtp_command == AUTH)
        {
            need_skip_lines = 2;
            if(rsp_code >= 500)
            {
               if(auth_subcmd != 0 && auth_subcmd != NTLM) eval("smtp-req-CVE-2011-1720-found", 1);
            }
            auth_subcmd = NTLM;
        }
    }

    sub fmt_count()
    {
        seen_percent_s++;
        if (seen_percent_s >= 2) 
        {
             if ((smtp_command == EHLO) ||
            (smtp_command == HELO) ||
            (smtp_command == MAIL) ||
            (smtp_command == SEND) || 
            (smtp_command == SAML) ||
            (smtp_command == SOML) ||
            (smtp_command == RCPT) ||
            (smtp_command == XTELLMAIL) ||
            (smtp_command == AUTH)) 
            {
                seen_percent_s = 0;
                eval("smtp-req-error-code", SMTP_FORMAT_STRING_ERROR);
            }
        }
        return 1;
    }
    cts ".*\n" : 
    {
        smtp_req_arg_len = $ - smtp_req_arg_len;
        if ((smtp_command == EHLO) ||  
            (smtp_command == HELO)) 
        {
            eval("smtp-req-helo-argument-length", smtp_req_arg_len);
        }
        else if ((smtp_command == MAIL ) ||
                 (smtp_command == SEND ) || 
                 (smtp_command == SAML ) ||
                 (smtp_command == SOML )) 
        {
            EVAL_QUALIFIER("smtp-req-mail-argument-length", smtp_req_arg_len,smtp_command,ANY,ANY,ANY);
        }
        else if (smtp_command == RCPT ) 
        {
            eval("smtp-req-rcpt-argument-length", smtp_req_arg_len);
        }
        else if (smtp_command == AUTH ) 
        {
            eval("smtp-req-auth-argument-length", smtp_req_arg_len);
        }
        else 
        {
            eval("smtp-req-argument-length", smtp_req_arg_len);
        }
        
        if (rcpt_addr_amp_found == TRUE) 
        {
            if (smtp_req_arg_len > 256) 
            {
                eval("smtp-req-error-code", RCPT_CVE_2006_4379_FORMAT_OVERLONG);
            }
        }
        
        field_end();

        //add if below for brut-force attack by cuichen.zealot
        if(1 == vrfy_expn_is_cached || smtp_command == AUTH)
        {
            BRUT_FORCE_ATTACK_CHECK("smtp-req-argument");
            vrfy_expn_is_cached = 0;
        }

		/* In the case of AUTH LOGIN, after 10th request check, we should mark back the no_smtp_check to be 0 to force the validation
		 * again.
		 */
		if (no_smtp_check == 3) {
			if (pktnum >= 10) {
				no_smtp_check = 0;
			}
		}	
        if(smtp_command == DATA || smtp_command == BDAT) 
        {
			no_smtp_check = 1;
            goto data_state;
        }
        else if(smtp_command == XEXCH50)
        {
			no_smtp_check = 1;
            ignore(ignore_data_length);
        }
        /* For MS05-021, the vulnerability is due to a heap overflow, when
        FIRST CHUNK is not seen, due to which no heap structures are init'ed.
        So when CHUNK= is seen, data is written to arbitrary heap structures.
        Hence, we check that we have not seen FIRST CHUNK, and then CHUNK len > 520 */
        else if (smtp_command == XLINK2STATE) 
        {
            if (xlink_found_first_chunk == FALSE) 
            {
                if (xlink_chunk_found == TRUE) 
                {
                    xlink_total_chunk_len += smtp_req_arg_len;
                    eval("smtp-req-xlink2state-chunk-len", xlink_total_chunk_len);
                }
            }
        }
        else if(smtp_command == STARTTLS)
        {
            auth_state = TLS_START;
			no_smtp_check = 1;
            if(($ + 4)< $+)
            {
                /* Normally, There should not has extra command after STARTTLS command */
                if((*($):32 & 0x80808080) == 0)
                {
                    eval("smtp-req-extra-command-after-stattls",1);    
                }
            }
        }
        else if(need_skip_lines > 0)
        {
            goto need_more_lines_state;
        }
        /* Default case */
        scope_end(PDU);
        //goto command_state ;
        //zealot modified 20131105
        goto back_to_response_state;
        
    }
}
state need_more_lines_state
{
    unsigned start_offset:32;
    
    FIELD_BEGIN_QUALIFIER("smtp-req-need-more-lines-content",smtp_command,ANY);
    if(need_skip_lines == 0)
    {
         scope_end(PDU);
         goto init;
    }
    start_offset = $;
    cts ".*\n":
    {
        if(bp_auth_gssapi_attack & 4)
        {
            eval("smtp-req-smtp-auth-evasive-gssapi-length",$ - start_offset);
        }
        if($ > start_offset)
        {
            EVAL_QUALIFIER("smtp-req-need-more-lines-length",$ - start_offset, smtp_command, auth_subcmd, ANY, ANY);
        }
        goto command_state;
    }
}    
state cycle_lines_state
{
    need_skip_lines--;
    goto need_more_lines_state;
}
state data_state {
      unsigned offset:32;
      unsigned datevar:32;
      unsigned saved_offset:32;
      unsigned filename_len:32;
      unsigned found_virus:8;
      unsigned file_type:8;
#if (PAN_ENGINE_VERSION >= (PAN_VERSION(5,0,0,0)))
      unsigned nested_level:8;
#endif

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,5)))
    set_smtp_data_end(0);
#endif
    /*  added by sunon.zealot submit sender and receiver in 2014/3/5 **/ \
    cts ".*From: " :
    {
        if(found_header_field == 0)
        { 
            found_header_field = 1;               
            field_begin("smtp-req-email-sender");        
        }                                         
    }                                             
    cts ".*\nTo: " :                                    
    {                                             
        if(found_header_field == 0)               
        {                                         
            found_header_field = 1;               
            field_begin("smtp-req-email-receiver");        
        }                                         
    }
    EMAIL_PARSING(SMTP)
    if((smtp_command == BDAT) && (smtp_bdat_chunk_size > 0) && (smtp_bdat_chunk_size < 100))
    {
        skip(1); 
        if($ + smtp_bdat_chunk_size + 9 < $+)
        {
            if(*($ + smtp_bdat_chunk_size - 1):32 == 0x41555448)
            {
                if(*($ + smtp_bdat_chunk_size + 3):32 == 0x204C4F47)
                {
                    if(*($ + smtp_bdat_chunk_size + 7):16== 0x494e)
                    {
                        eval("smtp-req-bdat-dos-auth-login",1);
                    }
                }
            }
        }
        smtp_bdat_chunk_size = 0;
    }                                            


    cts  ".*date: " ignore_case : {
        skip(5, "\x2c\x");
        if($? != 0)
        {
            skip(1);
            offset = $;
            skip(30, "\x20\x");
            if($? != 0)
            {
                datevar = atoi(offset, 10);
                eval("smtp-req-mime-head-date", datevar);
		datevar = 0;
            }
        }
    } 

  cts  ".*NIZER:MAILTO:" : {
      skip(128, "\x0a\x");
      if ($? == 0) {
	  eval("smtp-req-mime-long-mailto-addr", 1);
      }
  }

    cts  ".*\nDTSTAMP:" : 
    {
        skip(8,"\x0a\x");
        if($?)
        {
            eval("smtp-req-malicisou-date",1);
        }
    }

#if (PAN_ENGINE_VERSION >= (PAN_VERSION(4,0,0,5)))
    cts  ".*(\n\.\r\n|\n\.\n)" : {                   
        set_smtp_data_end(1);
        goto init;
    } 
#endif
                                                  
  stc start : {
    goto response_state;
  }
}

state back_to_response_state{
	stc start: {
		goto response_state;
	}

    // zealot add : 20130929
    cts start: {
            goto command_state;
    
    }
}

state response_state {
  unsigned rsp_offset:32;
  unsigned tmp:8;
  unsigned count:8;

  rsp_code = 0;
  rsp_offset = $;


  cts start : {
    if(rsp_code == 354) {
      goto data_state;
    }
    else{
      goto command_state;
    }
  }

  stc end: {
  	if (*($ - 1): 8 == 0x0a){
		/* We may check the response code after seeing 3 continious response packets.*/
		if (rsp_pktnum >= 3 && pktnum == 0){
			if (no_smtp_check == 0) {
	  			VALID_RSPCODE(rsp_code)
			}
		}
		if (rsp_code == 220){
			 /* Since rsp_code will be reset to 0, let's move the TLS check at the stc end.*/	
			if(auth_state == TLS_START)
			{
				auth_state = TLS_OKAY;
			}
		}
        /** zealot add */
        if (rsp_code == 535) 
        {
                  eval("smtp-rsp-authentication-failed",TRUE);
        }

		/* In case it is "unrecognised command" with rsp code 500 or 502, let it be. Otherwise, do validation here.
		 *
		 * 500	Syntax error, command unrecognised
		 * 502	Command not implemented
		 * 235  Authentication successful
		 */
		if (unknown_cmd_len > 15 && pktnum >= 1){
			if (no_smtp_check == 0){
				if (rsp_code != 500 && rsp_code != 502 && rsp_code!= 235){
					if (*($ - 1):8 == 0x0a || rsp_pktnum > 0){
						switch "unknown-tcp";
						exit();
					}
				}	
			}
		}
        //if ($ - rsp_offset >= $pktlen ){
        //zealot modified 20131105
        if ($ - rsp_offset >= $pktlen && rsp_code != 354){
			field_end();
			goto back_to_response_state;
		}
	} else {
	    /* After seeing 512 bytes in the end of any rsp packet not ending with "\n", if we haven't seen any legitimate request, switch to
		 * unknown-tcp.
		 */
		if (no_smtp_check == 0 && $ > 512 && (rsp_code == 0 || rsp_code > 600)) {
			if (smtp_command == UNKNOWN_CMD && pktnum > 0) {
				VALID_RSPCODE(rsp_code)
			}
		}
	}
  }	
 
  stc ".*(relay|connect|database|server)" ignore_case:{
    /** zealot modify */
  	no_smtp_check = 1;
	seen_esmtp = 1;
  }

 /* When seeing "Microsoft ESMTP " from banner, no smtp validation check will be enforced.*/
 stc ".* Microsoft ESMTP " ignore_case:{
  	no_smtp_check = 1;
	seen_esmtp = 1;
 }
  stc ".*Postfix" ignore_case:{
        seen_postfix = 1;
  }
  stc ".*( ESMTP| SMTP)" ignore_case:{
   	seen_esmtp = 1;
	if (*($ - 10):8 == 0x2e || *($ - 9):8 == 0x2e){
		if (rsp_code > 100 && rsp_code < 600) {
			no_smtp_check = 2;
		}
	}
  }

  stc ".*250 ok" ignore_case:{
   	 if (seen_esmtp == 1){
	 	no_smtp_check = 1;
	 }
	 if (smtp_command == RCPT) {
		eval("smtp-rsp-send-mail", 1);
	 }
  }

  /* Take care of connection related response code*/
  stc ".*\n220 " ignore_case:{
   	 rsp_code = 220;
  }

  stc ".*\n421 " ignore_case:{
   	 rsp_code = 421;
  }

  /** zealot add */
  stc "252 " ignore_case:{
     rsp_code = 252;
  }
  stc "334 " ignore_case:{
     rsp_code = 334;
  }
  stc "550 " ignore_case:{
     rsp_code = 550;
  }
  /* modify the rsp_code 535 pattern by sunon.zealot
   * .*\n535 can't match, because the state switch will create new match stream
   * to match the beginning of the stc data, we changed it.
   */
  stc ".*535 " ignore_case:{
         rsp_code = 535;
  }
  /** zealot end */

  stc ".*\n501 " ignore_case:{
         rsp_code = 501;
  }
    stc ".* GSSAPI ":
    {
        bp_auth_gssapi_attack |= 2;
    }

    stc ".*\r\n\r\n[C-Z]:\\" ignore_case:
    {
        eval("smtp-rsp-found-driveprompt",1);
    }

	stc ".*\r\n":{
		if (multiple_line_parse == 1){
			rsp_offset = $;
			skip(4,"\x 20 2d 0a\x");
			rsp_code = atoi(rsp_offset, 10);
			if (rsp_code == 235) { /* Seen the authentication successful.*/
				if (no_smtp_check == 3){no_smtp_check=0;}
			}	
			if (no_smtp_check == 0) {VALID_RSPCODE(rsp_code)}
			if (*($ - 1):8 == 0x20){
				multiple_line_parse = 0;
			}
		}
	}

  FIELD_BEGIN_IGNORE_CASE("smtp-rsp-content");
  rsp_pktnum++;
  #if (PAN_ENGINE_VERSION >= (PAN_VERSION(2,0,11,4)))
  
  /* Read the rsp code from 1st rsp packet.*/
  if (rsp_pktnum == 1) {
      skip(4,"\x 20 2d 0a\x");
	  rsp_code = atoi(rsp_offset, 10);
  }

  /* Selectively check the rsp_code after 1st rsp packets until seeing the DATA command.*/
  if (rsp_pktnum > 1){
	  if (*($ - 1):8 == 0x0a){
		rsp_offset = $;
		skip(4,"\x 20 2d 0a\x");
		rsp_code = atoi(rsp_offset, 10);
		if (rsp_code == 235) { /* Seen the authentication successful.*/
			if (no_smtp_check == 3){no_smtp_check=0;}
		}	
		if (pktnum >= 1 ){
			if (seen_esmtp == 1 && rsp_code < 600 && rsp_code >= 100) {
				no_smtp_check = 1;
			}
			if (*($ - 1):8 == 0x2d){
				if (multiple_line_parse == 0){
					if (no_smtp_check == 0) {
						VALID_RSPCODE(rsp_code)
					}
					multiple_line_parse = 1;
				}
			}
			if (*($ - 1):8 == 0x20){
				multiple_line_parse = 0;
				if (no_smtp_check == 0) {
					VALID_RSPCODE(rsp_code)
				}
			}
		}	
	  }
  }
#endif
  if ((smtp_command == MAIL || smtp_command == RCPT) && rsp_code > 400 && rsp_code < 600) 
  {
	eval("smtp-rsp-mail-transmit-fail", 1);	
  }

  if (rsp_code == 331)  
  {
	if ((ftp_command) && (proven_smtp == 0)) 
	{
		switch "ftp";
	}

  }

  if (rsp_code == 250) { 
        proven_smtp = 1;
  }

  /** zealot modify */
  /*
  if (rsp_code == 535) 
  {
        eval("smtp-rsp-authentication-failed",TRUE);
    }
   */
  /* add 252 and 550 by sunon.zealot */
  if(rsp_code == 252 && (smtp_command == VRFY ))
  {  
    eval("smtp-rsp-vrfy-failed", TRUE);
  }
  if(rsp_code == 550 && smtp_command == EXPN )
  {
    eval("smtp-rsp-expn-failed", TRUE);
  }
  /** zealot end */
}

