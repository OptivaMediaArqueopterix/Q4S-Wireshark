
/* packet-Q4S.c
 * Routines for PROTONAME dissection
 * Copyright 201x, VICTOR MANUEL MAROTO ORTEGA <VICTOR.MAROTO@OPTIVAMEDIA.COM>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *asdasd
 * SPDX-License-Identifier: GPL-2.0+
 */


/*
 * (A short description of the protocol including links to specifications,
 *  detailed documentation, etc.)
 *  Q4S dissection
 */

#include <config.h>

#if 1
/* "System" includes used only as needed */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#endif

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/expert.h>   /* Include only as needed */
#include <epan/prefs.h>    /* Include only as needed */



#if 0
/* IF AND ONLY IF your protocol dissector exposes code to other dissectors
 * (which most dissectors don't need to do) then the 'public' prototypes and
 * data structures can go in the header file packet-q4s.h. If not, then
 * a header file is not needed at all and this #include statement can be
 * removed. */
#include "packet-q4s.h"
#endif


#define q4s_PORT_UDP 27016
#define q4s_PORT_TCP 27015

#define BEGIN 5
#define READY 5
#define PING 4
#define BWIDTH 6
#define CANCEL 6
#define ALERT 9
#define RECOVERY 12
#define LENGTHVERSION 8 //7
#define LENGTHSTATUSCODE 6
#define SPACE 1

//static guint tcp_port_pref = q4s_TCP_PORT;

static guint proto_q4s = -1;

static int hf_q4s_method_type = -1;
static gint ett_q4s = -1;
static int hf_q4s_uri = -1;
static int hf_q4s_version = -1;
static int hf_q4s_statuscode = -1;
static int hf_q4s_headerfields = -1;
static int hf_q4s_payload = -1;

static const value_string methodnames[] = {
    { 1346981447 , "PING" }, //0x50494e47
    { 1113016644, "BWIDTH" },//0x425749445448 => da error con el ninja
    { 1111836489, "BEGIN" },//0x424547494e =>284630141262
    { 1380270404, "READY" },//0x5245414459 =>353349223513
    { 3, "CANCEL" },//0x43414e43454c =>73947764966732
    { 4, "Q4S_ALERT" },//0x5134535f414c455254 =>1497956732017570042452
    { 5 , "Q4S_RECOVERY" },//0x5134535f5245434f56455259 =>25131543652935894959284114009
    { 0, NULL }
};


static const value_string statuscodenames[] = {
    { 1 , "Provisional" },
    { 842018848, "Success" },
    { 3, "Redirection" },
    { 4, "Request Failure" },
    { 5, "Server Error" },
    { 6, "Global Failure" },
    { 0, NULL }
};

static const value_string headerfieldsnames[] = {
    { 1 , "Session-Id" },
    { 1399157109, "Sequence-Number" },
    { 1416195429, "Timestamp" },
    { 1400136039, "Stage" },
    { 5, "User-Agent" },
    { 6, "Signature" },
    { 1298489715, "Measurements" },
    { 6, "Expires" },
    { 0, NULL }
};

void proto_register_q4s(void){



    static hf_register_info hf[] = { 
        { &hf_q4s_method_type,
            { "q4s method", "q4s.methodtype",
            FT_UINT8, BASE_DEC,//FT_UINT8
            VALS(methodnames), 0x0,
            NULL, HFILL }
        },
        { &hf_q4s_uri,
            { "q4s  URI", "q4s.uri",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_q4s_version,
            { "q4s version", "q4s.version",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_q4s_statuscode,
            { "q4s status code", "q4s.status",
            FT_UINT8, BASE_DEC,
            VALS(statuscodenames), 0x0,
            NULL, HFILL }
        },
        { &hf_q4s_headerfields,
            { "q4s header fields", "q4s.headerfields",
            FT_UINT8, BASE_DEC,
            VALS(headerfieldsnames), 0x0,
            NULL, HFILL }
        },
        { &hf_q4s_payload,
            { "q4s payload", "q4s.payload",
            FT_UINT8, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        }
    };
 
 
  /* Setup protocol subtree array */
    static gint *ett[] = {
    &ett_q4s
    };

    proto_q4s=proto_register_protocol("Q4S Protocol","Q4S","q4s"); 
    proto_register_field_array(proto_q4s, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}

static gint dissect_q4s(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    gint offset = 0;
    proto_item  *ti = NULL;
    proto_tree  *q4s_tree=NULL;
    gboolean    FirstSearch=TRUE;
    gint        newlen=0, len=0;
   
 
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Q4S");
    /*Clear out stuff in the info column*/
    col_clear(pinfo->cinfo, COL_INFO);
    ti = proto_tree_add_item(tree, proto_q4s, tvb, 0, -1, ENC_NA);
    q4s_tree = proto_item_add_subtree(ti, ett_q4s);
    char *method;
    method = tvb_get_string_enc(NULL, tvb, offset, 15, ENC_UTF_8|ENC_BIG_ENDIAN);
    //method = tvb_get_string_enc(NULL, tvb, offset, 320, ENC_UTF_8|ENC_LITTLE_ENDIAN);
      
    switch (method[0]){

        case 'B':
            switch (method[1]) {
                case 'W': // BWIDT
                    proto_tree_add_item (q4s_tree, hf_q4s_method_type, tvb, offset, BWIDTH, ENC_BIG_ENDIAN);
                    offset+=BWIDTH;
                break;
                case 'E': //BEGIN
                    proto_tree_add_item (q4s_tree, hf_q4s_method_type, tvb, offset, BEGIN, ENC_BIG_ENDIAN);
                    offset+=BEGIN;
                break;
            }
        break;
        case 'P': //PING
            proto_tree_add_item (q4s_tree, hf_q4s_method_type, tvb, offset, PING, ENC_BIG_ENDIAN);
            offset+=PING;
        break;
        case 'R': //READY
            proto_tree_add_item (q4s_tree, hf_q4s_method_type, tvb, offset, READY, ENC_BIG_ENDIAN);
            offset+=READY;
        break;
        case 'C': //CANCEL
            proto_tree_add_item (q4s_tree, hf_q4s_method_type, tvb, offset, CANCEL, ENC_BIG_ENDIAN);
            offset+=CANCEL;
        break;
        case 'Q':
            switch (method[4]) {
                case 'A': //BEGIN
                    proto_tree_add_item (q4s_tree, hf_q4s_method_type, tvb, offset, ALERT, ENC_BIG_ENDIAN);
                    offset+=ALERT;
                break;
                case 'R': // RECOVERY
                    proto_tree_add_item (q4s_tree, hf_q4s_method_type, tvb, offset, RECOVERY, ENC_BIG_ENDIAN);
                    offset+=RECOVERY;
                break;
            }
        break;
        default:
        proto_tree_add_item (q4s_tree, hf_q4s_method_type, tvb, offset, PING, ENC_BIG_ENDIAN);
    }
    

    /***** URI SEARCH ****/

    char *uri, *field;
    len = tvb_captured_length_remaining(tvb, offset);
    uri = tvb_get_string_enc(NULL, tvb, offset, len, ENC_UTF_8|ENC_BIG_ENDIAN);

    for (int i=0; i<len; i++){
        if(uri[i]=='\n' && FirstSearch){
            newlen=i;
            FirstSearch=FALSE;
        }
    }
    uri = tvb_get_string_enc(NULL, tvb, offset, newlen, ENC_UTF_8|ENC_BIG_ENDIAN);
    if (uri[1]=='q'){
        proto_tree_add_item (q4s_tree, hf_q4s_uri, tvb, offset, newlen-LENGTHVERSION, ENC_BIG_ENDIAN);
        offset+=newlen-LENGTHVERSION+SPACE;
    }

    /***** END URI *****/

    proto_tree_add_item (q4s_tree, hf_q4s_version, tvb, offset, LENGTHVERSION, ENC_BIG_ENDIAN);
    offset+=LENGTHVERSION; 


    len = tvb_captured_length_remaining(tvb, offset);
    
    if (len>2){
        field = tvb_get_string_enc(NULL, tvb, offset, len, ENC_UTF_8|ENC_BIG_ENDIAN);
       
        /*FirstSearch=TRUE;
        for (int i=0; i<len; i++){
            if(field[i]=='\n' && FirstSearch ){ //&& FirstSearch 
                newlen=i;
                FirstSearch=FALSE;
            }
        }*/
        switch (field[0]){
            case '1':
                proto_tree_add_item (q4s_tree, hf_q4s_statuscode, tvb, offset, LENGTHSTATUSCODE, ENC_BIG_ENDIAN);
                offset+=LENGTHSTATUSCODE;
            break;
            case '2':
                proto_tree_add_item (q4s_tree, hf_q4s_statuscode, tvb, offset, LENGTHSTATUSCODE, ENC_BIG_ENDIAN);
                offset+=LENGTHSTATUSCODE;
            break;
            case '3':
                proto_tree_add_item (q4s_tree, hf_q4s_statuscode, tvb, offset, LENGTHSTATUSCODE, ENC_BIG_ENDIAN);
                offset+=LENGTHSTATUSCODE;
            break;
            case '4':
                proto_tree_add_item (q4s_tree, hf_q4s_statuscode, tvb, offset, LENGTHSTATUSCODE, ENC_BIG_ENDIAN);
                offset+=LENGTHSTATUSCODE;
            break;
            case '5':
                proto_tree_add_item (q4s_tree, hf_q4s_statuscode, tvb, offset, LENGTHSTATUSCODE, ENC_BIG_ENDIAN);
                offset+=LENGTHSTATUSCODE;
            break;
            case '6':
                proto_tree_add_item (q4s_tree, hf_q4s_statuscode, tvb, offset, LENGTHSTATUSCODE, ENC_BIG_ENDIAN);
                offset+=LENGTHSTATUSCODE;
            break;
        }
    }
  
    len = tvb_captured_length_remaining(tvb, offset);
    while ((len>2)){
        field = tvb_get_string_enc(NULL, tvb, offset, len, ENC_UTF_8|ENC_BIG_ENDIAN);
        FirstSearch=TRUE;
        for (int i=0; i<len; i++){
            if(field[i]=='\n'&& FirstSearch  ){ //&& FirstSearch 
                newlen=i;
                FirstSearch=FALSE;
            }
        }
        switch (field[0]){
            case 'S':
                switch (field[2]){
                    case 's':// Session-Id
                        proto_tree_add_item (q4s_tree, hf_q4s_headerfields, tvb, offset, newlen, ENC_BIG_ENDIAN);
                        offset+=newlen;
                    break;
                    case 'q': // Sequence-Number
                        proto_tree_add_item (q4s_tree, hf_q4s_headerfields, tvb, offset, newlen, ENC_BIG_ENDIAN);
                        offset+=newlen;
                    break;
                    case 'a': // Stage
                        proto_tree_add_item (q4s_tree, hf_q4s_headerfields, tvb, offset, newlen, ENC_BIG_ENDIAN);
                        offset+=newlen;
                    break;
                    case 'g': // Signature
                        proto_tree_add_item (q4s_tree, hf_q4s_headerfields, tvb, offset, newlen, ENC_BIG_ENDIAN);
                        offset+=newlen;
                    break;
                }
            break;
            case 'T': // Timestamp
                proto_tree_add_item (q4s_tree, hf_q4s_headerfields, tvb, offset, newlen, ENC_BIG_ENDIAN);
                offset+=newlen;
            break;
            case 'M': // Measurements
                proto_tree_add_item (q4s_tree, hf_q4s_headerfields, tvb, offset, newlen, ENC_BIG_ENDIAN);
                offset+=newlen;
            break;
            case 'U': // User-Agent
                proto_tree_add_item (q4s_tree, hf_q4s_headerfields, tvb, offset, newlen, ENC_BIG_ENDIAN);
                offset+=newlen;
            break;
            case 'E': // Expires
                proto_tree_add_item (q4s_tree, hf_q4s_headerfields, tvb, offset, newlen, ENC_BIG_ENDIAN);
                offset+=newlen;
            break;
            default:
                goto BREAK;
            break;
        }
        offset+=1;
        len = tvb_captured_length_remaining(tvb, offset);
    }

    BREAK:
    //printf("fin\n");
    if (len>2){
        proto_tree_add_item (q4s_tree, hf_q4s_payload, tvb, offset, len, ENC_BIG_ENDIAN);
    }


    return tvb_captured_length(tvb);
}

void proto_reg_handoff_q4s(void){

    static dissector_handle_t q4s_handle;
    q4s_handle =create_dissector_handle(dissect_q4s, proto_q4s);
    dissector_add_uint("udp.port", q4s_PORT_UDP, q4s_handle);
    dissector_add_uint("tcp.port", q4s_PORT_TCP, q4s_handle);
}



