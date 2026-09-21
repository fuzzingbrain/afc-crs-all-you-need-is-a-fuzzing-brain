/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2017, Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "curl_fuzzer.h"

/**
 * TLV access function - gets the first TLV from a data stream.
 */
int fuzz_get_first_tlv(FUZZ_DATA *fuzz,
                       TLV *tlv)
{
  /* Reset the cursor. */
  fuzz->state.data_pos = 0;
  return fuzz_get_tlv_comn(fuzz, tlv);
}

/**
 * TLV access function - gets the next TLV from a data stream.
*/
int fuzz_get_next_tlv(FUZZ_DATA *fuzz,
                      TLV *tlv)
{
  /* Advance the cursor by the full length of the previous TLV. */
  fuzz->state.data_pos += sizeof(TLV_RAW) + tlv->length;

  /* Work out if there's a TLV's worth of data to read */
  if(fuzz->state.data_pos + sizeof(TLV_RAW) > fuzz->state.data_len) {
    /* No more TLVs to parse */
    return TLV_RC_NO_MORE_TLVS;
  }

  return fuzz_get_tlv_comn(fuzz, tlv);
}

/**
 * Common TLV function for accessing TLVs in a data stream.
 */
int fuzz_get_tlv_comn(FUZZ_DATA *fuzz,
                      TLV *tlv)
{
  int rc = 0;
  size_t data_offset;
  TLV_RAW *raw;

  /* Start by casting the data stream to a TLV. */
  raw = (TLV_RAW *)&fuzz->state.data[fuzz->state.data_pos];
  data_offset = fuzz->state.data_pos + sizeof(TLV_RAW);

  /* Set the TLV values. */
  tlv->type = to_u16(raw->raw_type);
  tlv->length = to_u32(raw->raw_length);
  tlv->value = &fuzz->state.data[data_offset];

  FV_PRINTF(fuzz, "TLV: type %x length %u\n", tlv->type, tlv->length);

  /* Use uint64s to verify lengths of TLVs so that overflow problems don't
     matter. */
  uint64_t check_length = data_offset;
  check_length += tlv->length;

  uint64_t remaining_len = fuzz->state.data_len;
  FV_PRINTF(fuzz, "Check length of data: %" PRIu64 " \n", check_length);
  FV_PRINTF(fuzz, "Remaining length of data: %" PRIu64 " \n", remaining_len);

  /* Sanity check that the TLV length is ok. */
  if(check_length > remaining_len) {
    FV_PRINTF(fuzz, "Returning TLV_RC_SIZE_ERROR\n");
    rc = TLV_RC_SIZE_ERROR;
  }

  return rc;
}

/**
 * Do different actions on the CURL handle for different received TLVs.
 */
int fuzz_parse_tlv(FUZZ_DATA *fuzz, TLV *tlv)
{
  int rc;
  char *tmp = NULL;
  uint32_t tmp_u32;
  curl_slist *new_list;

  switch(tlv->type) {
    /* The pointers in response TLVs will always be valid as long as the fuzz
       data is in scope, which is the entirety of this file. */
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE0, 0);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE1, 1);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE2, 2);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE3, 3);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE4, 4);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE5, 5);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE6, 6);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE7, 7);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE8, 8);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE9, 9);
    FRESPONSETLV(&fuzz->sockman[0], TLV_TYPE_RESPONSE10, 10);

    FRESPONSETLV(&fuzz->sockman[1], TLV_TYPE_SECOND_RESPONSE0, 0);
    FRESPONSETLV(&fuzz->sockman[1], TLV_TYPE_SECOND_RESPONSE1, 1);

    case TLV_TYPE_UPLOAD1:
      /* The pointers in the TLV will always be valid as long as the fuzz data
         is in scope, which is the entirety of this file. */

      FCHECK_OPTION_UNSET(fuzz, CURLOPT_UPLOAD);

      fuzz->upload1_data = tlv->value;
      fuzz->upload1_data_len = tlv->length;

      FSET_OPTION(fuzz, CURLOPT_UPLOAD, 1L);
      FSET_OPTION(fuzz,
                  CURLOPT_INFILESIZE_LARGE,
                  (curl_off_t)fuzz->upload1_data_len);
      break;

    case TLV_TYPE_HEADER:
      /* Limit the number of headers that can be added to a message to prevent
         timeouts. */
      if(fuzz->header_list_count >= TLV_MAX_NUM_CURLOPT_HEADER) {
        rc = 255;
        goto EXIT_LABEL;
      }

      tmp = fuzz_tlv_to_string(tlv);
      if (tmp == NULL) {
        // keep on despite allocation failure
        break;
      }
      new_list = curl_slist_append(fuzz->header_list, tmp);
      if (new_list == NULL) {
        break;
      }
      fuzz->header_list = new_list;
      fuzz->header_list_count++;
      break;

    case TLV_TYPE_MAIL_RECIPIENT:
      /* Limit the number of headers that can be added to a message to prevent
         timeouts. */
      if(fuzz->header_list_count >= TLV_MAX_NUM_CURLOPT_HEADER) {
        rc = 255;
        goto EXIT_LABEL;
      }
      tmp = fuzz_tlv_to_string(tlv);
      if (tmp == NULL) {
        // keep on despite allocation failure
        break;
      }
      new_list = curl_slist_append(fuzz->mail_recipients_list, tmp);
      if (new_list != NULL) {
        fuzz->mail_recipients_list = new_list;
        fuzz->header_list_count++;
      }
      break;

    case TLV_TYPE_MIME_PART:
      if(fuzz->mime == NULL) {
        fuzz->mime = curl_mime_init(fuzz->easy);
      }

      fuzz->part = curl_mime_addpart(fuzz->mime);

      /* This TLV may have sub TLVs. */
      fuzz_add_mime_part(tlv, fuzz->part);

      break;

    case TLV_TYPE_POSTFIELDS:
      FCHECK_OPTION_UNSET(fuzz, CURLOPT_POSTFIELDS);
      fuzz->postfields = fuzz_tlv_to_string(tlv);
      FSET_OPTION(fuzz, CURLOPT_POSTFIELDS, fuzz->postfields);
      break;

    case TLV_TYPE_HTTPPOSTBODY:
      FCHECK_OPTION_UNSET(fuzz, CURLOPT_HTTPPOST);
      fuzz_setup_http_post(fuzz, tlv);
      FSET_OPTION(fuzz, CURLOPT_HTTPPOST, fuzz->httppost);
      break;

    /* Define a set of u32 options. */
    FU32TLV(fuzz, TLV_TYPE_HTTPAUTH, CURLOPT_HTTPAUTH);
    FU32TLV(fuzz, TLV_TYPE_OPTHEADER, CURLOPT_HEADER);
    FU32TLV(fuzz, TLV_TYPE_NOBODY, CURLOPT_NOBODY);
    FU32TLV(fuzz, TLV_TYPE_FOLLOWLOCATION, CURLOPT_FOLLOWLOCATION);
    FU32TLV(fuzz, TLV_TYPE_WILDCARDMATCH, CURLOPT_WILDCARDMATCH);
    FU32TLV(fuzz, TLV_TYPE_RTSP_REQUEST, CURLOPT_RTSP_REQUEST);
    FU32TLV(fuzz, TLV_TYPE_RTSP_CLIENT_CSEQ, CURLOPT_RTSP_CLIENT_CSEQ);
    FU32TLV(fuzz, TLV_TYPE_HTTP_VERSION, CURLOPT_HTTP_VERSION);
    FU32TLV(fuzz, TLV_TYPE_NETRC, CURLOPT_NETRC);
    FU32TLV(fuzz, TLV_TYPE_WS_OPTIONS, CURLOPT_WS_OPTIONS);
    FU32TLV(fuzz, TLV_TYPE_CONNECT_ONLY, CURLOPT_CONNECT_ONLY);
    FU32TLV(fuzz, TLV_TYPE_POST, CURLOPT_POST);
    FU32TLV(fuzz, TLV_TYPE_FILETIME, CURLOPT_FILETIME);

    /* Define a set of singleton TLVs - they can only have their value set once
       and all follow the same pattern. */
    FSINGLETONTLV(fuzz, TLV_TYPE_URL, CURLOPT_URL);
    FSINGLETONTLV(fuzz, TLV_TYPE_DOH_URL, CURLOPT_DOH_URL);
    FSINGLETONTLV(fuzz, TLV_TYPE_USERNAME, CURLOPT_USERNAME);
    FSINGLETONTLV(fuzz, TLV_TYPE_PASSWORD, CURLOPT_PASSWORD);
    FSINGLETONTLV(fuzz, TLV_TYPE_COOKIE, CURLOPT_COOKIE);
    FSINGLETONTLV(fuzz, TLV_TYPE_RANGE, CURLOPT_RANGE);
    FSINGLETONTLV(fuzz, TLV_TYPE_CUSTOMREQUEST, CURLOPT_CUSTOMREQUEST);
    FSINGLETONTLV(fuzz, TLV_TYPE_MAIL_FROM, CURLOPT_MAIL_FROM);
    FSINGLETONTLV(fuzz, TLV_TYPE_ACCEPTENCODING, CURLOPT_ACCEPT_ENCODING);
    FSINGLETONTLV(fuzz, TLV_TYPE_RTSP_SESSION_ID, CURLOPT_RTSP_SESSION_ID);
    FSINGLETONTLV(fuzz, TLV_TYPE_RTSP_STREAM_URI, CURLOPT_RTSP_STREAM_URI);
    FSINGLETONTLV(fuzz, TLV_TYPE_RTSP_TRANSPORT, CURLOPT_RTSP_TRANSPORT);
    FSINGLETONTLV(fuzz, TLV_TYPE_MAIL_AUTH, CURLOPT_MAIL_AUTH);
    FSINGLETONTLV(fuzz, TLV_TYPE_LOGIN_OPTIONS, CURLOPT_LOGIN_OPTIONS);
    FSINGLETONTLV(fuzz, TLV_TYPE_XOAUTH2_BEARER, CURLOPT_XOAUTH2_BEARER);
    FSINGLETONTLV(fuzz, TLV_TYPE_USERPWD, CURLOPT_USERPWD);
    FSINGLETONTLV(fuzz, TLV_TYPE_USERAGENT, CURLOPT_USERAGENT);
    FSINGLETONTLV(fuzz, TLV_TYPE_SSH_HOST_PUBLIC_KEY_SHA256, CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256);

    default:
      /* The fuzzer generates lots of unknown TLVs - we don't want these in the
         corpus so we reject any unknown TLVs. */
      rc = 127;
      goto EXIT_LABEL;
      break;
  }

  rc = 0;

EXIT_LABEL:

  fuzz_free((void **)&tmp);

  return rc;
}

/**
 * Converts a TLV data and length into an allocated string.
 */
char *fuzz_tlv_to_string(TLV *tlv)
{
  char *tlvstr;

  /* Allocate enough space, plus a null terminator */
  tlvstr = (char *)malloc(tlv->length + 1);

  if(tlvstr != NULL) {
    memcpy(tlvstr, tlv->value, tlv->length);
    tlvstr[tlv->length] = 0;
  }

  return tlvstr;
}

/* set up for CURLOPT_HTTPPOST, an alternative API to CURLOPT_MIMEPOST */
void fuzz_setup_http_post(FUZZ_DATA *fuzz, TLV *tlv)
{
  if (fuzz->httppost == NULL) {
    struct curl_httppost *post = NULL;
    struct curl_httppost *last = NULL;

    fuzz->post_body = fuzz_tlv_to_string(tlv);
    if (fuzz->post_body == NULL) {
      return;
    }

    /* This is just one of several possible entrypoints to
     * the HTTPPOST API. see https://curl.se/libcurl/c/curl_formadd.html
     * for lots of others which could be added here.
     */
    curl_formadd(&post, &last,
		 CURLFORM_COPYNAME, FUZZ_HTTPPOST_NAME,
		 CURLFORM_PTRCONTENTS, fuzz->post_body,
		 CURLFORM_CONTENTLEN, (curl_off_t) strlen(fuzz->post_body),
		 CURLFORM_END);

    fuzz->last_post_part = last;
    fuzz->httppost = post;
  }

  return;
}

/**
 * Extract the values from the TLV.
 */
int fuzz_add_mime_part(TLV *src_tlv, curl_mimepart *part)
{
  FUZZ_DATA part_fuzz;
  TLV tlv;
  int rc = 0;
  int tlv_rc;

  memset(&part_fuzz, 0, sizeof(FUZZ_DATA));

  if(src_tlv->length < sizeof(TLV_RAW)) {
    /* Not enough data for a single TLV - don't continue */
    goto EXIT_LABEL;
  }

  /* Set up the state parser */
  part_fuzz.state.data = src_tlv->value;
  part_fuzz.state.data_len = src_tlv->length;

  for(tlv_rc = fuzz_get_first_tlv(&part_fuzz, &tlv);
      tlv_rc == 0;
      tlv_rc = fuzz_get_next_tlv(&part_fuzz, &tlv)) {

    /* Have the TLV in hand. Parse the TLV. */
    rc = fuzz_parse_mime_tlv(part, &tlv);

    if(rc != 0) {
      /* Failed to parse the TLV. Can't continue. */
      goto EXIT_LABEL;
    }
  }

  if(tlv_rc != TLV_RC_NO_MORE_TLVS) {
    /* A TLV call failed. Can't continue. */
    goto EXIT_LABEL;
  }

EXIT_LABEL:

  return(rc);
}

/**
 * Do different actions on the mime part for different received TLVs.
 */
int fuzz_parse_mime_tlv(curl_mimepart *part, TLV *tlv)
{
  int rc;
  char *tmp;

  switch(tlv->type) {
    case TLV_TYPE_MIME_PART_NAME:
      tmp = fuzz_tlv_to_string(tlv);
      curl_mime_name(part, tmp);
      fuzz_free((void **)&tmp);
      break;

    case TLV_TYPE_MIME_PART_DATA:
      curl_mime_data(part, (const char *)tlv->value, tlv->length);
      break;

    default:
      /* The fuzzer generates lots of unknown TLVs - we don't want these in the
         corpus so we reject any unknown TLVs. */
      rc = 255;
      goto EXIT_LABEL;
      break;
  }

  rc = 0;

EXIT_LABEL:

  return rc;
}
