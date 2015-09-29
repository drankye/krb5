/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/preauth/jwt/jwt_token.c - jwt routines */
/*
 * Copyright (c) 2010 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2010 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Copyright (C) 2012 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <k5-json.h>
#include <jwt_token.h>
#include <k5-base64.h>
#include <time.h>
#include "jwt.h"

int
jwt_token_create(jwt_token **out)
{
    jwt_token *token;

    *out = NULL;

    token = (jwt_token*)calloc(1, sizeof(*token));
    k5_json_object_create(&token->header);
    k5_json_object_create(&token->body);

    *out = token;
    return 0;
}

static char*
json_value_to_str(k5_json_value jvalue)
{
    k5_json_tid type;

    if (jvalue == NULL) return NULL;

    type = k5_json_get_tid(jvalue);
    if (type == K5_JSON_TID_STRING) {
        return (char *)jvalue;
    }

    return NULL;
}

char*
jwt_token_header_attr(jwt_token *token, const char *name)
{
    k5_json_value jvalue;

    jvalue = k5_json_object_get(token->header, name);

    return json_value_to_str(jvalue);
}

char*
jwt_token_body_attr(jwt_token *token, const char *name)
{
    k5_json_value jvalue;

    jvalue = k5_json_object_get(token->body, name);

    return json_value_to_str(jvalue);
}

void
jwt_token_destroy(jwt_token *token)
{
    if (! token) return;
    k5_json_release(token->header);
    k5_json_release(token->body);
    free(token);
}

static
void *
base64url_decode(const char *str, size_t *len_out)
{
    char *tmp;
    size_t len, padding_len, i;
    void * ret;

    *len_out = SIZE_MAX;

    len = strlen(str);

    // Restore padding if missing
    padding_len = len % 4 == 0 ? 0 : 4 - (len % 4);
    tmp = (char*)malloc(len + padding_len + 1);
    strcpy(tmp, str);
    for (i = 0; i < padding_len; ++i) {
        tmp[len +i] = '=';
    }
    tmp[len + padding_len] = '\0';
    // Replace URL-safe chars
    for (i = 0; i < len; i++) {
        if (tmp[i] == '_') {
            tmp[i] = '/';
        } else if (tmp[i] == '-') {
            tmp[i] = '+';
        }
    }

    ret = k5_base64_decode(tmp, len_out);
    free(tmp);
    return ret;
}

int
jwt_token_decode(char *token, jwt_token **out)
{
    char *p, *part1, *part2, *header, *header_t, *body, *body_t, *principal;
    k5_json_value jvalue;
    jwt_token *token_out;
    size_t len_out = 0;
    int retval = 0;
    int x = 0;

    *out = NULL;
    p = strchr(token, '.');
    if (p == NULL) {
        return 1;
    }
    *p++ = 0;
    if (p == NULL) {
        return 1;
    }    
    part1 = token;
    part2 = p;
    p = strchr(part2, '.');
    if (p != NULL) {
        *p++ = 0;
    }
    
    header = (char*)base64url_decode((const char*)part1, &len_out);
    header_t = (char *)malloc(len_out);
    strncpy(header_t, header, len_out);
    header_t[len_out] = '\0';
    free(header);
    body = (char*)base64url_decode((const char*)part2, &len_out);
    body_t = (char *)malloc(len_out);
    strncpy(body_t, body, len_out);
    body_t[len_out] = '\0';
    free(body);
   
    token_out = (jwt_token*)calloc(1, sizeof(*token_out));
    k5_json_decode(header_t, &token_out->header);
    k5_json_decode(body_t, &token_out->body);

    free(header_t);
    free(body_t);

    principal = jwt_token_header_attr(token_out, "krbPrincipal");
    if (principal == NULL) {
    	principal = jwt_token_header_attr(token_out, "user_name");
    	if (principal == NULL) {
    	    principal = jwt_token_header_attr(token_out, "username");
    	}
    }
    if (principal == NULL) {
        principal = jwt_token_body_attr(token_out, "krbPrincipal");
        if (principal == NULL) {
    	    principal = jwt_token_body_attr(token_out, "user_name");
    	    if (principal == NULL) {
    	        principal = jwt_token_body_attr(token_out, "username");
    	    }
        }
    }
    if (principal == NULL) {
        printf("Invalid token, unknown kr5 principal or user name\n");
        return 1;
    }

    // replace @ to _
    for(x=0; x<strlen(principal); x++) {
      if(principal[x]=='@')
        principal[x] = '_';
    }

    printf("krbPrincipal: %s\n", principal);

    jwt_token_destroy(token_out);   

    return 0;
}

int
jwt_extract_int(const char *token, const char *sPattern) {
  const char * principal = token, * cPattern = sPattern;
  int x = -3;
  for(;*principal != 0;principal++) {
    if(x == -3) {
      if(*principal == *cPattern)
        cPattern++;
      else
        cPattern = sPattern;
      if(*cPattern == 0)
        x = -2;
    }
    else if(x == -2) {
      if(*principal == ' ' || *principal == '\t' || *principal == '\n')
        continue;
      if(*principal != ':') {
        x = -3;
        cPattern = sPattern;
      }
      else
        x = -1;
    }
    else if(x == -1) {
      if(*principal == ' ' || *principal == '\t' || *principal == '\n')
        continue;
      if(*principal < '0' || *principal > '9') {
        x = -3;
        cPattern = sPattern;
      }
      else
        x = *principal - '0';
    }
    else if(*principal >= '0' && *principal <= '9') {
      x = 10*x + (*principal) - '0';
    }
    else
      break;
  }
  return x;
}

void sha256(char *string, char outputBuffer[32])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int i = 0;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256); 
    strncpy(outputBuffer, hash, 32);
}

int
jwt_token_decode_and_check(char *token, const char *user_name, krb5_timestamp *endtime, void * rsa_public)
{
    char *p, *part1, *part2, *part3, *header, *header_t, *body, *body_t, *signature, *principal;
    k5_json_value jvalue;
    jwt_token *token_out;
    size_t len_out = 0;
    int retval = 0;
    int x = 0;
    RSA * rsa = (RSA *)rsa_public;

    p = strchr(token, '.');
    if (p == NULL) {
        return 1;
    }
    *p++ = 0;
    if (p == NULL) {
        return 1;
    }
    part1 = token;
    part2 = p;
    p = strchr(part2, '.');
    if (p != NULL) {
        *p++ = 0;
    }
    part3 = p;

    header = (char*)base64url_decode((const char*)part1, &len_out);
    header_t = (char *)malloc(len_out);
    strncpy(header_t, header, len_out);
    header_t[len_out] = '\0';
    free(header);
    body = (char*)base64url_decode((const char*)part2, &len_out);
    body_t = (char *)malloc(len_out);
    strncpy(body_t, body, len_out);
    body_t[len_out] = '\0';
    free(body);

    token_out = (jwt_token*)calloc(1, sizeof(*token_out));
    k5_json_decode(header_t, &token_out->header);
    k5_json_decode(body_t, &token_out->body);

    free(header_t);

    principal = jwt_token_header_attr(token_out, "krbPrincipal");
    if (principal == NULL) {
        principal = jwt_token_header_attr(token_out, "user_name");
        if (principal == NULL) {
            principal = jwt_token_header_attr(token_out, "username");
        }
    }
    if (principal == NULL) {
        principal = jwt_token_body_attr(token_out, "krbPrincipal");
        if (principal == NULL) {
            principal = jwt_token_body_attr(token_out, "user_name");
            if (principal == NULL) {
                principal = jwt_token_body_attr(token_out, "username");
            }
        }
    }
    if (principal == NULL) {
        printf("Invalid token, unknown kr5 principal or user name\n");
        retval = 1;
        com_err("jwt_err", 0, "Cannot find principal username");
        goto clean;
    }
    
    // replace @ to _
    for(x=0; x<strlen(principal); x++) {
      if(principal[x]=='@')
        principal[x] = '_';
    }

    if(strlen(principal) != strlen(user_name))
      retval = 1;
    else{
      for(x=0;x<strlen(principal);x++){
        if(principal[x]!=user_name[x]){
          retval = 1;
          com_err("jwt_compare", 0, "Compare names failed");
          goto clean;
        }
      }
    }

    x = jwt_extract_int(body_t, "\"exp\"");

    if(x<=(int)time(NULL)) {
      retval = 1;
      com_err("jwt_exp", 0, "Token expired");
      goto clean;
    }    
    
    *endtime = x;

    //Format part1 and part2
    part1[strlen(part1)] = '.';
    signature = (char*)base64url_decode((const char*)part3, &len_out);
  
    // If token is longer than sha256 hash result (32 bits) we have to hash it to expected lenght
    if(strlen(part1)>32) {
      part2 = malloc(32);
      sha256(part1, part2);
      x = RSA_verify(NID_sha256, part2, 32, signature, len_out, rsa);
      free(part2);
    } 
    else
      x = RSA_verify(NID_sha256, (unsigned char *)part1, strlen(part1), signature, len_out, rsa);

    // 0 - failed, 1 - success
    if(x != 1) {
      retval = 1;
      com_err("jwt_rsa", 0, "RSA PubKey validation failed");
      goto clean;
    }
clean:
    free(body_t);
    jwt_token_destroy(token_out);

    return retval;
}

