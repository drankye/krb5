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
jwt_token_create(jwt_token **out, char * token, int size)
{
    jwt_token * local_token;

    *out = NULL;

    local_token = (jwt_token*)calloc(1, sizeof(*local_token));
    
    local_token->data = malloc(size + 1);
    strncpy(local_token->data, token, size);
    local_token->data[size] = 0;
    local_token->head = NULL;
    local_token->payload = NULL;
    local_token->signature = NULL;
    local_token->head_d = NULL;
    local_token->payload_d = NULL;
    
    *out = local_token;
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
    char * out;
    k5_json_object * obj;
    
    k5_json_object_create(&obj);
    k5_json_decode(token->head_d, &obj);
    jvalue = k5_json_object_get(obj, name);
    
    out = json_value_to_str(jvalue);
    k5_json_release(obj);
    return out;
}

char*
jwt_token_body_attr(jwt_token *token, const char *name)
{
    k5_json_value jvalue;
    char * out;
    k5_json_object * obj = NULL;
    
    k5_json_object_create(&obj);
    k5_json_decode(token->payload_d, &obj);
    jvalue = k5_json_object_get(obj, name);
    
    out = json_value_to_str(jvalue);
    k5_json_release(obj);
    return out;
}

void
jwt_token_destroy(jwt_token *local_token)
{
    if (! local_token) return;
    if (local_token->data) free(local_token->data);
    if (local_token->head) free(local_token->head);
    if (local_token->payload) free(local_token->payload);
    if (local_token->signature) free(local_token->signature);
    if (local_token->head_d) free(local_token->head_d);
    if (local_token->payload_d) free(local_token->payload_d);
    free(local_token);
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
jwt_token_extract_int(const char *token, const char *sPattern) 
{
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


int
jwt_token_structure_check(jwt_token * token)
{
    char * part1, * part2, * part3, * p, * local_token;
    
    if (token == NULL || token->data == NULL) {
      return 1;
    }
    
    local_token = (char *)malloc(strlen(token->data) + 1);
    strncpy(local_token, token->data, strlen(token->data));
    local_token[strlen(token->data)] = 0;
    
    part1 = local_token;
    
    p = strchr(local_token, '.');
    if (p == NULL) {
        return 1;
    }
    *p++ = 0;
    
    part2 = p;
    p = strchr(p, '.');
    if (p == NULL) {
        return 1;
    }
    *p++ = 0;
    
    if (*p == 0) {
      return 1;
    }
    part3 = p;
    
    token->head = (char *)malloc(strlen(part1) + 1);
    strncpy(token->head, part1, strlen(part1) + 1);
    
    token->payload = (char *)malloc(strlen(part2) + 1);
    strncpy(token->payload, part2, strlen(part2) + 1);
    
    token->signature = (char *)malloc(strlen(part3) + 1);
    strncpy(token->signature, part3, strlen(part3) + 1);
    
    free(local_token);
    return 0;
}

int
jwt_token_decode(jwt_token * token) 
{
  size_t len_out = 0;
  char * part1, * part2, * part1_d, * part2_d;
  
  if (token == NULL || token->head == NULL || token->payload == NULL) {
    return 1;
  }
  
  part1 = (char *)base64url_decode(token->head, &len_out);
  if (part1 == NULL) {
    return 1;
  }
  
  part2 = (char *)base64url_decode(token->payload, &len_out);
  if (part2 == NULL) {
    return 1;
  }
  
  token->head_d = part1;
  token->payload_d = part2;
  
  return 0;
}

char * jwt_token_get_name(jwt_token * token) 
{
  char * principal;
  int x;
  
  if (token == NULL || token->head_d == NULL || token->payload_d == NULL) {
    return NULL;
  }
  
  principal = jwt_token_header_attr(token, "krbPrincipal");
  if (principal == NULL) {
    principal = jwt_token_header_attr(token, "user_name");
    if (principal == NULL) {
      principal = jwt_token_header_attr(token, "username");
    }
  }
  
  if (principal == NULL) {
    principal = jwt_token_body_attr(token, "krbPrincipal");
    if (principal == NULL) {
      principal = jwt_token_body_attr(token, "user_name");
      if (principal == NULL) {
        principal = jwt_token_body_attr(token, "username");
      }
    }
  }
  
  if (principal == NULL) {
    return NULL;
  }
  
  // Replace @ to _ in principal name from token
  for(x=0; x<strlen(principal); x++) {
    if(principal[x]=='@')
      principal[x] = '_';
  }
  
  return principal;
}

int jwt_token_validate_principal_name(jwt_token * token, const char * user_name) 
{
  char * principal;
  int x;
  
  principal = jwt_token_get_name(token);
  
  if (principal == NULL) {
    return 2;
  }
  
  if(strlen(principal) != strlen(user_name))
    return 1;
  else{
    for(x=0;x<strlen(principal);x++){
      if(principal[x]!=user_name[x]){
        return 1;
      }
    }
  }
  
  return 0;
}

int jwt_token_lifetime(jwt_token * token, krb5_timestamp * endtime) 
{
  int x = jwt_token_extract_int(token->payload_d, "\"exp\"");
  
  if(x<=(int)time(NULL)) {
    return 1;
  }
  
  *endtime = x;
  
  return 0;
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

int jwt_token_verify_signature(jwt_token * token, const RSA * rsa_public) 
{
  char * part1, * signature_d;
  int ret;
  size_t len_out;
  char * head = (char *)malloc(strlen(token->head) + strlen(token->payload) + 2);
  
  strncpy(head, token->head, strlen(token->head));
  head[strlen(token->head)] = '.';
  
  strncpy(head + 1 + strlen(token->head), token->payload, strlen(token->payload));
  head[strlen(token->head) + strlen(token->payload) + 1] = 0;
  
  part1 = (char *)base64url_decode(token->signature, &len_out);
  if (part1 == NULL) {
    return 1;
  }
  signature_d = (char *)malloc(len_out + 1);
  strncpy(signature_d, part1, len_out);
  free(part1);
  
  if(strlen(head)>32) {
    part1 = malloc(32);
    sha256(head, part1);
    ret = RSA_verify(NID_sha256, part1, 32, signature_d, len_out, rsa_public);
    free(part1);
  } 
  else
    ret = RSA_verify(NID_sha256, (unsigned char *)head, strlen(head), signature_d, len_out, rsa_public);
  
  free(head);
  if (ret == 0) {
    return 1;
  }
  return 0;
}