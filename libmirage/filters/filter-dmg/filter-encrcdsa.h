/*
 *  libMirage: EncrCDSA filter
 *  Copyright (C) 2026 Rok Mandeljc
 *
 *  Based on the MIT-licensed readencrcdsa.py utility, written by Willem Hengeveld:
 *  https://github.com/nlitsme/encrypteddmg
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#pragma once

#include "mirage/config.h"
#include <mirage/mirage.h>

#include <glib/gi18n-lib.h>

#include "filter-stream-encrcdsa.h"

G_BEGIN_DECLS


#define CSSM_ALGMODE_CBC_IV8 5
#define CSSM_ALGMODE_CBCPadIV8 6

#define CSSM_PKCS5_PBKDF2_PRF_HMAC_SHA1 0

#define CSSM_ALGID_3DES_3KEY_EDE 0x11
#define CSSM_ALGID_SHA1HMAC 0x5b
#define CSSM_ALGID_PKCS5_PBKDF2 0x67
#define CSSM_ALGID_AES 0x80000001

#define CSSM_PADDING_PKCS7 7

#define CSSM_APPLE_UNLOCK_TYPE_KEY_DIRECT 1


#pragma pack(1)

typedef struct
{
    gchar signature[8];
    guint32 version;
    guint32 block_iv_len;
    guint32 block_mode;
    guint32 block_algorithm;
    guint32 key_bits;
    guint32 ivkey_algorithm;
    guint32 ivkey_bits;
    guint8 uuid[16];
    guint32 block_size;
    guint64 data_len;
    guint64 data_offset;
    guint32 num_keys;
} encrcdsa_header_t;

typedef struct
{
    guint32 type;
    guint64 offset;
    guint64 size;
} encrcdsa_key_pointer_t;

typedef struct
{
    guint32 kdf_algorithm; /* CSSM_ALGID_PKCS5_PBKDF2 */
    guint32 kdf_prf; /* CSSM_PKCS5_PBKDF2_PRF_HMAC_SHA1 */
    guint32 kdf_iteration_count;
    guint32 kdf_salt_len; /* 20 */
    guint8 kdf_salt[32];
    guint32 blob_enc_iv_len; /* 8 */
    guint8 blob_enc_iv[32];
    guint32 blob_enc_key_bits; /* 192 */
    guint32 blob_enc_algorithm; /* CSSM_ALGID_3DES_3KEY_EDE */
    guint32 blob_enc_padding; /* CSSM_PADDING_PKCS7 */
    guint32 blob_enc_mode; /* CSSM_ALGMODE_CBCPadIV8 */
    guint32 blob_len; /* 48 or 64 */
} encrcdsa_passphrase_wrapped_key_header_t;

#pragma pack()


G_END_DECLS
