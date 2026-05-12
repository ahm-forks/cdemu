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

#include "filter-encrcdsa.h"

#if defined(HAVE_LIBGCRYPT)
#include <gcrypt.h>
#endif

#define __debug__ "EncrCDSA-FilterStream"


static const guint8 encrcdsa_signature[8] = {'e', 'n', 'c', 'r', 'c', 'd', 's', 'a'};


/**********************************************************************\
 *                  Object and its private structure                  *
\**********************************************************************/
struct _MirageFilterStreamEncrCdsaPrivate
{
    MirageStream *stream;

    encrcdsa_header_t header;
    encrcdsa_key_pointer_t key_pointer;

    encrcdsa_passphrase_wrapped_key_header_t key_header;
    guint8 key_data[64]; /* since length is either 48 or 64 bytes */
    gsize key_length;

    /* Decryption */
#if defined(HAVE_LIBGCRYPT)
    gcry_cipher_hd_t crypt_handle;
    gcry_mac_hd_t hmac_handle;

    guint8 block_iv[32]; /* 20 bytes should suffice for HMAC-SHA1 */
    guint8 block_data[512];
    guint32 cached_block_idx;
#endif
};


G_DEFINE_DYNAMIC_TYPE_EXTENDED(
    MirageFilterStreamEncrCdsa,
    mirage_filter_stream_encrcdsa,
    MIRAGE_TYPE_FILTER_STREAM,
    0,
    G_ADD_PRIVATE_DYNAMIC(MirageFilterStreamEncrCdsa)
)

void mirage_filter_stream_encrcdsa_type_register (GTypeModule *type_module)
{
    mirage_filter_stream_encrcdsa_register_type(type_module);
}


/**********************************************************************\
 *                    Endian-conversion functions                     *
\**********************************************************************/
static inline void mirage_filter_stream_encrcdsa_header_fix_endian (encrcdsa_header_t *header)
{
    g_assert(header);

    header->version = GUINT32_FROM_BE(header->version);
    header->block_iv_len = GUINT32_FROM_BE(header->block_iv_len);
    header->block_mode = GUINT32_FROM_BE(header->block_mode);
    header->block_algorithm = GUINT32_FROM_BE(header->block_algorithm);
    header->key_bits = GUINT32_FROM_BE(header->key_bits);
    header->ivkey_algorithm = GUINT32_FROM_BE(header->ivkey_algorithm);
    header->ivkey_bits = GUINT32_FROM_BE(header->ivkey_bits);
    header->block_size = GUINT32_FROM_BE(header->block_size);
    header->data_len = GUINT64_FROM_BE(header->data_len);
    header->data_offset = GUINT64_FROM_BE(header->data_offset);
    header->num_keys = GUINT32_FROM_BE(header->num_keys);
}

static inline void mirage_filter_stream_encrcdsa_key_pointer_fix_endian (encrcdsa_key_pointer_t *pointer)
{
    g_assert(pointer);

    pointer->type = GUINT32_FROM_BE(pointer->type);
    pointer->offset = GUINT64_FROM_BE(pointer->offset);
    pointer->size = GUINT64_FROM_BE(pointer->size);
}

static inline void mirage_filter_stream_encrcdsa_passphrase_wrapped_key_header_fix_endian (encrcdsa_passphrase_wrapped_key_header_t *header)
{
    g_assert(header);

    header->kdf_algorithm = GUINT32_FROM_BE(header->kdf_algorithm);
    header->kdf_prf = GUINT32_FROM_BE(header->kdf_prf);
    header->kdf_iteration_count = GUINT32_FROM_BE(header->kdf_iteration_count);
    header->kdf_salt_len = GUINT32_FROM_BE(header->kdf_salt_len);
    header->blob_enc_iv_len = GUINT32_FROM_BE(header->blob_enc_iv_len);
    header->blob_enc_key_bits = GUINT32_FROM_BE(header->blob_enc_key_bits);
    header->blob_enc_algorithm = GUINT32_FROM_BE(header->blob_enc_algorithm);
    header->blob_enc_padding = GUINT32_FROM_BE(header->blob_enc_padding);
    header->blob_enc_mode = GUINT32_FROM_BE(header->blob_enc_mode);
    header->blob_len = GUINT32_FROM_BE(header->blob_len);
}


/**********************************************************************\
 *                         Debug functions                            *
\**********************************************************************/
static GString *dump_buffer_to_hex (const guint8 *data, gsize data_size, gboolean add_spaces, gint wrap)
{
    GString *data_dump = g_string_new("");

    for (gsize i = 0; i < data_size; i++) {
        g_string_append_printf(data_dump, "%02hhx", data[i]);
        if (wrap > 0 && ((i + 1) % wrap == 0) && (i != data_size - 1)) {
            g_string_append(data_dump, "\n");
        } else if (add_spaces) {
            g_string_append(data_dump, " ");
        }
    }

    return data_dump;
}


/**********************************************************************\
 *                         Parsing functions                          *
\**********************************************************************/
static gboolean mirage_filter_stream_encrcdsa_find_compatible_key_header (MirageFilterStreamEncrCdsa *self, GError **error)
{
    encrcdsa_key_pointer_t *key_pointer = &self->priv->key_pointer;

    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: reading key pointers (%u)...\n", __debug__, self->priv->header.num_keys);

    for (guint i = 0; i < self->priv->header.num_keys; i++) {
        if (mirage_stream_read(self->priv->stream, key_pointer, sizeof(encrcdsa_key_pointer_t), NULL) != sizeof(encrcdsa_key_pointer_t)) {
            MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to read key pointer at index %u!\n", __debug__, i);
            g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_STREAM_ERROR, Q_("Failed to read key pointer!"));
            return FALSE;
        }

        mirage_filter_stream_encrcdsa_key_pointer_fix_endian(key_pointer);

        MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: key pointer #%u:\n", __debug__, i);
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  type: 0x%X\n", __debug__, key_pointer->type);
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  offset: %" G_GINT64_MODIFIER "u (0x%" G_GINT64_MODIFIER "X)\n", __debug__, key_pointer->offset, key_pointer->offset);
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  size: %" G_GINT64_MODIFIER "u (0x%" G_GINT64_MODIFIER "X)\n", __debug__, key_pointer->size, key_pointer->size);

        if (key_pointer->type == CSSM_APPLE_UNLOCK_TYPE_KEY_DIRECT) {
            MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: found compatible key pointer at index %u - stopping search!\n\n", __debug__, i);
            return TRUE;
        }
    }

    /* No compatible key pointer found */
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: could not find a key pointer with supported key-wrapping type!\n\n", __debug__);
    g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_STREAM_ERROR, Q_("Unsupported encryption parameters!"));
    return FALSE;
}

static gboolean mirage_filter_stream_encrcdsa_read_passphrase_wrapped_key (MirageFilterStreamEncrCdsa *self, GError **error)
{
    const encrcdsa_key_pointer_t *key_pointer = &self->priv->key_pointer;
    encrcdsa_passphrase_wrapped_key_header_t *key_header = &self->priv->key_header;
    guint8 *key_data = self->priv->key_data;

    gboolean supported;

    /* Sanity check; length of header and data blob should be within
     * the size declared in the pointer entry (although it seems there
     * is a large zero-padded area included) */
    if (sizeof(encrcdsa_passphrase_wrapped_key_header_t) > key_pointer->size) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: sanity check failed: length of header (%lu) exceeds the size declared in key pointer entry (%" G_GINT64_MODIFIER "u)\n", __debug__, sizeof(encrcdsa_passphrase_wrapped_key_header_t), key_pointer->size);
        g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_STREAM_ERROR, Q_("Sanity check failed!"));
        return FALSE;
    }

    /* Read the passphrase-wrapped key header */
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: reading passphrase-wrapped key header...\n", __debug__);

    mirage_stream_seek(self->priv->stream, key_pointer->offset, G_SEEK_SET, NULL);
    if (mirage_stream_read(self->priv->stream, key_header, sizeof(encrcdsa_passphrase_wrapped_key_header_t), NULL) != sizeof(encrcdsa_passphrase_wrapped_key_header_t)) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to read passphrase-wrapped key header!\n", __debug__);
        g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_STREAM_ERROR, Q_("Failed to read passphrase-wrapped key header!"));
        return FALSE;
    }

    /* Fix endianness */
    mirage_filter_stream_encrcdsa_passphrase_wrapped_key_header_fix_endian(key_header);

    /* Display header */
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: passphrase-wrapped key header:\n", __debug__);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  kdf_algorithm: 0x%X\n", __debug__, key_header->kdf_algorithm);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  kdf_prf: 0x%X\n", __debug__, key_header->kdf_prf);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  kdf_iteration_count: %u\n", __debug__, key_header->kdf_iteration_count);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  kdf_salt_len: %u\n", __debug__, key_header->kdf_salt_len);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  blob_enc_iv_len: %u\n", __debug__, key_header->blob_enc_iv_len);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  blob_enc_key_bits: %u\n", __debug__, key_header->blob_enc_key_bits);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  blob_enc_algorithm: 0x%X\n", __debug__, key_header->blob_enc_algorithm);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  blob_enc_padding: 0x%X\n", __debug__, key_header->blob_enc_padding);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  blob_enc_mode: 0x%X\n", __debug__, key_header->blob_enc_mode);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  blob_len: %u\n", __debug__, key_header->blob_len);

    /* Sanity check; length of header and data blob should be within
     * the size declared in the pointer entry (although it seems there
     * is a large zero-padded area included) */
    if (sizeof(encrcdsa_passphrase_wrapped_key_header_t) + key_header->blob_len > key_pointer->size) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: sanity check failed: length of header (%lu) + blob length (%u) exceeds the size declared in key pointer entry (%" G_GINT64_MODIFIER "u)\n", __debug__, sizeof(encrcdsa_passphrase_wrapped_key_header_t), key_header->blob_len, key_pointer->size);
        g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_STREAM_ERROR, Q_("Sanity check failed!"));
        return FALSE;
    }

    /* Validate key encryption parameters */
    supported = FALSE;
    if (key_header->kdf_algorithm != CSSM_ALGID_PKCS5_PBKDF2) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: unsupported kdf_algorithm (0x%X)!\n", __debug__, key_header->kdf_algorithm);
    } else if (key_header->kdf_prf != CSSM_PKCS5_PBKDF2_PRF_HMAC_SHA1) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: unsupported kdf_prf (0x%X)!\n", __debug__, key_header->kdf_prf);
    } else if (key_header->blob_enc_key_bits > 32 * 8) {
        /* This one is tied to size of statically-allocated derived_key[] buffer that we use... */
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: unsupported blob_enc_key_bits (%u)!\n", __debug__, key_header->blob_enc_key_bits);
    } else if (key_header->blob_enc_algorithm != CSSM_ALGID_3DES_3KEY_EDE) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: unsupported blob_enc_algorithm (0x%X)!\n", __debug__, key_header->blob_enc_algorithm);
    } else if (key_header->blob_enc_padding != CSSM_PADDING_PKCS7) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: unsupported blob_enc_padding (0x%X)!\n", __debug__, key_header->blob_enc_padding);
    } else if (key_header->blob_enc_mode != CSSM_ALGMODE_CBCPadIV8) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: unsupported blob_enc_mode (0x%X)!\n", __debug__, key_header->blob_enc_mode);
    } else if (key_header->blob_len != 48 && key_header->blob_len != 64) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: unsupported blob_len (0x%X)!\n", __debug__, key_header->blob_len);
    } else {
        supported = TRUE;
    }
    if (!supported) {
        g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_STREAM_ERROR, Q_("Unsupported encryption parameters!"));
        return FALSE;
    }

    /* Read encrypted key blob */
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: reading passphrase-wrapped key blob (%u bytes)...\n", __debug__, key_header->blob_len);

    if (mirage_stream_read(self->priv->stream, key_data, key_header->blob_len, NULL) != key_header->blob_len) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to read passphrase-wrapped key blob!\n", __debug__);
        g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_STREAM_ERROR, Q_("Failed to read passphrase-wrapped key blob!"));
        return FALSE;
    }

    if (MIRAGE_DEBUG_ON(self, MIRAGE_DEBUG_PARSER)) {
        GString *key_data_dump = dump_buffer_to_hex(key_data, key_header->blob_len, FALSE, 0);
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: passphrase-wrapped key blob (%u): %s\n", __debug__, key_header->blob_len, key_data_dump->str);
        g_string_free(key_data_dump, TRUE);
    }

    return TRUE;
}

/* These functions are applicable only if we have libgcrypt */
#if defined(HAVE_LIBGCRYPT)

static gboolean mirage_filter_stream_encrcdsa_ensure_libgcrypt_initialized (MirageFilterStreamEncrCdsa *self G_GNUC_UNUSED, GError **error)
{
    const gchar *required_libgcrypt_version = "1.2.0"; /* All versions after v1.2 should be API/ABI compatible */

    if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: libgcrypt is not yet initialized. Initializing...\n", __debug__);

        if (!gcry_check_version(required_libgcrypt_version)) {
            const gchar *libgcrypt_version = gcry_check_version(NULL);
            MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: installed version of libgcrypt (%s) does not satisfy minimum requirement (%s)!\n", __debug__, libgcrypt_version, required_libgcrypt_version);
            g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_STREAM_ERROR, Q_("Installed version of libgcrypt (%s) does not satisfy minimum requirement (%s)!"), libgcrypt_version, required_libgcrypt_version);
            return FALSE;
        }

        gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
        gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
        gcry_control(GCRYCTL_RESUME_SECMEM_WARN);

        gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    } else {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: libgcrypt is already initialized.\n", __debug__);
    }

    return TRUE;
}

static gboolean mirage_filter_stream_encrcdsa_unwrap_passphrase_wrapped_key (MirageFilterStreamEncrCdsa *self, const gchar *password)
{
    const encrcdsa_passphrase_wrapped_key_header_t *key_header = &self->priv->key_header;
    guint8 *key_data = self->priv->key_data;

    guint8 derived_key[32]; /* must accommodate (key_header->blob_enc_key_bits / 8) bytes */
    gcry_cipher_hd_t crypt_handle;
    gcry_error_t rc;

    /* Derive the key using PKCS#5 PBKDF2 with HMAC-SHA1 as hashling algorithm */
    rc = gcry_kdf_derive(
        password,
        strlen(password),
        GCRY_KDF_PBKDF2, /* PKCS#5 PBKDF2 */
        GCRY_MD_SHA1, /* SHA1 */
        key_header->kdf_salt,
        key_header->kdf_salt_len, /* 20 */
        key_header->kdf_iteration_count,
        key_header->blob_enc_key_bits / 8,
        derived_key
    );

    if (rc != 0) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to compute PKCS#5 PBKDF2 with SHA-1! Error code: %d (%X)!", __debug__, rc, rc);
        return FALSE;
    }

    /* Dump derived key and IV */
    if (MIRAGE_DEBUG_ON(self, MIRAGE_DEBUG_PARSER)) {
        const gsize derived_key_len = key_header->blob_enc_key_bits / 8;
        GString *derived_key_dump = dump_buffer_to_hex(derived_key, derived_key_len, FALSE, 0);
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: derived key (%" G_GINT64_MODIFIER "u): %s\n", __debug__, derived_key_len, derived_key_dump->str);
        g_string_free(derived_key_dump, TRUE);

        GString *iv_dump = dump_buffer_to_hex(key_header->blob_enc_iv, key_header->blob_enc_iv_len, FALSE, 0);
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: IV (%u): %s\n", __debug__, key_header->blob_enc_iv_len, iv_dump->str);
        g_string_free(iv_dump, TRUE);
    }

    /* Decrypt key blob */
    rc = gcry_cipher_open(
        &crypt_handle,
        GCRY_CIPHER_3DES,
        GCRY_CIPHER_MODE_CBC,
        0
    );
    if (rc != 0) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to initialize 3DES cipher! Error code: %d (%X)!", __debug__, rc, rc);
        return FALSE;
    }

    rc = gcry_cipher_setkey(crypt_handle, derived_key, key_header->blob_enc_key_bits / 8);
    if (rc != 0) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to set cipher key! Error code: %d (%X)!", __debug__, rc, rc);
        gcry_cipher_close(crypt_handle);
        return FALSE;
    }

    rc = gcry_cipher_setiv(crypt_handle, key_header->blob_enc_iv, key_header->blob_enc_iv_len);
    if (rc != 0) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to set IV! Error code: %d (%X)!", __debug__, rc, rc);
        gcry_cipher_close(crypt_handle);
        return FALSE;
    }

    rc = gcry_cipher_decrypt(crypt_handle, key_data, key_header->blob_len, NULL, 0);
    if (rc != 0) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: gcry_cipher_decrypt() failed with error code: %d (%X)", __debug__, rc, rc);
        gcry_cipher_close(crypt_handle);
        return FALSE;
    }

    gcry_cipher_close(crypt_handle);

    self->priv->key_length = key_header->blob_len;

    return TRUE;
}

static gboolean _remove_pkcs7_padding (const guint8 *key_data, gsize *key_length)
{
    const gsize block_size = 8; /* 3DES */
    gsize length = *key_length;
    gsize padding_length;

    /* Last byte should be padding length */
    const guint8 *ptr = key_data + length - 1;
    padding_length = *ptr;

    if (padding_length == 0 || padding_length > block_size) {
        return FALSE; /* Invalid padding byte */
    }

    for (gsize i = 0; i < padding_length; i++) {
        /* Sanity check */
        if (ptr < key_data) {
            return FALSE;
        }
        if (*ptr != padding_length) {
            return FALSE;
        }
        ptr--;
    }

    *key_length -= padding_length;
    return TRUE;
}

static gboolean _check_for_ckie_suffix (const guint8 *key_data, gsize key_length)
{
    static const guint8 CKIE_SUFFIX[5] = {'C', 'K', 'I', 'E', 0};
    gsize offset;

    if (key_length < sizeof(CKIE_SUFFIX)) {
        return FALSE;
    }

    offset = key_length - sizeof(CKIE_SUFFIX); /* last five bytes */
    return memcmp(key_data + offset, CKIE_SUFFIX, sizeof(CKIE_SUFFIX)) == 0;
}

static gboolean mirage_filter_stream_encrcdsa_initialize_crypto_handles (MirageFilterStreamEncrCdsa *self)
{
    const encrcdsa_header_t *header = &self->priv->header;
    const guint8 *key_data = self->priv->key_data;

    const guint aes_key_size = header->key_bits / 8;
    const guint hmac_key_size = header->ivkey_bits / 8;

    gcry_error_t rc;

    /* AES cipher in CBC mode, using lower part of the image key.
     * IV is computed for each block using HMAC. */
    rc = gcry_cipher_open(&self->priv->crypt_handle, aes_key_size == 16 ? GCRY_CIPHER_AES128 : GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    if (rc != 0) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to initialize AES cipher! Error code: %d (%X)!", __debug__, rc, rc);
        return FALSE;
    }

    rc = gcry_cipher_setkey(self->priv->crypt_handle, key_data, aes_key_size);
    if (rc != 0) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to set AES key! Error code: %d (%X)!", __debug__, rc, rc);
        return FALSE;
    }

    /* HMAC: SHA1, using upper part of the image key. */
    rc = gcry_mac_open(&self->priv->hmac_handle, GCRY_MAC_HMAC_SHA1, 0, NULL);
    if (rc != 0) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to initialize HMAC! Error code: %d (%X)!", __debug__, rc, rc);
        return FALSE;
    }

    rc = gcry_mac_setkey(self->priv->hmac_handle, key_data + aes_key_size, hmac_key_size);
    if (rc != 0) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to set HMAC key! Error code: %d (%X)!", __debug__, rc, rc);
        return FALSE;
    }

    return TRUE;
}

#endif /* defined(HAVE_LIBGCRYPT) */


/**********************************************************************\
 *               MirageFilterStream methods implementation            *
\**********************************************************************/
static gboolean mirage_filter_stream_encrcdsa_open (MirageFilterStream *_self, MirageStream *stream, gboolean writable G_GNUC_UNUSED, GError **error)
{
    MirageFilterStreamEncrCdsa *self = MIRAGE_FILTER_STREAM_ENCRCDSA(_self);

    encrcdsa_header_t *header = &self->priv->header;
    gboolean supported;

    /* Read header */
    mirage_stream_seek(stream, 0, G_SEEK_SET, NULL);
    if (mirage_stream_read(stream, header, sizeof(encrcdsa_header_t), NULL) != sizeof(encrcdsa_header_t)) {
        g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_CANNOT_HANDLE, Q_("Filter cannot handle given data: failed to read EncrCDSA header!"));
        return FALSE;
    }

    /* Fixup header endianness */
    mirage_filter_stream_encrcdsa_header_fix_endian(header);

    /* Validate header */
    if (memcmp(&header->signature, encrcdsa_signature, sizeof(encrcdsa_signature))) {
        g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_CANNOT_HANDLE, Q_("Filter cannot handle given data: invalid EncrCDSA header!"));
        return FALSE;
    }

    /* Display header */
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: header:\n", __debug__);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  signature: %.8s\n", __debug__, header->signature);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  version: %u\n", __debug__, header->version);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  block_iv_len: %u\n", __debug__, header->block_iv_len);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  block_mode: 0x%X\n", __debug__, header->block_mode);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  block_algorithm: 0x%X\n", __debug__, header->block_algorithm);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  key_bits: %u\n", __debug__, header->key_bits);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  ivkey_algorithm: 0x%X\n", __debug__, header->ivkey_algorithm);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  ivkey_bits: %u\n", __debug__, header->ivkey_bits);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  block_size: %u\n", __debug__, header->block_size);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  data_len: %" G_GINT64_MODIFIER "u (0x%" G_GINT64_MODIFIER "X)\n", __debug__, header->data_len, header->data_len);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  data_offset: %" G_GINT64_MODIFIER "u (0x%" G_GINT64_MODIFIER "X)\n", __debug__, header->data_offset, header->data_offset);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  num_keys: %u\n\n", __debug__, header->num_keys);

    /* Validate encryption parameters */
    supported = FALSE;
    if (header->version != 2) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: unsupported version (%u)!\n", __debug__, header->version);
    } else if (header->block_iv_len != 16) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: unsupported block_iv_len (%u)!\n", __debug__, header->block_iv_len);
    } else  if (header->block_mode != CSSM_ALGMODE_CBC_IV8) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: unsupported block_mode (0x%X)!\n", __debug__, header->block_mode);
    } else if (header->block_algorithm != CSSM_ALGID_AES) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: unsupported block_algorithm (0x%X)!\n", __debug__, header->block_algorithm);
    } else if (header->key_bits != 128 && header->key_bits != 256) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: unsupported key_bits (%u)!\n", __debug__, header->key_bits);
    } else if (header->ivkey_algorithm != CSSM_ALGID_SHA1HMAC) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: unsupported ivkey_algorithm (0x%X)!\n", __debug__, header->ivkey_algorithm);
    } else if (header->block_size != 512) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: unsupported block_size (%u)!\n", __debug__, header->block_size);
    } else {
        supported = TRUE;
    }
    if (!supported) {
        g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_STREAM_ERROR, Q_("Unsupported encryption parameters!"));
        return FALSE;
    }

    /* Store stream for further use */
    self->priv->stream = (MirageStream *)g_object_ref(stream);

    /* Read and process key item pointer table; try to find entry with
     * type SSM_APPLE_UNLOCK_TYPE_KEY_DIRECT, which indicates
     * passphrase-wrapped key. Upon success, self->priv->key_pointer
     * contains the corresponding entry's access info (offset and size). */
    if (!mirage_filter_stream_encrcdsa_find_compatible_key_header(self, error)) {
        return FALSE;
    }

    /* Read the passphrase-wrapped key header and data blob */
    if (!mirage_filter_stream_encrcdsa_read_passphrase_wrapped_key(self, error)) {
        return FALSE;
    }

    /* From this point on, we need libgcrypt... */
#if !defined(HAVE_LIBGCRYPT)
    g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_STREAM_ERROR, Q_("Support for image decryption is missing!"));
    return FALSE;
#else
    /* Ensure libgcrypt is initialized */
    if (!mirage_filter_stream_encrcdsa_ensure_libgcrypt_initialized(self, error)) {
        return FALSE;
    }

    /* At this point, we require password */
    GVariant *password_value;
    gchar *password;

    password_value = mirage_contextual_get_option(MIRAGE_CONTEXTUAL(self), "password");
    if (password_value) {
        password = g_variant_dup_string(password_value, NULL);
        g_variant_unref(password_value);
    } else {
        /* Get password from user via password function */
        password = mirage_contextual_obtain_password(MIRAGE_CONTEXTUAL(self), NULL);
    }

    if (!password) {
        /* Password not provided (or password function is not set) */
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: failed to obtain password for encrypted image!\n", __debug__);
        g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_ENCRYPTED_IMAGE, Q_("Image is encrypted!"));
        return FALSE;
    }

    /* Unwrap the passphrase-wrapped image key with provided password */
    if (!mirage_filter_stream_encrcdsa_unwrap_passphrase_wrapped_key(self, password)) {
        g_free(password);
        g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_ENCRYPTED_IMAGE, Q_("Failed to decrypt image key!"));
        return FALSE;
    }

    g_free(password);

    /* Dump decrypted key blob */
    if (MIRAGE_DEBUG_ON(self, MIRAGE_DEBUG_PARSER)) {
        GString *key_data_dump = dump_buffer_to_hex(self->priv->key_data, self->priv->key_length, FALSE, 0);
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: decrypted key blob (%" G_GSIZE_MODIFIER "u): %s\n", __debug__, self->priv->key_length, key_data_dump->str);
        g_string_free(key_data_dump, TRUE);
    }

    /* Remove PKCS#7 padding - failure to do so may indicate that decryption
     * failed due to incorrect password. */
    if (!_remove_pkcs7_padding(self->priv->key_data, &self->priv->key_length)) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: failed to remove PKCS#7 padding!\n", __debug__);
        g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_ENCRYPTED_IMAGE, Q_("Failed to decrypt image key! Incorrect password?"));
        return FALSE;
    }

    /* Check for presence of CKIE suffix - lack of it indicates that decryption
     * failed due to incorrect password. */
    if (!_check_for_ckie_suffix(self->priv->key_data, self->priv->key_length)) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: decrypted key blob does not end with CKIE suffix!\n", __debug__);
        g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_ENCRYPTED_IMAGE, Q_("Failed to decrypt image key! Incorrect password?"));
        return FALSE;
    }
    self->priv->key_length -= 5;

    if (MIRAGE_DEBUG_ON(self, MIRAGE_DEBUG_PARSER)) {
        GString *key_data_dump = dump_buffer_to_hex(self->priv->key_data, self->priv->key_length, FALSE, 0);
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: image key (%" G_GSIZE_MODIFIER "u): %s\n", __debug__, self->priv->key_length, key_data_dump->str);
        g_string_free(key_data_dump, TRUE);
    }

    /* Sanity check */
    const guint aes_key_size = header->key_bits / 8;
    const guint hmac_key_size = header->ivkey_bits / 8;
    if (aes_key_size + hmac_key_size != self->priv->key_length) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: sanity check failed: AES key size (%u bits / %u bytes) and HMAC key size (%u bits / %u bytes) does not match the obtained key size (%" G_GSIZE_MODIFIER "u bytes)!\n", __debug__, header->key_bits, aes_key_size, header->ivkey_bits, hmac_key_size, self->priv->key_length);
        g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_STREAM_ERROR, Q_("Sanity check failed!"));
        return FALSE;
    }

    /* Finally, initialize HMAC and cipher handles using corresponding parts
     * of obtained key */
    if (!mirage_filter_stream_encrcdsa_initialize_crypto_handles(self)) {
        g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_ENCRYPTED_IMAGE, Q_("Failed to initialize crypto handles!"));
        return FALSE;
    }

    /* Set file size */
    mirage_filter_stream_simplified_set_stream_length(_self, header->data_len);

    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: parsing completed successfully\n\n", __debug__);

    return TRUE;
#endif
}

#if defined(HAVE_LIBGCRYPT)

static gssize mirage_filter_stream_encrcdsa_partial_read (MirageFilterStream *_self, void *buffer, gsize count)
{
    MirageFilterStreamEncrCdsa *self = MIRAGE_FILTER_STREAM_ENCRCDSA(_self);
    const guint32 BLOCK_SIZE = 512; /* same as header->block_size */
    goffset position;
    guint32 block_idx;
    guint cache_offset;

    /* Find block that corresponds to current position. Since encrypted
     * images have fixed block size of 512, this is fairly straight-forward */
    position = mirage_filter_stream_simplified_get_position(MIRAGE_FILTER_STREAM(self));
    block_idx = position / BLOCK_SIZE;

    MIRAGE_DEBUG(self, MIRAGE_DEBUG_STREAM, "%s: stream position: %" G_GOFFSET_MODIFIER "d (0x%" G_GOFFSET_MODIFIER "X) -> block #%u (cached: #%u)\n", __debug__, position, position, block_idx, self->priv->cached_block_idx);

    /* If we do not the block in cache, read and decrypt it */
    if (block_idx != self->priv->cached_block_idx) {
        goffset data_offset;
        gssize read_bytes;
        size_t iv_length;
        gcry_error_t rc;

        const guint32 block_idx_be = GUINT32_TO_BE(block_idx);

        MIRAGE_DEBUG(self, MIRAGE_DEBUG_STREAM, "%s: block not cached, reading...\n", __debug__);

        /* Read the 512-byte data block. The very last block seems to be
         * padded to 512 bytes as necessary, so we do not have to worry
         * about its true size. */
        data_offset = self->priv->header.data_offset + (guint64)block_idx * BLOCK_SIZE; /* Make sure second operand becomes 64-bit! */

        if (!mirage_stream_seek(self->priv->stream, data_offset, G_SEEK_SET, NULL)) {
            MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to seek to %" G_GOFFSET_MODIFIER "d in underlying stream!\n", __debug__, data_offset);
            return -1;
        }

        read_bytes = mirage_stream_read(self->priv->stream, self->priv->block_data, BLOCK_SIZE, NULL);
        if (read_bytes < 0 || (gsize)read_bytes != BLOCK_SIZE) {
            MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to read %u bytes from underlying stream!\n", __debug__, BLOCK_SIZE);
            return -1;
        }

        /* Derive IV using the configured HMAC and block index */
        iv_length = sizeof(self->priv->block_iv) / sizeof(self->priv->block_iv[0]); /* 32 bytes */

        rc = gcry_mac_reset(self->priv->hmac_handle);
        if (rc != 0) {
            MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to reset HMAC! Error code: %d (%X)!", __debug__, rc, rc);
            return -1;
        }

        rc = gcry_mac_write(self->priv->hmac_handle, &block_idx_be, sizeof(block_idx_be));
        if (rc != 0) {
            MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to update HMAC! Error code: %d (%X)!", __debug__, rc, rc);
            return -1;
        }

        rc = gcry_mac_read(self->priv->hmac_handle, self->priv->block_iv, &iv_length);
        if (rc != 0) {
            MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to read HMAC! Error code: %d (%X)!", __debug__, rc, rc);
            return -1;
        }

        /* Dump IV for debug purposes */
        if (MIRAGE_DEBUG_ON(self, MIRAGE_DEBUG_STREAM)) {
            GString *iv_dump = dump_buffer_to_hex(self->priv->block_iv, iv_length, FALSE, 0);
            MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: IV for block #%u (%" G_GSIZE_MODIFIER "u): %s\n", __debug__, block_idx, iv_length, iv_dump->str);
            g_string_free(iv_dump, TRUE);
        }

        /* Decrypt */
        rc = gcry_cipher_reset(self->priv->crypt_handle);
        if (rc != 0) {
            MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to reset AES! Error code: %d (%X)!", __debug__, rc, rc);
            return -1;
        }

        rc = gcry_cipher_setiv(self->priv->crypt_handle, self->priv->block_iv, 16); /* iv_length should be 20, but only 16 bytes are required for AES... */
        if (rc != 0) {
            MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to set IV to AES! Error code: %d (%X)!", __debug__, rc, rc);
            return -1;
        }

        rc = gcry_cipher_decrypt(self->priv->crypt_handle, self->priv->block_data, BLOCK_SIZE, NULL, 0);
        if (rc != 0) {
            MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: gcry_cipher_decrypt() failed with error code: %d (%X)!", __debug__, rc, rc);
            return -1;
        }

        self->priv->cached_block_idx = block_idx;
    }

    /* Copy data from cache */
    cache_offset = position - ((goffset)block_idx * (goffset)BLOCK_SIZE); /* Offset within cache buffer */
    count = MIN(count, BLOCK_SIZE - cache_offset);

    MIRAGE_DEBUG(self, MIRAGE_DEBUG_STREAM, "%s: offset within block: %u, copying %" G_GSIZE_MODIFIER "u bytes\n", __debug__, cache_offset, count);

    memcpy(buffer, self->priv->block_data + cache_offset, count);

    return count;
}

#else

static gssize mirage_filter_stream_encrcdsa_partial_read (MirageFilterStream *_self, void *buffer G_GNUC_UNUSED, gsize count G_GNUC_UNUSED)
{
    MirageFilterStreamEncrCdsa *self = MIRAGE_FILTER_STREAM_ENCRCDSA(_self);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: not supported - libgcrypt not available!", __debug__);
    return -1;
}

#endif


/**********************************************************************\
 *                             Object init                            *
\**********************************************************************/
static void mirage_filter_stream_encrcdsa_init (MirageFilterStreamEncrCdsa *self)
{
    self->priv = mirage_filter_stream_encrcdsa_get_instance_private(self);

    mirage_filter_stream_generate_info(MIRAGE_FILTER_STREAM(self),
        "FILTER-ENCRCDSA",
        Q_("EncrCDSA File Filter"),
        FALSE,
        1,
        Q_("Encrypted Apple Disk Image (*.dmg)"), "application/x-apple-diskimage"
    );

    self->priv->stream = NULL;

    self->priv->key_length = 0;

#if defined(HAVE_LIBGCRYPT)
    self->priv->hmac_handle = NULL;
    self->priv->crypt_handle = NULL;

    self->priv->cached_block_idx = -1;
#endif
}

static void mirage_filter_stream_encrcdsa_dispose (GObject *gobject)
{
    MirageFilterStreamEncrCdsa *self = MIRAGE_FILTER_STREAM_ENCRCDSA(gobject);

    if (self->priv->stream) {
        g_object_unref(self->priv->stream);
        self->priv->stream = NULL;
    }

    /* Chain up to the parent class */
    G_OBJECT_CLASS(mirage_filter_stream_encrcdsa_parent_class)->dispose(gobject);
}

static void mirage_filter_stream_encrcdsa_finalize (GObject *gobject)
{
    MirageFilterStreamEncrCdsa *self = MIRAGE_FILTER_STREAM_ENCRCDSA(gobject);

#if defined(HAVE_LIBGCRYPT)
    if (self->priv->hmac_handle) {
        gcry_mac_close(self->priv->hmac_handle);
        self->priv->hmac_handle = NULL;
    }

    if (self->priv->crypt_handle) {
        gcry_cipher_close(self->priv->crypt_handle);
        self->priv->crypt_handle = NULL;
    }
#else
    (void)self; /* Suppress unused variable warning */
#endif

    /* Chain up to the parent class */
    G_OBJECT_CLASS(mirage_filter_stream_encrcdsa_parent_class)->finalize(gobject);
}

static void mirage_filter_stream_encrcdsa_class_init (MirageFilterStreamEncrCdsaClass *klass)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
    MirageFilterStreamClass *filter_stream_class = MIRAGE_FILTER_STREAM_CLASS(klass);

    gobject_class->dispose = mirage_filter_stream_encrcdsa_dispose;
    gobject_class->finalize = mirage_filter_stream_encrcdsa_finalize;

    filter_stream_class->open = mirage_filter_stream_encrcdsa_open;

    filter_stream_class->simplified_partial_read = mirage_filter_stream_encrcdsa_partial_read;
}

static void mirage_filter_stream_encrcdsa_class_finalize (MirageFilterStreamEncrCdsaClass *klass G_GNUC_UNUSED)
{
}
