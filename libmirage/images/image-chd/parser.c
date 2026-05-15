/*
 *  libMirage: CHD image: parser
 *  Copyright (C) 2026 Rok Mandeljc
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

#include "image-chd.h"

#include <chd.h>

#define __debug__ "CHD-Parser"


/**********************************************************************\
 *                  Object and its private structure                  *
\**********************************************************************/
struct _MirageParserChdPrivate
{
    MirageDisc *disc;
};


G_DEFINE_DYNAMIC_TYPE_EXTENDED(
    MirageParserChd,
    mirage_parser_chd,
    MIRAGE_TYPE_PARSER,
    0,
    G_ADD_PRIVATE_DYNAMIC(MirageParserChd)
)

void mirage_parser_chd_type_register (GTypeModule *type_module)
{
    mirage_parser_chd_register_type(type_module);
}


/**********************************************************************\
 *                         Debug functions                            *
\**********************************************************************/
static const char *_chd_error_str (chd_error error_code)
{
    #define _CASE(x) \
        case x: { \
            return #x; \
        }

    switch (error_code) {
        _CASE(CHDERR_NONE)
        _CASE(CHDERR_NO_INTERFACE)
        _CASE(CHDERR_OUT_OF_MEMORY)
        _CASE(CHDERR_INVALID_FILE)
        _CASE(CHDERR_INVALID_PARAMETER)
        _CASE(CHDERR_INVALID_DATA)
        _CASE(CHDERR_FILE_NOT_FOUND)
        _CASE(CHDERR_REQUIRES_PARENT)
        _CASE(CHDERR_FILE_NOT_WRITEABLE)
        _CASE(CHDERR_READ_ERROR)
        _CASE(CHDERR_WRITE_ERROR)
        _CASE(CHDERR_CODEC_ERROR)
        _CASE(CHDERR_INVALID_PARENT)
        _CASE(CHDERR_HUNK_OUT_OF_RANGE)
        _CASE(CHDERR_DECOMPRESSION_ERROR)
        _CASE(CHDERR_COMPRESSION_ERROR)
        _CASE(CHDERR_CANT_CREATE_FILE)
        _CASE(CHDERR_CANT_VERIFY)
        _CASE(CHDERR_NOT_SUPPORTED)
        _CASE(CHDERR_METADATA_NOT_FOUND)
        _CASE(CHDERR_INVALID_METADATA_SIZE)
        _CASE(CHDERR_UNSUPPORTED_VERSION)
        _CASE(CHDERR_VERIFY_INCOMPLETE)
        _CASE(CHDERR_INVALID_METADATA)
        _CASE(CHDERR_INVALID_STATE)
        _CASE(CHDERR_OPERATION_PENDING)
        _CASE(CHDERR_NO_ASYNC_OPERATION)
        _CASE(CHDERR_UNSUPPORTED_FORMAT)
        default: {
            return "<unknown>";
        }
    }

    #undef _CASE
}

static const char *_chd_tag_str (uint32_t tag)
{
    #define _CASE(x) \
        case x: { \
            return #x; \
        }

    switch (tag) {
        /* Compression type tags */
        _CASE(CHD_CODEC_NONE)
        _CASE(CHD_CODEC_ZLIB)
        _CASE(CHD_CODEC_LZMA)
        _CASE(CHD_CODEC_HUFFMAN)
        _CASE(CHD_CODEC_FLAC)
        _CASE(CHD_CODEC_ZSTD)
        _CASE(CHD_CODEC_CD_ZLIB)
        _CASE(CHD_CODEC_CD_LZMA)
        _CASE(CHD_CODEC_CD_FLAC)
        _CASE(CHD_CODEC_CD_ZSTD)
        /* Metadata tags */
        _CASE(HARD_DISK_METADATA_TAG)
        _CASE(HARD_DISK_IDENT_METADATA_TAG)
        _CASE(HARD_DISK_KEY_METADATA_TAG)
        _CASE(PCMCIA_CIS_METADATA_TAG)
        _CASE(CDROM_OLD_METADATA_TAG)
        _CASE(CDROM_TRACK_METADATA_TAG)
        _CASE(CDROM_TRACK_METADATA2_TAG)
        _CASE(GDROM_OLD_METADATA_TAG)
        _CASE(GDROM_TRACK_METADATA_TAG)
        _CASE(AV_METADATA_TAG)
        _CASE(AV_LD_METADATA_TAG)
        _CASE(DVD_METADATA_TAG)
        default: {
            return "<unknown>";
        }
    }

    #undef _CASE
}


/**********************************************************************\
 *               I/O adapter for chd_core_file_callbacks               *
\**********************************************************************/
static uint64_t _chd_fsize (void *fp)
{
    MirageStream *stream = MIRAGE_STREAM(fp);

    goffset cur_position;
    goffset end_position;
    GError *local_error = NULL;

    cur_position = mirage_stream_tell(stream);

    if (!mirage_stream_seek(stream, 0, G_SEEK_END, &local_error)) {
        MIRAGE_DEBUG(stream, MIRAGE_DEBUG_WARNING, "%s: failed to seek to end of stream: %s\n", __debug__, local_error->message);
        g_error_free(local_error);
        return 0;
    }

    end_position = mirage_stream_tell(stream);

    if (!mirage_stream_seek(stream, cur_position, G_SEEK_SET, &local_error)) {
        MIRAGE_DEBUG(stream, MIRAGE_DEBUG_WARNING, "%s: failed to seek to original position: %s\n", __debug__, local_error->message);
        g_error_free(local_error);
        local_error = NULL;
    }

    return end_position;
}

static size_t _chd_fread (void *ptr, size_t size, size_t n, void *fp)
{
    MirageStream *stream = MIRAGE_STREAM(fp);

    GError *local_error = NULL;
    gssize ret;


    ret = mirage_stream_read(stream, ptr, n * size, &local_error);
    if (ret < 0) {
        MIRAGE_DEBUG(stream, MIRAGE_DEBUG_WARNING, "%s: failed to read data: %s\n", __debug__, local_error->message);
        g_error_free(local_error);
        local_error = NULL;
        ret = 0; /* Reset to 0, since return type is unsigned */
    }

    return ret;
}

static int _chd_fclose (void *fp)
{
    MirageStream *stream = MIRAGE_STREAM(fp);
    (void)stream; /* Nothing to do here - stream is externally managed! */
    return 0;
}

static int _chd_fseek (void *fp, int64_t where, int whence)
{
    MirageStream *stream = MIRAGE_STREAM(fp);
    GError *local_error = NULL;
    gint seek_type;

    /* Map stdio fseek() whence codes to GLib's GSeekType (because
     * _CUR and _SET have switched values in these APIs). */
    switch (whence) {
        case SEEK_CUR:
            seek_type = G_SEEK_CUR;
            break;
        case SEEK_SET:
            seek_type = G_SEEK_SET;
            break;
        case SEEK_END:
            seek_type = G_SEEK_END;
            break;
        default: {
            return -1;
        }
    }

    if (!mirage_stream_seek(stream, where, seek_type, &local_error)) {
        MIRAGE_DEBUG(stream, MIRAGE_DEBUG_WARNING, "%s: failed to seek: %s\n", __debug__, local_error->message);
        g_error_free(local_error);
        return -1;
    }

    return 0;
}


static const struct chd_core_file_callbacks _chd_file_adapter = {
    .fsize = _chd_fsize,
    .fread = _chd_fread,
    .fclose = _chd_fclose,
    .fseek = _chd_fseek
};


/**********************************************************************\
 *                MirageParser methods implementation                *
\**********************************************************************/
static MirageDisc *mirage_parser_chd_load_image (MirageParser *_self, MirageStream **streams, GError **error)
{
    MirageParserChd *self = MIRAGE_PARSER_CHD(_self);

    const chd_header *header;
    chd_file *chd = NULL;
    chd_error status;

    gchar metadata_buffer[256];
    guint32 metadata_tag = 0;

    /* Try to open */
    status = chd_open_core_file_callbacks(
        &_chd_file_adapter,
        streams[0],
        CHD_OPEN_READ,
        NULL,
        &chd
    );

    if (status != CHDERR_NONE) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_IMAGE_ID, "%s: chd_open() failed with error code %d (%s)\n", __debug__, status, _chd_error_str(status));
        g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_CANNOT_HANDLE, Q_("Parser cannot handle given image: chd_open() failed with error code %d (%s)!"), status, _chd_error_str(status));
        return NULL;
    }

    /* Grab header */
    header = chd_get_header(chd);

    /* Dump header */
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: CHD header:\n", __debug__);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  length: %u\n", __debug__, header->length);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  version: %u\n", __debug__, header->version);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  flags: %u (0x%X)\n", __debug__, header->flags, header->flags);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  compression:\n", __debug__);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:   %s (0x%X)\n", __debug__, _chd_tag_str(header->compression[0]), header->compression[0]);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:   %s (0x%X)\n", __debug__, _chd_tag_str(header->compression[1]), header->compression[1]);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:   %s (0x%X)\n", __debug__, _chd_tag_str(header->compression[2]), header->compression[2]);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:   %s (0x%X)\n", __debug__, _chd_tag_str(header->compression[3]), header->compression[3]);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  hunkbytes: %u\n", __debug__, header->hunkbytes);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  totalhunks: %u\n", __debug__, header->totalhunks);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  logicalbytes: %" G_GINT64_MODIFIER "u\n", __debug__, header->logicalbytes);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  metaoffset: %" G_GINT64_MODIFIER "u\n", __debug__, header->metaoffset);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  mapoffset: %" G_GINT64_MODIFIER "u\n", __debug__, header->mapoffset);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  unitbytes: %u\n", __debug__, header->unitbytes);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  unitcount: %" G_GINT64_MODIFIER "u\n", __debug__, header->unitcount);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  hunkcount: %u\n", __debug__, header->hunkcount);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  mapentrybytes: %u\n", __debug__, header->mapentrybytes);
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  rawmap: %p\n", __debug__, header->rawmap);

    /* Determine what kind of CD-ROM metadata is available, if any */
    MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s: CHD metadata entries:\n", __debug__);
    for (guint i = 0;; i++) {
        uint32_t resultlen;
        uint32_t resulttag;
        uint8_t resultflags;

        memset(metadata_buffer, 0, sizeof(metadata_buffer));
        status = chd_get_metadata(chd, CHDMETATAG_WILDCARD, i, metadata_buffer, sizeof(metadata_buffer), &resultlen, &resulttag, &resultflags);
        if (status == CHDERR_METADATA_NOT_FOUND) {
            break;
        } else if (status != CHDERR_NONE) {
            MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: failed to read metadata entry #%u: %s (%d)\n", __debug__, i, _chd_error_str(status), status);
            g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_PARSER_ERROR, Q_("Failed to read metadata!"));
            goto end;
        }

        MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:  entry #%u: %s (0x%X), %d bytes, flags: 0x%X\n", __debug__, i, _chd_tag_str(resulttag), resulttag, resultlen, resultflags);
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_PARSER, "%s:   %s\n", __debug__, metadata_buffer);

        /* It is probably safe to assume that different metadata tags
         * are not mixed within the same image. */
        switch (resulttag) {
            case CDROM_OLD_METADATA_TAG:
            case CDROM_TRACK_METADATA_TAG:
            case CDROM_TRACK_METADATA2_TAG:
            case DVD_METADATA_TAG: {
                /* Ensure the metadata buffer is large enough */
                if (resultlen >= sizeof(metadata_buffer)) {
                    MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: metadata buffer is too small - %u bytes required, %" G_GSIZE_MODIFIER "u bytes available!\n", __debug__, resultlen, sizeof(metadata_buffer));
                    g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_PARSER_ERROR, Q_("Failed to read metadata!"));
                    goto end;
                }

                metadata_tag = resulttag;
                break;
            }
        }
    }

    if (metadata_tag == 0) {
        MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: no CD-ROM / DVD-ROM metadata entries found!\n", __debug__);
        g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_PARSER_ERROR, Q_("Unsupported CHD image type!"));
        goto end;
    }

    MIRAGE_DEBUG(self, MIRAGE_DEBUG_WARNING, "%s: using metadata tag: %s (0x%X)\n", __debug__, _chd_tag_str(metadata_tag), metadata_tag);

    /* Parse the metadata and reconstruct tracks: TODO */
    g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_PARSER_ERROR, Q_("Not yet implemented!"));

end:
    chd_close(chd);

    return self->priv->disc;
}


/**********************************************************************\
 *                             Object init                            *
\**********************************************************************/
static void mirage_parser_chd_init (MirageParserChd *self)
{
    self->priv = mirage_parser_chd_get_instance_private(self);

    mirage_parser_generate_info(MIRAGE_PARSER(self),
        "PARSER-CHD",
        Q_("CHD Image Parser"),
        1,
        Q_("MAME CHD images (*.chd)"), "application/x-mame-chd"
    );
}

static void mirage_parser_chd_class_init (MirageParserChdClass *klass)
{
    MirageParserClass *parser_class = MIRAGE_PARSER_CLASS(klass);

    parser_class->load_image = mirage_parser_chd_load_image;
}

static void mirage_parser_chd_class_finalize (MirageParserChdClass *klass G_GNUC_UNUSED)
{
}
