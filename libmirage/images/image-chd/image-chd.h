/*
 *  libMirage: CHD image
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

#pragma once

#include "mirage/config.h"
#include <mirage/mirage.h>

#include <glib/gi18n-lib.h>

#include <chd.h>

#include "parser.h"


G_BEGIN_DECLS


/* Missing from libchdr 0.0~git20230918.9108f34+dfsg-2 packaged by
 * Ubuntu 24.04; added by https://github.com/rtissera/libchdr/pull/106
 * We need these tags just for diagnostic purposes. */
#if !defined(CHD_CODEC_ZSTD)
#define CHD_CODEC_ZSTD CHD_MAKE_TAG('z', 's', 't', 'd')
#endif
#if !defined(CHD_CODEC_CD_ZSTD)
#define CHD_CODEC_CD_ZSTD CHD_MAKE_TAG('c','d','z','s')
#endif

/* Missing from libchdr 0.0~git20240929.aaca599+dfsg-1 packaged by
 * Debian Trixie; added by https://github.com/rtissera/libchdr/commit/ba5656f6f674331e4f512fb25cd7ac8bf7bbd6f0
 * We need this tag to properly handle DVD images. */
#if !defined(DVD_METADATA_TAG)
#define DVD_METADATA_TAG CHD_MAKE_TAG('D','V','D',' ')
#endif


typedef struct _shared_chd_file_t
{
    chd_file *chd_file;
    MirageStream *stream;

    /* Legacy I/O adapter structure */
#if !defined(HAVE_NEW_IO_API)
    struct chd_core_file legacy_io_adapter;
#endif
} shared_chd_file_t;

void shared_chd_file_cleanup (shared_chd_file_t *p);

const char *_chd_error_str (chd_error error_code);
const char *_chd_tag_str (uint32_t tag);


G_END_DECLS
