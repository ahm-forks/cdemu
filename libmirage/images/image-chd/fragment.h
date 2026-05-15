/*
 *  libMirage: CHD image: custom fragment for handling data chunking
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

G_BEGIN_DECLS


#define MIRAGE_TYPE_FRAGMENT_CHD            (mirage_fragment_chd_get_type())
#define MIRAGE_FRAGMENT_CHD(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MIRAGE_TYPE_FRAGMENT_CHD, MirageFragmentChd))
#define MIRAGE_FRAGMENT_CHD_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), MIRAGE_TYPE_FRAGMENT_CHD, MirageFragmentChdClass))
#define MIRAGE_IS_FRAGMENT_CHD(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MIRAGE_TYPE_FRAGMENT_CHD))
#define MIRAGE_IS_FRAGMENT_CHD_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), MIRAGE_TYPE_FRAGMENT_CHD))
#define MIRAGE_FRAGMENT_CHD_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), MIRAGE_TYPE_FRAGMENT_CHD, MirageFragmentChdClass))

typedef struct _MirageFragmentChd         MirageFragmentChd;
typedef struct _MirageFragmentChdClass    MirageFragmentChdClass;
typedef struct _MirageFragmentChdPrivate  MirageFragmentChdPrivate;

struct _MirageFragmentChd
{
    MirageFragment parent_instance;

    /*< private >*/
    MirageFragmentChdPrivate *priv;
};

struct _MirageFragmentChdClass
{
    MirageFragmentClass parent_class;
};

/* Used by MIRAGE_TYPE_FRAGMENT_CHD */
GType mirage_fragment_chd_get_type (void);

gboolean mirage_fragment_chd_setup (
    MirageFragmentChd *self,
    shared_chd_file_t *chd_file_ptr,
    guint32 start_sector,
    guint32 num_sectors,
    guint32 hunk_size,
    guint32 sector_size,
    gint main_size,
    gint main_format,
    gint subchannel_size,
    gint subchannel_format,
    GError **error
);


G_END_DECLS
