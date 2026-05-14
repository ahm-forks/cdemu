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
 *                MirageParser methods implementation                *
\**********************************************************************/
static MirageDisc *mirage_parser_chd_load_image (MirageParser *_self, MirageStream **streams, GError **error)
{
    MirageParserChd *self = MIRAGE_PARSER_CHD(_self);

    (void)self;
    (void)streams;

    g_set_error(error, MIRAGE_ERROR, MIRAGE_ERROR_CANNOT_HANDLE, Q_("Parser cannot handle given image: not yet implemented!"));
    return NULL;
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
