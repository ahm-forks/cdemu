/*
 *  Optical disc image load test
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

#include <stdio.h>
#include <unistd.h>

#include <glib.h>

#include <mirage/mirage.h>


static void _libmirage_log_handler (
    const gchar *log_domain,
    GLogLevelFlags log_level,
    const gchar *message,
    gpointer unused_data G_GNUC_UNUSED
)
{
    switch (log_level) {
        case G_LOG_LEVEL_ERROR: {
            g_printerr("%s [ERROR]: %s\n", log_domain, message);
            break;
        }
        case G_LOG_LEVEL_WARNING: {
            g_printerr("%s [WARNING]: %s\n", log_domain, message);
            break;
        }
        default: {
            g_printerr("%s: %s\n", log_domain, message);
            break;
        }
    }
}

static gchar *_password_function (gpointer user_data G_GNUC_UNUSED)
{
    g_print("Image is password protected!\n");
    char *password = getpass("Password: ");
    return g_strdup(password);
}

static gboolean _parse_debug_mask_string (const gchar *mask_str, gint *mask);
static gchar *_debug_mask_to_string (gint mask);

static gchar *_main_data_format_to_string (gint format);
static gchar *_subchannel_format_to_string (gint format);

static void _run_interative_mode (MirageDisc *disc);

int main (int argc, char **argv)
{
    GError *error = NULL;
    gboolean succeeded;
    MirageContext *context;
    MirageDisc *disc;

    gchar *password = NULL;
    gchar *debug_mask_str = NULL;
    gboolean interactive_mode = FALSE;
    gint debug_mask;

    GOptionContext *option_context;
    GOptionEntry option_entries[] = {
        {"debug-mask", 'd', 0, G_OPTION_ARG_STRING, &debug_mask_str, "Debug mask for libMirage.", "mask"},
        {"password", 'p', 0, G_OPTION_ARG_STRING, &password, "Password to use when loading image.", "pasword"},
        {"interactive", 'i', 0, G_OPTION_ARG_NONE, &interactive_mode, "Enter interactive mode after image is loaded.", NULL},
        {NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
    };

    /* Parse command-line */
    option_context = g_option_context_new(" - optical disc image load test");
    g_option_context_add_main_entries(option_context, option_entries, NULL);
    succeeded = g_option_context_parse(option_context, &argc, &argv, &error);
    g_option_context_free(option_context);

    if (!succeeded) {
        g_printerr("Failed to parse options: %s\n", error->message);
        g_error_free(error);
        return 1;
    }

    if (argc < 2) {
        g_printerr("No image filenames were given!\n");
        return 1;
    }

    /* Parse debug mask */
    succeeded = _parse_debug_mask_string(debug_mask_str, &debug_mask);
    if (!succeeded) {
        g_printerr("Failed to parse debug-mask argument: %s\n", debug_mask_str);
        g_free(debug_mask_str);
        g_free(password);
        return 1;
    }
    g_free(debug_mask_str);

    /* Display options */
    g_printerr("Program options:\n");
    g_printerr(" * filename(s) (%d):\n", argc - 1);
    for (gint i = 1; i < argc; i++) {
        g_printerr("   - filename[%d]: %s\n", i - 1, argv[i]);
    }
    g_printerr(" - debug mask: 0x%08X (%s)\n", debug_mask, _debug_mask_to_string(debug_mask));
    g_printerr(" - password: %s\n", password ? "[REDACTED]" : "N/A");
    g_printerr(" - interactive mode: %s\n\n", interactive_mode ? "yes" : "no");

    /* Set up log handler */
    g_log_set_handler(
        "libMirage",
        G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
        _libmirage_log_handler,
        NULL
    );

    /* Initialize libMirage */
    if (!mirage_initialize(&error)) {
        g_printerr("Failed to initialize libMirage: %s!\n", error->message);
        g_error_free(error);
        g_free(password);
        return 2;
    }

    /* Create context */
    context = g_object_new(MIRAGE_TYPE_CONTEXT, NULL);
    mirage_context_set_debug_domain(context, "libMirage");
    mirage_context_set_debug_mask(context, debug_mask);

    mirage_context_set_password_function(context, _password_function, NULL, NULL);

    if (password) {
        /* NOTE: variant takes ownership of password buffer; floating
         * reference on the variant itself! */
        GVariant *password_var = g_variant_new_take_string(password);
        mirage_context_set_option(context, "password", password_var);
    }

    /* Load image */
    /* NOTE: argv was modified by g_option_context_parse(), so it should
     * contain only the executable name and image filename(s); and by
     * convention, argv is NULL terminated, so we can pass it directly
     * to mirage_context_load_image(). */
    g_printerr("Trying to load the image...\n");
    disc = mirage_context_load_image(context, argv + 1, &error);
    if (!disc) {
        g_printerr("Failed to load image: %s\n", error->message);
        g_error_free(error);
        return 3;
    }
    g_printerr("Image successfully loaded!\n\n");

    if (interactive_mode) {
        _run_interative_mode(disc);
    }

    /* Cleanup */
    g_printerr("Cleaning up...\n");
    g_object_unref(disc);
    g_object_unref(context);

    if (!mirage_shutdown(&error)) {
        g_printerr("Failed to shut down libMirage: %s!\n", error->message);
        g_error_free(error);
    }

    return 0;
}


/**********************************************************************\
 *                          Interactive mode                          *
\**********************************************************************/
void _run_interative_mode (MirageDisc *disc)
{
    g_printerr("Entering interactive mode...\n");

    g_print("Enter command or help for list of available commands.\n");
    while (TRUE) {
        gint input_len;
        gchar input_msg[256];

        // Read from stdin
        g_print("\ncommand: ");
        if (fgets(input_msg, sizeof(input_msg), stdin) == NULL) {
            break;
        }

        // Strip trailing newline
        input_len = strlen(input_msg);
        input_len -= 1;
        input_msg[input_len] = 0;

        // Help
        if (g_ascii_strcasecmp(input_msg, "help") == 0
            || g_ascii_strcasecmp(input_msg, "h") == 0) {
            g_print("Supported commands:\n");
            g_print("  quit|exit|q|x: exits the interactive mode\n");
            g_print("  help|h: display this message\n");
            g_print("  debug-mask: displays currently set debug mask value\n");
            g_print("  debug-mask <value>: sets new debug mask value\n");
            g_print("  read-sector <address>: attempts to read sector at the specified address\n");
            g_print("  dump-sector <address>: attempts to read sector at the specified address and dumps its data.\n");
            g_print("  dump-raw-sector <address>: attempts to read raw data for sector at the specified address from corresponding fragment.\n");
            continue;
        }

        // Exit/quit
        if (g_ascii_strcasecmp(input_msg, "exit") == 0
            || g_ascii_strcasecmp(input_msg, "x") == 0
            || g_ascii_strcasecmp(input_msg, "quit") == 0
            || g_ascii_strcasecmp(input_msg, "q") == 0) {
            break;
        }

        // Debug mask
        if (g_ascii_strncasecmp(input_msg, "debug-mask", 10) == 0) {
            if (input_len == 10) {
                MirageContext *context = mirage_contextual_get_context(MIRAGE_CONTEXTUAL(disc));
                gint debug_mask = mirage_context_get_debug_mask(context);
                g_print("Current debug mask: 0x%08X (%s)\n", debug_mask, _debug_mask_to_string(debug_mask));
                g_object_unref(context);
            } else {
                const gchar *mask_str = input_msg + 10;

                if (*mask_str != ' ') {
                    g_print("Usage: debug-mask [value]\n");
                    continue;
                }
                mask_str++;

                gint debug_mask;
                if (!_parse_debug_mask_string(mask_str, &debug_mask)) {
                    g_print("Failed to parse mask string: \"%s\"\n", mask_str);
                    continue;
                }

                MirageContext *context = mirage_contextual_get_context(MIRAGE_CONTEXTUAL(disc));
                mirage_context_set_debug_mask(context, debug_mask);

                g_print("Debug mask set to: 0x%08X (%s)\n", debug_mask, _debug_mask_to_string(debug_mask));
            }

            continue;
        }

        // Read sector / dump sector
        if (g_ascii_strncasecmp(input_msg, "read-sector ", 12) == 0
            || g_ascii_strncasecmp(input_msg, "dump-sector ", 12) == 0) {
            const gchar *address_str = input_msg + 12;

            if (input_len < 13) {
                g_print("Usage: %.12s <address>\n", input_msg);
                continue;
            }

            gchar *end_ptr;
            guint64 address = strtoll(address_str, &end_ptr, 0);
            if (*end_ptr != 0) {
                g_print("Failed to parse address argument \"%s\" as int64!\n", address_str);
                continue;
            }

            g_print("Reading sector %" G_GINT64_MODIFIER "u (0x%" G_GINT64_MODIFIER "X)...\n", address, address);

            GError *error = NULL;
            MirageSector *sector = mirage_disc_get_sector(disc, address, &error);
            if (!sector) {
                g_print("Failed to read sector: %s\n", error->message);
                g_clear_error(&error);
                continue;
            }

            g_print("Sector successfully read!\n");

            /* Do we need to dump sector data? */
            if (input_msg[0] == 'd') {
                gboolean succeeded;

                gboolean has_sync;
                gboolean has_header;
                gboolean has_subheader;
                gboolean has_data;
                gboolean has_edc_ecc;

                gint sector_type = mirage_sector_get_sector_type(sector);

                switch (sector_type) {
                    case MIRAGE_SECTOR_AUDIO: {
                        g_print("Audio sector\n\n");
                        has_sync = FALSE;
                        has_header = FALSE;
                        has_subheader = FALSE;
                        has_data = TRUE;
                        has_edc_ecc = FALSE;
                        break;
                    }
                    case MIRAGE_SECTOR_MODE0: {
                        g_print("Mode 0 sector\n\n");
                        has_sync = TRUE;
                        has_header = TRUE;
                        has_subheader = FALSE;
                        has_data = TRUE;
                        has_edc_ecc = FALSE;
                        break;
                    }
                    case MIRAGE_SECTOR_MODE1: {
                        g_print("Mode 1 sector\n\n");
                        has_sync = TRUE;
                        has_header = TRUE;
                        has_subheader = FALSE;
                        has_data = TRUE;
                        has_edc_ecc = TRUE;
                        break;
                    }
                    case MIRAGE_SECTOR_MODE2: {
                        g_print("Mode 2 sector\n\n");
                        has_sync = TRUE;
                        has_header = TRUE;
                        has_subheader = FALSE;
                        has_data = TRUE;
                        has_edc_ecc = FALSE;
                        break;
                    }
                    case MIRAGE_SECTOR_MODE2_FORM1: {
                        g_print("Mode 2 Form 1 sector\n\n");
                        has_sync = TRUE;
                        has_header = TRUE;
                        has_subheader = TRUE;
                        has_data = TRUE;
                        has_edc_ecc = TRUE;
                        break;
                    }
                    case MIRAGE_SECTOR_MODE2_FORM2: {
                        g_print("Mode 2 Form 2 sector\n\n");
                        has_sync = TRUE;
                        has_header = TRUE;
                        has_subheader = TRUE;
                        has_data = TRUE;
                        has_edc_ecc = TRUE;
                        break;
                    }
                    default: {
                        g_print("Unknown sector type: %d\n\n", sector_type);
                        has_sync = FALSE;
                        has_header = FALSE;
                        has_subheader = FALSE;
                        has_data = TRUE;
                        has_edc_ecc = FALSE;
                        break;
                    }
                }

                /* Sync pattern */
                if (has_sync) {
                    const guint8 *buffer;
                    gint length;

                    succeeded = mirage_sector_get_sync(sector, &buffer, &length, &error);
                    if (succeeded) {
                        gchar *buffer_dump = mirage_helper_dump_buffer_to_hex(buffer, length, TRUE, 16);
                        g_print("Sync pattern (%d):\n%s\n\n", length, buffer_dump);
                        g_free(buffer_dump);
                    } else {
                        g_print("Failed to retrieve sync pattern: %s\n", error->message);
                        g_clear_error(&error);
                    }
                }

                /* Header */
                if (has_header) {
                    const guint8 *buffer;
                    gint length;

                    succeeded = mirage_sector_get_header(sector, &buffer, &length, &error);
                    if (succeeded) {
                        gchar *buffer_dump = mirage_helper_dump_buffer_to_hex(buffer, length, TRUE, 16);
                        g_print("Header (%d):\n%s\n\n", length, buffer_dump);
                        g_free(buffer_dump);
                    } else {
                        g_print("Failed to retrieve header: %s\n", error->message);
                        g_clear_error(&error);
                    }
                }

                /* Subheader */
                if (has_subheader) {
                    const guint8 *buffer;
                    gint length;

                    succeeded = mirage_sector_get_subheader(sector, &buffer, &length, &error);
                    if (succeeded) {
                        gchar *buffer_dump = mirage_helper_dump_buffer_to_hex(buffer, length, TRUE, 16);
                        g_print("Sub-header (%d):\n%s\n\n", length, buffer_dump);
                        g_free(buffer_dump);
                    } else {
                        g_print("Failed to retrieve sub-header: %s\n", error->message);
                        g_clear_error(&error);
                    }
                }

                /* Data */
                if (has_data) {
                    const guint8 *buffer;
                    gint length;

                    succeeded = mirage_sector_get_data(sector, &buffer, &length, &error);
                    if (succeeded) {
                        gchar *buffer_dump = mirage_helper_dump_buffer_to_hex(buffer, length, TRUE, 16);
                        g_print("Data (%d):\n%s\n\n", length, buffer_dump);
                        g_free(buffer_dump);
                    } else {
                        g_print("Failed to retrieve data: %s\n", error->message);
                        g_clear_error(&error);
                    }
                }

                /* EDC/ECC */
                if (has_edc_ecc) {
                    const guint8 *buffer;
                    gint length;

                    succeeded = mirage_sector_get_edc_ecc(sector, &buffer, &length, &error);
                    if (succeeded) {
                        gchar *buffer_dump = mirage_helper_dump_buffer_to_hex(buffer, length, TRUE, 16);
                        g_print("EDC/ECC (%d):\n%s\n\n", length, buffer_dump);
                        g_free(buffer_dump);
                    } else {
                        g_print("Failed to retrieve EDC/ECC: %s\n", error->message);
                        g_clear_error(&error);
                    }
                }

                /* Subchannel */
                if (TRUE) {
                    const guint8 *buffer;
                    gint length;

                    succeeded = mirage_sector_get_subchannel(sector, MIRAGE_SUBCHANNEL_Q, &buffer, &length, &error);
                    if (succeeded) {
                        gchar *buffer_dump = mirage_helper_dump_buffer_to_hex(buffer, length, TRUE, 16);
                        g_print("P/Q subchannel (%d):\n%s\n\n", length, buffer_dump);
                        g_free(buffer_dump);
                    } else {
                        g_print("Failed to retrieve P/Q subchannel: %s\n", error->message);
                        g_clear_error(&error);
                    }
                }

                if (TRUE) {
                    const guint8 *buffer;
                    gint length;

                    succeeded = mirage_sector_get_subchannel(sector, MIRAGE_SUBCHANNEL_PW, &buffer, &length, &error);
                    if (succeeded) {
                        gchar *buffer_dump = mirage_helper_dump_buffer_to_hex(buffer, length, TRUE, 16);
                        g_print("Raw P/W subchannel (%d):\n%s\n\n", length, buffer_dump);
                        g_free(buffer_dump);
                    } else {
                        g_print("Failed to retrieve raw P/W subchannel: %s\n", error->message);
                        g_clear_error(&error);
                    }
                }
            }

            g_object_unref(sector);

            continue;
        }

        // Dump raw sector data (directly from fragment)
        if (g_ascii_strncasecmp(input_msg, "dump-raw-sector ", 16) == 0) {
            const gchar *address_str = input_msg + 16;

            if (input_len < 17) {
                g_print("Usage: %.15s <address>\n", input_msg);
                continue;
            }

            gchar *end_ptr;
            guint64 address = strtoll(address_str, &end_ptr, 0);
            if (*end_ptr != 0) {
                g_print("Failed to parse address argument \"%s\" as int64!\n", address_str);
                continue;
            }

            g_print("Reading raw data for sector %" G_GINT64_MODIFIER "u (0x%" G_GINT64_MODIFIER "X)...\n", address, address);

            /* Find track using disc/absolute address */
            GError *error = NULL;
            MirageTrack *track;

            track = mirage_disc_get_track_by_address(disc, address, &error);
            if (track) {
                /* Find fragment using track-relative address */
                gint relative_address;
                MirageFragment *fragment;

                relative_address = address - mirage_track_layout_get_start_sector(track);
                fragment = mirage_track_get_fragment_by_address(track, relative_address, &error);
                if (fragment) {
                    guint8 *buffer;
                    gint length;
                    gboolean succeeded;

                    /* Fragments work with fragment-relative addresses */
                    relative_address -= mirage_fragment_get_address(fragment);

                    /* Read and dump main channel data */
                    succeeded = mirage_fragment_read_main_data(fragment, relative_address, &buffer, &length, &error);
                    if (succeeded) {
                        gint format = mirage_fragment_main_data_get_format(fragment);
                        g_print("Main channel data: %u bytes, format: 0x%X (%s)\n", length, format, _main_data_format_to_string(format));
                        if (length) {
                            gchar *buffer_dump = mirage_helper_dump_buffer_to_hex(buffer, length, TRUE, 16);
                            g_print("%s\n\n", buffer_dump);
                            g_free(buffer_dump);
                        } else {
                            g_print("N/A\n");
                        }
                        g_free(buffer);
                    } else {
                        g_print("Failed to read main channel data: %s\n", error->message);
                        g_clear_error(&error);
                    }

                    /* Read and dump subchannel data */
                    succeeded = mirage_fragment_read_subchannel_data(fragment, relative_address, &buffer, &length, &error);
                    if (succeeded) {
                        gint format = mirage_fragment_subchannel_data_get_format(fragment);
                        g_print("Subchannel data: %u bytes, format: 0x%X (%s)\n", length, format, _subchannel_format_to_string(format));
                        if (length) {
                            gchar *buffer_dump = mirage_helper_dump_buffer_to_hex(buffer, length, TRUE, 16);
                            g_print("%s\n\n", buffer_dump);
                            g_free(buffer_dump);
                        } else {
                            g_print("N/A\n");
                        }
                        g_free(buffer);
                    } else {
                        g_print("Failed to read subchannel data: %s\n", error->message);
                        g_clear_error(&error);
                    }

                    g_object_unref(fragment);
                } else {
                    g_print("Could not find fragment: %s\n", error->message);
                    g_clear_error(&error);
                }

                g_object_unref(track);
            } else {
                g_print("Could not find track: %s\n", error->message);
                g_clear_error(&error);
            }

            continue;
        }

        g_print("Unrecognized command string: %s\n", input_msg);
    }

    g_print("Exited interactive mode!\n");
}


/**********************************************************************\
 *                         Debug mask helpers                         *
\**********************************************************************/
struct _name_value_entry_t
{
    gchar *name;
    gint value;
};

/* Short names, as used in GI bindings */
static const struct _name_value_entry_t _DEBUG_MASK_ENTRIES_SHORT[] = {
    {"PARSER", MIRAGE_DEBUG_PARSER},
    {"DISC", MIRAGE_DEBUG_DISC},
    {"SESSION", MIRAGE_DEBUG_SESSION},
    {"TRACK", MIRAGE_DEBUG_TRACK},
    {"SECTOR", MIRAGE_DEBUG_SECTOR},
    {"FRAGMENT", MIRAGE_DEBUG_FRAGMENT},
    {"CDTEXT", MIRAGE_DEBUG_CDTEXT},
    {"STREAM", MIRAGE_DEBUG_STREAM},
    {"IMAGE_ID", MIRAGE_DEBUG_IMAGE_ID},
    {"WRITER", MIRAGE_DEBUG_WRITER}
};

/* Full names with MIRAGE_DEBUG_ prefix */
static const struct _name_value_entry_t _DEBUG_MASK_ENTRIES_LONG[] = {
    {"MIRAGE_DEBUG_PARSER", MIRAGE_DEBUG_PARSER},
    {"MIRAGE_DEBUG_DISC", MIRAGE_DEBUG_DISC},
    {"MIRAGE_DEBUG_SESSION", MIRAGE_DEBUG_SESSION},
    {"MIRAGE_DEBUG_TRACK", MIRAGE_DEBUG_TRACK},
    {"MIRAGE_DEBUG_SECTOR", MIRAGE_DEBUG_SECTOR},
    {"MIRAGE_DEBUG_FRAGMENT", MIRAGE_DEBUG_FRAGMENT},
    {"MIRAGE_DEBUG_CDTEXT", MIRAGE_DEBUG_CDTEXT},
    {"MIRAGE_DEBUG_STREAM", MIRAGE_DEBUG_STREAM},
    {"MIRAGE_DEBUG_IMAGE_ID", MIRAGE_DEBUG_IMAGE_ID},
    {"MIRAGE_DEBUG_WRITER", MIRAGE_DEBUG_WRITER},
};

static gboolean _match_debug_mask_name (const gchar *name, const guint len, const struct _name_value_entry_t *entries, const guint num_entries, glong *out_value)
{
    for (guint i = 0; i < num_entries; i++) {
        const struct _name_value_entry_t *entry = &entries[i];
        if (g_ascii_strncasecmp(entry->name, name, len) == 0) {
            *out_value |= entry->value;
            return TRUE;
        }
    }
    return FALSE;
}

static gboolean _parse_debug_mask_string (const gchar *mask_str, gint *mask)
{
    *mask = 0;

    /* No string or empty string */
    if (!mask_str || !mask_str[0]) {
        return TRUE;
    }

    /* Try to parse as integer */
    gchar *end_ptr;
    glong tmp_value = strtol(mask_str, &end_ptr, 0);
    if (*end_ptr == 0) {
        *mask = tmp_value;
        return TRUE;
    }

    /* Try to parse as NAME1|NAME2|... */
    tmp_value = 0;
    const gchar *ptr = mask_str;

    while (ptr && *ptr != 0) {
        gboolean valid = FALSE;
        guint len;

        end_ptr = strchr(ptr, '|');
        if (end_ptr) {
            len = end_ptr - ptr;
        } else {
            len = strlen(ptr);
        }

        /* Try to match short name */
        valid = _match_debug_mask_name(ptr, len, _DEBUG_MASK_ENTRIES_SHORT, G_N_ELEMENTS(_DEBUG_MASK_ENTRIES_SHORT), &tmp_value);
        if (!valid) {
            valid = _match_debug_mask_name(ptr, len, _DEBUG_MASK_ENTRIES_LONG, G_N_ELEMENTS(_DEBUG_MASK_ENTRIES_LONG), &tmp_value);
        }
        if (!valid) {
            g_printerr("Unhandled debug mask string: %.*s\n", len, ptr);
            return FALSE;
        }

        ptr = end_ptr ? (end_ptr + 1) : NULL;
    }

    *mask = tmp_value;
    return TRUE;
}

static gchar *_debug_mask_to_string (gint mask)
{
    static gchar buffer[1024];
    gchar *ptr = buffer;

    *ptr = 0;

    for (guint i = 0; i < G_N_ELEMENTS(_DEBUG_MASK_ENTRIES_SHORT); i++) {
        const struct _name_value_entry_t *entry = &_DEBUG_MASK_ENTRIES_SHORT[i];
        if (mask & entry->value) {
            if (ptr != buffer) {
                ptr = stpcpy(ptr, "|");
            }
            ptr = stpcpy(ptr, entry->name);
        }
    }

    return buffer;
}


/**********************************************************************\
 *                         Data format helpers                        *
\**********************************************************************/
static gchar *_main_data_format_to_string (gint format)
{
    static const struct _name_value_entry_t _MAIN_DATA_FORMAT_ENTRIES[] = {
        {"DATA", MIRAGE_MAIN_DATA_FORMAT_DATA},
        {"AUDIO", MIRAGE_MAIN_DATA_FORMAT_AUDIO},
        {"AUDIO_SWAP", MIRAGE_MAIN_DATA_FORMAT_AUDIO_SWAP}
    };

    static gchar buffer[1024];
    gchar *ptr = buffer;

    *ptr = 0;

    for (guint i = 0; i < G_N_ELEMENTS(_MAIN_DATA_FORMAT_ENTRIES); i++) {
        const struct _name_value_entry_t *entry = &_MAIN_DATA_FORMAT_ENTRIES[i];
        if (format & entry->value) {
            if (ptr != buffer) {
                ptr = stpcpy(ptr, "|");
            }
            ptr = stpcpy(ptr, entry->name);
        }
    }

    return buffer;
}

static gchar *_subchannel_format_to_string (gint format)
{
    static const struct _name_value_entry_t _SUBCHANNEL_DATA_FORMAT_ENTRIES[] = {
        {"INTERNAL", MIRAGE_SUBCHANNEL_DATA_FORMAT_INTERNAL},
        {"EXTERNAL", MIRAGE_SUBCHANNEL_DATA_FORMAT_EXTERNAL},
        {"PW96_INTERLEAVED", MIRAGE_SUBCHANNEL_DATA_FORMAT_PW96_INTERLEAVED},
        {"PW96_LINEAR", MIRAGE_SUBCHANNEL_DATA_FORMAT_PW96_LINEAR},
        {"RW96", MIRAGE_SUBCHANNEL_DATA_FORMAT_RW96},
        {"Q16", MIRAGE_SUBCHANNEL_DATA_FORMAT_Q16}
    };

    static gchar buffer[1024];
    gchar *ptr = buffer;

    *ptr = 0;

    for (guint i = 0; i < G_N_ELEMENTS(_SUBCHANNEL_DATA_FORMAT_ENTRIES); i++) {
        const struct _name_value_entry_t *entry = &_SUBCHANNEL_DATA_FORMAT_ENTRIES[i];
        if (format & entry->value) {
            if (ptr != buffer) {
                ptr = stpcpy(ptr, "|");
            }
            ptr = stpcpy(ptr, entry->name);
        }
    }

    return buffer;
}
