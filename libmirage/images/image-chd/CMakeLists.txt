set(image_short "chd")
set(image_name "image-${image_short}")

project(${image_name} LANGUAGES C)

# Dependencies
pkg_check_modules(LIBCHDR libchdr>=0.2 IMPORTED_TARGET)

# Build
if(LIBCHDR_FOUND AND (GLIB_glib-2.0_VERSION VERSION_GREATER_EQUAL "2.58"))
    # Check if libchdr has the new file I/O API; this was introduced in
    # v0.3.0, but since some distributions seem to be packaging older git
    # snapshots, do a feature check rather than version check.
    include(CheckSourceCompiles)
    include(CMakePushCheckState)

    cmake_push_check_state(RESET)
        set(CMAKE_REQUIRED_LIBRARIES PkgConfig::LIBCHDR)
        set(CMAKE_REQUIRED_QUIET ON)
        check_source_compiles(C [[
            #include <chd.h>
            int main (void)
            {
                struct chd_core_file_callbacks chd_io_adapter;
                (void)chd_io_adapter;
                return 0;
            }
        ]] HAVE_NEW_IO_API)
    cmake_pop_check_state()

    add_library(${image_name} MODULE
        fragment.c
        parser.c
        plugin.c
    )
    target_link_libraries(${image_name} PRIVATE mirage)
    target_link_libraries(${image_name} PRIVATE PkgConfig::LIBCHDR)

    if(HAVE_NEW_IO_API)
        message(STATUS "libchdr: using new I/O adapter API")
        target_compile_definitions(${image_name} PUBLIC HAVE_NEW_IO_API)
    else()
        message(STATUS "libchdr: using legacy I/O adapter API")
    endif()

    # Disable library prefix
    set_target_properties(${image_name} PROPERTIES PREFIX "")

    # Install
    install(TARGETS ${image_name} DESTINATION ${MIRAGE_PLUGIN_DIR})

    # Add to list of enabled image formats
    list(APPEND IMAGE_FORMATS_ENABLED ${image_short})
    set(IMAGE_FORMATS_ENABLED ${IMAGE_FORMATS_ENABLED} PARENT_SCOPE)
else()
    # Add to list of disabled image formats
    list(APPEND IMAGE_FORMATS_DISABLED ${image_short})
    set(IMAGE_FORMATS_DISABLED ${IMAGE_FORMATS_DISABLED} PARENT_SCOPE)
endif()
