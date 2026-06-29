/*
 * Fuzz harness: libpff folder hierarchy traversal
 *
 * Exercises recursive sub-folder walking, folder name reading,
 * and sub-item enumeration — tests the B-tree descend path.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" {
#include "../ossfuzz/ossfuzz_libbfio.h"
#include "../ossfuzz/ossfuzz_libpff.h"

#if !defined( LIBPFF_HAVE_BFIO )
LIBPFF_EXTERN \
int libpff_file_open_file_io_handle(
     libpff_file_t *file, libbfio_handle_t *file_io_handle,
     int access_flags, libpff_error_t **error );
#endif

static void fuzz_folder( libpff_item_t *folder, int depth )
{
	uint8_t  buf[1024];
	size_t   sz    = 0;
	int      count = 0;
	uint8_t  ftype = 0;

	if( depth > 4 ) return;

	libpff_folder_get_type( folder, &ftype, NULL );
	libpff_folder_get_utf8_name_size( folder, &sz, NULL );
	if( sz > 0 && sz <= sizeof(buf) )
		libpff_folder_get_utf8_name( folder, buf, sz, NULL );

	/* Recurse into sub-folders */
	if( libpff_folder_get_number_of_sub_folders( folder, &count, NULL ) == 1 ) {
		if( count > 4 ) count = 4;
		for( int i = 0; i < count; i++ ) {
			libpff_item_t *sub = NULL;
			if( libpff_folder_get_sub_folder( folder, i, &sub, NULL ) == 1 ) {
				fuzz_folder( sub, depth + 1 );
				libpff_item_free( &sub, NULL );
			}
		}
	}

	/* Sub-messages */
	if( libpff_folder_get_number_of_sub_messages( folder, &count, NULL ) == 1 ) {
		if( count > 8 ) count = 8;
		for( int i = 0; i < count; i++ ) {
			libpff_item_t *msg = NULL;
			if( libpff_folder_get_sub_message( folder, i, &msg, NULL ) == 1 ) {
				uint32_t ident = 0;
				libpff_item_get_identifier( msg, &ident, NULL );
				libpff_item_free( &msg, NULL );
			}
		}
	}

	/* Associated contents */
	if( libpff_folder_get_number_of_sub_associated_contents( folder, &count, NULL ) == 1 ) {
		if( count > 4 ) count = 4;
		for( int i = 0; i < count; i++ ) {
			libpff_item_t *assoc = NULL;
			if( libpff_folder_get_sub_associated_content( folder, i, &assoc, NULL ) == 1 )
				libpff_item_free( &assoc, NULL );
		}
	}

	/* Unknown items container */
	libpff_item_t *unknowns = NULL;
	if( libpff_folder_get_unknowns( folder, &unknowns, NULL ) == 1 && unknowns != NULL )
		libpff_item_free( &unknowns, NULL );
}

int LLVMFuzzerTestOneInput( const uint8_t *data, size_t size )
{
	libbfio_handle_t *bio       = NULL;
	libpff_file_t    *file      = NULL;
	libpff_item_t    *root      = NULL;
	libpff_item_t    *root_item = NULL;    /* declared before any goto */
	int               ret       = 0;

	if( size < 4 ) return 0;

	if( libbfio_memory_range_initialize( &bio, NULL ) != 1 )
		return 0;
	if( libbfio_memory_range_set( bio, (uint8_t *)data, size, NULL ) != 1 )
		goto done;
	if( libpff_file_initialize( &file, NULL ) != 1 )
		goto done;
	if( libpff_file_open_file_io_handle( file, bio, LIBPFF_OPEN_READ, NULL ) != 1 )
		goto done_file;

	if( libpff_file_get_root_folder( file, &root, NULL ) == 1 ) {
		fuzz_folder( root, 0 );
		libpff_item_free( &root, NULL );
	}

	if( libpff_file_get_root_item( file, &root_item, NULL ) == 1 ) {
		int nsub = 0;
		if( libpff_item_get_number_of_sub_items( root_item, &nsub, NULL ) == 1 ) {
			if( nsub > 8 ) nsub = 8;
			for( int i = 0; i < nsub; i++ ) {
				libpff_item_t *sub = NULL;
				if( libpff_item_get_sub_item( root_item, i, &sub, NULL ) == 1 )
					libpff_item_free( &sub, NULL );
			}
		}
		libpff_item_free( &root_item, NULL );
	}

	libpff_file_close( file, NULL );
done_file:
	libpff_file_free( &file, NULL );
done:
	libbfio_handle_free( &bio, NULL );
	return ret;
}

} /* extern "C" */
