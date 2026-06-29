/*
 * Fuzz harness: libpff attachment data extraction
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

static void fuzz_attachment( libpff_item_t *attachment )
{
	uint8_t buf[2048]; size_t sz = 0; int type = 0;

	libpff_attachment_get_type( attachment, &type, NULL );

	libpff_attachment_get_utf8_short_filename_size( attachment, &sz, NULL );
	if( sz > 0 && sz <= sizeof(buf) )
		libpff_attachment_get_utf8_short_filename( attachment, buf, sz, NULL );
	sz = 0;
	libpff_attachment_get_utf8_long_filename_size( attachment, &sz, NULL );
	if( sz > 0 && sz <= sizeof(buf) )
		libpff_attachment_get_utf8_long_filename( attachment, buf, sz, NULL );

	size_t dsz = 0;
	if( libpff_attachment_get_data_size( attachment, &dsz, NULL ) == 1 && dsz > 0 ) {
		size_t rsz = dsz < 65536 ? dsz : 65536;
		uint8_t *d = (uint8_t*)malloc(rsz);
		if(d) { libpff_attachment_data_read_buffer( attachment, d, rsz, NULL ); free(d); }
	}

	if( type == LIBPFF_ATTACHMENT_TYPE_ITEM ) {
		libpff_item_t *embedded = NULL;
		if( libpff_attachment_get_item( attachment, &embedded, NULL ) == 1 && embedded ) {
			sz = 0;
			libpff_message_get_utf8_subject_size( embedded, &sz, NULL );
			if( sz > 0 && sz <= sizeof(buf) )
				libpff_message_get_utf8_subject( embedded, buf, sz, NULL );
			libpff_item_free( &embedded, NULL );
		}
	}
}

int LLVMFuzzerTestOneInput( const uint8_t *data, size_t size )
{
	libbfio_handle_t *bio = NULL; libpff_file_t *file = NULL;
	libpff_item_t *root = NULL;

	if( size < 4 ) return 0;
	if( libbfio_memory_range_initialize( &bio, NULL ) != 1 ) return 0;
	if( libbfio_memory_range_set( bio, (uint8_t*)data, size, NULL ) != 1 ) goto done;
	if( libpff_file_initialize( &file, NULL ) != 1 ) goto done;
	if( libpff_file_open_file_io_handle( file, bio, LIBPFF_OPEN_READ, NULL ) != 1 ) goto done_file;

	if( libpff_file_get_root_folder( file, &root, NULL ) == 1 ) {
		int n_msg = 0;
		if( libpff_folder_get_number_of_sub_messages( root, &n_msg, NULL ) == 1 ) {
			if( n_msg > 8 ) n_msg = 8;
			for( int mi = 0; mi < n_msg; mi++ ) {
				libpff_item_t *msg = NULL;
				if( libpff_folder_get_sub_message( root, mi, &msg, NULL ) != 1 ) continue;
				int n_att = 0;
				if( libpff_message_get_number_of_attachments( msg, &n_att, NULL ) == 1 ) {
					if( n_att > 8 ) n_att = 8;
					for( int ai = 0; ai < n_att; ai++ ) {
						libpff_item_t *att = NULL;
						if( libpff_message_get_attachment( msg, ai, &att, NULL ) == 1 ) {
							fuzz_attachment( att );
							libpff_item_free( &att, NULL );
						}
					}
				}
				libpff_item_free( &msg, NULL );
			}
		}
		libpff_item_free( &root, NULL );
	}
	libpff_file_close( file, NULL );
done_file:
	libpff_file_free( &file, NULL );
done:
	libbfio_handle_free( &bio, NULL );
	return 0;
}
} /* extern "C" */
