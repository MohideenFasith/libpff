/*
 * Fuzz harness: libpff name-to-id map (MAPI named properties)
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

int LLVMFuzzerTestOneInput( const uint8_t *data, size_t size )
{
	libbfio_handle_t *bio = NULL; libpff_file_t *file = NULL;
	libpff_item_t *nid_map = NULL;

	if( size < 4 ) return 0;
	if( libbfio_memory_range_initialize( &bio, NULL ) != 1 ) return 0;
	if( libbfio_memory_range_set( bio, (uint8_t*)data, size, NULL ) != 1 ) goto done;
	if( libpff_file_initialize( &file, NULL ) != 1 ) goto done;
	if( libpff_file_open_file_io_handle( file, bio, LIBPFF_OPEN_READ, NULL ) != 1 ) goto done_file;

	if( libpff_file_get_name_to_id_map( file, &nid_map, NULL ) == 1 ) {
		int n_sets = 0;
		if( libpff_item_get_number_of_record_sets( nid_map, &n_sets, NULL ) == 1 ) {
			if( n_sets > 4 ) n_sets = 4;
			for( int si = 0; si < n_sets; si++ ) {
				libpff_record_set_t *rs = NULL;
				if( libpff_item_get_record_set_by_index( nid_map, si, &rs, NULL ) != 1 ) continue;

				int n_re = 0;
				if( libpff_record_set_get_number_of_entries( rs, &n_re, NULL ) == 1 ) {
					if( n_re > 32 ) n_re = 32;
					for( int ei = 0; ei < n_re; ei++ ) {
						libpff_record_entry_t *re = NULL;
						if( libpff_record_set_get_entry_by_index( rs, ei, &re, NULL ) == 1 ) {
							libpff_name_to_id_map_entry_t *nid = NULL;
							if( libpff_record_entry_get_name_to_id_map_entry( re, &nid, NULL ) == 1 && nid ) {
								uint8_t ntype = 0; libpff_name_to_id_map_entry_get_type( nid, &ntype, NULL );
								
								if( ntype == LIBPFF_NAME_TO_ID_MAP_ENTRY_TYPE_STRING ) {
									size_t slen = 0;
									if( libpff_name_to_id_map_entry_get_utf8_string_size( nid, &slen, NULL ) == 1 && slen > 0 ) {
										uint8_t *sb = (uint8_t*)malloc(slen);
										if(sb) { libpff_name_to_id_map_entry_get_utf8_string( nid, sb, slen, NULL ); free(sb); }
									}
								} else {
									uint32_t num = 0;
									libpff_name_to_id_map_entry_get_number( nid, &num, NULL );
								}
							}
							libpff_record_entry_free( &re, NULL );
						}
					}
				}
				libpff_record_set_free( &rs, NULL );
			}
		}
		libpff_item_free( &nid_map, NULL );
	}
	libpff_file_close( file, NULL );
done_file:
	libpff_file_free( &file, NULL );
done:
	libbfio_handle_free( &bio, NULL );
	return 0;
}
} /* extern "C" */
