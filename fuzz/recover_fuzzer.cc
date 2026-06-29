/*
 * Fuzz harness: libpff corrupted-file recovery path
 *
 * Exercises libpff_file_recover_items() — a low-level block scan that
 * rebuilds items from corrupt PST files. Tests allocation table parsing,
 * block tree reconstruction, and orphan item detection.
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
	libbfio_handle_t *bio      = NULL;
	libpff_file_t    *file     = NULL;
	/* All local vars declared before first goto to satisfy C++ rules */
	int       n_rec     = 0;
	int       n_orphan  = 0;
	int       n_unalloc = 0;
	uint8_t   ftype     = 0;
	uint8_t   ctype     = 0;
	uint8_t   etype     = 0;
	size64_t  fsize     = 0;

	if( size < 4 ) return 0;

	if( libbfio_memory_range_initialize( &bio, NULL ) != 1 )
		return 0;
	if( libbfio_memory_range_set( bio, (uint8_t *)data, size, NULL ) != 1 )
		goto done;
	if( libpff_file_initialize( &file, NULL ) != 1 )
		goto done;

	/* Open regardless of validity — recovery path handles corrupt files */
	libpff_file_open_file_io_handle( file, bio, LIBPFF_OPEN_READ, NULL );

	/* Trigger recovery scan: walks raw allocation tables + block trees */
	libpff_file_recover_items( file, 0, NULL );

	/* Walk recovered items */
	if( libpff_file_get_number_of_recovered_items( file, &n_rec, NULL ) == 1 ) {
		if( n_rec > 16 ) n_rec = 16;
		for( int i = 0; i < n_rec; i++ ) {
			libpff_item_t  *item     = NULL;
			uint32_t        ident    = 0;
			uint8_t         itype    = 0;
			int             n_sets   = 0;

			if( libpff_file_get_recovered_item_by_index( file, i, &item, NULL ) != 1 )
				continue;

			libpff_item_get_identifier( item, &ident, NULL );
			libpff_item_get_type( item, &itype, NULL );

			if( libpff_item_get_number_of_record_sets( item, &n_sets, NULL ) == 1 && n_sets > 0 ) {
				libpff_record_set_t *rs = NULL;
				if( libpff_item_get_record_set_by_index( item, 0, &rs, NULL ) == 1 ) {
					int ne = 0;
					libpff_record_set_get_number_of_entries( rs, &ne, NULL );
					libpff_record_set_free( &rs, NULL );
				}
			}
			libpff_item_free( &item, NULL );
		}
	}

	/* Walk orphan items (disconnected from folder tree) */
	if( libpff_file_get_number_of_orphan_items( file, &n_orphan, NULL ) == 1 ) {
		if( n_orphan > 8 ) n_orphan = 8;
		for( int i = 0; i < n_orphan; i++ ) {
			libpff_item_t *item = NULL;
			if( libpff_file_get_orphan_item_by_index( file, i, &item, NULL ) == 1 )
				libpff_item_free( &item, NULL );
		}
	}

	/* File-level metadata */
	libpff_file_get_type( file, &ftype, NULL );
	libpff_file_get_content_type( file, &ctype, NULL );
	libpff_file_get_encryption_type( file, &etype, NULL );
	libpff_file_get_size( file, &fsize, NULL );

	/* Unallocated block table (type 0 = data, 1 = sub-node) */
	if( libpff_file_get_number_of_unallocated_blocks( file, 0, &n_unalloc, NULL ) == 1 && n_unalloc > 0 ) {
		off64_t  off = 0;
		size64_t bsz = 0;
		libpff_file_get_unallocated_block( file, 0, 0, &off, &bsz, NULL );
	}

	libpff_file_close( file, NULL );
	libpff_file_free( &file, NULL );
	file = NULL;
done:
	libbfio_handle_free( &bio, NULL );
	return 0;
}

} /* extern "C" */
