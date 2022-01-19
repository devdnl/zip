/*=========================================================================*//**
File     zip.h

Author   Daniel Zorychta

Brief    Ultra Lightweight ZIP library.

         Copyright (C) 2021 Daniel Zorychta <daniel.zorychta@gmail.com>

         This program is free software; you can redistribute it and/or modify
         it under the terms of the GNU General Public License as published by
         the  Free Software  Foundation;  either version 2 of the License, or
         any later version.

         This  program  is  distributed  in the hope that  it will be useful,
         but  WITHOUT  ANY  WARRANTY;  without  even  the implied warranty of
         MERCHANTABILITY  or  FITNESS  FOR  A  PARTICULAR  PURPOSE.  See  the
         GNU General Public License for more details.

         You  should  have received a copy  of the GNU General Public License
         along  with  this  program;  if not,  write  to  the  Free  Software
         Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


*//*==========================================================================*/

/**
@defgroup ZIP_ZIP_H_ ZIP_ZIP_H_

Detailed Doxygen description.
*/
/**@{*/

#pragma once

/*==============================================================================
  Include files
==============================================================================*/
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
  Exported macros
==============================================================================*/
/*
 * Enable(1)/Disable(0) compression in zip archive by using ZLIB library.
 */
#define ZIP_ENABLE_COMPRESSION          0

/*
 * File copy buffer size.
 */
#define ZIP_FILE_BUFFER_SIZE            2048

/*==============================================================================
  Exported object types
==============================================================================*/
typedef struct zip zip_t;

typedef enum {
        zip_compression__store,
        zip_compression__deflate,
        zip_compression__amount
} zip_compression_t;

/*==============================================================================
  Exported objects
==============================================================================*/

/*==============================================================================
  Exported functions
==============================================================================*/
/*
 * Usage example:
 *
 * zip_t *zip = zip__open("my_zip.zip", "w");
 * if (zip) {
 *      if (zip__create_dir(zip, "my_dir/")) {
 *
 *              if (zip__entry_open(zip, "my_dir/file1", zip_compression__store)) {
 *                      zip__entry_write_file(zip, "file1");
 *                      zip__entry_close(zip);
 *              }
 *
 *              if (zip__entry_open(zip, "my_dir/file2.txt", zip_compression__store)) {
 *                      char *data = "The first line!\n";
 *                      zip__entry_write_buf(zip, data, strlen(data));
 *
 *                      data = "The second line!\n";
 *                      zip__entry_write_buf(zip, data, strlen(data));
 *
 *                      zip__entry_close(zip);
 *              }
 *
 *              if (zip__entry_open(zip, "another_file", zip_compression__store)) {
 *                      zip__entry_write_file(zip, "another_file");
 *                      zip__entry_close(zip);
 *              }
 *      }
 *
 *      zip__close(zip);
 * }
 */

extern zip_t *zip__open(const char *path, const char *mode);
extern void   zip__close(zip_t *zip);
extern int    zip__create_dir(zip_t *zip, const char *dirname);
extern int    zip__entry_open(zip_t *zip, const char *name, zip_compression_t compression);
extern size_t zip__entry_write_buf(zip_t *zip, const void *buf, size_t buflen);
extern size_t zip__entry_write_file(zip_t *zip, const char *path);
extern int    zip__entry_close(zip_t *zip);

/*==============================================================================
  Exported inline functions
==============================================================================*/

#ifdef __cplusplus
}
#endif

/**@}*/
/*==============================================================================
  End of file
==============================================================================*/
