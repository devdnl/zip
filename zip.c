/*=========================================================================*//**
File     zip.c

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

/*==============================================================================
  Include files
==============================================================================*/
#include "zip.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#if ZIP_ENABLE_COMPRESSION
#include <zlib.h>
#endif

/*==============================================================================
  Local macros
==============================================================================*/
#if defined (__GNUC__)
#define PACKED __attribute__((packed))
#else
#error UNKNOWN COMPILER
#endif

#define local_file_header__file_name(header) ((char*)&header->file_name_extra_field[0])
#define local_file_header__extra_field(header) &header->file_name_extra_field[header->file_name_len]
#define central_directory_file_header__file_name(header) ((char*)&header->file_name_extra_field_file_comment[0])
#define central_directory_file_header__extra_field(header) &header->file_name_extra_field_file_comment[header->file_name_len]
#define central_directory_file_header__file_comment(header) &header->file_name_extra_field_file_comment[header->file_name_len + header->extra_field_len]

#define flag_encrypted_file             (1<<0)
#define flag_compression_option1        (1<<1)
#define flag_compression_option2        (1<<2)
#define flag_data_descriptor            (1<<3)
#define flag_enhanced_deflation         (1<<4)
#define flag_compressed_patched_data    (1<<5)
#define flag_strong_encryption          (1<<6)
#define flag_unused7                    (1<<7)
#define flag_unused8                    (1<<8)
#define flag_unused9                    (1<<9)
#define flag_unused10                   (1<<10)
#define flag_language_encoding          (1<<11)
#define flag_reserved12                 (1<<12)
#define flag_mask_header_values         (1<<13)
#define flag_reserved14                 (1<<14)
#define flag_reserved15                 (1<<15)

#define compression_method_store        0
#define compression_method_deflated     8

/*==============================================================================
  Local object types
==============================================================================*/
typedef struct PACKED {
        uint32_t signature;
        uint16_t version;
        uint16_t flags;
        uint16_t compression;
        uint16_t mod_time;
        uint16_t mod_date;
        uint32_t CRC32;
        uint32_t compressed_size;
        uint32_t uncompressed_size;
        uint16_t file_name_len;
        uint16_t extra_field_len;
        uint8_t  file_name_extra_field[];
} local_file_header_t;

typedef struct PACKED {
        uint32_t CRC32;
        uint32_t compressed_size;
        uint32_t uncompressed_size;
} data_descriptor_t;

typedef struct PACKED {
        uint32_t signature;
        uint16_t version;
        uint16_t version_needed;
        uint16_t flags;
        uint16_t compression;
        uint16_t mod_time;
        uint16_t mod_date;
        uint32_t CRC32;
        uint32_t compressed_size;
        uint32_t uncompressed_size;
        uint16_t file_name_len;
        uint16_t extra_field_len;
        uint16_t file_comm_len;
        uint16_t disk_num_start;
        uint16_t internal_attr;
        uint32_t external_attr;
        uint32_t offset_of_local_header;
        uint8_t  file_name_extra_field_file_comment[];
} central_directory_file_header_t;

typedef struct PACKED {
        uint32_t signature;
        uint16_t disk_number;
        uint16_t disk_num_w_cd;
        uint16_t disk_entries;
        uint16_t total_entries;
        uint32_t central_directory_size;
        uint32_t offset_of_cd_wrt_to_starting_disk;
        uint16_t comment_len;
        uint8_t  zip_file_comment[];
} end_of_central_directory_record_t;

struct zip {
        FILE *file;
        uint32_t last_offset;
        local_file_header_t *local_file_header;

        struct node {
                uint32_t offset;
                struct node *next;
        } *root;
};

/*==============================================================================
  Local function prototypes
==============================================================================*/
static uint16_t unix_timestamp_to_dos_time(time_t *time);
static uint16_t unix_timestamp_to_dos_date(time_t *time);
static int write_central_directory(zip_t *zip);
static uint32_t crc32(const void *buf, uint32_t buflen, uint32_t init);

/*==============================================================================
  Local objects
==============================================================================*/
static const uint32_t local_file_header_signature = 0x04034b50;
static const uint32_t central_directory_file_header_signature = 0x02014b50;
static const uint32_t end_of_central_directory_record_signature = 0x06054b50;
static const uint16_t archive_version = 0x0014;
static const uint32_t zip_crc32_init = 0; // negated 0xFFFFFFFF;

static const uint32_t crc32_table[256] = {
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
        0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
        0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
        0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
        0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
        0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
        0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
        0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
        0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
        0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
        0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
        0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
        0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
        0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
        0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
        0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
        0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
        0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
        0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
        0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
        0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
        0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
        0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
        0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
        0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
        0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
        0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
        0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
        0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
        0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
        0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
        0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
};

/*==============================================================================
  Exported objects
==============================================================================*/

/*==============================================================================
  External objects
==============================================================================*/

/*==============================================================================
  Function definitions
==============================================================================*/

//==============================================================================
/**
 * @brief  Open new zip file.
 *
 * @param  path         zip file path
 * @param  mode         "w"-write or "r"-read flags
 *
 * @return ZIP file object.
 */
//==============================================================================
zip_t *zip__open(const char *path, const char *mode)
{
        if (!((strcmp(mode, "r") || strcmp(mode, "w")))) {
                return NULL;
        }

        zip_t *zip = calloc(1, sizeof(*zip));
        if (zip) {
                zip->file = fopen(path, mode);
                if (zip->file) {
                        zip->file = freopen(path, "r+", zip->file);
                        if (zip->file) {
                                return zip;
                        }
                }

                zip__close(zip);
        }

        return NULL;
}

//==============================================================================
/**
 * @brief  Close zip container.
 *
 * @param  zip          zip file object
 */
//==============================================================================
void zip__close(zip_t *zip)
{
        if (zip) {
                write_central_directory(zip);
                fclose(zip->file);
                free(zip->local_file_header);
                free(zip);
        }
}

//==============================================================================
/**
 * @brief  Add directory to the archive.
 *
 * @param  zip          zip archive
 * @param  dirname      directory name
 *
 * @return On success 0 is returned.
 */
//==============================================================================
int zip__create_dir(zip_t *zip, const char *dirname)
{
        if (!zip || !dirname) {
                return EINVAL;
        }

        char *dir_path = NULL;
        size_t name_len = strlen(dirname);
        if (dirname[name_len - 1] != '/') {

                dir_path = calloc(1, name_len + 2);
                if (dir_path) {
                        strcpy(dir_path, dirname);
                        strcat(dir_path, "/");
                } else {
                        return ENOMEM;
                }
        } else {
                dir_path = (char*)dirname;
        }

        int err = zip__entry_open(zip, dir_path, zip_compression__store);
        if (!err) {
                err = zip__entry_close(zip);
        }

        if (dir_path != dirname) {
                free(dir_path);
        }

        return err;
}

//==============================================================================
/**
 * @brief  Open zip entry.
 *
 * @param  zip          zip object
 * @param  name         entry name
 *
 * @return On success 0 is returned.
 */
//==============================================================================
int zip__entry_open(zip_t *zip, const char *name, zip_compression_t compression)
{
        if (!zip || !name || (compression >= zip_compression__amount)) {
                return EINVAL;
        }

        if (!zip->local_file_header) {
                zip->local_file_header = calloc(1, sizeof(*zip->local_file_header));
                if (!zip->local_file_header) {
                        return ENOMEM;
                }
        }

        struct node **node = &zip->root;
        while (*node) {
                struct node *n = *node;
                node = &n->next;
        }

        *node = calloc(1, sizeof(struct node));
        if (*node) {
                struct node *n = * node;
                n->offset = ftell(zip->file);
                zip->last_offset = n->offset;
        } else {
                return ENOMEM;
        }

        time_t timer = time(NULL);

        zip->local_file_header->signature = local_file_header_signature;
        zip->local_file_header->version = archive_version;
        zip->local_file_header->flags = 0;
        zip->local_file_header->compression = (compression == zip_compression__store)
                                            ? compression_method_store
                                            : compression_method_deflated;
        zip->local_file_header->mod_time = unix_timestamp_to_dos_time(&timer);
        zip->local_file_header->mod_date = unix_timestamp_to_dos_date(&timer);
        zip->local_file_header->CRC32 = zip_crc32_init;
        zip->local_file_header->compressed_size = 0;
        zip->local_file_header->uncompressed_size = 0;
        zip->local_file_header->file_name_len = strlen(name);
        zip->local_file_header->extra_field_len = 0;

        errno = 0;
        fwrite(zip->local_file_header, sizeof(*zip->local_file_header), 1, zip->file);
        if (errno) return errno;

        errno = 0;
        fwrite(name, sizeof(char), zip->local_file_header->file_name_len, zip->file);
        if (errno) return errno;

        return 0;
}

//==============================================================================
/**
 * @brief  Write buffer to opened entry.
 *
 * @param  zip          zip object
 * @param  buf          buffer
 * @param  buflen       buffer length
 *
 * @return On success 0 is returned.
 */
//==============================================================================
size_t zip__entry_write_buf(zip_t *zip, const void *buf, size_t buflen)
{
        if (!zip || !buf || !buflen) {
                return EINVAL;
        }

        size_t n = 0;

        if (zip->local_file_header->compression == compression_method_store) {
                n = fwrite(buf, 1, buflen, zip->file);
                if (n) {
                        zip->local_file_header->CRC32 = crc32(buf, buflen, ~zip->local_file_header->CRC32);
                        zip->local_file_header->compressed_size += n;
                        zip->local_file_header->uncompressed_size += n;
                }

#if ZIP_ENABLE_COMPRESSION
        } else if (zip->local_file_header->compression == compression_method_deflated) {
                // TODO
#endif
        }

        return n;
}

//==============================================================================
/**
 * @brief  Write file to opened entry.
 *
 * @param  zip          zip object
 * @param  path         file path
 *
 * @return On success 0 is returned.
 */
//==============================================================================
size_t zip__entry_write_file(zip_t *zip, const char *path)
{
        size_t count = 0;

        if (!zip || !path) {
                return count;
        }

        uint8_t *buf = malloc(ZIP_FILE_BUFFER_SIZE);
        FILE *f = fopen(path, "r");

        if (buf && f) {
                size_t n;
                while ((n = fread(buf, 1, ZIP_FILE_BUFFER_SIZE, f)) > 0) {

                        if (zip__entry_write_buf(zip, buf, n) == n) {
                                count += n;
                        } else {
                                break;
                        }
                }
        }

        fclose(f);
        free(buf);

        return count;
}

//==============================================================================
/**
 * @brief  Close opened entry.
 *
 * @param  zip          zip object
 *
 * @return On success 0 is returned.
 */
//==============================================================================
int zip__entry_close(zip_t *zip)
{
        if (!zip) {
                return EINVAL;
        }

        uint32_t last = ftell(zip->file);
        errno = 0;
        fseek(zip->file, zip->last_offset, SEEK_SET);
        fwrite(zip->local_file_header, sizeof(local_file_header_t), 1, zip->file);
        fseek(zip->file, last, SEEK_SET);

        return errno;
}

//==============================================================================
/**
 * @brief  Write central directory.
 *
 * @param  zip          zip object
 *
 * @return On succecss 0 is returned.
 */
//==============================================================================
static int write_central_directory(zip_t *zip)
{
        uint8_t *name_extra_field = NULL;
        size_t central_directory_size = 0;
        uint32_t central_directory_start = ftell(zip->file);
        uint32_t entries = 0;
        int err = 0;

        struct node *node = zip->root;
        while (node) {
                uint32_t end = ftell(zip->file);

                /*
                 * Read local file header data
                 */
                local_file_header_t local_file_header;
                errno = 0;
                fseek(zip->file, node->offset, SEEK_SET);
                fread(&local_file_header, sizeof(local_file_header), 1, zip->file);
                if (errno) {
                        err = errno;
                        break;
                }

                size_t name_extra_len = local_file_header.file_name_len + local_file_header.extra_field_len;
                name_extra_field = malloc(name_extra_len);
                if (name_extra_field) {
                        errno = 0;
                        fread(name_extra_field, 1, name_extra_len, zip->file);
                        if (errno) {
                                err = errno;
                                break;
                        }

                } else {
                        err = ENOMEM;
                        break;
                }

                /*
                 * Write central directory file header
                 */
                central_directory_file_header_t central_directory_file_header;
                central_directory_file_header.signature = central_directory_file_header_signature;
                central_directory_file_header.version = archive_version | (3 << 8);
                central_directory_file_header.version_needed = archive_version;
                central_directory_file_header.flags = local_file_header.flags;
                central_directory_file_header.compression = local_file_header.compression;
                central_directory_file_header.mod_time = local_file_header.mod_time;
                central_directory_file_header.mod_date = local_file_header.mod_date;
                central_directory_file_header.CRC32 = local_file_header.CRC32;
                central_directory_file_header.compressed_size = local_file_header.compressed_size;
                central_directory_file_header.uncompressed_size = local_file_header.uncompressed_size;
                central_directory_file_header.file_name_len = local_file_header.file_name_len;
                central_directory_file_header.extra_field_len = local_file_header.extra_field_len;
                central_directory_file_header.file_comm_len = 0;
                central_directory_file_header.disk_num_start = 0;
                central_directory_file_header.internal_attr = 0;
                central_directory_file_header.external_attr = 0x81A40000;
                central_directory_file_header.offset_of_local_header = node->offset;

                errno = 0;
                fseek(zip->file, end, SEEK_SET);
                fwrite(&central_directory_file_header, sizeof(central_directory_file_header), 1, zip->file);
                if (errno) {
                        err = errno;
                        break;
                }

                errno = 0;
                fwrite(name_extra_field, 1, name_extra_len, zip->file);
                if (errno) {
                        err = errno;
                        break;
                }

                free(name_extra_field);
                name_extra_field = NULL;

                central_directory_size += sizeof(central_directory_file_header);
                central_directory_size += name_extra_len;

                entries++;

                struct node *next = node->next;
                free(node);
                node = next;
        }

        if (!err) {
                end_of_central_directory_record_t end_of_central_dir_record;
                end_of_central_dir_record.signature = end_of_central_directory_record_signature;
                end_of_central_dir_record.disk_number = 0;
                end_of_central_dir_record.disk_num_w_cd = 0;
                end_of_central_dir_record.disk_entries = entries;
                end_of_central_dir_record.total_entries = entries;
                end_of_central_dir_record.central_directory_size = central_directory_size;
                end_of_central_dir_record.offset_of_cd_wrt_to_starting_disk = central_directory_start;
                end_of_central_dir_record.comment_len = 0;

                errno = 0;
                fwrite(&end_of_central_dir_record, sizeof(end_of_central_dir_record), 1, zip->file);
                err = errno;
        }

        free(name_extra_field);

        return err;
}

//==============================================================================
/**
 * @brief  Convert unix timestamp to DOS time.
 *
 * @param  unix         unix timestamp
 *
 * @return DOS 16-bit time format.
 */
//==============================================================================
static uint16_t unix_timestamp_to_dos_time(time_t *time)
{
        struct tm tm;
        if (localtime_r(time, &tm)) {
                return ((tm.tm_sec / 2) & 0x1F)
                     | ((tm.tm_min & 0x3F) << 5)
                     | ((tm.tm_hour & 0x1F) << 11);
        } else {
                return 0;
        }
}


//==============================================================================
/**
 * @brief  Convert unix timestamp to DOS date.
 *
 * @param  unix         unix timestamp
 *
 * @return DOS 16-bit date format.
 */
//==============================================================================
static uint16_t unix_timestamp_to_dos_date(time_t *time)
{
        struct tm tm;
        if (localtime_r(time, &tm)) {
                return ((((tm.tm_year + 1900) - 1980) & 0x7F) << 9)
                     | (((tm.tm_mon + 1) & 0xF) << 5)
                     | (((tm.tm_mday) & 0x1F) << 0);
        } else {
                return 0;
        }
}

//==============================================================================
/**
 * @brief  Calculate ZIP CRC32.
 *
 * @param  buff         buffer
 * @param  bufflen      buffer length
 * @param  init         last CRC value
 *
 * @return New CRC value.
 */
//==============================================================================
static uint32_t crc32(const void *buf, uint32_t buflen, uint32_t init)
{
        uint32_t crc = init;
        const uint8_t *b = buf;

        for (size_t i = 0; i < buflen; i++) {
                char ch = b[i];
                uint32_t t = (ch ^ crc) & 0xFF;
                crc = (crc >> 8) ^ crc32_table[t];
        }

        return ~crc;
}

/*==============================================================================
  End of file
==============================================================================*/
