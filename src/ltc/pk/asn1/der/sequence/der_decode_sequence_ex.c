/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt.h"


/**
  @file der_decode_sequence_ex.c
  ASN.1 DER, decode a SEQUENCE, Tom St Denis
*/

#ifdef LTC_DER

/**
   Decode a SEQUENCE
   @param in       The DER encoded input
   @param inlen    The size of the input
   @param list     The list of items to decode
   @param outlen   The number of items in the list
   @param ordered  Search an unordered or ordered list
   @return CRYPT_OK on success
*/
int der_decode_sequence_ex(const unsigned char *in, unsigned long  inlen,
                           ltc_asn1_list *list,     unsigned long  outlen, unsigned int flags)
{
   int           err, seq_err, i, ordered;
   ltc_asn1_type type;
   unsigned long size, x, y, z, blksize;
   void          *data;

   LTC_ARGCHK(in   != NULL);
   LTC_ARGCHK(list != NULL);

   /* get blk size */
   if (inlen < 2) {
      return CRYPT_INVALID_PACKET;
   }

   /* sequence type? We allow 0x30 SEQUENCE and 0x31 SET since fundamentally they're the same structure */
   x = 0;
   if (in[x] != 0x30 && in[x] != 0x31) {
      return CRYPT_INVALID_PACKET;
   }
   ++x;

   /* check if the msb is set, which signals that the
    * 7 lsb bits represent the number of bytes of the length
    */
   y = inlen - x;
   if ((err = der_decode_asn1_length(&in[x], &y, &blksize)) != CRYPT_OK) {
      return err;
   }
   x += y;

   /* would this blksize overflow? */
   if (blksize > (inlen - x)) {
      return CRYPT_INVALID_PACKET;
   }

   /* mark all as unused */
   for (i = 0; i < (int)outlen; i++) {
       list[i].used = 0;
   }
   ordered = flags & LTC_DER_SEQ_ORDERED;

   /* ok read data */
   seq_err  = CRYPT_OK;
   blksize += x;
   inlen   -= x;
   for (i = 0; i < (int)outlen; i++) {
       z    = 0;
       type = list[i].type;
       size = list[i].size;
       data = list[i].data;
       if (!ordered && list[i].used == 1) { continue; }

       if (type == LTC_ASN1_EOL) {
          break;
       }

       switch (type) {
           case LTC_ASN1_BOOLEAN:
               z = inlen;
               if ((err = der_decode_boolean(in + x, z, ((int *)data))) != CRYPT_OK) {
                   if (!ordered || list[i].optional) { continue; }
                   goto LBL_ERR;
               }
               if ((err = der_length_boolean(&z)) != CRYPT_OK) {
                   goto LBL_ERR;
               }
               break;

           case LTC_ASN1_INTEGER:
               z = inlen;
               if ((err = der_decode_integer(in + x, z, data)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_integer(data, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_SHORT_INTEGER:
               z = inlen;
               if ((err = der_decode_short_integer(in + x, z, data)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_short_integer(((unsigned long*)data)[0], &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }

               break;

           case LTC_ASN1_BIT_STRING:
               z = inlen;
               if ((err = der_decode_bit_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_bit_string(size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_RAW_BIT_STRING:
               z = inlen;
               if ((err = der_decode_raw_bit_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_bit_string(size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_OCTET_STRING:
               z = inlen;
               if ((err = der_decode_octet_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_octet_string(size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_NULL:
               if (inlen < 2 || in[x] != 0x05 || in[x+1] != 0x00) {
                  if (!ordered || list[i].optional) { continue; }
                  err = CRYPT_INVALID_PACKET;
                  goto LBL_ERR;
               }
               z = 2;
               break;

           case LTC_ASN1_OBJECT_IDENTIFIER:
               z = inlen;
               if ((err = der_decode_object_identifier(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_object_identifier(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_TELETEX_STRING:
               z = inlen;
               if ((err = der_decode_teletex_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_teletex_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_IA5_STRING:
               z = inlen;
               if ((err = der_decode_ia5_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_ia5_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;


           case LTC_ASN1_PRINTABLE_STRING:
               z = inlen;
               if ((err = der_decode_printable_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_printable_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_UTF8_STRING:
               z = inlen;
               if ((err = der_decode_utf8_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_utf8_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_UTCTIME:
               z = inlen;
               if ((err = der_decode_utctime(in + x, &z, data)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_GENERALIZEDTIME:
               z = inlen;
               if ((err = der_decode_generalizedtime(in + x, &z, data)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_SET:
               z = inlen;
               if ((err = der_decode_set(in + x, z, data, size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_sequence(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_SETOF:
           case LTC_ASN1_SEQUENCE:
               /* detect if we have the right type */
               if ((type == LTC_ASN1_SETOF && (in[x] & 0x3F) != 0x31) || (type == LTC_ASN1_SEQUENCE && (in[x] & 0x3F) != 0x30)) {
                  err = CRYPT_INVALID_PACKET;
                  goto LBL_ERR;
               }

               z = inlen;
               err = der_decode_sequence_ex(in + x, z, data, size, flags);
               if (err == CRYPT_INPUT_TOO_LONG) {
                  seq_err = CRYPT_INPUT_TOO_LONG;
                  err = CRYPT_OK;
               }
               if (err != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_sequence(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_CUSTOM_TYPE:
               z = inlen;
               if ((err = der_decode_custom_type(in + x, z, &list[i])) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_custom_type(&list[i], &z, NULL)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_CHOICE:
               z = inlen;
               if ((err = der_decode_choice(in + x, &z, data, size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_EOL:
               err = CRYPT_INVALID_ARG;
               goto LBL_ERR;
       }
       x           += z;
       inlen       -= z;
       list[i].used = 1;
       if (!ordered) {
          /* restart the decoder */
          i = -1;
       }
   }

   for (i = 0; i < (int)outlen; i++) {
      if (list[i].used == 0 && list[i].optional == 0) {
          err = CRYPT_INVALID_PACKET;
          goto LBL_ERR;
      }
   }

   if (blksize == x && seq_err == CRYPT_OK && inlen == 0) {
      /* everything decoded and no errors in nested sequences */
      err = CRYPT_OK;
   } else if (blksize == x && seq_err == CRYPT_INPUT_TOO_LONG && inlen == 0) {
      /* a sequence reported too-long input, but now we've decoded everything */
      err = CRYPT_OK;
   } else if (blksize != x && ((flags & LTC_DER_SEQ_RELAXED) != LTC_DER_SEQ_RELAXED)) {
      err = CRYPT_INVALID_PACKET;
   } else {
      err = CRYPT_INPUT_TOO_LONG;
   }

LBL_ERR:
   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
