/* ==========================================================================
   MED9info (Basic Freeware)
   by 2020 Nefomoto Forum

   Permission is hereby granted, free of charge, to any person obtaining
   a copy of this software and associated documentation files (the
   "Software"), to deal in the Software without restriction, including
   without limitation the rights to use, copy, modify, merge, publish,
   distribute, sublicense, and/or sell copies of the Software, and to
   permit persons to whom the Software is furnished to do so, subject to
   the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
   OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
   AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF
   OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
   IN THE SOFTWARE.
   ========================================================================== */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

uint8_t *load_file(const char *filename, size_t *filelen);

typedef struct ImageHandle {
	union {
//		uint32_t	*u32;
		uint16_t	*u16;
		uint8_t		*u8;
		char		*s;
		void		*p;
	} d;
	size_t	len;
} ImageHandle;

// simple structure to define all rom information in a simple table (reduces written code)
typedef struct ROMINFO
{
    unsigned char *sig;               // signature bytes for function to find
    unsigned char *mask;              // signature mask bytes for function to find
    unsigned int   sig_length;        // length in bytes of signature
    char *info_string;                // information format string
} ROMINFO;



/* Basic ROM Info signatures
 * -------------------------
 * These match bytes can be found using IDA or similar tool to discover the
 * functions locations in the rom and extract appropriate offsets
 *
 *                                           opcode                    address             (relative to data segment address starting at 0x400000)
 */
unsigned char Bosch_HW_ID_Signature[] =    { 0x92,0x06,0x00,0x0A,0x00, 0x50,0x00,0x00 };
unsigned char string1_signature[] =        { 0x94,0x06,0x00,0x0A,0x00, 0x50,0x00,0x00 };
unsigned char string2_signature[] =        { 0x87,0x06,0x00,0x07,0x00, 0x50,0x00,0x00 };
unsigned char string3_signature[] =        { 0x9B,0x06,0x00,0x0C,0x00, 0x50,0x00,0x00 };
unsigned char string4_signature[] =        { 0x9A,0x06,0x00,0x04,0x00, 0x50,0x00,0x00 };
unsigned char string5_signature[] =        { 0x9B,0x06,0x00,0x0F,0x00, 0x50,0x00,0x00 };
unsigned char string6_signature[] =        { 0x97,0x06,0x00,0x04,0x00, 0x50,0x00,0x00 };
unsigned char Bosch_HW_ID_Mask[] =         { 0xFF,0xFF,0xFF,0xFF,0xFF, 0xF0,0x00,0x00 };


ROMINFO rominfo[] =
{
    { Bosch_HW_ID_Signature,  Bosch_HW_ID_Mask,  sizeof(Bosch_HW_ID_Signature), "Bosch hardware number      : %s\n" },
    { string1_signature,      Bosch_HW_ID_Mask,  sizeof(string1_signature),     "Bosch software number      : %s\n" },
    { string2_signature,      Bosch_HW_ID_Mask,  sizeof(string2_signature),     "Bosch software version     : %s\n" },
    { string3_signature,      Bosch_HW_ID_Mask,  sizeof(string3_signature),     "Bosch OEM Part number      : %s\n" },
    { string4_signature,      Bosch_HW_ID_Mask,  sizeof(string4_signature),     "Bosch OEM software version : %s\n" },
    { string5_signature,      Bosch_HW_ID_Mask,  sizeof(string5_signature),     "Bosch OEM engine info      : %s\n" },
    { 0,0,0,0 }               // end table
};

//
// VAG specific code signatures for dumping memory variables.. TO DO :)
//
unsigned char blah_signature[] =           { 0x88, 0x0D, 0x00, 0x00 };
unsigned char blah_mask[] =                { 0xFF, 0x1F, 0x00, 0x00 };

unsigned char bb1_signature[] =            { 0xA0, 0x0D, 0x00, 0x00 };
unsigned char bb2_signature[] =            { 0xA0, 0x0D, 0x00, 0x00 };

unsigned char element_signature[] =        { 0x4B, 0xFF, 0x00, 0x00 };
unsigned char element_mask[] =             { 0xFF, 0xFF, 0x00, 0x00 };

unsigned char ecuid_tab_signature[] =      { 0x87, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x87, 0x06, 0x00, 0x05, 0x00, 0x50, 0x00, 0x00 };
unsigned char ecuid_tab_signature_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

unsigned char MemoryVars_Signature[]     = {
                                             0x94, 0x21, 0xFF, 0xF0, 0x7C, 0x08, 0x02, 0xA6, 0x93, 0xE1, 0x00, 0x0C, 0x90, 0x01,
                                             0x00, 0x14, 0x28, 0x03, 0x00, 0x00, 0x40, 0x80, 0x00, 0x2C, 0x3D, 0x80, 0x00, 0x00,
                                             0x39, 0x8C, 0x00, 0x00, 0x54, 0x6B, 0x10, 0x3A, 0x7F, 0xEC, 0x58, 0x2E, 0x7F, 0xE8,
                                             0x03, 0xA6, 0x39, 0x40, 0x00, 0x00, 0x93, 0xED, 0x00, 0x00, 0x99, 0x4D, 0x00, 0x00,
                                             0x4E, 0x80, 0x00, 0x21, 0x48, 0x00, 0x00, 0x14, 0x38, 0x60, 0x00, 0x25, 0x38, 0x80,
                                             0x00, 0x00, 0x38, 0xA4, 0x00, 0x00, 0x4B, 0xFF, 0x00, 0x00, 0x80, 0x01, 0x00, 0x14,
                                             0x83, 0xE1, 0x00, 0x0C, 0x7C, 0x08, 0x03, 0xA6, 0x38, 0x21, 0x00, 0x10, 0x4E, 0x80,
                                             0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00
};

unsigned char MemoryVars_Signature_Mask[]  = {
                                             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                             0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
                                             0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
                                             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                                             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                             0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00
};

/* helper functions to extract data in an "endian safe" way ... */
unsigned short get16(unsigned char *s)   { if(s == 0) return 0; return (unsigned short)( ((s[1] <<  8)) | ((s[0] )) );                                   }
unsigned short get16le(unsigned char *s) { if(s == 0) return 0; return (unsigned short)( ((s[0] <<  8)) | ((s[1]                                   )) ); }
unsigned long  get32(unsigned char *s)   { if(s == 0) return 0; return (unsigned long )( ((s[3] << 24)) | ((s[2] <<  16)) |((s[1] <<  8)) |  ((s[0])) ); }
unsigned long  get32le(unsigned char *s) { if(s == 0) return 0; return (unsigned long )( ((s[3])) | ((s[2] <<  8)) |((s[1] <<  16)) |  ((s[0] << 24)) ); }

int iload_file(struct ImageHandle *ih, const char *fname, int rw)
{
	// init image handle structure to zero's
	memset(ih, 0, sizeof(*ih));
	// load file into memory
	if(((ih->d.p)= (void *)load_file(fname,&ih->len)) == 0) return -1;
	return 0;
}

int ifree_file(struct ImageHandle *ih)
{
	if((ih->d.p) != 0) { /*printf("Freeing %d bytes at %p.\n", (int)ih->len, ih->d.p);*/ free(ih->d.p); } else { printf("Nothing to free\n"); }
	memset(ih, 0, sizeof(*ih));
	return 0;
}

/* load a file into memory and return buffer */
uint8_t *load_file(const char *filename, size_t *filelen)
{
	FILE *fp;
	uint8_t *data;
	size_t size,bytesRead;

	/* open file */
	printf("þ Opening '%s' file\n",filename);
	if ((fp = (FILE *)fopen(filename, "rb")) == NULL){ printf("\nCan't open file \"%s\".", filename); return(0); }

	/* get file length */
//	printf("þ Getting length of '%s' file\n",filename);
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if(size <= 0) { printf("Error: Problem with seeking filesize\n"); fclose(fp); return(0); }

	*filelen = size;		/* return size of file to caller */

	/* alloc buffer for file */
//	printf("þ Allocating buffer of %d bytes (%p)\n",(int)size,(void *)size);
	data = (uint8_t *)malloc(size);
	if(data == 0) { printf("\nfailed to allocate memory to load module\n"); fclose(fp); return 0; }

	/* load file into buffer */
//	printf("þ Reading file to buffer\n");
	bytesRead = fread(data, 1, size, fp);

	/* validate it all loaded correctly */
//	printf("þ Validating size correct %d=%d\n",(int)bytesRead,(int)size);
	if(bytesRead != size) { printf("\nfailed to load module into buffer\n"); free(data); fclose(fp); return 0; }

	/* close the file */
//	printf("þ Closing file\n\n");
	fclose(fp);
	return(data);
}

/* find_signature() - match a signature using  mask bytes */
signed int find_signature(int rom_load_addr, unsigned char *signature, unsigned char *signature_mask, int rom_filesize, int signature_size, int offset, int skip_bytes)
{
  unsigned char *pSearchBuffer;
  int bytes_left = rom_filesize - signature_size;
  int pos=0;
  int i;
  unsigned char match_byte;
  unsigned int matched;

    while ( bytes_left >= 0 )                               // keep searching until we reach end of buffer
    {
            pSearchBuffer = (rom_load_addr + pos + offset);       // calculate address of current search buffer point
            matched = 0;
            for ( i = 0; i < signature_size; ++i )                // see if signature match on this buffer
            {
                match_byte  = *(pSearchBuffer + i);               // get byte from input search buffer
                match_byte &= *(i + signature_mask);              // apply signature mask to remove any bits we are uninterested in matching on
                if(match_byte == *(i + signature)) { matched++; } // check match and count number of byte matches in buffer until full signature is matched
            }

            if(matched == signature_size) {
//                printf("Fully matched entire full signature mask of %d bytes at file-offset: 0x%x!\n",matched, offset+pos);
                return pos;                                       // return offset where it was discovered
            }

            pos += skip_bytes;                                    // move on to next search point in buffer
            bytes_left -= skip_bytes;                             // deduct number of bytes searched so far..
    }
    return -1;                                                    // masked bytes where not found in buffer
}

int main(int argc, char **argv)
{
	ImageHandle f;
	ImageHandle *fh = &f;
	int load_result;
	unsigned char *rom_load_addr;
    int rom_filesize;
    int found_pos=0;
    int ecuid_tab=0;
    int next;
    int num_entries=0;
    int entry=0;
    int pAdr=0;
    int len;
    int pTmp1=0,pTmp2=0,pTmp3=0,pTmp4=0,pTmp5=0,_pTmp1Cpy=0;
    int num_elements_found=0;
    char *element_buffer;
    unsigned char ecuid_table_offset;
    unsigned int MED9_ROM_DATA_OFFSET = 0x400000;

       printf("MED9BasicInf v0.1 (c) 2019 by 360trev. << Freeware >>\n\n");
       if(argc < 2) {
            printf("Usage: %s <filename> ...\n\n",argv[0]);
            return 0;
       }
       
      /* load file from storage */
      load_result = iload_file(fh, argv[1], 0);
	  if(load_result != 0) 
      {
            printf("Failed to load rom file. Exiting...\n");
            return 0;
      }
      printf("Succeded loading file.\n\n");
      rom_load_addr = (unsigned char *)(fh->d.p);
      rom_filesize  = fh->len;
      
      printf("Searching for MED 9 ECUID signature function...");
      // search for signature match for ECUID routine
      found_pos = find_signature( rom_load_addr, ecuid_tab_signature, ecuid_tab_signature_mask, rom_filesize, sizeof(ecuid_tab_signature), 0, 1);
      if ( found_pos >= 0 ) // found ?
      {
            next      = found_pos;   // save next position to continue searching from
            ecuid_tab = (get32le( (rom_load_addr+found_pos+4) )) - found_pos;

            printf("\nFound an MED9 ECUID signature @ offset:0x%x, table offset @ offset:0x%x...\n\n",found_pos, ecuid_tab);

            while(1) {
                  if(rominfo[entry].info_string == 0) { break; }      // last entry?
                  /// find and show entry from rom table
                  found_pos = find_signature(rom_load_addr, rominfo[entry].sig , rominfo[entry].mask, ecuid_tab, rominfo[entry].sig_length, next, 8);
                  if ( found_pos >= 0 ) { printf(rominfo[entry].info_string, ((get32le( (&rom_load_addr[found_pos + 4 + next]) )) - MED9_ROM_DATA_OFFSET) + rom_load_addr); num_entries++; }
                  entry++;
            };

            if ( ecuid_tab != 232 ) // does this type of rom have engine code too?
            {
              found_pos = find_signature(rom_load_addr, string6_signature, Bosch_HW_ID_Mask, ecuid_tab, sizeof(string5_signature), next, 8);
              if ( found_pos >= 0 ) { printf("Bosch OEM engine code      : %s\n", ((get32le( (&rom_load_addr[found_pos + 4 + next]) )) - MED9_ROM_DATA_OFFSET) + rom_load_addr); num_entries++; }
            }

            // FIXME: Walk through and dump variables memory table AND dump variables..
            num_entries = 0;
            puts("\nLooking for memory variables...");
            found_pos = find_signature(rom_load_addr, MemoryVars_Signature, MemoryVars_Signature_Mask, rom_filesize, sizeof(MemoryVars_Signature), 0, 1);
            if ( found_pos < 0 ) {
                printf("Couldn't find memory variables.");
            } else {
                printf("found memory vars function @ offset: 0x%x\n",found_pos);
                printf("table has %d elements\n",((get16le( (&rom_load_addr[found_pos + 18]) )) ));
            }

      } else {

          printf("\nProbably NOT a Bosch MED9 ROM file...Giving up!\n");
          ifree_file(&f);
          return -1;
      }

      ifree_file(&f);
      return 0;
}
