
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "debug.h"
#include "ext_attributes.h"
#include "fatfs/ff.h"
#include "filesystem.h"


static const int MAX_PREFS_TOKEN_LEN = 255;
static const int MAX_PREFS_VALUE_LEN = 511;
static const int MAX_PREFS_LINE_LEN = MAX_PREFS_TOKEN_LEN + MAX_PREFS_VALUE_LEN+1;

// Token written to start of ext attributes files
#define PREFS_TOKEN "# Drive Extended attributes - keep this line"

// Globals to track extended attributes
bool extAttributes = false;
char extAttributes_fileName[255];       // path and filename for .ext filename


// INQUIRY Command default data
// at least 36 bytes.
static uint8_t DefaultInquiryData[] = 
{
0x00,                                           // Peripherial Device Type
0x00,                                           // RMB / Device-Type Qualifier
0x00,                                           // ISO Version | ECMA Version | ANSI Version
0x00,                                           // Reserved
0x1E,                                           // Additional Length
0x00,                                           // Vendor Unique
0x00,                                           // Vendor Unique
0x00,                                           // Vendor Unique
0x42, 0x45, 0x45, 0x42, 0x53, 0x43, 0x53, 0x49, // Vendor  Identification ASCII "BEEBSCSI"
0x20, 0x47, 0x45, 0x4e, 0x45, 0x52, 0x49, 0x43, // Product Identification ASCII " GENERIC HD     "
0x20, 0x48, 0x44, 0x20, 0x20, 0x20, 0x20, 0x00,
0x31, 0x2E, 0x30, 0x30                          // Product Revision Level ASCII "1.00"
};

/* 
 * Function: read_attribute
 * Arguments:
 * token    - param name to be looked up
 * buf      - buffer for string value.
 */
uint8_t read_attribute(const char *token, char **buf) {

    char msg[256];

/*    if (!token || (!buf)) {
        if (debugFlag_extended_attributes) debugString_P(PSTR("ext_attributes: read_attribute: Invalid argument\r\n"));
        return 1;
    }
*/

    FIL fileObject;
    FRESULT fsResult;

    if (debugFlag_extended_attributes) {
        sprintf(msg, "ext_attributes: read_attribute: Opening file '%s'\r\n", extAttributes_fileName);
        debugString_P(PSTR(msg));
    }

    fsResult = f_open(&fileObject, extAttributes_fileName, FA_READ);

    if (fsResult != FR_OK) {
        // Something went wrong
        if (debugFlag_extended_attributes) debugString_P(PSTR("ext_attributes: read_attribute: ERROR: Could not read .ext file\r\n"));
        return 1;
    }
    
    char left[MAX_PREFS_TOKEN_LEN];
    char right[MAX_PREFS_VALUE_LEN];
    char *dlim_ptr, *end_ptr;
    char fbuf[MAX_PREFS_LINE_LEN];

    if (debugFlag_extended_attributes) {
        sprintf(msg, "ext_attributes: read_attribute: Attempting to find attribute '%s'\r\n", token);
        debugString_P(PSTR(msg));
    }

    // loop through the file looking for the parameter
    while (f_gets(fbuf, MAX_PREFS_LINE_LEN, &fileObject)) {

        // Discard any lines that don't start with A-Z, a-z
        if ( !(((fbuf[0] & 0xDF) >= 'A') && ((fbuf[0] & 0xDF) <= 'Z')))
            continue;

        if (debugFlag_extended_attributes) {
            sprintf(msg, "ext_attributes: read_attribute: File read line: '%s'\r\n", fbuf);
            debugString_P(PSTR(msg));
        }

        // try find a delimiting =, and the end of the line
        dlim_ptr = strstr(fbuf, "=");
        end_ptr = strstr(dlim_ptr, "\n");

        // check if a delimiter was found
        if (StartsWith(dlim_ptr, "=")){

            *left ='\0';
            *right = '\0';

            // get the token and the value from the line of data
            size_t token_length, value_length;
            token_length = (size_t)(dlim_ptr - fbuf);

            if (token_length > MAX_PREFS_TOKEN_LEN){
                if (debugFlag_extended_attributes) debugString_P(PSTR("ext_attributes: read_attribute: token > MAX_TOKEN_LEN chars\r\n"));
                f_close(&fileObject);
                return 1;
            }

            // this is the token
            strncpy(left, fbuf, token_length);
            left[token_length+1]='\0';

            if (debugFlag_extended_attributes) {
                sprintf(msg, "ext_attributes: Token: '%s'\r\n", left);
                debugString_P(PSTR(msg));
                debugStringInt32_P(PSTR("ext_attributes: read_attribute: Token Length: "), (uint32_t)token_length, true);
            }

            // is the left value the same as the token being searched for?
            if (strcmp(left, token) == 0) {
                if (debugFlag_extended_attributes) debugString_P(PSTR("ext_attributes: read_attribute: Attribute token found\r\n"));


                // get the value
                value_length = (size_t)(end_ptr - dlim_ptr - 1);

                // this is the value
                strncpy(right, dlim_ptr + 1, value_length);
                right[value_length]='\0';

                if (debugFlag_extended_attributes) {
                    sprintf(msg, "ext_attributes: Value: '%s'\r\n", right);
                    debugString_P(PSTR(msg));
                    debugStringInt32_P(PSTR("ext_attributes: read_attribute: Value length: "), (uint32_t)value_length, true);
                }

                if (value_length > MAX_PREFS_VALUE_LEN){
                    if (debugFlag_extended_attributes) debugString_P(PSTR("ext_attributes: read_attribute: value > MAX_VALUE_LEN chars\r\n"));
                    f_close(&fileObject);
                    return 1;
                }

                if (value_length == 0)  {
                    if (debugFlag_extended_attributes) debugString_P(PSTR("ext_attributes: read_attribute: no value found for the token\r\n"));
                    f_close(&fileObject);
                    return 1;
                }

                // does the value contain valid Hex digits


                // Attribute found 
                if (buf != NULL){
                    *buf = strdup(right);
                    f_close(&fileObject);
                    return 0;
                }
            }
         
        }
       
    }

    f_close(&fileObject);
    
    if (debugFlag_extended_attributes) debugString_P(PSTR("ext_attributes: read_attribute: ERROR: Attribute token not found\r\n"));

    return 1;
}


// Gets the Inquiry Data from the file or uses default data
//
// length is the number of expected bytes and the size of the buffer
//
// Returns 0 if successful and the Inquiry data in the buffer
//
uint8_t getInquiryData(uint8_t bytesRequested, uint8_t *buf, uint8_t LUN) {
    
    uint8_t dbLength = sizeof  DefaultInquiryData;   // length of the default data block

//    uint8_t byteCounter;

    // ensure buffer is fully zeroed in case default data or ext attributes in file
    // is shorter than the amount of bytes requested

    uint8_t buffSize = sizeof buf;
    memset(buf, 0x30 , buffSize);
    char msg[256];

// if extended attributes
    if (extAttributes){
        if (debugFlag_extended_attributes) debugString_P(PSTR("ext_attributes: getInquiryData: Extended attributes are available\r\n"));
        
        // read the attribute from the file
        if (read_attribute("Inquiry",  (char **)&buf) == 0) {
            sprintf(msg, "ext_attributes: getInquiryData: buffer returned and contains:'%s'\r\n", buf);
            debugString_P(PSTR(msg));
            return 0;
        }
        else {
            if (debugFlag_extended_attributes) debugString_P(PSTR("ext_attributes: getInquiryData: ERROR reading extended attribute 'Inquiry'\r\n"));
            // drop through and use the default data
        }
    }

    // use the default data
    if (debugFlag_extended_attributes) debugString_P(PSTR("ext_attributes: getInquiryData: Use the default data\r\n"));

    for (uint8_t i = 0; ((i != bytesRequested) && (i != dbLength)); i++){
        buf[i] = DefaultInquiryData[i];
    }

    // get the LUN size to add to the default model
    uint16_t LUN_size =  (uint16_t)((filesystemGetLunSizeFromDsc(LUN)) >> 20);   // size in MB

    if (debugFlag_extended_attributes) debugStringInt16_P(PSTR("ext_attributes: getInquiryData: LUN Size = "),LUN_size, true);

    // Place drive size in the drive model name - Max 5 chars
    if ((LUN_size >=1) && (LUN_size <= 999 )) 
        snprintf((char*)buf+25,7,"%dMB",LUN_size);
    else    
        sprintf((char*)buf+25,"BAD MB");

    // buffer updated - return
    return 0;

}

// Checks if string a starts with the character(s) given in b
//
bool StartsWith(const char *a, const char *b)
{
    return strncmp(a, b, strlen(b)) == 0;
}