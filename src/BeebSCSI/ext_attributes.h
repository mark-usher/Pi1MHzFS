
#ifndef EXT_ATTRIBUTES_H_
#define EXT_ATTRIBUTES_H

// Function prototypes
uint16_t read_attribute(const char *token, char *buf);

uint8_t getInquiryData(uint8_t bytesRequested, uint8_t *buf, uint8_t LUN);
uint8_t readModePage(uint8_t LUN, uint8_t Page, uint8_t PageLength, uint8_t *returnBuffer);
uint8_t getModePage(uint8_t LUN, uint8_t *DefaultValue, uint8_t Page, uint8_t PageLength, uint8_t *returnBuffer) ;

bool StartsWith(const char *a, const char *b);
void ToHexString(char *hex, char *string);
void FromHexString(char *hex, char *string, size_t length);
bool ValidHexString(char *buf);


// Globals to track extended attributes
extern char extAttributes_fileName[255];

#endif /* EXT_ATTRIBUTES_H_ */