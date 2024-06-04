
#ifndef EXT_ATTRIBUTES_H_
#define EXT_ATTRIBUTES_H

// Function prototypes
uint8_t read_attribute(const char *token, char **buf);

uint8_t getInquiryData(uint8_t bytesRequested, uint8_t *buf, uint8_t LUN);
bool StartsWith(const char *a, const char *b);


// Globals to track extended attributes
extern bool extAttributes;
extern char extAttributes_fileName[255];

#endif /* EXT_ATTRIBUTES_H_ */