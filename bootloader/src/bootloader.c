/**
 * @file bootloader.c
 * @author Kyle Scaplen
 * @brief Bootloader implementation
 * @date 2022
 * 
 * This source file is part of an example system for MITRE's 2022 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2022 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 * 
 * @copyright Copyright (c) 2022 The MITRE Corporation
 */

#include <stdint.h>
#include <stdbool.h>

#include "driverlib/interrupt.h"
#include "driverlib/eeprom.h"
#include "driverlib/sysctl.h"

#include "inc/hw_eeprom.h"
#include "inc/hw_types.h"

#include "flash.h"
#include "uart.h"

#include "common.h"
#include "crypto.h"
#include "chacha20.h"
#include "sha256.h"

// this will run if EXAMPLE_AES is defined in the Makefile (see line 54)
#ifdef EXAMPLE_AES
#include "aes.h"
#endif

// Storage layout

/*
 * Firmware:
 *      Size:       0x0002B400 : 0x0002B404 (4B)
 *      Version:    0x0002B404 : 0x0002B408 (4B)
 *      Signature:  0x0002B408 : 0x0002B460 (88B)
 *      Hash:       0x0002B460 : 0x0002B480 (32B)
 *      Msg:        0x0002B800 : 0x0002BC00 (2KB = 1KB + 1B + pad)
 *      Fw:         0x0002BC00 : 0x0002FC00 (16KB)
 * Configuration:
 *      Signature:  0x0002FC00 : 0x0002FC58 (88B)
 *      Size:       0x0002FC58 : 0x0002FC5C (4B)
 *      Cfg:        0x0002FC5C : 0x0003FC5C (64KB)
 */

#define SIG_SIZE 88
//      Name                                        Start                       Offset
#define FIRMWARE_METADATA_PTR           ((uint32_t)(FLASH_START                 + 0x0002B400))
#define FIRMWARE_SIZE_PTR               ((uint32_t)(FIRMWARE_METADATA_PTR       + 0))
#define FIRMWARE_VERSION_PTR            ((uint32_t)(FIRMWARE_SIZE_PTR           + 4))
#define FIRMWARE_SIGNATURE_PTR          ((uint32_t)(FIRMWARE_VERSION_PTR        + 4))
#define FIRMWARE_HASH_PTR               ((uint32_t)(FIRMWARE_SIGNATURE_PTR      + SIG_SIZE))
#define FIRMWARE_RELEASE_MSG_PTR        ((uint32_t)(FIRMWARE_METADATA_PTR       + FLASH_PAGE_SIZE))
#define FIRMWARE_RELEASE_MSG_PTR2       ((uint32_t)(FIRMWARE_METADATA_PTR       + (FLASH_PAGE_SIZE*2)))

#define FIRMWARE_STORAGE_PTR            ((uint32_t)(FIRMWARE_METADATA_PTR       + (FLASH_PAGE_SIZE*4)))
#define FIRMWARE_BOOT_PTR               ((uint32_t)(0x20004000                  + 0))

#define CONFIGURATION_METADATA_PTR      ((uint32_t)(FIRMWARE_STORAGE_PTR        + (FLASH_PAGE_SIZE*16)))
#define CONFIGURATION_SIGNATURE_PTR     ((uint32_t)(CONFIGURATION_METADATA_PTR  + 0))
#define CONFIGURATION_SIZE_PTR          ((uint32_t)(CONFIGURATION_SIGNATURE_PTR + SIG_SIZE))

#define CONFIGURATION_STORAGE_PTR       ((uint32_t)(CONFIGURATION_SIZE_PTR      + 4))

#define EEPROM_CHACHA_SIZE  (8)
#define EEPROM_CHACHA_PTR   (0)

// Firmware update constants
#define FRAME_OK 0x00
#define FRAME_BAD 0x01

/**
 * @brief Boot the firmware.
 */
void handle_boot(void)
{
    uint32_t size;
    uint32_t i = 0;
    uint32_t chacha_key[8];

    uint8_t *rel_msg;

    HWREG(EEPROM_EEOFFSET) = 0;
    EEPROMRead(chacha_key, EEPROM_CHACHA_PTR, EEPROM_CHACHA_SIZE * 4);

    // Acknowledge the host
    uart_writeb(HOST_UART, 'B');

    // Find the metadata
    size = *((uint32_t *)FIRMWARE_SIZE_PTR);

    int result = verify_data(FIRMWARE_SIGNATURE_PTR, SIG_SIZE, FIRMWARE_STORAGE_PTR, size, chacha_key);
    uart_writeb(HOST_UART, (uint8_t)result);
    if(result != VERIFY_OK)
    {
        return;
    }

    // Copy the firmware into the Boot RAM section

    uint8_t* fw = (uint8_t*)FIRMWARE_STORAGE_PTR;

    stream_state chacha;
    chacha20_init(&chacha, chacha_key, 32, fw, 12);
    chacha20_encrypt(&chacha, &fw[12], FIRMWARE_BOOT_PTR, size - 12);

    result = verify_hash(FIRMWARE_BOOT_PTR, size - 12, FIRMWARE_HASH_PTR);
    uart_writeb(HOST_UART, (uint8_t)result);
    if(result != VERIFY_OK)
    {
        return;
    }

    // Print the release message
    rel_msg = (uint8_t *)FIRMWARE_RELEASE_MSG_PTR;
    while (*rel_msg != 0) {
        uart_writeb(HOST_UART, *rel_msg);
        rel_msg++;
    }
    uart_writeb(HOST_UART, '\0');

    // Execute the firmware
    void (*firmware)(void) = (void (*)(void))(FIRMWARE_BOOT_PTR + 1);
    firmware();
}


/**
 * @brief Send the firmware data over the host interface.
 */
void handle_readback(void)
{
    uint8_t region;
    uint8_t *address;
    uint32_t size = 0;

    // Acknowledge the host
    uart_writeb(HOST_UART, 'R');

    // Receive region identifier
    region = (uint32_t)uart_readb(HOST_UART);

    if (region == 'F') {
        // Set the base address for the readback
        address = (uint8_t *)FIRMWARE_STORAGE_PTR;
        // Acknowledge the host
        uart_writeb(HOST_UART, 'F');
    } else if (region == 'C') {
        // Set the base address for the readback
        address = (uint8_t *)CONFIGURATION_STORAGE_PTR;
        // Acknowledge the hose
        uart_writeb(HOST_UART, 'C');
    } else {
        return;
    }

    // Receive the size to send back to the host
    size = ((uint32_t)uart_readb(HOST_UART)) << 24;
    size |= ((uint32_t)uart_readb(HOST_UART)) << 16;
    size |= ((uint32_t)uart_readb(HOST_UART)) << 8;
    size |= (uint32_t)uart_readb(HOST_UART);

    // Read out the memory
    uart_write(HOST_UART, address, size);
}


/**
 * @brief Read data from a UART interface and program to flash memory.
 * 
 * @param interface is the base address of the UART interface to read from.
 * @param dst is the starting page address to store the data.
 * @param size is the number of bytes to load.
 */
void load_data(uint32_t interface, uint32_t dst, uint32_t size)
{
    int i;
    uint32_t frame_size;
    uint8_t page_buffer[FLASH_PAGE_SIZE];

    while(size > 0) {
        // calculate frame size
        frame_size = size > FLASH_PAGE_SIZE ? FLASH_PAGE_SIZE : size;
        // read frame into buffer
        uart_read(HOST_UART, page_buffer, frame_size);
        // pad buffer if frame is smaller than the page
        for(i = frame_size; i < FLASH_PAGE_SIZE; i++) {
            page_buffer[i] = 0xFF;
        }
        // clear flash page
        flash_erase_page(dst);
        // write flash page
        flash_write((uint32_t *)page_buffer, dst, FLASH_PAGE_SIZE >> 2);
        // next page and decrease size
        dst += FLASH_PAGE_SIZE;
        size -= frame_size;
        // send frame ok
        uart_writeb(HOST_UART, FRAME_OK);
    }
}

/**
 * @brief Update the firmware.
 */
void handle_update(void)
{
    // metadata
    uint32_t current_version;
    uint32_t version = 0;
    uint32_t size = 0;
    uint32_t rel_msg_size = 0;
    uint32_t signature[SIG_SIZE/4];
    uint32_t fw_signature[SIG_SIZE/4];
    uint32_t chacha_key[8];
    uint8_t rel_msg[1025]; // 1024 + terminator
    uint8_t u8_sha_out[32];
    uint8_t fw_raw_hash[32];

    struct sha256_context sha;
    sha256_init(&sha);

    HWREG(EEPROM_EEOFFSET) = 0;
    EEPROMRead(chacha_key, EEPROM_CHACHA_PTR, EEPROM_CHACHA_SIZE * 4);

    // Acknowledge the host
    uart_writeb(HOST_UART, 'U');

    uart_read(HOST_UART, (uint8_t*)signature, SIG_SIZE);
    uart_writeb(HOST_UART, 0);

    uart_read(HOST_UART, (uint8_t*)fw_signature, SIG_SIZE);
    uart_writeb(HOST_UART, 0);

    uart_read(HOST_UART, (uint8_t*)&size, 4);
    uart_read(HOST_UART, (uint8_t*)&version, 4);
    uart_read(HOST_UART, fw_raw_hash, 32);
    
    rel_msg_size = uart_readline(HOST_UART, rel_msg) + 1;

    sha256_hash(&sha, &version, 4);
    sha256_hash(&sha, &size, 4);
    sha256_hash(&sha, fw_raw_hash, 32);
    sha256_hash(&sha, rel_msg, rel_msg_size);
    sha256_done(&sha, u8_sha_out);

    int result = verify_data_prehash(signature, SIG_SIZE, u8_sha_out, chacha_key);
    uart_writeb(HOST_UART, (uint8_t)result);
    if(result != VERIFY_OK)
    {
        return;
    }

    // Check the version
    current_version = *((uint32_t *)FIRMWARE_VERSION_PTR);
    if (current_version == 0xFFFFFFFF) {
        current_version = (uint32_t)OLDEST_VERSION;
    }

    if ((version != 0) && (version < current_version)) 
    {
        // Version is not acceptable
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }
    else
    {
        uart_writeb(HOST_UART, FRAME_OK);
    }

    // Clear firmware metadata
    flash_erase_page(FIRMWARE_METADATA_PTR);

    // Only save new version if it is not 0
    if (version != 0) {
        flash_write_word(version, FIRMWARE_VERSION_PTR);
    } else {
        flash_write_word(current_version, FIRMWARE_VERSION_PTR);
    }

    // Save size
    flash_write_word(size, FIRMWARE_SIZE_PTR);

    // Save signature
    flash_write(fw_signature, FIRMWARE_SIGNATURE_PTR, SIG_SIZE >> 2);

    // Save raw hash
    flash_write(fw_raw_hash, FIRMWARE_HASH_PTR, 8);

    // Write release message
    uint8_t *rel_msg_read_ptr = rel_msg;
    uint32_t rel_msg_write_ptr = FIRMWARE_RELEASE_MSG_PTR;
    uint32_t rem_bytes = rel_msg_size;

    // If release message goes outside of the first page, write the first full page
    if (rel_msg_size > (FLASH_PAGE_SIZE-96)) {

        // Write first page
        flash_write((uint32_t *)rel_msg, FIRMWARE_RELEASE_MSG_PTR, (FLASH_PAGE_SIZE-96) >> 2); // This is always a multiple of 4

        // Set up second page
        rem_bytes = rel_msg_size - (FLASH_PAGE_SIZE-96);
        rel_msg_read_ptr = rel_msg + (FLASH_PAGE_SIZE-96);
        rel_msg_write_ptr = FIRMWARE_RELEASE_MSG_PTR2;
        flash_erase_page(rel_msg_write_ptr);
    }

    // Program last or only page of release message
    if (rem_bytes % 4 != 0) {
        rem_bytes += 4 - (rem_bytes % 4); // Account for partial word
    }
    flash_write((uint32_t *)rel_msg_read_ptr, rel_msg_write_ptr, rem_bytes >> 2);
    
    // Retrieve firmware
    load_data(HOST_UART, FIRMWARE_STORAGE_PTR, size);

    uart_writeb(HOST_UART, FRAME_OK);
}


/**
 * @brief Load configuration data.
 */
void handle_configure(void)
{
    uint32_t size = 0;
    uint32_t chacha_key[8];
    uint32_t signature[SIG_SIZE/4];

    HWREG(EEPROM_EEOFFSET) = 0;
    EEPROMRead(chacha_key, EEPROM_CHACHA_PTR, EEPROM_CHACHA_SIZE * 4);

    // Acknowledge the host
    uart_writeb(HOST_UART, 'C');

    // Receive size
    size =  (((uint32_t)uart_readb(HOST_UART)) << 24);
    size |= (((uint32_t)uart_readb(HOST_UART)) << 16);
    size |= (((uint32_t)uart_readb(HOST_UART)) << 8);
    size |= ((uint32_t)uart_readb(HOST_UART));
    uart_read(HOST_UART, signature, SIG_SIZE);

    uart_writeb(HOST_UART, FRAME_OK);

    flash_erase_page(CONFIGURATION_METADATA_PTR);
    flash_write(signature, CONFIGURATION_SIGNATURE_PTR, SIG_SIZE >> 4);
    flash_write_word(size, CONFIGURATION_SIZE_PTR);

    load_data(HOST_UART, CONFIGURATION_STORAGE_PTR, size);

    int result = verify_data(signature, SIG_SIZE, CONFIGURATION_STORAGE_PTR, size, chacha_key);
    uart_writeb(HOST_UART, (uint8_t)result);
}


/**
 * @brief Host interface polling loop to receive configure, update, readback,
 * and boot commands.
 * 
 * @return int
 */
int main(void) {

    uint8_t cmd = 0;

    // Initialize IO components
    uart_init();

    SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
    EEPROMInit();



    // Handle host commands
    while (1) {
        cmd = uart_readb(HOST_UART);

        switch (cmd) {
        case 'C':
            handle_configure();
            break;
        case 'U':
            handle_update();
            break;
        case 'R':
            handle_readback();
            break;
        case 'B':
            handle_boot();
            break;
        default:
            break;
        }
    }
}
