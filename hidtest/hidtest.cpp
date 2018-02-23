/*******************************************************
 Windows HID simplification

 Alan Ott
 Signal 11 Software

 8/22/2009

 Copyright 2009
 
 This contents of this file may be used by anyone
 for any reason without any conditions and may be
 used as a starting point for your own applications
 which use HIDAPI.
********************************************************/

#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include <stdlib.h>
#include "hidapi.h"

typedef unsigned          char uint8_t;
typedef unsigned short     int uint16_t;
typedef unsigned           int uint32_t;

#define PC_CONTROL_CMD_START_CODE 0x7E
#define PC_CONTROL_CMD_STOP_CODE 0xEF
#define CMD_CONTROL_AT_COMMAND      179

#define USB_VID 0x0416
#define USB_PID 0x5020

#define USB_VID_1 0x0417
#define USB_PID_1 0x5021

#define USB_MAX_REPORT_SIZE 64

// Headers needed for sleeping.
#ifdef _WIN32
	#include <windows.h>
#else
	#include <unistd.h>
    #include <pthread.h>
#endif


uint8_t make_control_cmd_message(uint8_t *msg_buf, uint8_t cmd_type, void *cmd_content, uint8_t content_size)
{
    uint8_t i = 0;
    uint8_t cmd_crc = 0;
    uint8_t *p_msg = msg_buf;
    uint8_t *p_content = (uint8_t *)cmd_content;

    p_msg[0] = PC_CONTROL_CMD_START_CODE;

    p_msg[1] = cmd_type;
    cmd_crc += p_msg[1];

    p_msg[2] = content_size + 3;
    cmd_crc += p_msg[2];

    memcpy(p_msg + 3, p_content, content_size);
    for (i = 0; i < content_size; i++)
    {
        cmd_crc += p_content[i];
    }

    p_msg[content_size + 3] = cmd_crc;
    p_msg[content_size + 4] = PC_CONTROL_CMD_STOP_CODE;

    return content_size + 5;
}



static void __output_device_info(hid_device *handle)
{
    unsigned char buf[256];
    int res;

    while (1)
    {
#ifdef WIN32
        Sleep(500);
#else
        usleep(20 * 1000);
#endif

        res = hid_read(handle, buf, USB_MAX_REPORT_SIZE);
        if (res > 0)
        {
            printf("hid device0: %s\n", buf);
        }
    }
}

#ifndef WIN32
void * thread_output_device_info(void *arg)
{
    hid_device *handle = (hid_device*)arg;

    __output_device_info(handle);

    return NULL;
}

void * thread_output_device1_info(void *arg)
{
    hid_device *handle = (hid_device*)arg;


    unsigned char buf[256];
    int res;

    while (1)
    {
#ifdef WIN32
        Sleep(500);
#else
        usleep(20 * 1000);
#endif

        res = hid_read(handle, buf, USB_MAX_REPORT_SIZE);
        if (res > 0 && strcmp((char*)buf, "...") != 0)
        {
            printf("hid device1: %s\n", buf);
        }
    }

    return NULL;
}
#endif

static hid_device *open_hid_device(unsigned short vendor_id, unsigned short product_id)
{
    int res;
    hid_device *handle;
    #define MAX_STR 255
    wchar_t wstr[MAX_STR];

    // Open the device using the VID, PID,
    // and optionally the Serial number.
    ////handle = hid_open(0x4d8, 0x3f, L"12345");
    handle = hid_open(vendor_id, product_id, NULL);
    if (!handle) {
        printf("unable to open device\n");
        return NULL;
    }

    // Read the Manufacturer String
    wstr[0] = 0x0000;
    res = hid_get_manufacturer_string(handle, wstr, MAX_STR);
    if (res < 0)
        printf("Unable to read manufacturer string\n");
    printf("Manufacturer String: %ls\n", wstr);

    // Read the Product String
    wstr[0] = 0x0000;
    res = hid_get_product_string(handle, wstr, MAX_STR);
    if (res < 0)
        printf("Unable to read product string\n");
    printf("Product String: %ls\n", wstr);

    // Read the Serial Number String
    wstr[0] = 0x0000;
    res = hid_get_serial_number_string(handle, wstr, MAX_STR);
    if (res < 0)
        printf("Unable to read serial number string\n");
    printf("Serial Number String: (%d) %ls", wstr[0], wstr);
    printf("\n");

    // Read Indexed String 1
    wstr[0] = 0x0000;
    res = hid_get_indexed_string(handle, 1, wstr, MAX_STR);
    if (res < 0)
        printf("Unable to read indexed string 1\n");
    printf("Indexed String 1: %ls\n", wstr);

    // Set the hid_read() function to be non-blocking.
    hid_set_nonblocking(handle, 1);

    return handle;
}


int main(int argc, char* argv[])
{
	int res;
	unsigned char buf[256];
	#define MAX_STR 255
	wchar_t wstr[MAX_STR];
	hid_device *handle, *handle1;
	int i;

#ifdef WIN32
	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);
#endif

	struct hid_device_info *devs, *cur_dev;
	
	if (hid_init())
		return -1;
#if 0
	devs = hid_enumerate(0x0, 0x0);
	cur_dev = devs;	
	while (cur_dev) {
		printf("Device Found\n  type: %04hx %04hx\n  path: %s\n  serial_number: %ls", cur_dev->vendor_id, cur_dev->product_id, cur_dev->path, cur_dev->serial_number);
		printf("\n");
		printf("  Manufacturer: %ls\n", cur_dev->manufacturer_string);
		printf("  Product:      %ls\n", cur_dev->product_string);
		printf("  Release:      %hx\n", cur_dev->release_number);
		printf("  Interface:    %d\n",  cur_dev->interface_number);
		printf("\n");
		cur_dev = cur_dev->next;
	}
	hid_free_enumeration(devs);

	// Set up the command buffer.
	memset(buf,0x00,sizeof(buf));
	buf[0] = 0x01;
	buf[1] = 0x81;
#endif

    handle = open_hid_device(USB_VID, USB_PID);
    if (!handle) {
        printf("unable to open hid device\n");
        return NULL;
    }


    handle1 = open_hid_device(USB_VID_1, USB_PID_1);
    if (!handle1) {
        printf("unable to open hid device 1\n");
        return NULL;
    }

#ifdef WIN32
    __output_device_info(handle);
#else
    {
        pthread_t tid1, tid2;
        char str_cmd[64] = { 0 };
        char msg_buf[1 + USB_MAX_REPORT_SIZE] = { 0 };
        uint8_t msg_length = 0;

        pthread_create(&tid1, NULL, thread_output_device_info, (void *)handle);
        pthread_create(&tid2, NULL, thread_output_device1_info, (void *)handle1);

        while (1)
        {
            scanf("%s", str_cmd);
            strcat(str_cmd, "\r\n");
            printf("send command:%s\n", str_cmd);

            hid_write(handle1,(unsigned char*) str_cmd, strlen(str_cmd));

            memset(msg_buf, 0, sizeof(msg_buf));
            msg_length = make_control_cmd_message((uint8_t *)msg_buf, CMD_CONTROL_AT_COMMAND, (uint8_t *)str_cmd, strlen(str_cmd));
            hid_write(handle, (unsigned char*)msg_buf, msg_length);
        }
    }
#endif // WIN32

#if 0
	// Send a Feature Report to the device
	buf[0] = 0x2;
	buf[1] = 0xa0;
	buf[2] = 0x0a;
	buf[3] = 0x00;
	buf[4] = 0x00;
	res = hid_send_feature_report(handle, buf, 17);
	if (res < 0) {
		printf("Unable to send a feature report.\n");
	}

	memset(buf,0,sizeof(buf));

	// Read a Feature Report from the device
	buf[0] = 0x2;
	res = hid_get_feature_report(handle, buf, sizeof(buf));
	if (res < 0) {
		printf("Unable to get a feature report.\n");
		printf("%ls", hid_error(handle));
	}
	else {
		// Print out the returned buffer.
		printf("Feature Report\n   ");
		for (i = 0; i < res; i++)
			printf("%02hhx ", buf[i]);
		printf("\n");
	}

	memset(buf,0,sizeof(buf));

	// Toggle LED (cmd 0x80). The first byte is the report number (0x1).
	buf[0] = 0x1;
	buf[1] = 0x80;
	res = hid_write(handle, buf, 17);
	if (res < 0) {
		printf("Unable to write()\n");
		printf("Error: %ls\n", hid_error(handle));
	}
	

	// Request state (cmd 0x81). The first byte is the report number (0x1).
	buf[0] = 0x1;
	buf[1] = 0x81;
	hid_write(handle, buf, 17);
	if (res < 0)
		printf("Unable to write() (2)\n");

	// Read requested state. hid_read() has been set to be
	// non-blocking by the call to hid_set_nonblocking() above.
	// This loop demonstrates the non-blocking nature of hid_read().
	res = 0;
	while (res == 0) {
		res = hid_read(handle, buf, sizeof(buf));
		if (res == 0)
			printf("waiting...\n");
		if (res < 0)
			printf("Unable to read()\n");
		#ifdef WIN32
		Sleep(500);
		#else
		usleep(500*1000);
		#endif
	}

	printf("Data read:\n   ");
	// Print out the returned buffer.
	for (i = 0; i < res; i++)
		printf("%02hhx ", buf[i]);
	printf("\n");
#endif

	hid_close(handle);

	/* Free static HIDAPI objects. */
	hid_exit();

#ifdef WIN32
	system("pause");
#endif

	return 0;
}
