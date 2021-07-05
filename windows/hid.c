/*******************************************************
 HIDAPI - Multi-Platform library for
 communication with HID devices.

 Alan Ott
 Signal 11 Software

 8/22/2009

 Copyright 2009, All Rights Reserved.

 At the discretion of the user of this library,
 this software may be licensed under the terms of the
 GNU General Public License v3, a BSD-Style license, or the
 original HIDAPI license as outlined in the LICENSE.txt,
 LICENSE-gpl3.txt, LICENSE-bsd.txt, and LICENSE-orig.txt
 files located at the root of the source distribution.
 These files may also be found in the public source
 code repository located at:
        https://github.com/libusb/hidapi .
********************************************************/

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
// Do not warn about mbsrtowcs and wcsncpy usage.
// https://docs.microsoft.com/cpp/c-runtime-library/security-features-in-the-crt
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <windows.h>

#ifndef _NTDEF_
typedef LONG NTSTATUS;
#endif

#ifdef __MINGW32__
#include <ntdef.h>
#include <winbase.h>
#endif

#ifdef __CYGWIN__
#include <ntdef.h>
#define _wcsdup wcsdup
#endif

/* The maximum number of characters that can be passed into the
   HidD_Get*String() functions without it failing.*/
#define MAX_STRING_WCHARS 0xFFF

/*#define HIDAPI_USE_DDK*/

#ifdef __cplusplus
extern "C" {
#endif
	#include <setupapi.h>
	#include <winioctl.h>
	#ifdef HIDAPI_USE_DDK
		#include <hidsdi.h>
	#endif

	/* Copied from inc/ddk/hidclass.h, part of the Windows DDK. */
	#define HID_OUT_CTL_CODE(id)  \
		CTL_CODE(FILE_DEVICE_KEYBOARD, (id), METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
	#define IOCTL_HID_GET_FEATURE                   HID_OUT_CTL_CODE(100)
	#define IOCTL_HID_GET_INPUT_REPORT              HID_OUT_CTL_CODE(104)

#ifdef __cplusplus
} /* extern "C" */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hidapi.h"

#undef MIN
#define MIN(x,y) ((x) < (y)? (x): (y))

#ifdef __cplusplus
extern "C" {
#endif

static struct hid_api_version api_version = {
	.major = HID_API_VERSION_MAJOR,
	.minor = HID_API_VERSION_MINOR,
	.patch = HID_API_VERSION_PATCH
};

#ifndef HIDAPI_USE_DDK
	/* Since we're not building with the DDK, and the HID header
	   files aren't part of the SDK, we have to define all this
	   stuff here. In lookup_functions(), the function pointers
	   defined below are set. */
	typedef struct _HIDD_ATTRIBUTES{
		ULONG Size;
		USHORT VendorID;
		USHORT ProductID;
		USHORT VersionNumber;
	} HIDD_ATTRIBUTES, *PHIDD_ATTRIBUTES;

	typedef USHORT USAGE;
	typedef struct _HIDP_CAPS {
		USAGE Usage;
		USAGE UsagePage;
		USHORT InputReportByteLength;
		USHORT OutputReportByteLength;
		USHORT FeatureReportByteLength;
		USHORT Reserved[17];
		USHORT fields_not_used_by_hidapi[10];
	} HIDP_CAPS, *PHIDP_CAPS;
	typedef void* PHIDP_PREPARSED_DATA;
	#define HIDP_STATUS_SUCCESS 0x110000

	typedef void (__stdcall *HidD_GetHidGuid_)(LPGUID hid_guid);
	typedef BOOLEAN (__stdcall *HidD_GetAttributes_)(HANDLE device, PHIDD_ATTRIBUTES attrib);
	typedef BOOLEAN (__stdcall *HidD_GetSerialNumberString_)(HANDLE device, PVOID buffer, ULONG buffer_len);
	typedef BOOLEAN (__stdcall *HidD_GetManufacturerString_)(HANDLE handle, PVOID buffer, ULONG buffer_len);
	typedef BOOLEAN (__stdcall *HidD_GetProductString_)(HANDLE handle, PVOID buffer, ULONG buffer_len);
	typedef BOOLEAN (__stdcall *HidD_SetFeature_)(HANDLE handle, PVOID data, ULONG length);
	typedef BOOLEAN (__stdcall *HidD_GetFeature_)(HANDLE handle, PVOID data, ULONG length);
	typedef BOOLEAN (__stdcall *HidD_GetInputReport_)(HANDLE handle, PVOID data, ULONG length);
	typedef BOOLEAN (__stdcall *HidD_GetIndexedString_)(HANDLE handle, ULONG string_index, PVOID buffer, ULONG buffer_len);
	typedef BOOLEAN (__stdcall *HidD_GetPreparsedData_)(HANDLE handle, PHIDP_PREPARSED_DATA *preparsed_data);
	typedef BOOLEAN (__stdcall *HidD_FreePreparsedData_)(PHIDP_PREPARSED_DATA preparsed_data);
	typedef NTSTATUS (__stdcall *HidP_GetCaps_)(PHIDP_PREPARSED_DATA preparsed_data, HIDP_CAPS *caps);
	typedef BOOLEAN (__stdcall *HidD_SetNumInputBuffers_)(HANDLE handle, ULONG number_buffers);

	static HidD_GetHidGuid_ HidD_GetHidGuid;
	static HidD_GetAttributes_ HidD_GetAttributes;
	static HidD_GetSerialNumberString_ HidD_GetSerialNumberString;
	static HidD_GetManufacturerString_ HidD_GetManufacturerString;
	static HidD_GetProductString_ HidD_GetProductString;
	static HidD_SetFeature_ HidD_SetFeature;
	static HidD_GetFeature_ HidD_GetFeature;
	static HidD_GetInputReport_ HidD_GetInputReport;
	static HidD_GetIndexedString_ HidD_GetIndexedString;
	static HidD_GetPreparsedData_ HidD_GetPreparsedData;
	static HidD_FreePreparsedData_ HidD_FreePreparsedData;
	static HidP_GetCaps_ HidP_GetCaps;
	static HidD_SetNumInputBuffers_ HidD_SetNumInputBuffers;

	static HMODULE lib_handle = NULL;
	static BOOLEAN initialized = FALSE;

	typedef DWORD RETURN_TYPE;
	typedef RETURN_TYPE CONFIGRET;
	typedef DWORD DEVNODE, DEVINST;
	typedef DEVNODE* PDEVNODE, * PDEVINST;
	typedef WCHAR* DEVNODEID_W, * DEVINSTID_W;

#define CR_SUCCESS (0x00000000)
#define CR_BUFFER_SMALL (0x0000001A)

#define CM_LOCATE_DEVNODE_NORMAL 0x00000000

#define DEVPROP_TYPEMOD_LIST 0x00002000

#define DEVPROP_TYPE_STRING 0x00000012
#define DEVPROP_TYPE_STRING_LIST (DEVPROP_TYPE_STRING|DEVPROP_TYPEMOD_LIST)

	typedef CONFIGRET(__stdcall* CM_Locate_DevNodeW_)(PDEVINST pdnDevInst, DEVINSTID_W pDeviceID, ULONG ulFlags);
	typedef CONFIGRET(__stdcall* CM_Get_Parent_)(PDEVINST pdnDevInst, DEVINST dnDevInst, ULONG ulFlags);
	typedef CONFIGRET(__stdcall* CM_Get_DevNode_PropertyW_)(DEVINST dnDevInst, CONST DEVPROPKEY* PropertyKey, DEVPROPTYPE* PropertyType, PBYTE PropertyBuffer, PULONG PropertyBufferSize, ULONG ulFlags);
	typedef CONFIGRET(__stdcall* CM_Get_Device_Interface_PropertyW_)(LPCWSTR pszDeviceInterface, CONST DEVPROPKEY* PropertyKey, DEVPROPTYPE* PropertyType, PBYTE PropertyBuffer, PULONG PropertyBufferSize, ULONG ulFlags);

	DECLARE_HANDLE(HCMNOTIFICATION);
	typedef HCMNOTIFICATION* PHCMNOTIFICATION;

	typedef enum _CM_NOTIFY_FILTER_TYPE {
		CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE = 0,
		CM_NOTIFY_FILTER_TYPE_DEVICEHANDLE,
		CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE,
		CM_NOTIFY_FILTER_TYPE_MAX
	} CM_NOTIFY_FILTER_TYPE, * PCM_NOTIFY_FILTER_TYPE;

	typedef struct _CM_NOTIFY_FILTER {
		DWORD cbSize;
		DWORD Flags;
		CM_NOTIFY_FILTER_TYPE FilterType;
		DWORD Reserved;
		union {
			struct {
				GUID ClassGuid;
			} DeviceInterface;
			struct {
				HANDLE  hTarget;
			} DeviceHandle;
			struct {
				WCHAR InstanceId[200];
			} DeviceInstance;
		} u;
	} CM_NOTIFY_FILTER, * PCM_NOTIFY_FILTER;

	typedef enum _CM_NOTIFY_ACTION {
		CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL = 0,
		CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL,
		CM_NOTIFY_ACTION_DEVICEQUERYREMOVE,
		CM_NOTIFY_ACTION_DEVICEQUERYREMOVEFAILED,
		CM_NOTIFY_ACTION_DEVICEREMOVEPENDING,
		CM_NOTIFY_ACTION_DEVICEREMOVECOMPLETE,
		CM_NOTIFY_ACTION_DEVICECUSTOMEVENT,
		CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED,
		CM_NOTIFY_ACTION_DEVICEINSTANCESTARTED,
		CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED,
		CM_NOTIFY_ACTION_MAX
	} CM_NOTIFY_ACTION, * PCM_NOTIFY_ACTION;

	typedef struct _CM_NOTIFY_EVENT_DATA {
		CM_NOTIFY_FILTER_TYPE FilterType;
		DWORD Reserved;
		union {
			struct {
				GUID ClassGuid;
				WCHAR SymbolicLink[ANYSIZE_ARRAY];
			} DeviceInterface;
			struct {
				GUID EventGuid;
				LONG NameOffset;
				DWORD DataSize;
				BYTE Data[ANYSIZE_ARRAY];
			} DeviceHandle;
			struct {
				WCHAR InstanceId[ANYSIZE_ARRAY];
			} DeviceInstance;
		} u;
	} CM_NOTIFY_EVENT_DATA, * PCM_NOTIFY_EVENT_DATA;

	typedef DWORD(CALLBACK* PCM_NOTIFY_CALLBACK)(HCMNOTIFICATION hNotify, PVOID Context, CM_NOTIFY_ACTION Action, PCM_NOTIFY_EVENT_DATA EventData, DWORD EventDataSize);

	typedef CONFIGRET(__stdcall* CM_Register_Notification_)(PCM_NOTIFY_FILTER pFilter, PVOID pContext, PCM_NOTIFY_CALLBACK pCallback, PHCMNOTIFICATION pNotifyContext);
	typedef CONFIGRET(__stdcall* CM_Unregister_Notification_)(HCMNOTIFICATION NotifyContext);

	static CM_Locate_DevNodeW_ CM_Locate_DevNodeW = NULL;
	static CM_Get_Parent_ CM_Get_Parent = NULL;
	static CM_Get_DevNode_PropertyW_ CM_Get_DevNode_PropertyW = NULL;
	static CM_Get_Device_Interface_PropertyW_ CM_Get_Device_Interface_PropertyW = NULL;
	static CM_Register_Notification_ CM_Register_Notification = NULL;
	static CM_Unregister_Notification_ CM_Unregister_Notification = NULL;

	static HMODULE cfgmgr32_lib_handle = NULL;
#endif /* HIDAPI_USE_DDK */

struct hid_device_ {
		HANDLE device_handle;
		BOOL blocking;
		USHORT output_report_length;
		unsigned char *write_buf;
		size_t input_report_length;
		USHORT feature_report_length;
		unsigned char *feature_buf;
		void *last_error_str;
		DWORD last_error_num;
		BOOL read_pending;
		char *read_buf;
		OVERLAPPED ol;
		OVERLAPPED write_ol;
		struct hid_device_info* device_info;
};

static hid_device *new_hid_device()
{
	hid_device *dev = (hid_device*) calloc(1, sizeof(hid_device));
	dev->device_handle = INVALID_HANDLE_VALUE;
	dev->blocking = TRUE;
	dev->output_report_length = 0;
	dev->write_buf = NULL;
	dev->input_report_length = 0;
	dev->feature_report_length = 0;
	dev->feature_buf = NULL;
	dev->last_error_str = NULL;
	dev->last_error_num = 0;
	dev->read_pending = FALSE;
	dev->read_buf = NULL;
	memset(&dev->ol, 0, sizeof(dev->ol));
	dev->ol.hEvent = CreateEvent(NULL, FALSE, FALSE /*initial state f=nonsignaled*/, NULL);
	memset(&dev->write_ol, 0, sizeof(dev->write_ol));
	dev->write_ol.hEvent = CreateEvent(NULL, FALSE, FALSE /*inital state f=nonsignaled*/, NULL);
	dev->device_info = NULL;

	return dev;
}

static void free_hid_device(hid_device *dev)
{
	CloseHandle(dev->ol.hEvent);
	CloseHandle(dev->write_ol.hEvent);
	CloseHandle(dev->device_handle);
	LocalFree(dev->last_error_str);
	free(dev->write_buf);
	free(dev->feature_buf);
	free(dev->read_buf);
	free(dev->device_info);
	free(dev);
}

static void register_error(hid_device *dev, const char *op)
{
	WCHAR *ptr, *msg;
	(void)op; // unreferenced  param
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPWSTR)&msg, 0/*sz*/,
		NULL);

	/* Get rid of the CR and LF that FormatMessage() sticks at the
	   end of the message. Thanks Microsoft! */
	ptr = msg;
	while (*ptr) {
		if (*ptr == L'\r') {
			*ptr = L'\0';
			break;
		}
		ptr++;
	}

	/* Store the message off in the Device entry so that
	   the hid_error() function can pick it up. */
	LocalFree(dev->last_error_str);
	dev->last_error_str = msg;
}

#ifndef HIDAPI_USE_DDK
static int lookup_functions()
{
	lib_handle = LoadLibraryA("hid.dll");
	if (lib_handle) {
#if defined(__GNUC__)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
#define RESOLVE(x) x = (x##_)GetProcAddress(lib_handle, #x); if (!x) return -1;
		RESOLVE(HidD_GetHidGuid);
		RESOLVE(HidD_GetAttributes);
		RESOLVE(HidD_GetSerialNumberString);
		RESOLVE(HidD_GetManufacturerString);
		RESOLVE(HidD_GetProductString);
		RESOLVE(HidD_SetFeature);
		RESOLVE(HidD_GetFeature);
		RESOLVE(HidD_GetInputReport);
		RESOLVE(HidD_GetIndexedString);
		RESOLVE(HidD_GetPreparsedData);
		RESOLVE(HidD_FreePreparsedData);
		RESOLVE(HidP_GetCaps);
		RESOLVE(HidD_SetNumInputBuffers);
#undef RESOLVE
#if defined(__GNUC__)
# pragma GCC diagnostic pop
#endif
	}
	else
		return -1;

	cfgmgr32_lib_handle = LoadLibraryA("cfgmgr32.dll");
	if (cfgmgr32_lib_handle) {
#if defined(__GNUC__)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
#define RESOLVE(x) x = (x##_)GetProcAddress(cfgmgr32_lib_handle, #x);
		RESOLVE(CM_Locate_DevNodeW);
		RESOLVE(CM_Get_Parent);
		RESOLVE(CM_Get_DevNode_PropertyW);
		RESOLVE(CM_Get_Device_Interface_PropertyW);
		RESOLVE(CM_Register_Notification);
		RESOLVE(CM_Unregister_Notification);
#undef RESOLVE
#if defined(__GNUC__)
# pragma GCC diagnostic pop
#endif
	}
	else {
		CM_Locate_DevNodeW = NULL;
		CM_Get_Parent = NULL;
		CM_Get_DevNode_PropertyW = NULL;
		CM_Get_Device_Interface_PropertyW = NULL;
		CM_Register_Notification = NULL;
		CM_Unregister_Notification = NULL;
	}

	return 0;
}
#endif

static HANDLE open_device(const char *path, BOOL open_rw)
{
	HANDLE handle;
	DWORD desired_access = (open_rw)? (GENERIC_WRITE | GENERIC_READ): 0;
	DWORD share_mode = FILE_SHARE_READ|FILE_SHARE_WRITE;

	handle = CreateFileA(path,
		desired_access,
		share_mode,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED,/*FILE_ATTRIBUTE_NORMAL,*/
		0);

	return handle;
}

HID_API_EXPORT const struct hid_api_version* HID_API_CALL hid_version()
{
	return &api_version;
}

HID_API_EXPORT const char* HID_API_CALL hid_version_str()
{
	return HID_API_VERSION_STR;
}

int HID_API_EXPORT hid_init(void)
{
#ifndef HIDAPI_USE_DDK
	if (!initialized) {
		if (lookup_functions() < 0) {
			hid_exit();
			return -1;
		}
		initialized = TRUE;
	}
#endif
	return 0;
}

int HID_API_EXPORT hid_exit(void)
{
#ifndef HIDAPI_USE_DDK
	if (lib_handle)
		FreeLibrary(lib_handle);
	lib_handle = NULL;
	if (cfgmgr32_lib_handle)
		FreeLibrary(cfgmgr32_lib_handle);
	cfgmgr32_lib_handle = NULL;
	initialized = FALSE;
#endif
	return 0;
}

static void hid_internal_get_ble_info(struct hid_device_info* dev, DEVINST dev_node)
{
	ULONG len;
	CONFIGRET cr;
	DEVPROPTYPE property_type;

	static DEVPROPKEY DEVPKEY_NAME = { { 0xb725f130, 0x47ef, 0x101a, 0xa5, 0xf1, 0x02, 0x60, 0x8c, 0x9e, 0xeb, 0xac }, 10 }; // DEVPROP_TYPE_STRING
	static DEVPROPKEY PKEY_DeviceInterface_Bluetooth_DeviceAddress = { { 0x2BD67D8B, 0x8BEB, 0x48D5, 0x87, 0xE0, 0x6C, 0xDA, 0x34, 0x28, 0x04, 0x0A }, 1 }; // DEVPROP_TYPE_STRING
	static DEVPROPKEY PKEY_DeviceInterface_Bluetooth_Manufacturer = { { 0x2BD67D8B, 0x8BEB, 0x48D5, 0x87, 0xE0, 0x6C, 0xDA, 0x34, 0x28, 0x04, 0x0A }, 4 }; // DEVPROP_TYPE_STRING

	/* Manufacturer String */
	len = 0;
	cr = CM_Get_DevNode_PropertyW(dev_node, &PKEY_DeviceInterface_Bluetooth_Manufacturer, &property_type, NULL, &len, 0);
	if (cr == CR_BUFFER_SMALL && property_type == DEVPROP_TYPE_STRING) {
		free(dev->manufacturer_string);
		dev->manufacturer_string = (wchar_t*)calloc(len, sizeof(BYTE));
		CM_Get_DevNode_PropertyW(dev_node, &PKEY_DeviceInterface_Bluetooth_Manufacturer, &property_type, (PBYTE)dev->manufacturer_string, &len, 0);
	}

	/* Serial Number String (MAC Address) */
	len = 0;
	cr = CM_Get_DevNode_PropertyW(dev_node, &PKEY_DeviceInterface_Bluetooth_DeviceAddress, &property_type, NULL, &len, 0);
	if (cr == CR_BUFFER_SMALL && property_type == DEVPROP_TYPE_STRING) {
		free(dev->serial_number);
		dev->serial_number = (wchar_t*)calloc(len, sizeof(BYTE));
		CM_Get_DevNode_PropertyW(dev_node, &PKEY_DeviceInterface_Bluetooth_DeviceAddress, &property_type, (PBYTE)dev->serial_number, &len, 0);
	}

	/* Get devnode grandparent to reach out Bluetooth LE device node */
	cr = CM_Get_Parent(&dev_node, dev_node, 0);
	if (cr != CR_SUCCESS)
		return;

	/* Product String */
	len = 0;
	cr = CM_Get_DevNode_PropertyW(dev_node, &DEVPKEY_NAME, &property_type, NULL, &len, 0);
	if (cr == CR_BUFFER_SMALL && property_type == DEVPROP_TYPE_STRING) {
		free(dev->product_string);
		dev->product_string = (wchar_t*)calloc(len, sizeof(BYTE));
		CM_Get_DevNode_PropertyW(dev_node, &DEVPKEY_NAME, &property_type, (PBYTE)dev->product_string, &len, 0);
	}
}

static void hid_internal_get_info(struct hid_device_info* dev)
{
	char *tmp = NULL;
	wchar_t *interface_path = NULL, *device_id = NULL, *compatible_ids = NULL;
	mbstate_t state;
	ULONG len;
	CONFIGRET cr;
	DEVPROPTYPE property_type;
	DEVINST dev_node;

	static DEVPROPKEY DEVPKEY_Device_InstanceId = { { 0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57 }, 256 }; // DEVPROP_TYPE_STRING
	static DEVPROPKEY DEVPKEY_Device_CompatibleIds = { { 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0}, 4 }; // DEVPROP_TYPE_STRING_LIST

	if (!CM_Get_Device_Interface_PropertyW ||
		!CM_Locate_DevNodeW ||
		!CM_Get_Parent ||
		!CM_Get_DevNode_PropertyW)
		goto end;

	tmp = dev->path;

	len = (ULONG)strlen(tmp);
	interface_path = (wchar_t*)calloc(len + 1, sizeof(wchar_t));
	memset(&state, 0, sizeof(state));

	if (mbsrtowcs(interface_path, &tmp, len, &state) == (size_t)-1)
		goto end;

	/* Get the device id from interface path */
	len = 0;
	cr = CM_Get_Device_Interface_PropertyW(interface_path, &DEVPKEY_Device_InstanceId, &property_type, NULL, &len, 0);
	if (cr == CR_BUFFER_SMALL && property_type == DEVPROP_TYPE_STRING) {
		device_id = (wchar_t*)calloc(len, sizeof(BYTE));
		cr = CM_Get_Device_Interface_PropertyW(interface_path, &DEVPKEY_Device_InstanceId, &property_type, (PBYTE)device_id, &len, 0);
	}
	if (cr != CR_SUCCESS)
		goto end;

	/* Open devnode from device id */
	cr = CM_Locate_DevNodeW(&dev_node, (DEVINSTID_W)device_id, CM_LOCATE_DEVNODE_NORMAL);
	if (cr != CR_SUCCESS)
		goto end;

	/* Get devnode parent */
	cr = CM_Get_Parent(&dev_node, dev_node, 0);
	if (cr != CR_SUCCESS)
		goto end;

	/* Get the compatible ids from parent devnode */
	len = 0;
	cr = CM_Get_DevNode_PropertyW(dev_node, &DEVPKEY_Device_CompatibleIds, &property_type, NULL, &len, 0);
	if (cr == CR_BUFFER_SMALL && property_type == DEVPROP_TYPE_STRING_LIST) {
		compatible_ids = (wchar_t*)calloc(len, sizeof(BYTE));
		cr = CM_Get_DevNode_PropertyW(dev_node, &DEVPKEY_Device_CompatibleIds, &property_type, (PBYTE)compatible_ids, &len, 0);
	}
	if (cr != CR_SUCCESS)
		goto end;

	/* Now we can parse parent's compatible IDs to find out the device bus type */
	for (wchar_t* compatible_id = compatible_ids; *compatible_id; compatible_id += wcslen(compatible_id) + 1) {
		/* Normalize to upper case */
		for (wchar_t* p = compatible_id; *p; ++p) *p = towupper(*p);

		/* Bluetooth LE devices */
		if (wcsstr(compatible_id, L"BTHLEDEVICE") != NULL) {
			/* HidD_GetProductString/HidD_GetManufacturerString/HidD_GetSerialNumberString is not working for BLE HID devices
			   Request this info via dev node properties instead.
			   https://docs.microsoft.com/answers/questions/401236/hidd-getproductstring-with-ble-hid-device.html */
			hid_internal_get_ble_info(dev, dev_node);
			break;
		}
	}
end:
	free(interface_path);
	free(device_id);
	free(compatible_ids);
}

static struct hid_device_info *hid_get_device_info(const char *path, HANDLE handle)
{
	struct hid_device_info *dev = NULL; /* return object */

	BOOL res;
	HIDD_ATTRIBUTES attrib;
	PHIDP_PREPARSED_DATA pp_data = NULL;
	HIDP_CAPS caps;

	#define WSTR_LEN 512
	wchar_t wstr[WSTR_LEN]; /* TODO: Determine Size */

	/* Create the record. */
	dev = (struct hid_device_info*)calloc(1, sizeof(struct hid_device_info));

	/* Fill out the record */
	dev->next = NULL;

	if (path) {
		size_t len = strlen(path);
		dev->path = (char*)calloc(len + 1, sizeof(char));
		memcpy(dev->path, path, len + 1);
	}
	else
		dev->path = NULL;

	attrib.Size = sizeof(HIDD_ATTRIBUTES);
	res = HidD_GetAttributes(handle, &attrib);
	if (res) {
		/* VID/PID */
		dev->vendor_id = attrib.VendorID;
		dev->product_id = attrib.ProductID;

		/* Release Number */
		dev->release_number = attrib.VersionNumber;
	}

	/* Get the Usage Page and Usage for this device. */
	res = HidD_GetPreparsedData(handle, &pp_data);
	if (res) {
		NTSTATUS nt_res = HidP_GetCaps(pp_data, &caps);
		if (nt_res == HIDP_STATUS_SUCCESS) {
			dev->usage_page = caps.UsagePage;
			dev->usage = caps.Usage;
		}

		HidD_FreePreparsedData(pp_data);
	}

	/* Serial Number */
	wstr[0] = L'\0';
	res = HidD_GetSerialNumberString(handle, wstr, sizeof(wstr));
	wstr[WSTR_LEN - 1] = L'\0';
	dev->serial_number = _wcsdup(wstr);

	/* Manufacturer String */
	wstr[0] = L'\0';
	res = HidD_GetManufacturerString(handle, wstr, sizeof(wstr));
	wstr[WSTR_LEN - 1] = L'\0';
	dev->manufacturer_string = _wcsdup(wstr);

	/* Product String */
	wstr[0] = L'\0';
	res = HidD_GetProductString(handle, wstr, sizeof(wstr));
	wstr[WSTR_LEN - 1] = L'\0';
	dev->product_string = _wcsdup(wstr);

	/* Interface Number. It can sometimes be parsed out of the path
	   on Windows if a device has multiple interfaces. See
	   https://docs.microsoft.com/windows-hardware/drivers/hid/hidclass-hardware-ids-for-top-level-collections
	   or search for "HIDClass Hardware IDs for Top-Level Collections" at Microsoft Docs. If it's not
	   in the path, it's set to -1. */
	dev->interface_number = -1;
	if (dev->path) {
		char* interface_component = strstr(dev->path, "&mi_");
		if (interface_component) {
			char* hex_str = interface_component + 4;
			char* endptr = NULL;
			dev->interface_number = strtol(hex_str, &endptr, 16);
			if (endptr == hex_str) {
				/* The parsing failed. Set interface_number to -1. */
				dev->interface_number = -1;
			}
		}
	}

	hid_internal_get_info(dev);

	return dev;
}

struct hid_device_info HID_API_EXPORT * HID_API_CALL hid_enumerate(unsigned short vendor_id, unsigned short product_id)
{
	BOOL res;
	struct hid_device_info *root = NULL; /* return object */
	struct hid_device_info *cur_dev = NULL;
	GUID interface_class_guid;

	/* Windows objects for interacting with the driver. */
	SP_DEVINFO_DATA devinfo_data;
	SP_DEVICE_INTERFACE_DATA device_interface_data;
	SP_DEVICE_INTERFACE_DETAIL_DATA_A *device_interface_detail_data = NULL;
	HDEVINFO device_info_set = INVALID_HANDLE_VALUE;
	char driver_name[256];
	int device_index = 0;

	if (hid_init() < 0)
		return NULL;

	/* Retrieve HID Interface Class GUID
	   https://docs.microsoft.com/windows-hardware/drivers/install/guid-devinterface-hid */
	HidD_GetHidGuid(&interface_class_guid);

	/* Initialize the Windows objects. */
	memset(&devinfo_data, 0x0, sizeof(devinfo_data));
	devinfo_data.cbSize = sizeof(SP_DEVINFO_DATA);
	device_interface_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

	/* Get information for all the devices belonging to the HID class. */
	device_info_set = SetupDiGetClassDevsA(&interface_class_guid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

	/* Iterate over each device in the HID class, looking for the right one. */

	for (;;) {
		HANDLE read_handle = INVALID_HANDLE_VALUE;
		DWORD required_size = 0;
		HIDD_ATTRIBUTES attrib;

		res = SetupDiEnumDeviceInterfaces(device_info_set,
			NULL,
			&interface_class_guid,
			device_index,
			&device_interface_data);

		if (!res) {
			/* A return of FALSE from this function means that
			   there are no more devices. */
			break;
		}

		/* Call with 0-sized detail size, and let the function
		   tell us how long the detail struct needs to be. The
		   size is put in &required_size. */
		res = SetupDiGetDeviceInterfaceDetailA(device_info_set,
			&device_interface_data,
			NULL,
			0,
			&required_size,
			NULL);

		/* Allocate a long enough structure for device_interface_detail_data. */
		device_interface_detail_data = (SP_DEVICE_INTERFACE_DETAIL_DATA_A*) malloc(required_size);
		device_interface_detail_data->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_A);

		/* Get the detailed data for this device. The detail data gives us
		   the device path for this device, which is then passed into
		   CreateFile() to get a handle to the device. */
		res = SetupDiGetDeviceInterfaceDetailA(device_info_set,
			&device_interface_data,
			device_interface_detail_data,
			required_size,
			NULL,
			NULL);

		if (!res) {
			/* register_error(dev, "Unable to call SetupDiGetDeviceInterfaceDetail");
			   Continue to the next device. */
			goto cont;
		}

		/* Populate devinfo_data. This function will return failure
		   when the device with such index doesn't exist. We've already checked it does. */
		res = SetupDiEnumDeviceInfo(device_info_set, device_index, &devinfo_data);
		if (!res)
			goto cont;


		/* Make sure this device has a driver bound to it. */
		res = SetupDiGetDeviceRegistryPropertyA(device_info_set, &devinfo_data,
			   SPDRP_DRIVER, NULL, (PBYTE)driver_name, sizeof(driver_name), NULL);
		if (!res)
			goto cont;

		//wprintf(L"HandleName: %s\n", device_interface_detail_data->DevicePath);

		/* Normalize the path */
		for (char* p = device_interface_detail_data->DevicePath; *p; ++p) *p = tolower(*p);

		/* Open read-only handle to the device */
		read_handle = open_device(device_interface_detail_data->DevicePath, FALSE);

		/* Check validity of read_handle. */
		if (read_handle == INVALID_HANDLE_VALUE) {
			/* Unable to open the device. */
			//register_error(dev, "CreateFile");
			goto cont;
		}

		/* Get the Vendor ID and Product ID for this device. */
		attrib.Size = sizeof(HIDD_ATTRIBUTES);
		HidD_GetAttributes(read_handle, &attrib);
		//wprintf(L"Product/Vendor: %x %x\n", attrib.ProductID, attrib.VendorID);

		/* Check the VID/PID to see if we should add this
		   device to the enumeration list. */
		if ((vendor_id == 0x0 || attrib.VendorID == vendor_id) &&
		    (product_id == 0x0 || attrib.ProductID == product_id)) {

			/* VID/PID match. Create the record. */
			struct hid_device_info *tmp = hid_get_device_info(device_interface_detail_data->DevicePath, read_handle);

			if (tmp == NULL) {
				goto cont_close;
			}

			if (cur_dev) {
				cur_dev->next = tmp;
			}
			else {
				root = tmp;
			}
			cur_dev = tmp;
		}

cont_close:
		CloseHandle(read_handle);
cont:
		/* We no longer need the detail data. It can be freed */
		free(device_interface_detail_data);

		device_index++;

	}

	/* Close the device information handle. */
	SetupDiDestroyDeviceInfoList(device_info_set);

	return root;
}

void  HID_API_EXPORT HID_API_CALL hid_free_enumeration(struct hid_device_info *devs)
{
	/* TODO: Merge this with the Linux version. This function is platform-independent. */
	struct hid_device_info *d = devs;
	while (d) {
		struct hid_device_info *next = d->next;
		free(d->path);
		free(d->serial_number);
		free(d->manufacturer_string);
		free(d->product_string);
		free(d);
		d = next;
	}
}

struct hid_hotplug_callback {
	hid_hotplug_callback_handle handle;
	unsigned short vendor_id;
	unsigned short product_id;
	int events;
	void *user_data;
	hid_hotplug_callback_fn callback;

	/** Pointer to the next notification */
	struct hid_hotplug_callback *next;
};

static struct hid_hotplug_context {
	HCMNOTIFICATION notify_handle;
	hid_hotplug_callback_handle next_hotplug_cb_handle;
	struct hid_hotplug_callback *hotplug_cbs;
	struct hid_device_info *devs;
} hid_hotplug_context = {
	.notify_handle = NULL,
	.next_hotplug_cb_handle = 1,
	.hotplug_cbs = NULL,
	.devs = NULL
};

DWORD WINAPI interface_notify_callback(HCMNOTIFICATION notify, PVOID context, CM_NOTIFY_ACTION action, PCM_NOTIFY_EVENT_DATA event_data, DWORD event_data_size)
{
	hid_hotplug_event event;
	if (action == CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL)
		event = HID_API_HOTPLUG_EVENT_DEVICE_ARRIVED;
	else if (action == CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL)
		event = HID_API_HOTPLUG_EVENT_DEVICE_LEFT;

	if (!event)
		return ERROR_SUCCESS;

	char *path;
	size_t len;
	struct hid_device_info *dev = NULL;

	len = wcslen(event_data->u.DeviceInterface.SymbolicLink);
	path = (char*)calloc(len + 1, sizeof(char));

	if (wcstombs(path, event_data->u.DeviceInterface.SymbolicLink, len) == (size_t)-1)
		goto close;

	/* Normalize the path */
	for (char* p = path; *p; ++p) *p = tolower(*p);

	if (event == HID_API_HOTPLUG_EVENT_DEVICE_ARRIVED) {
		/* Open read-only handle to the device */
		HANDLE read_handle = open_device(path, FALSE);

		/* Check validity of read_handle. */
		if (read_handle == INVALID_HANDLE_VALUE) {
			/* Unable to open the device. */
			goto close;
		}

		dev = hid_get_device_info(path, read_handle);

		/* Append to the end of the device list */
		if (hid_hotplug_context.devs) {
			struct hid_device_info* last = hid_hotplug_context.devs;
			while (last->next) {
				last = last->next;
			}
			last->next = dev;
		}
		else {
			hid_hotplug_context.devs = dev;
		}

		CloseHandle(read_handle);
	}
	else /* if (event == HID_API_HOTPLUG_EVENT_DEVICE_LEFT) */ {
		/* Remove this device from the device list */
		for (struct hid_device_info** current = &hid_hotplug_context.devs; *current; current = &(*current)->next) {
			if (strcmp((*current)->path, path) == 0) {
				struct hid_device_info* next = (*current)->next;
				dev = *current;
				*current = next;
				break;
			}
		}
	}

	if (dev) {
		/* Call the notifications for this device */
		struct hid_hotplug_callback *hotplug_cb = hid_hotplug_context.hotplug_cbs;
		while (hotplug_cb) {
			if ((hotplug_cb->events & event) &&
				(hotplug_cb->vendor_id == 0x0 || hotplug_cb->vendor_id == dev->vendor_id) &&
				(hotplug_cb->product_id == 0x0 || hotplug_cb->product_id == dev->product_id)) {
				struct hid_hotplug_callback* cur_hotplug_cb = hotplug_cb;
				hotplug_cb = cur_hotplug_cb->next;
				if ((*cur_hotplug_cb->callback)(cur_hotplug_cb->handle, dev, event, cur_hotplug_cb->user_data)) {
					hid_hotplug_deregister_callback(cur_hotplug_cb->handle);

					/* Last callback was deregistered */
					if (hid_hotplug_context.notify_handle == NULL) {
						break;
					}
				}
			}
			else {
				hotplug_cb = hotplug_cb->next;
			}
		}

		/* Clean removed device info */
		if (event == HID_API_HOTPLUG_EVENT_DEVICE_LEFT)
			free(dev);
	}

close:
	free(path);

	return ERROR_SUCCESS;
}

int HID_API_EXPORT HID_API_CALL hid_hotplug_register_callback(unsigned short vendor_id, unsigned short product_id, int events, int flags, hid_hotplug_callback_fn callback, void *user_data, hid_hotplug_callback_handle *callback_handle)
{
	/* Create the record. */
	struct hid_hotplug_callback *hotplug_cb;

	/* Not available on Windows 7 and older systems. */
	if (CM_Register_Notification == NULL ||
		CM_Unregister_Notification == NULL)
		return -1;

	if (!events ||
		(events & ~(HID_API_HOTPLUG_EVENT_DEVICE_ARRIVED | HID_API_HOTPLUG_EVENT_DEVICE_LEFT)) ||
		(flags & ~(HID_API_HOTPLUG_ENUMERATE)) ||
		!callback)
		return -1;

	hotplug_cb = (struct hid_hotplug_callback*)calloc(1, sizeof(struct hid_hotplug_callback));

	/* Fill out the record */
	hotplug_cb->next = NULL;
	hotplug_cb->vendor_id = vendor_id;
	hotplug_cb->product_id = product_id;
	hotplug_cb->events = events;
	hotplug_cb->user_data = user_data;
	hotplug_cb->callback = callback;

	/* protect the handle by the context hotplug lock */
	hotplug_cb->handle = hid_hotplug_context.next_hotplug_cb_handle++;

	/* handle the unlikely case of overflow */
	if (hid_hotplug_context.next_hotplug_cb_handle < 0)
		hid_hotplug_context.next_hotplug_cb_handle = 1;

	/* Append to the end */
	if (hid_hotplug_context.hotplug_cbs) {
		struct hid_hotplug_callback *last = hid_hotplug_context.hotplug_cbs;
		while (last->next) {
			last = last->next;
		}
		last->next = hotplug_cb;
	}
	else {
		struct hid_device_info *dev;

		/* Register device connection notification after adding first callback */
		if (hid_hotplug_context.notify_handle == NULL) {
			GUID interface_class_guid;
			CONFIGRET cr = CR_SUCCESS;
			CM_NOTIFY_FILTER notify_filter = { 0 };

			HidD_GetHidGuid(&interface_class_guid);

			notify_filter.cbSize = sizeof(notify_filter);
			notify_filter.FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE;
			notify_filter.u.DeviceInterface.ClassGuid = interface_class_guid;
			cr = CM_Register_Notification(&notify_filter, NULL, interface_notify_callback, &hid_hotplug_context.notify_handle);
			if (cr != CR_SUCCESS) {
				return -1;
			}
		}

		hid_hotplug_context.hotplug_cbs = hotplug_cb;

		/* Fill already connected devices */
		dev = hid_enumerate(0, 0);
		hid_hotplug_context.devs = dev;
	}

	if ((flags & HID_API_HOTPLUG_ENUMERATE) && (events & HID_API_HOTPLUG_EVENT_DEVICE_ARRIVED)) {
		struct hid_device_info* dev = hid_hotplug_context.devs;
		/* Notify about already connected devices */
		while (dev) {
			if ((hotplug_cb->vendor_id == 0x0 || hotplug_cb->vendor_id == dev->vendor_id) &&
				(hotplug_cb->product_id == 0x0 || hotplug_cb->product_id == dev->product_id)) {
				(*hotplug_cb->callback)(hotplug_cb->handle, dev, HID_API_HOTPLUG_EVENT_DEVICE_ARRIVED, hotplug_cb->user_data);
			}

			dev = dev->next;
		}
	}

	if (callback_handle != NULL) {
		*callback_handle = hotplug_cb->handle;
	}

	return 0;
}

int HID_API_EXPORT HID_API_CALL hid_hotplug_deregister_callback(hid_hotplug_callback_handle callback_handle)
{
	struct hid_hotplug_callback *hotplug_cb = NULL;

	if (callback_handle <= 0 || hid_hotplug_context.hotplug_cbs == NULL)
		return -1;

	/* Remove this notification */
	for (struct hid_hotplug_callback **current = &hid_hotplug_context.hotplug_cbs; *current; current = &(*current)->next) {
		if (hotplug_cb->handle == callback_handle) {
			struct hid_hotplug_callback *next = (*current)->next;
			hotplug_cb = *current;
			*current = next;
			break;
		}
	}

	if (!hotplug_cb)
		return -1;

	free(hotplug_cb);

	/* Unregister device connection notification on removing last callback */
	if (hid_hotplug_context.hotplug_cbs == NULL) {
		/* Cleanup connected device list */
		hid_free_enumeration(hid_hotplug_context.devs);
		hid_hotplug_context.devs = NULL;

		if (hid_hotplug_context.notify_handle != NULL) {
			CONFIGRET cr = CM_Unregister_Notification(hid_hotplug_context.notify_handle);
			hid_hotplug_context.notify_handle = NULL;
			if (cr != CR_SUCCESS) {
				return -1;
			}
		}
	}

	return 0;
}

HID_API_EXPORT hid_device * HID_API_CALL hid_open(unsigned short vendor_id, unsigned short product_id, const wchar_t *serial_number)
{
	/* TODO: Merge this functions with the Linux version. This function should be platform independent. */
	struct hid_device_info *devs, *cur_dev;
	const char *path_to_open = NULL;
	hid_device *handle = NULL;

	devs = hid_enumerate(vendor_id, product_id);
	cur_dev = devs;
	while (cur_dev) {
		if (cur_dev->vendor_id == vendor_id &&
		    cur_dev->product_id == product_id) {
			if (serial_number) {
				if (cur_dev->serial_number && wcscmp(serial_number, cur_dev->serial_number) == 0) {
					path_to_open = cur_dev->path;
					break;
				}
			}
			else {
				path_to_open = cur_dev->path;
				break;
			}
		}
		cur_dev = cur_dev->next;
	}

	if (path_to_open) {
		/* Open the device */
		handle = hid_open_path(path_to_open);
	}

	hid_free_enumeration(devs);

	return handle;
}

HID_API_EXPORT hid_device * HID_API_CALL hid_open_path(const char *path)
{
	hid_device *dev;
	HIDP_CAPS caps;
	PHIDP_PREPARSED_DATA pp_data = NULL;
	BOOLEAN res;
	NTSTATUS nt_res;

	if (hid_init() < 0) {
		return NULL;
	}

	dev = new_hid_device();

	/* Open a handle to the device */
	dev->device_handle = open_device(path, TRUE);

	/* Check validity of write_handle. */
	if (dev->device_handle == INVALID_HANDLE_VALUE) {
		/* System devices, such as keyboards and mice, cannot be opened in
		   read-write mode, because the system takes exclusive control over
		   them.  This is to prevent keyloggers.  However, feature reports
		   can still be sent and received.  Retry opening the device, but
		   without read/write access. */
		dev->device_handle = open_device(path, FALSE);

		/* Check the validity of the limited device_handle. */
		if (dev->device_handle == INVALID_HANDLE_VALUE) {
			/* Unable to open the device, even without read-write mode. */
			register_error(dev, "CreateFile");
			goto err;
		}
	}

	/* Set the Input Report buffer size to 64 reports. */
	res = HidD_SetNumInputBuffers(dev->device_handle, 64);
	if (!res) {
		register_error(dev, "HidD_SetNumInputBuffers");
		goto err;
	}

	/* Get the Input Report length for the device. */
	res = HidD_GetPreparsedData(dev->device_handle, &pp_data);
	if (!res) {
		register_error(dev, "HidD_GetPreparsedData");
		goto err;
	}
	nt_res = HidP_GetCaps(pp_data, &caps);
	if (nt_res != HIDP_STATUS_SUCCESS) {
		register_error(dev, "HidP_GetCaps");
		goto err_pp_data;
	}
	dev->output_report_length = caps.OutputReportByteLength;
	dev->input_report_length = caps.InputReportByteLength;
	dev->feature_report_length = caps.FeatureReportByteLength;
	HidD_FreePreparsedData(pp_data);

	dev->read_buf = (char*) malloc(dev->input_report_length);

	dev->device_info = hid_get_device_info(path, dev->device_handle);

	return dev;

err_pp_data:
		HidD_FreePreparsedData(pp_data);
err:
		free_hid_device(dev);
		return NULL;
}

int HID_API_EXPORT HID_API_CALL hid_write(hid_device *dev, const unsigned char *data, size_t length)
{
	DWORD bytes_written = 0;
	int function_result = -1;
	BOOL res;
	BOOL overlapped = FALSE;

	unsigned char *buf;

	if (!data || (length==0)) {
		register_error(dev, "Zero length buffer");
		return function_result;
	}

	/* Make sure the right number of bytes are passed to WriteFile. Windows
	   expects the number of bytes which are in the _longest_ report (plus
	   one for the report number) bytes even if the data is a report
	   which is shorter than that. Windows gives us this value in
	   caps.OutputReportByteLength. If a user passes in fewer bytes than this,
	   use cached temporary buffer which is the proper size. */
	if (length >= dev->output_report_length) {
		/* The user passed the right number of bytes. Use the buffer as-is. */
		buf = (unsigned char *) data;
	} else {
		if (dev->write_buf == NULL)
			dev->write_buf = (unsigned char *) malloc(dev->output_report_length);
		buf = dev->write_buf;
		memcpy(buf, data, length);
		memset(buf + length, 0, dev->output_report_length - length);
		length = dev->output_report_length;
	}

	res = WriteFile(dev->device_handle, buf, (DWORD) length, NULL, &dev->write_ol);

	if (!res) {
		if (GetLastError() != ERROR_IO_PENDING) {
			/* WriteFile() failed. Return error. */
			register_error(dev, "WriteFile");
			goto end_of_function;
		}
		overlapped = TRUE;
	}

	if (overlapped) {
		/* Wait for the transaction to complete. This makes
		   hid_write() synchronous. */
		res = WaitForSingleObject(dev->write_ol.hEvent, 1000);
		if (res != WAIT_OBJECT_0) {
			/* There was a Timeout. */
			register_error(dev, "WriteFile/WaitForSingleObject Timeout");
			goto end_of_function;
		}

		/* Get the result. */
		res = GetOverlappedResult(dev->device_handle, &dev->write_ol, &bytes_written, FALSE/*wait*/);
		if (res) {
			function_result = bytes_written;
		}
		else {
			/* The Write operation failed. */
			register_error(dev, "WriteFile");
			goto end_of_function;
		}
	}

end_of_function:
	return function_result;
}


int HID_API_EXPORT HID_API_CALL hid_read_timeout(hid_device *dev, unsigned char *data, size_t length, int milliseconds)
{
	DWORD bytes_read = 0;
	size_t copy_len = 0;
	BOOL res = FALSE;
	BOOL overlapped = FALSE;

	/* Copy the handle for convenience. */
	HANDLE ev = dev->ol.hEvent;

	if (!dev->read_pending) {
		/* Start an Overlapped I/O read. */
		dev->read_pending = TRUE;
		memset(dev->read_buf, 0, dev->input_report_length);
		ResetEvent(ev);
		res = ReadFile(dev->device_handle, dev->read_buf, (DWORD) dev->input_report_length, &bytes_read, &dev->ol);

		if (!res) {
			if (GetLastError() != ERROR_IO_PENDING) {
				/* ReadFile() has failed.
				   Clean up and return error. */
				CancelIo(dev->device_handle);
				dev->read_pending = FALSE;
				goto end_of_function;
			}
			overlapped = TRUE;
		}
	}
	else {
		overlapped = TRUE;
	}

	if (overlapped) {
		if (milliseconds >= 0) {
			/* See if there is any data yet. */
			res = WaitForSingleObject(ev, milliseconds);
			if (res != WAIT_OBJECT_0) {
				/* There was no data this time. Return zero bytes available,
				   but leave the Overlapped I/O running. */
				return 0;
			}
		}

		/* Either WaitForSingleObject() told us that ReadFile has completed, or
		   we are in non-blocking mode. Get the number of bytes read. The actual
		   data has been copied to the data[] array which was passed to ReadFile(). */
		res = GetOverlappedResult(dev->device_handle, &dev->ol, &bytes_read, TRUE/*wait*/);
	}
	/* Set pending back to false, even if GetOverlappedResult() returned error. */
	dev->read_pending = FALSE;

	if (res && bytes_read > 0) {
		if (dev->read_buf[0] == 0x0) {
			/* If report numbers aren't being used, but Windows sticks a report
			   number (0x0) on the beginning of the report anyway. To make this
			   work like the other platforms, and to make it work more like the
			   HID spec, we'll skip over this byte. */
			bytes_read--;
			copy_len = length > bytes_read ? bytes_read : length;
			memcpy(data, dev->read_buf+1, copy_len);
		}
		else {
			/* Copy the whole buffer, report number and all. */
			copy_len = length > bytes_read ? bytes_read : length;
			memcpy(data, dev->read_buf, copy_len);
		}
	}

end_of_function:
	if (!res) {
		register_error(dev, "GetOverlappedResult");
		return -1;
	}

	return (int) copy_len;
}

int HID_API_EXPORT HID_API_CALL hid_read(hid_device *dev, unsigned char *data, size_t length)
{
	return hid_read_timeout(dev, data, length, (dev->blocking)? -1: 0);
}

int HID_API_EXPORT HID_API_CALL hid_set_nonblocking(hid_device *dev, int nonblock)
{
	dev->blocking = !nonblock;
	return 0; /* Success */
}

int HID_API_EXPORT HID_API_CALL hid_send_feature_report(hid_device *dev, const unsigned char *data, size_t length)
{
	BOOL res = FALSE;
	unsigned char *buf;
	size_t length_to_send;

	/* Windows expects at least caps.FeatureReportByteLength bytes passed
	   to HidD_SetFeature(), even if the report is shorter. Any less sent and
	   the function fails with error ERROR_INVALID_PARAMETER set. Any more
	   and HidD_SetFeature() silently truncates the data sent in the report
	   to caps.FeatureReportByteLength. */
	if (length >= dev->feature_report_length) {
		buf = (unsigned char *) data;
		length_to_send = length;
	} else {
		if (dev->feature_buf == NULL)
			dev->feature_buf = (unsigned char *) malloc(dev->feature_report_length);
		buf = dev->feature_buf;
		memcpy(buf, data, length);
		memset(buf + length, 0, dev->feature_report_length - length);
		length_to_send = dev->feature_report_length;
	}

	res = HidD_SetFeature(dev->device_handle, (PVOID)buf, (DWORD) length_to_send);

	if (!res) {
		register_error(dev, "HidD_SetFeature");
		return -1;
	}

	return (int) length;
}


int HID_API_EXPORT HID_API_CALL hid_get_feature_report(hid_device *dev, unsigned char *data, size_t length)
{
	BOOL res;
#if 0
	res = HidD_GetFeature(dev->device_handle, data, length);
	if (!res) {
		register_error(dev, "HidD_GetFeature");
		return -1;
	}
	return 0; /* HidD_GetFeature() doesn't give us an actual length, unfortunately */
#else
	DWORD bytes_returned;

	OVERLAPPED ol;
	memset(&ol, 0, sizeof(ol));

	res = DeviceIoControl(dev->device_handle,
		IOCTL_HID_GET_FEATURE,
		data, (DWORD) length,
		data, (DWORD) length,
		&bytes_returned, &ol);

	if (!res) {
		if (GetLastError() != ERROR_IO_PENDING) {
			/* DeviceIoControl() failed. Return error. */
			register_error(dev, "Send Feature Report DeviceIoControl");
			return -1;
		}
	}

	/* Wait here until the write is done. This makes
	   hid_get_feature_report() synchronous. */
	res = GetOverlappedResult(dev->device_handle, &ol, &bytes_returned, TRUE/*wait*/);
	if (!res) {
		/* The operation failed. */
		register_error(dev, "Send Feature Report GetOverLappedResult");
		return -1;
	}

	return bytes_returned;
#endif
}


int HID_API_EXPORT HID_API_CALL hid_get_input_report(hid_device *dev, unsigned char *data, size_t length)
{
	BOOL res;
#if 0
	res = HidD_GetInputReport(dev->device_handle, data, length);
	if (!res) {
		register_error(dev, "HidD_GetInputReport");
		return -1;
	}
	return length;
#else
	DWORD bytes_returned;

	OVERLAPPED ol;
	memset(&ol, 0, sizeof(ol));

	res = DeviceIoControl(dev->device_handle,
		IOCTL_HID_GET_INPUT_REPORT,
		data, (DWORD) length,
		data, (DWORD) length,
		&bytes_returned, &ol);

	if (!res) {
		if (GetLastError() != ERROR_IO_PENDING) {
			/* DeviceIoControl() failed. Return error. */
			register_error(dev, "Send Input Report DeviceIoControl");
			return -1;
		}
	}

	/* Wait here until the write is done. This makes
	   hid_get_feature_report() synchronous. */
	res = GetOverlappedResult(dev->device_handle, &ol, &bytes_returned, TRUE/*wait*/);
	if (!res) {
		/* The operation failed. */
		register_error(dev, "Send Input Report GetOverLappedResult");
		return -1;
	}

	return bytes_returned;
#endif
}

void HID_API_EXPORT HID_API_CALL hid_close(hid_device *dev)
{
	if (!dev)
		return;
	CancelIo(dev->device_handle);
	free_hid_device(dev);
}

int HID_API_EXPORT_CALL HID_API_CALL hid_get_manufacturer_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
	if (!dev->device_info || !string || !maxlen)
		return -1;

	wcsncpy(string, dev->device_info->manufacturer_string, maxlen);
	string[maxlen] = L'\0';

	return 0;
}

int HID_API_EXPORT_CALL HID_API_CALL hid_get_product_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
	if (!dev->device_info || !string || !maxlen)
		return -1;

	wcsncpy(string, dev->device_info->product_string, maxlen);
	string[maxlen] = L'\0';

	return 0;
}

int HID_API_EXPORT_CALL HID_API_CALL hid_get_serial_number_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
	if (!dev->device_info || !string || !maxlen)
		return -1;

	wcsncpy(string, dev->device_info->serial_number, maxlen);
	string[maxlen] = L'\0';

	return 0;
}

int HID_API_EXPORT_CALL HID_API_CALL hid_get_indexed_string(hid_device *dev, int string_index, wchar_t *string, size_t maxlen)
{
	BOOL res;

	res = HidD_GetIndexedString(dev->device_handle, string_index, string, sizeof(wchar_t) * (DWORD) MIN(maxlen, MAX_STRING_WCHARS));
	if (!res) {
		register_error(dev, "HidD_GetIndexedString");
		return -1;
	}

	return 0;
}


HID_API_EXPORT const wchar_t * HID_API_CALL  hid_error(hid_device *dev)
{
	if (dev) {
		if (dev->last_error_str == NULL)
			return L"Success";
		return (wchar_t*)dev->last_error_str;
	}

	// Global error messages are not (yet) implemented on Windows.
	return L"hid_error for global errors is not implemented yet";
}


/*#define PICPGM*/
/*#define S11*/
#define P32
#ifdef S11
  unsigned short VendorID = 0xa0a0;
	unsigned short ProductID = 0x0001;
#endif

#ifdef P32
  unsigned short VendorID = 0x04d8;
	unsigned short ProductID = 0x3f;
#endif


#ifdef PICPGM
  unsigned short VendorID = 0x04d8;
  unsigned short ProductID = 0x0033;
#endif


#if 0
int __cdecl main(int argc, char* argv[])
{
	int res;
	unsigned char buf[65];

	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	/* Set up the command buffer. */
	memset(buf,0x00,sizeof(buf));
	buf[0] = 0;
	buf[1] = 0x81;


	/* Open the device. */
	int handle = open(VendorID, ProductID, L"12345");
	if (handle < 0)
		printf("unable to open device\n");


	/* Toggle LED (cmd 0x80) */
	buf[1] = 0x80;
	res = write(handle, buf, 65);
	if (res < 0)
		printf("Unable to write()\n");

	/* Request state (cmd 0x81) */
	buf[1] = 0x81;
	write(handle, buf, 65);
	if (res < 0)
		printf("Unable to write() (2)\n");

	/* Read requested state */
	read(handle, buf, 65);
	if (res < 0)
		printf("Unable to read()\n");

	/* Print out the returned buffer. */
	for (int i = 0; i < 4; i++)
		printf("buf[%d]: %d\n", i, buf[i]);

	return 0;
}
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif
