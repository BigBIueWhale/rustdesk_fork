/* Portable execution of the production reader, with controlled COM types/RPC.
 * This fixture does not establish the Windows ABI or concurrent callback safety. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t UINT, UINT32, ULONG, DWORD;
typedef int32_t HRESULT;
typedef struct { int unused; } IStream;
typedef union {
	struct { uint32_t LowPart, HighPart; };
	uint64_t QuadPart;
} ULARGE_INTEGER;
typedef struct {
	IStream iStream;
	ULONG m_lIndex;
	ULARGE_INTEGER m_lSize, m_lOffset;
	void *m_pData;
	UINT32 m_connID;
} CliprdrStream;
typedef struct { ULONG req_fsize; char *req_fdata; } wfClipboard;
#define STDMETHODCALLTYPE
#define ERROR_SUCCESS 0u
#define S_OK ((HRESULT)0)
#define S_FALSE ((HRESULT)1)
#define E_FAIL ((HRESULT)UINT32_C(0x80004005))
#define E_INVALIDARG ((HRESULT)UINT32_C(0x80070057))
#define FILECONTENTS_RANGE 2u
#define CopyMemory memcpy

struct Scenario {
	ULONG requested, response;
	UINT transfer_status;
	uint64_t offset, size;
	int payload;
	HRESULT status;
	ULONG read;
	unsigned requests;
};
static const struct Scenario scenarios[] = {
	{8, 8, 0, 2, 32, 1, S_OK, 8, 1},
	{8, 3, 0, 2, 32, 1, S_FALSE, 3, 1},
	{8, 0, 0, 32, 32, 0, S_FALSE, 0, 0},
	{8, 0, 0, 2, 32, 1, S_FALSE, 0, 1},
	{8, 0, (UINT)E_FAIL, 2, 32, 0, E_FAIL, 0, 1},
	{8, 16, 0, 0, 32, 1, E_FAIL, 0, 1},
	{16, 8, 0, 28, 32, 1, E_FAIL, 0, 1},
	{8, 8, 0, UINT64_MAX - 3, UINT64_MAX, 1, E_FAIL, 0, 1},
	{8, 0, 5, 2, 32, 0, E_FAIL, 0, 1},
	{0, 0, 0, 32, 32, 0, S_OK, 0, 0},
	{8, 4, 0, 2, 32, 0, E_FAIL, 0, 1},
	{0, 0, 0, 2, 32, 1, S_OK, 0, 0},
};
static const struct Scenario *active;
static unsigned requests, releases;

static void observed_free(void *data)
{
	if (data) releases++;
	free(data);
}
static UINT cliprdr_send_request_filecontents(wfClipboard *clipboard, UINT32 conn,
	const void *stream, ULONG index, UINT32 flags, DWORD high, DWORD low, ULONG requested)
{
	if (conn != 7 || !stream || index != 3 || flags != FILECONTENTS_RANGE ||
		(((uint64_t)high << 32) | low) != active->offset || requested != active->requested)
		abort();
	requests++;
	clipboard->req_fsize = active->response;
	if (active->payload) {
		clipboard->req_fdata = malloc(64);
		if (!clipboard->req_fdata) abort();
		memset(clipboard->req_fdata, 0x73, 64);
	}
	return active->transfer_status;
}

#define free observed_free
#include "production_read.c"
#undef free

int cliprdr_read_test(unsigned scenario)
{
	if (scenario >= sizeof(scenarios) / sizeof(scenarios[0])) return -1;
	active = &scenarios[scenario];
	requests = releases = 0;
	wfClipboard clipboard = {0};
	CliprdrStream stream = {0};
	stream.m_lIndex = 3;
	stream.m_connID = 7;
	stream.m_pData = &clipboard;
	stream.m_lOffset.QuadPart = active->offset;
	stream.m_lSize.QuadPart = active->size;
	unsigned char destination[64], expected[64];
	memset(destination, 0xa5, sizeof(destination));
	memset(expected, 0xa5, sizeof(expected));
	memset(expected, 0x73, active->read);
	ULONG read = 99;
	HRESULT status = CliprdrStream_Read(&stream.iStream, destination, active->requested, &read);
	unsigned failures = 0;
	if (status != active->status) failures |= 1;
	if (read != active->read) failures |= 2;
	if (stream.m_lOffset.QuadPart != active->offset + active->read) failures |= 4;
	/* The full backing array includes canaries beyond the caller's logical cb. */
	if (memcmp(destination, expected, sizeof(expected)) != 0) failures |= 8;
	if (requests != active->requests) failures |= 16;
	if (releases != (active->requests && active->payload ? 1u : 0u)) failures |= 32;
	if (failures) fprintf(stderr, "case=%u failures=%u status=%08x read=%u requests=%u releases=%u\n",
		scenario, failures, (unsigned)status, read, requests, releases);
	wf_cliprdr_clear_file_response(&clipboard);
	return (int)failures;
}
