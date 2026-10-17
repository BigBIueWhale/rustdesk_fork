// Exact CliprdrStream_Read at eabb4e8abf4d2695d870adf21c7f0f9e28ad9ea0.
// Body SHA-256: a96b8f3b2c19eb99a1337f930ab905066784648130aa4c37d77b31cc9fdb52e9
/*
 * FreeRDP Windows Clipboard Redirection
 * Copyright 2012 Jason Champion
 * Copyright 2014 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 * Copyright 2015 Thincast Technologies GmbH
 * Copyright 2015 DI (FH) Martin Haimberger <martin.haimberger@thincast.com>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
static HRESULT STDMETHODCALLTYPE CliprdrStream_Read(IStream *This, void *pv, ULONG cb,
													ULONG *pcbRead)
{
	int ret;
	CliprdrStream *instance = (CliprdrStream *)This;
	wfClipboard *clipboard = NULL;

	if (!pv || !pcbRead || !instance)
		return E_INVALIDARG;

	clipboard = (wfClipboard *)instance->m_pData;
	*pcbRead = 0;

	if (instance->m_lOffset.QuadPart >= instance->m_lSize.QuadPart)
		return S_FALSE;

	ret = cliprdr_send_request_filecontents(clipboard, instance->m_connID, (void *)This, instance->m_lIndex,
											FILECONTENTS_RANGE, instance->m_lOffset.HighPart,
											instance->m_lOffset.LowPart, cb);

	if (ret < 0)
		return E_FAIL;

	if (clipboard->req_fdata)
	{
		CopyMemory(pv, clipboard->req_fdata, clipboard->req_fsize);
		free(clipboard->req_fdata);
		clipboard->req_fdata = NULL;
	}

	*pcbRead = clipboard->req_fsize;
	// Check overflow, can not be a real case
	if ((instance->m_lOffset.QuadPart + clipboard->req_fsize) < instance->m_lOffset.QuadPart) {
		// It's better to crash to release the explorer.exe
		// This is a critical error, because the explorer is waiting for the data
		// and the m_lOffset is wrong(overflowed)
		return S_FALSE;
	}
	instance->m_lOffset.QuadPart += clipboard->req_fsize;

	if (clipboard->req_fsize < cb)
		return S_FALSE;

	return S_OK;
}
