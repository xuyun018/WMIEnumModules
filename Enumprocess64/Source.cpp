#include <windows.h>
#include <string>
#include <map>
#include <list>
#include <vector>
#define _WIN32_DCOM
#include <comdef.h>
#include <Wbemidl.h>
#include <tchar.h>
#include <algorithm>
#if defined(UNICODE) || defined(_UNICODE)
#define  UPDATESTRING_ std::wstring
#else
#define  UPDATESTRING_ std::string
#endif
#pragma comment(lib, "wbemuuid.lib")
std::map<unsigned int, std::list<UPDATESTRING_ > > g_mapProcModule;
void split(UPDATESTRING_& s, UPDATESTRING_& delim, std::vector< UPDATESTRING_ >* ret)
{
	size_t last(0);
	size_t index = s.find_first_of(delim, last);
	while (UPDATESTRING_::npos != index)
	{
		ret->push_back(s.substr(last, index - last));
		last = index + 1;
		index = s.find_first_of(delim, last);
	}
	if (index - last > 0)
	{
		ret->push_back(s.substr(last, index - last));
	}
}

bool isFileExist(const TCHAR* szFileFullName, bool* pbIsDir = NULL)
{
	WIN32_FIND_DATA Win32_Find_Data;
	HANDLE hFindFile(INVALID_HANDLE_VALUE);
	bool bExist(false);
	hFindFile = FindFirstFile(szFileFullName, &Win32_Find_Data);
	if (INVALID_HANDLE_VALUE != hFindFile)
	{
		if (pbIsDir)
		{
			*pbIsDir = (FILE_ATTRIBUTE_DIRECTORY == Win32_Find_Data.dwFileAttributes) ? true : false;
		}
		FindClose(hFindFile);
		bExist = true;
	}

	return bExist;
}

bool getFullFileName(const TCHAR* strFile, UPDATESTRING_& strFullPath)
{
	if (NULL == strFile
		|| !isFileExist(strFile))
	{
		return false;
	}

	TCHAR sz[MAX_PATH * 3] = { 0 };
	GetLongPathName(strFile, sz, MAX_PATH * 2);
	strFullPath.assign(sz);
	std::transform(strFullPath.begin(), strFullPath.end(), strFullPath.begin(), ::tolower);
	return true;
}

int getProcID(TCHAR* szWMIDependent)
{
	unsigned int procId(0);
	if (szWMIDependent)
	{
		UPDATESTRING_ str(szWMIDependent);
		std::vector< UPDATESTRING_ > lst;
		split(str, UPDATESTRING_(_T("\"")), &lst);
		if (lst.size() >= 3)
		{
			procId = _ttoi(lst[lst.size() - 2].c_str());
		}
	}

	return procId;
}

UPDATESTRING_ getFilePath(TCHAR* szWMIAntecedent)
{

	UPDATESTRING_ filePath(_T(""));
	if (szWMIAntecedent)
	{
		UPDATESTRING_ str(szWMIAntecedent);
		std::vector< UPDATESTRING_ > lst;
		split(str, UPDATESTRING_(_T("\"")), &lst);
		if (lst.size() >= 3)
		{
			filePath = lst[lst.size() - 2];
			UPDATESTRING_::size_type index = filePath.find(_T("\\\\"));
			while (UPDATESTRING_::npos != index)
			{
				filePath.erase(index, 1);
				index = filePath.find(_T("\\\\"));
			}
		}
	}

	UPDATESTRING_ str;
	getFullFileName(filePath.c_str(), str);

	return str;
}

bool enumPorcessModule64()
{
	bool bRet(false);
	bool bComInit(false);
	IWbemServices *pSvc(NULL);
	IWbemLocator *pLoc(NULL);
	IEnumWbemClassObject* pEnumerator(NULL);
	do
	{
		HRESULT hres(S_OK);
		hres = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
		if (FAILED(hres))
		{
			break;
		}

		bComInit = true;
		hres = CoInitializeSecurity(
			NULL,
			-1,      // COM negotiates service                  
			NULL,    // Authentication services
			NULL,    // Reserved
			RPC_C_AUTHN_LEVEL_DEFAULT,    // authentication
			RPC_C_IMP_LEVEL_IMPERSONATE,  // Impersonation
			NULL,             // Authentication info 
			EOAC_NONE,        // Additional capabilities
			NULL              // Reserved
		);
		if (FAILED(hres))
		{
			break;
		}

		hres = CoCreateInstance(
			CLSID_WbemLocator,
			0,
			CLSCTX_INPROC_SERVER,
			IID_IWbemLocator, (LPVOID *)&pLoc);
		if (FAILED(hres))
		{
			break;
		}

		hres = pLoc->ConnectServer(
			_bstr_t(_T("ROOT\\CIMV2")), // WMI namespace
			NULL,                    // User name
			NULL,                    // User password
			0,                       // Locale
			NULL,                    // Security flags                 
			0,                       // Authority       
			0,                       // Context object
			&pSvc                    // IWbemServices proxy
		);
		if (FAILED(hres))
		{
			break;
		}

		hres = CoSetProxyBlanket(
			pSvc,                         // the proxy to set
			RPC_C_AUTHN_WINNT,            // authentication service
			RPC_C_AUTHZ_NONE,             // authorization service
			NULL,                         // Server principal name
			RPC_C_AUTHN_LEVEL_CALL,       // authentication level
			RPC_C_IMP_LEVEL_IMPERSONATE,  // impersonation level
			NULL,                         // client identity 
			EOAC_NONE                     // proxy capabilities     
		);
		if (FAILED(hres))
		{
			break;
		}

		TCHAR* sz = _T("SELECT * FROM CIM_ProcessExecutable");
		hres = pSvc->ExecQuery(
			bstr_t(_T("WQL")),
			bstr_t(sz),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			NULL,
			&pEnumerator);
		if (FAILED(hres))
		{
			break;
		}

		IWbemClassObject *pclsObj(NULL);
		ULONG uReturn = 0;
		while (pEnumerator)
		{
			hres = pEnumerator->Next(WBEM_INFINITE, 1,
				&pclsObj, &uReturn);

			if (0 == uReturn)
			{
				break;
			}

			VARIANT vtPropID, vtPropFile;
			hres = pclsObj->Get(L"Dependent", 0, &vtPropID, 0, 0);
			if (FAILED(hres))
				continue;
			//\\WIN-KLJPKO8EM0M\root\cimv2:Win32_Process.Handle="1156"
			unsigned int procId = getProcID((TCHAR*)vtPropID.bstrVal);
			if (0 != procId)
			{
				hres = pclsObj->Get(L"Antecedent", 0, &vtPropFile, 0, 0);
				if (FAILED(hres))
					continue;
				//\\WIN-KLJPKO8EM0M\root\cimv2:CIM_DataFile.Name="C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
				UPDATESTRING_ filePath = getFilePath((TCHAR*)vtPropFile.bstrVal);
				if (filePath.empty())
					continue;

				std::list<UPDATESTRING_ > lst;
				lst.push_back(filePath);
				std::pair<unsigned int, std::list<UPDATESTRING_ > > prInsert(procId, lst);
				std::pair<std::map<unsigned int, std::list<UPDATESTRING_ > >::iterator, bool > prRet =
					g_mapProcModule.insert(prInsert);
				if (!prRet.second)
				{
					prRet.first->second.push_back(filePath);
				}
			}

			VariantClear(&vtPropID);
			VariantClear(&vtPropFile);
		}

		bRet = true;
	} while (false);
	if (pSvc)
		pSvc->Release();
	if (pLoc)
		pLoc->Release();
	if (bComInit)
		CoUninitialize();

	return bRet;
}
int main()
{
	enumPorcessModule64();
	std::map<unsigned int, std::list<UPDATESTRING_ > >::iterator it = g_mapProcModule.begin();
	for (; g_mapProcModule.end() != it; it++)
	{
		_tprintf(_T("procID>>%d\r\n"), it->first);
		std::list<UPDATESTRING_ >::iterator itModule = it->second.begin();
		for (; it->second.end() != itModule; itModule++)
		{
			_tprintf(_T("Module:%s\r\n"), (*itModule).c_str());
		}
		_tprintf(_T("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\r\n"));
	}
	getchar();
	return 0;
}