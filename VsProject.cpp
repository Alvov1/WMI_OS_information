#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <wincred.h>
#include <strsafe.h>
#include <conio.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")
#define _WIN32_DCOM
#define UNICODE
using namespace std;

constexpr auto pcName = L"DESKTOP-36QF4OO";
constexpr auto CIMV = L"\\\\DESKTOP-36QF4OO\\root\\CIMV2";
constexpr auto SECURITY_CENTER = L"\\\\DESKTOP-36QF4OO\\root\\SecurityCenter2";

int __cdecl main(int argc, char** argv)
{
	setlocale(LC_ALL, "Russian");
	HRESULT hres;
	// Шаг 1: --------------------------------------------------
	// Инициализация COM. ------------------------------------------
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		cout << "Failed to initialize COM library. Error code = 0x"
			<< hex << hres << endl;
		return 1;
	}
	// Шаг 2: --------------------------------------------------
	// Установка уровней безопасности COM --------------------------
	hres = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IDENTIFY,
		NULL,
		EOAC_NONE,
		NULL
	);
	if (FAILED(hres))
	{
		cout << "Failed to initialize security. Error code = 0x"
			<< hex << hres << endl;
		CoUninitialize();
		return 1;
	}
	// Шаг 3: ---------------------------------------------------
	// Создание локатора WMI -------------------------
	IWbemLocator* pLoc = NULL;
	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)&pLoc);
	if (FAILED(hres))
	{
		cout << "Failed to create IWbemLocator object."
			<< " Err code = 0x"
			<< hex << hres << endl;
		CoUninitialize();
		return 1;
	}
	// Шаг 4: -----------------------------------------------------
	// Подключение к WMI через IWbemLocator::ConnectServer
	IWbemServices* pSvc = NULL;
	// Получение реквизитов доступа к удаленному компьютеру
	CREDUI_INFO cui;
	bool useToken = false;
	bool useNTLM = true;
	wchar_t pszName[CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
	wchar_t pszPwd[CREDUI_MAX_PASSWORD_LENGTH + 1] = { 0 };
	wchar_t pszDomain[CREDUI_MAX_USERNAME_LENGTH + 1];
	wchar_t pszUserName[CREDUI_MAX_USERNAME_LENGTH + 1];
	wchar_t pszAuthority[CREDUI_MAX_USERNAME_LENGTH + 1];
	BOOL fSave;
	DWORD dwErr;
	memset(&cui, 0, sizeof(CREDUI_INFO));
	cui.cbSize = sizeof(CREDUI_INFO);
	cui.hwndParent = NULL;
	cui.pszMessageText = TEXT("Press cancel to use process token");
	cui.pszCaptionText = TEXT("Enter Account Information");
	cui.hbmBanner = NULL;
	fSave = FALSE;
	dwErr = CredUIPromptForCredentials(
		&cui,
		TEXT(""),
		NULL,
		0,
		pszName,
		CREDUI_MAX_USERNAME_LENGTH + 1,
		pszPwd,
		CREDUI_MAX_PASSWORD_LENGTH + 1,
		&fSave,
		CREDUI_FLAGS_GENERIC_CREDENTIALS |
		CREDUI_FLAGS_ALWAYS_SHOW_UI |
		CREDUI_FLAGS_DO_NOT_PERSIST);
	if (dwErr == ERROR_CANCELLED)
	{
		useToken = true;
	}
	else if (dwErr)
	{
		cout << "Did not get credentials " << dwErr << endl;
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	// Подключение к пространству имен root\cimv2
	//---------------------------------------------------------
	hres = pLoc->ConnectServer(
		_bstr_t(CIMV),
		_bstr_t(useToken ? NULL : pszName),
		_bstr_t(useToken ? NULL : pszPwd),
		NULL,
		NULL,
		_bstr_t(useNTLM ? NULL : pszAuthority),
		NULL,
		&pSvc
	);
	if (FAILED(hres))
	{
		cout << "Could not connect. Error code = 0x"
			<< hex << hres << endl;
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	cout << "# Connected to ROOT\\CIMV2 WMI namespace" << endl;
	// Шаг 5: --------------------------------------------------
	// Создание структуры COAUTHIDENTITY
	COAUTHIDENTITY* userAcct = NULL;
	COAUTHIDENTITY authIdent;
	if (!useToken)
	{
		memset(&authIdent, 0, sizeof(COAUTHIDENTITY));
		authIdent.PasswordLength = wcslen(pszPwd);
		authIdent.Password = (USHORT*)pszPwd;
		LPWSTR slash = wcschr(pszName, L'\\');
		if (slash == NULL)
		{
			cout << "Could not create Auth identity. No domain specified\n";
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			return 1;
		}
		StringCchCopy(pszUserName, CREDUI_MAX_USERNAME_LENGTH + 1, slash + 1);
		authIdent.User = (USHORT*)pszUserName;
		authIdent.UserLength = wcslen(pszUserName);
		StringCchCopyN(pszDomain, CREDUI_MAX_USERNAME_LENGTH + 1, pszName,
			slash - pszName);
		authIdent.Domain = (USHORT*)pszDomain;
		authIdent.DomainLength = slash - pszName;
		authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
		userAcct = &authIdent;
	}
	// Шаг 6: --------------------------------------------------
	// Установка защиты прокси сервера ------------------
	hres = CoSetProxyBlanket(
		pSvc,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);
	if (FAILED(hres))
	{
		cout << "Could not set proxy blanket. Error code = 0x"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	// Шаг 7: --------------------------------------------------
	// Получение данных через WMI ----
	// Например, получим имя ОС

	IEnumWbemClassObject* pEnumerator = NULL;
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;

	/* ------------------------------------------------------------------------------------------------ */
	/*									Operating system information									*/
	/* ------------------------------------------------------------------------------------------------ */

	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("Select * from Win32_OperatingSystem"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);
	if (FAILED(hres))
	{
		cout << "Query for operating system name failed."
			<< " Error code = 0x"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	hres = CoSetProxyBlanket(
		pEnumerator,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);
	if (FAILED(hres))
	{
		cout << "Could not set proxy blanket on enumerator. Error code = 0x"
			<< hex << hres << endl;
		pEnumerator->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);
		if (0 == uReturn)
		{
			break;
		}
		VARIANT vtProp;

		hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
		wcout << "OS Name : " << vtProp.bstrVal << endl;

		hr = pclsObj->Get(L"FreePhysicalMemory", 0, &vtProp, 0, 0);
		wcout << "Free physical memory (in kilobytes): " << vtProp.bstrVal << endl;

		hr = pclsObj->Get(L"FreeVirtualMemory", 0, &vtProp, 0, 0);
		std::wcout << "Free virtual memory (in kilobytes): " << vtProp.bstrVal << std::endl;

		hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
		std::wcout << "Manufacturer: " << vtProp.bstrVal << std::endl;

		hr = pclsObj->Get(L"OSLanguage", 0, &vtProp, 0, 0);
		std::wcout << "OSLanguage: " << vtProp.uintVal << std::endl;

		hr = pclsObj->Get(L"SystemDirectory", 0, &vtProp, 0, 0);
		std::wcout << "SystemDirectory: " << vtProp.bstrVal << std::endl;

		hr = pclsObj->Get(L"RegisteredUser", 0, &vtProp, 0, 0);
		std::wcout << "RegisteredUser: " << vtProp.bstrVal << std::endl;

		hr = pclsObj->Get(L"NumberOfLicensedUsers", 0, &vtProp, 0, 0);
		std::wcout << "NumberOfLicensedUsers: " << vtProp.uintVal << std::endl;

		hr = pclsObj->Get(L"Version", 0, &vtProp, 0, 0);
		std::wcout << "Version: " << vtProp.bstrVal << std::endl;

		VariantClear(&vtProp);
		pclsObj->Release();
		pclsObj = NULL;
	}

	/* ------------------------------------------------------------------------------------------------ */
	/*									Installed programs information									*/
	/* ------------------------------------------------------------------------------------------------ */

	pEnumerator = nullptr;
	
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("Select * from Win32_Product"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);
	if (FAILED(hres))
	{
		cout << "Query for operating system name failed."
			<< " Error code = 0x"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	hres = CoSetProxyBlanket(
		pEnumerator,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);
	if (FAILED(hres))
	{
		cout << "Could not set proxy blanket on enumerator. Error code = 0x"
			<< hex << hres << endl;
		pEnumerator->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}

	pclsObj = NULL;
	uReturn = 0;
	std::cout << "Installed programs:" << std::endl;
	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);
		if (0 == uReturn)
		{
			break;
		}
		VARIANT vtProp;

		hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
		wcout << "Program Name : " << vtProp.bstrVal << endl;

		VariantClear(&vtProp);
		pclsObj->Release();
		pclsObj = NULL;
	}
	
	/* ------------------------------------------------------------------------------------------------ */
	/*								Connecting to the Security Service									*/
	/* ------------------------------------------------------------------------------------------------ */
	// Подключение к пространству имен root\SecurityCenter2
	//---------------------------------------------------------
	hres = pLoc->ConnectServer(
		_bstr_t(SECURITY_CENTER),
		_bstr_t(useToken ? NULL : pszName),
		_bstr_t(useToken ? NULL : pszPwd),
		NULL,
		NULL,
		_bstr_t(useNTLM ? NULL : pszAuthority),
		NULL,
		&pSvc
	);
	if (FAILED(hres))
	{
		cout << "Could not connect. Error code = 0x"
			<< hex << hres << endl;
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	cout << std::endl << "# Connected to ROOT\\SecurityCenter2 WMI namespace" << endl;
	userAcct = NULL;
	authIdent;
	if (!useToken)
	{
		memset(&authIdent, 0, sizeof(COAUTHIDENTITY));
		authIdent.PasswordLength = wcslen(pszPwd);
		authIdent.Password = (USHORT*)pszPwd;
		LPWSTR slash = wcschr(pszName, L'\\');
		if (slash == NULL)
		{
			cout << "Could not create Auth identity. No domain specified\n";
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			return 1;
		}
		StringCchCopy(pszUserName, CREDUI_MAX_USERNAME_LENGTH + 1, slash + 1);
		authIdent.User = (USHORT*)pszUserName;
		authIdent.UserLength = wcslen(pszUserName);
		StringCchCopyN(pszDomain, CREDUI_MAX_USERNAME_LENGTH + 1, pszName,
			slash - pszName);
		authIdent.Domain = (USHORT*)pszDomain;
		authIdent.DomainLength = slash - pszName;
		authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
		userAcct = &authIdent;
	}
	// Шаг 6: --------------------------------------------------
	// Установка защиты прокси сервера ------------------
	hres = CoSetProxyBlanket(
		pSvc,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);
	if (FAILED(hres))
	{
		cout << "Could not set proxy blanket. Error code = 0x"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}

	/* ------------------------------------------------------------------------------------------------ */
	/*										Antiviruses information										*/
	/* ------------------------------------------------------------------------------------------------ */

	pEnumerator = nullptr;

	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("Select * from AntiVirusProduct"),
		/*WBEM_FLAG_FORWARD_ONLY*/ WBEM_FLAG_BIDIRECTIONAL | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);
	if (FAILED(hres))
	{
		cout << "Query for operating system name failed."
			<< " Error code = 0x"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	hres = CoSetProxyBlanket(
		pEnumerator,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);
	if (FAILED(hres))
	{
		cout << "Could not set proxy blanket on enumerator. Error code = 0x"
			<< hex << hres << endl;
		pEnumerator->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}

	pclsObj = NULL;
	uReturn = 0;
	std::cout << std::endl <<  "Antiviruses infromation:" << std::endl;
	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);
		if (0 == uReturn)
		{
			break;
		}
		VARIANT vtProp;

		hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
		wcout << "Name : " << vtProp.bstrVal << endl;

		hr = pclsObj->Get(L"instanceGuid", 0, &vtProp, 0, 0);
		std::wcout << "GUID: " << vtProp.bstrVal << std::endl;

		hr = pclsObj->Get(L"pathToSignedProductExe", 0, &vtProp, 0, 0);
		std::wcout << "Path to the file: " << vtProp.bstrVal << std::endl;

		VariantClear(&vtProp);
		pclsObj->Release();
		pclsObj = NULL;
	}

	/* ------------------------------------------------------------------------------------------------ */
	/*										Firewalls information										*/
	/* ------------------------------------------------------------------------------------------------ */

	pEnumerator = nullptr;

	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("Select * from FirewallProduct"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);
	if (FAILED(hres))
	{
		cout << "Query for operating system name failed."
			<< " Error code = 0x"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	hres = CoSetProxyBlanket(
		pEnumerator,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);
	if (FAILED(hres))
	{
		cout << "Could not set proxy blanket on enumerator. Error code = 0x"
			<< hex << hres << endl;
		pEnumerator->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}

	pclsObj = NULL;
	uReturn = 0;
	std::cout << std::endl << "Firewalls information:" << std::endl;
	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);
		if (0 == uReturn)
		{
			break;
		}
		VARIANT vtProp;

		hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
		wcout << "Name : " << vtProp.bstrVal << endl;

		hr = pclsObj->Get(L"instanceGuid", 0, &vtProp, 0, 0);
		std::wcout << "GUID: " << vtProp.bstrVal << std::endl;

		hr = pclsObj->Get(L"pathToSignedProductExe", 0, &vtProp, 0, 0);
		std::wcout << "Path to the file: " << vtProp.bstrVal << std::endl;

		VariantClear(&vtProp);
		pclsObj->Release();
		pclsObj = NULL;
	}

	/* ------------------------------------------------------------------------------------------------ */
	/*									   Antispywares information										*/
	/* ------------------------------------------------------------------------------------------------ */

	pEnumerator = nullptr;

	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("Select * from AntiSpywareProduct"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);
	if (FAILED(hres))
	{
		cout << "Query for operating system name failed."
			<< " Error code = 0x"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	hres = CoSetProxyBlanket(
		pEnumerator,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);
	if (FAILED(hres))
	{
		cout << "Could not set proxy blanket on enumerator. Error code = 0x"
			<< hex << hres << endl;
		pEnumerator->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}

	pclsObj = NULL;
	uReturn = 0;
	std::cout << std::endl << "Antispywares information:" << std::endl;
	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);
		if (0 == uReturn)
		{
			break;
		}
		VARIANT vtProp;

		hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
		wcout << "Name : " << vtProp.bstrVal << endl;

		hr = pclsObj->Get(L"instanceGuid", 0, &vtProp, 0, 0);
		std::wcout << "GUID: " << vtProp.bstrVal << std::endl;

		hr = pclsObj->Get(L"pathToSignedProductExe", 0, &vtProp, 0, 0);
		std::wcout << "Path to the file: " << vtProp.bstrVal << std::endl;

		VariantClear(&vtProp);
		pclsObj->Release();
		pclsObj = NULL;
	}

	SecureZeroMemory(pszName, sizeof(pszName));
	SecureZeroMemory(pszPwd, sizeof(pszPwd));
	SecureZeroMemory(pszUserName, sizeof(pszUserName));
	SecureZeroMemory(pszDomain, sizeof(pszDomain));

	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	if (pclsObj)
	{
		pclsObj->Release();
	}
	CoUninitialize();


	return 0;
}