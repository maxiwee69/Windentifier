#define WIN32_WINNT 0x0501
#include <iostream>
#include <windows.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <iomanip>
#include <comdef.h>
#include <Wbemidl.h>
#include <Lmcons.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")

void GetUsername() {
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    GetUserName(username, &username_len);
    std::cout << "Username: " << username << "\n";
}

void GetMotherboardSerialNumber() {
    HRESULT hres;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM library\n";
        return;
    }

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize security\n";
        CoUninitialize();
        return;
    }

    IWbemLocator *pLoc = NULL;

    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);
    if (FAILED(hres)) {
        std::cerr << "Failed to create IWbemLocator object\n";
        CoUninitialize();
        return;
    }

    IWbemServices *pSvc = NULL;

    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        std::cerr << "Could not connect\n";
        pLoc->Release();
        CoUninitialize();
        return;
    }

    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        std::cerr << "Could not set proxy blanket\n";
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_BaseBoard"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hres)) {
        std::cerr << "Query for operating system name failed\n";
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (!uReturn) {
            break;
        }

        VARIANT vtProp;
        hr = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
        std::wcout << "Motherboard Serial Number: " << vtProp.bstrVal << "\n";
        VariantClear(&vtProp);
        pclsObj->Release();
    }

    pSvc->Release();
    pEnumerator->Release();
    pLoc->Release();

    CoUninitialize();
}

void GetSystemUUID() {
    HRESULT hres;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM library\n";
        return;
    }

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize security\n";
        CoUninitialize();
        return;
    }

    IWbemLocator *pLoc = NULL;

    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);
    if (FAILED(hres)) {
        std::cerr << "Failed to create IWbemLocator object\n";
        CoUninitialize();
        return;
    }

    IWbemServices *pSvc = NULL;

    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        std::cerr << "Could not connect\n";
        pLoc->Release();
        CoUninitialize();
        return;
    }

    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        std::cerr << "Could not set proxy blanket\n";
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_ComputerSystemProduct"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hres)) {
        std::cerr << "Query for system information failed\n";
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    // Enumerate the results
    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (!uReturn) {
            break;
        }

        // Get the UUID property
        VARIANT vtProp;
        hr = pclsObj->Get(L"UUID", 0, &vtProp, 0, 0);
        std::wcout << "System UUID: " << vtProp.bstrVal << "\n";
        VariantClear(&vtProp);
        pclsObj->Release();
    }

    pSvc->Release();
    pEnumerator->Release();
    pLoc->Release();

    CoUninitialize();
}

void GetPhysicalMacAddress() {
    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD dwBufLen = sizeof(AdapterInfo);

    DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
    if (dwStatus != ERROR_SUCCESS) {
        std::cerr << "GetAdaptersInfo failed\n";
        return;
    }

    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
    do {
        if (pAdapterInfo->Type == MIB_IF_TYPE_ETHERNET) {
            std::cout << "Physical MAC Address: ";
            for (UINT i = 0; i < pAdapterInfo->AddressLength; i++) {
                if (i == (pAdapterInfo->AddressLength - 1))
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)pAdapterInfo->Address[i];
                else
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)pAdapterInfo->Address[i] << "-";
            }
            std::cout << "\n";
            break;
        }
        pAdapterInfo = pAdapterInfo->Next;
    } while (pAdapterInfo);
}

void GetVolumeSerialNumbers() {
    char volumeName[MAX_PATH + 1] = { 0 };
    char fileSystemName[MAX_PATH + 1] = { 0 };
    DWORD serialNumber = 0;

    for (char driveLetter = 'A'; driveLetter <= 'Z'; driveLetter++) {
        std::string drivePath = std::string(1, driveLetter) + ":\\";
        if (GetVolumeInformation(drivePath.c_str(), volumeName, sizeof(volumeName), &serialNumber, NULL, NULL, fileSystemName, sizeof(fileSystemName))) {
            std::cout << "Volume Serial Number of drive " << driveLetter << ": " << std::hex << std::setw(8) << std::setfill('0') << serialNumber << "\n";
        }
    }
}


void GetMachineGuid() {
    HKEY hKey;
    DWORD dwType = REG_SZ;
    char value[255];
    DWORD value_length = 255;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Cryptography", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        std::cerr << "Cannot open registry key\n";
        return;
    }

    if (RegQueryValueEx(hKey, "MachineGuid", NULL, &dwType, (LPBYTE)&value, &value_length) != ERROR_SUCCESS) {
        std::cerr << "Cannot read registry value\n";
    } else {
        std::cout << "MachineGuid: " << value << "\n";
    }

    RegCloseKey(hKey);
}

void GetWindowsProductId() {
    HKEY hKey;
    char value[255];
    DWORD value_length = 255;
    DWORD dwType = REG_SZ;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        std::cerr << "Cannot open registry key\n";
        return;
    }

    if (RegQueryValueEx(hKey, "ProductId", NULL, &dwType, (LPBYTE)&value, &value_length) != ERROR_SUCCESS) {
        std::cerr << "Cannot read registry value\n";
    } else {
        std::cout << "Windows ProductId: " << value << "\n";
    }

    RegCloseKey(hKey);
}

void GetRouterMacAddress() {
    PMIB_IPFORWARDTABLE pIpForwardTable = new MIB_IPFORWARDTABLE;
    DWORD dwSize = 0;
    if (GetIpForwardTable(pIpForwardTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
        delete pIpForwardTable;
        pIpForwardTable = (PMIB_IPFORWARDTABLE)new BYTE[dwSize];
    }
    if (GetIpForwardTable(pIpForwardTable, &dwSize, 0) == NO_ERROR) {
        for (DWORD i = 0; i < pIpForwardTable->dwNumEntries; i++) {
            if (pIpForwardTable->table[i].dwForwardDest == 0) { 
                IPAddr DestIp = pIpForwardTable->table[i].dwForwardNextHop; 
                ULONG MacAddr[2];
                ULONG PhysAddrLen = 6; 
                SendARP(DestIp, 0, MacAddr, &PhysAddrLen);
                BYTE* bMacAddr = (BYTE*)&MacAddr;
                std::cout << "Router's MAC Address: ";
                for (int j = 0; j < (int)PhysAddrLen; j++) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)bMacAddr[j];
                    if (j != (int)PhysAddrLen - 1) std::cout << "-";
                }
                std::cout << "\n";
                break;
            }
        }
    }
    delete pIpForwardTable;
}

int main() {
    GetRouterMacAddress();
    GetWindowsProductId();
    GetUsername();
    GetMotherboardSerialNumber();
    GetPhysicalMacAddress();
    GetVolumeSerialNumbers();
    GetMachineGuid();
    std::cin.get();
    return 0;
}