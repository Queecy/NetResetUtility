#include <iostream>
#include <windows.h>
#include <Lmcons.h>
#include <random>
#include <string>
#include <atlbase.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <fstream>
#include <sstream> 
#include <iomanip>  

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "comsuppw.lib")

void ClearControls()
{
    std::cout << "Cleared controls." << std::endl;
}

void ExecuteCommand(const std::string& command) 
{
    try 
    {
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        ZeroMemory(&pi, sizeof(pi));

        if (CreateProcessA("C:\\Windows\\System32\\cmd.exe", (LPSTR)std::string("/c " + command).c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        {
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        else 
        {
            std::cerr << "Failed to execute command: " << command << std::endl;
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception occurred while executing command: " << ex.what() << std::endl;
    }
}

void ExecuteNetshCommand(const std::string& arguments)
{
    ExecuteCommand("netsh " + arguments);
}

std::string GenerateRandomMacAddress() 
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::ostringstream mac;
    for (int i = 0; i < 6; i++) 
    {
        int val = dis(gen);
        if (i != 0) mac << "-";
        mac << std::setw(2) << std::setfill('0') << std::hex << val;  
    }
    return mac.str();
}

void macchange()
{
    try
    {
        HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) 
        {
            std::cerr << "Failed to initialize COM library." << std::endl;
            return;
        }

        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (FAILED(hres))
        {
            std::cerr << "Failed to initialize security." << std::endl;
            CoUninitialize();
            return;
        }

        IWbemLocator* pLoc = NULL;
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres)) 
        {
            std::cerr << "Failed to create IWbemLocator object." << std::endl;
            CoUninitialize();
            return;
        }

        IWbemServices* pSvc = NULL;
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (FAILED(hres)) 
        {
            std::cerr << "Failed to connect to WMI namespace." << std::endl;
            pLoc->Release();
            CoUninitialize();
            return;
        }

        hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
        if (FAILED(hres)) 
        {
            std::cerr << "Failed to set proxy blanket." << std::endl;
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return;
        }

        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter=True"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

        if (FAILED(hres)) 
        {
            std::cerr << "Query for network adapters failed." << std::endl;
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return;
        }

        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;
        while (pEnumerator) 
        {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) break;

            VARIANT vtProp;
            hr = pclsObj->Get(L"NetConnectionID", 0, &vtProp, 0, 0);
            std::wstring netConnectionID = vtProp.bstrVal ? vtProp.bstrVal : L"";

            hr = pclsObj->Get(L"Caption", 0, &vtProp, 0, 0);
            std::wstring caption = vtProp.bstrVal ? vtProp.bstrVal : L"";

            hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
            std::wstring name = vtProp.bstrVal ? vtProp.bstrVal : L"";

            hr = pclsObj->Get(L"DeviceID", 0, &vtProp, 0, 0);
            std::wstring deviceId = vtProp.bstrVal ? vtProp.bstrVal : L"";
            deviceId = std::wstring(4 - deviceId.length(), L'0') + deviceId;

            if (caption.find(L"Bluetooth") != std::wstring::npos || name.find(L"Bluetooth") != std::wstring::npos || netConnectionID.find(L"Bluetooth") != std::wstring::npos) 
            {
                continue;
            }

            std::string spoofedMacAddress = GenerateRandomMacAddress();

            std::wstring regPath = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\" + deviceId;
            HKEY hKey;
            if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
            {
                RegSetValueExA(hKey, "NetworkAddress", 0, REG_SZ, (const BYTE*)spoofedMacAddress.c_str(), spoofedMacAddress.size());
                RegCloseKey(hKey);
            }

            ExecuteNetshCommand("interface set interface \"" + std::string(netConnectionID.begin(), netConnectionID.end()) + "\" admin=disable");
            ExecuteNetshCommand("interface set interface \"" + std::string(netConnectionID.begin(), netConnectionID.end()) + "\" admin=enable");

            VariantClear(&vtProp);
            pclsObj->Release();
        }

        pSvc->Release();
        pLoc->Release();
        pEnumerator->Release();
        CoUninitialize();
    }
    catch (const std::exception& ex)
    {
        std::cerr << "An error occurred: " << ex.what() << std::endl;
    }
}

void NetworkResetUtility() 
{
    macchange();
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 9999);

    std::string randomString = std::to_string(dis(gen));

    ExecuteCommand("wmic computersystem where name=%computername% call rename=" + randomString);
    ExecuteCommand("netsh winsock reset");
    ExecuteCommand("netsh winsock reset catalog");
    ExecuteCommand("netsh int ip reset");
    ExecuteCommand("netsh advfirewall reset");
    ExecuteCommand("netsh int reset all");
    ExecuteCommand("netsh int ipv4 reset");
    ExecuteCommand("netsh int ipv6 reset");
    ExecuteCommand("ipconfig /release");
    ExecuteCommand("ipconfig /renew");
    ExecuteCommand("ipconfig /flushdns");
    ExecuteCommand("WMIC PATH WIN32_NETWORKADAPTER WHERE PHYSICALADAPTER=TRUE CALL DISABLE >nul 2>&1");
    ExecuteCommand("WMIC PATH WIN32_NETWORKADAPTER WHERE PHYSICALADAPTER=TRUE CALL ENABLE >nul 2>&1");
    ExecuteCommand("net stop winmgmt /y");
    ExecuteCommand("net start winmgmt /y");
    ExecuteCommand("sc stop winmgmt");
    ExecuteCommand("sc start winmgmt");

    ClearControls();
    std::cout << "Successfully reset: IPV4 | IPV6 | MAC" << std::endl;
    Sleep(2000);
    ClearControls();
}

int main() 
{
    NetworkResetUtility();
    return 0;
}