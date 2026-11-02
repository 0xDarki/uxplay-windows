#include "mdns_responder.hpp"

#include <windows.h>
#include <shellapi.h>

#include <iostream>
#include <stdexcept>

namespace mdns
{
namespace
{
// Bonjour only answers mDNS queries that Windows Firewall lets in. The
// default inbound policy blocks them, so the service alone is not enough.
const wchar_t kFirewallRuleName[] = L"Bonjour Service (mDNS UDP 5353 In)";

std::wstring quoted(const std::wstring& value)
{
    return L"\"" + value + L"\"";
}

std::wstring getProcessExeDir()
{
    wchar_t buf[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (len == 0 || len == MAX_PATH) {
        throw std::runtime_error("GetModuleFileNameW failed");
    }

    std::wstring fullPath(buf, len);
    size_t pos = fullPath.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        throw std::runtime_error("Unable to determine module directory");
    }
    return fullPath.substr(0, pos);
}

// Runs a cmd.exe command line elevated (UAC prompt unless already elevated)
// and returns 0 when it exits with 0, 1 when it could not start, 2 otherwise.
int runElevated(const std::wstring& dir, const std::wstring& commandLine)
{
    // /S keeps the outer quotes intact so the embedded quoted paths survive.
    std::wstring params = L"/S /C " + quoted(commandLine);

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = L"cmd.exe";
    sei.lpParameters = params.c_str();
    sei.lpDirectory = dir.c_str();
    sei.nShow = SW_HIDE;

    if (!ShellExecuteExW(&sei)) {
        std::wcerr << L"ShellExecuteExW(runas) failed. Error=" << GetLastError()
                   << L"\n";
        return 1;
    }
    if (!sei.hProcess) {
        return 0;
    }

    WaitForSingleObject(sei.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(sei.hProcess, &exitCode);
    CloseHandle(sei.hProcess);
    return exitCode == 0 ? 0 : 2;
}
} // namespace

int MdnsResponder::installFromDir(const std::wstring& dir)
{
    const std::wstring exe = quoted(dir + L"\\mDNSResponder.exe");
    return runElevated(dir,
        exe + L" -install"
        L" && netsh advfirewall firewall add rule name=" + quoted(kFirewallRuleName) +
        L" dir=in action=allow protocol=UDP localport=5353"
        L" remoteip=localsubnet profile=any program=" + exe);
}

int MdnsResponder::removeFromDir(const std::wstring& dir)
{
    const std::wstring exe = quoted(dir + L"\\mDNSResponder.exe");
    // The rule may already be gone; only the service removal decides the result.
    return runElevated(dir,
        L"netsh advfirewall firewall delete rule name=" + quoted(kFirewallRuleName) +
        L" >nul 2>&1 & " + exe + L" -remove");
}

int MdnsResponder::install()
{
    return installFromDir(getProcessExeDir());
}

int MdnsResponder::remove()
{
    return removeFromDir(getProcessExeDir());
}
} // namespace mdns
