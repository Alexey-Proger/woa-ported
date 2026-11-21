/**
 * FileName: MHostHelper.cpp
 *
 * Copyright (C) 2024 Maplespe
 *
 * This file is part of MToolBox and DWMBlurGlass.
 * DWMBlurGlass is free software: you can redistribute it and/or modify it under the terms of the
 * GNU Lesser General Public License as published by the Free Software Foundation, either version 3
 * of the License, or any later version.
 *
 * DWMBlurGlass is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with Foobar.
 * If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.
*/
#include "MHostHelper.h"
#include "Helper/SymbolResolver.h"
#include "Helper/Helper.h"
#include "UIManager.h"
#include "Common.h"
#include "../DWMBlurGlassExt/Common/DefFunctionList.h"
#include <TlHelp32.h>
#include "Helper/wil.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <unordered_map>
#include <vector>

#if defined(_M_ARM64)
#include <winhttp.h>
#include <cstring>
#pragma comment(lib, "winhttp.lib")
#endif

#pragma data_seg(".DWMBlurGlassShared")

DWORD64 g_hookFunOffsetList[MDWMBlurGlassExt::g_hookFunList.size()] = { 0 };

size_t g_dwmcoreFunCount = 0;
size_t g_udwmFunCount = 0;

HWND g_hostMsgWnd = nullptr;

#pragma data_seg()
#pragma comment(linker,"/SECTION:.DWMBlurGlassShared,RWS")

namespace MDWMBlurGlass
{
    SymbolResolver g_symResolver;

	std::vector<DWORD> g_proclist;
	UINT_PTR g_timerID = 0;

	extern void OnProcessStart(DWORD id);

	void RefreshProcessList()
	{
		PROCESSENTRY32W pe;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pe.dwSize = sizeof(PROCESSENTRY32W);
		if (!Process32FirstW(hSnapshot, &pe))
			return;

		std::vector<DWORD> list;

		while (Process32NextW(hSnapshot, &pe) != FALSE)
		{
			std::wstring exe = pe.szExeFile;
			std::ranges::transform(exe, exe.begin(), ::tolower);

			if(exe == L"dwm.exe")
				list.push_back(pe.th32ProcessID);
		}
		CloseHandle(hSnapshot);

		for (const auto& id : list)
		{
			if (auto iter = std::ranges::find(g_proclist, id); iter != g_proclist.end())
				continue;

			OnProcessStart(id);
		}
		g_proclist = list;
	}

	bool IsEnableTransparency()
	{
		HKEY hKey = nullptr;
		DWORD dwValue = 1;
		if (RegOpenKeyExW(HKEY_CURRENT_USER, LR"(SOFTWARE\Microsoft\Windows\CurrentVersion\themes\personalize)", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
		{
			DWORD dwType = REG_DWORD;
			DWORD dwDataSize = sizeof(DWORD);

			RegQueryValueExW(hKey, L"EnableTransparency", nullptr, &dwType, (LPBYTE)&dwValue, &dwDataSize);

			RegCloseKey(hKey);
		}
		return dwValue;
	}

	HWND FindMessageWnd(DWORD pid)
	{
		if (!pid)
			return nullptr;

		HWND hwnd = nullptr;
		do
		{
			hwnd = FindWindowExW(HWND_MESSAGE, hwnd, DWMBlurGlassNotifyClassName, nullptr);
			if (hwnd != nullptr)
			{
				DWORD ProcessId = NULL;
				GetWindowThreadProcessId(hwnd, &ProcessId);
				if (ProcessId == pid)
					return hwnd;
			}
		} while (hwnd != nullptr);
		return nullptr;
	}

	void ParsingSymbol(PSYMBOL_INFO symInfo, std::string& funName, std::string& fullName, DWORD64& offset)
	{
		std::string_view functionName{ symInfo->Name, symInfo->NameLen };

		fullName = functionName;

		CHAR fullyUnDecoratedFunctionName[MAX_PATH + 1]{};
		UnDecorateSymbolName(
			functionName.data(), fullyUnDecoratedFunctionName, MAX_PATH,
			UNDNAME_NAME_ONLY
		);

		funName = fullyUnDecoratedFunctionName;
		offset = symInfo->Address - symInfo->ModBase;
	}

#if defined(_M_ARM64)
	namespace
	{
		// dwmcore and uDwm are compiled per architecture, and in the arm64 build a few of the
		// private helpers the extension calls were renamed or ended up in the base class instead
		// of the derived one. Fill those hook slots from the arm64 equivalent: same signature, so
		// the extension keeps working. The x64 build resolves the original names and never looks
		// at this table.
		std::string_view GetSymbolAlias(std::string_view symbolName)
		{
			static constexpr std::pair<std::string_view, std::string_view> g_aliases[]{
				{ "CContainerVisual::SetDirtyChildren", "CVisual::SetDirtyChildren" },
				{ "CVisual::SetDirtyFlags", "CTopLevelWindow::SetDirtyFlags" },
				{ "CTopLevelWindow::GetFrameMargins", "CTopLevelWindow::GetBorderMargins" },
				{ "CDWriteText::SetColor", "CText::SetColor" },
				{ "CDWriteText::SetText", "CText::SetText" },
			};

			for (auto& [symbol, hookName] : g_aliases)
			{
				if (symbol == symbolName)
					return hookName;
			}
			return {};
		}
	}
#endif

	bool SymCallback_Dwmcore(PSYMBOL_INFO symInfo, ULONG symbolSize)
	{
		DWORD64 offset = 0;
		std::string funName, fullName;
		ParsingSymbol(symInfo, funName, fullName, offset);

#if defined(_M_ARM64)
		if (auto alias = GetSymbolAlias(funName); !alias.empty())
			funName = std::string(alias);
#endif

		size_t funCount = 0;
		for (size_t i = 0; i < MDWMBlurGlassExt::g_hookFunList.size(); ++i)
		{
			auto& [type, _funName] = MDWMBlurGlassExt::g_hookFunList[i];
			if (type == dwmcore && (funName == _funName || fullName == _funName))
			{
				g_hookFunOffsetList[i] = offset;
				funCount++;
			}
		}

		return 1;
	}

	bool SymCallback_uDwm(PSYMBOL_INFO symInfo, ULONG symbolSize)
	{
		DWORD64 offset = 0;
		std::string funName, fullName;
		ParsingSymbol(symInfo, funName, fullName, offset);

#if defined(_M_ARM64)
		if (auto alias = GetSymbolAlias(funName); !alias.empty())
			funName = std::string(alias);
#endif

		size_t funCount = 0;
		for (size_t i = 0; i < MDWMBlurGlassExt::g_hookFunList.size(); ++i)
		{
			auto& [type, _funName] = MDWMBlurGlassExt::g_hookFunList[i];
			if (type == udwm && (funName == _funName || fullName == _funName))
			{
				g_hookFunOffsetList[i] = offset;
				funCount++;
			}
		}

		return g_udwmFunCount != funCount;
	}

    bool MHostGetSymbolState()
    {
		const auto symPath = SymbolResolver::LocalSymbolPath();
		auto callback = [](PSYMBOL_INFO, ULONG) { return false; };
        HRESULT hr = g_symResolver.Walk(L"dwmcore.dll", "*!*", symPath, callback);
		if (FAILED(hr))
			return false;
		hr = g_symResolver.Walk(L"uDwm.dll", "*!*", symPath, callback);
        return SUCCEEDED(hr);
    }

#if defined(_M_ARM64)
	namespace
	{
		std::wstring g_symbolError;

		void SetSymbolError(std::wstring_view what, const wchar_t* detail)
		{
			g_symbolError = std::wstring(what) + L": " + detail + L", gle=" + std::to_wstring(GetLastError());
		}

		struct PdbLocator
		{
			std::wstring fileName;	// name on the symbol server, e.g. dwmcore.pdb
			std::wstring buildId;	// CodeView GUID followed by the age
		};

		// The symbol server stores every PDB under <name>/<GUID+age>/<name>, and both parts are
		// in the DLL's CODEVIEW debug record, so the whole lookup works without dbghelp/symsrv.
		bool ReadPdbLocator(const std::wstring& dllPath, PdbLocator& out)
		{
			HANDLE hFile = CreateFileW(dllPath.c_str(), GENERIC_READ,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
				OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
			if (hFile == INVALID_HANDLE_VALUE)
			{
				SetSymbolError(dllPath, L"CreateFile");
				return false;
			}

			HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
			CloseHandle(hFile);
			if (!hMap)
			{
				SetSymbolError(dllPath, L"CreateFileMapping");
				return false;
			}

			const auto* base = static_cast<const BYTE*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
			auto cleanUp = wil::scope_exit([&]
			{
				if (base != nullptr)
					UnmapViewOfFile(base);
				CloseHandle(hMap);
			});
			if (!base)
			{
				SetSymbolError(dllPath, L"MapViewOfFile");
				return false;
			}

			const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
			if (dos->e_magic != IMAGE_DOS_SIGNATURE)
			{
				g_symbolError = dllPath + L": bad DOS header";
				return false;
			}
			const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
			if (nt->Signature != IMAGE_NT_SIGNATURE)
			{
				g_symbolError = dllPath + L": bad NT header";
				return false;
			}

			const auto& debugDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
			const auto* section = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
				reinterpret_cast<const BYTE*>(&nt->OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader);

			auto rvaToPointer = [&](DWORD rva) -> const void*
			{
				for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
				{
					const auto rawSize = section[i].SizeOfRawData > section[i].Misc.VirtualSize
						? section[i].SizeOfRawData : section[i].Misc.VirtualSize;
					if (rva >= section[i].VirtualAddress && rva < section[i].VirtualAddress + rawSize)
						return base + (rva - section[i].VirtualAddress) + section[i].PointerToRawData;
				}
				return nullptr;
			};

			const auto* entries = static_cast<const IMAGE_DEBUG_DIRECTORY*>(debugDir.VirtualAddress != 0
				? rvaToPointer(debugDir.VirtualAddress) : nullptr);
			if (!entries)
			{
				g_symbolError = dllPath + L": no debug directory";
				return false;
			}

			struct CvInfoPdb70
			{
				ULONG Signature;
				GUID Guid;
				ULONG Age;
			};

			for (DWORD i = 0; i < debugDir.Size / sizeof(IMAGE_DEBUG_DIRECTORY); ++i)
			{
				if (entries[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW)
					continue;

				const auto* cv = entries[i].PointerToRawData != 0
					? base + entries[i].PointerToRawData
					: static_cast<const BYTE*>(rvaToPointer(entries[i].AddressOfRawData));
				if (!cv)
				{
					g_symbolError = dllPath + L": unreadable CodeView record";
					return false;
				}
				if (memcmp(cv, "RSDS", 4) != 0)
				{
					g_symbolError = dllPath + L": unsupported CodeView format";
					return false;
				}

				const auto* info = reinterpret_cast<const CvInfoPdb70*>(cv);
				const char* rawName = reinterpret_cast<const char*>(cv + sizeof(CvInfoPdb70));
				const auto nameCapacity = entries[i].SizeOfData > sizeof(CvInfoPdb70)
					? entries[i].SizeOfData - sizeof(CvInfoPdb70) : 0;
				if (nameCapacity == 0)
				{
					g_symbolError = dllPath + L": empty CodeView name";
					return false;
				}
				std::string name(rawName, strnlen_s(rawName, nameCapacity));
				if (auto pos = name.find_last_of("\\/"); pos != std::string::npos)
					name.erase(0, pos + 1);

				wchar_t id[64]{};
				swprintf_s(id, L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%lX",
					info->Guid.Data1, info->Guid.Data2, info->Guid.Data3,
					info->Guid.Data4[0], info->Guid.Data4[1], info->Guid.Data4[2], info->Guid.Data4[3],
					info->Guid.Data4[4], info->Guid.Data4[5], info->Guid.Data4[6], info->Guid.Data4[7],
					static_cast<unsigned long>(info->Age));

				out.fileName.assign(name.begin(), name.end());
				out.buildId = id;
				return true;
			}

			g_symbolError = dllPath + L": no CodeView record";
			return false;
		}

		bool DownloadPdb(const PdbLocator& locator, const std::wstring& target)
		{
			const std::wstring urlPath = L"/download/symbols/" + locator.fileName
				+ L"/" + locator.buildId + L"/" + locator.fileName;

			struct Session
			{
				HINTERNET handle = nullptr;
				~Session() { if (handle != nullptr) WinHttpCloseHandle(handle); }
				explicit operator bool() const { return handle != nullptr; }
			};

			Session session{ WinHttpOpen(L"DWMBlurGlass", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
				WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0) };
			if (!session)
			{
				SetSymbolError(L"msdl.microsoft.com", L"WinHttpOpen");
				return false;
			}
			DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
			WinHttpSetOption(session.handle, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));
			WinHttpSetTimeouts(session.handle, 10000, 10000, 30000, 120000);

			Session connect{ WinHttpConnect(session.handle, L"msdl.microsoft.com",
				INTERNET_DEFAULT_HTTPS_PORT, 0) };
			if (!connect)
			{
				SetSymbolError(L"msdl.microsoft.com", L"WinHttpConnect");
				return false;
			}

			Session request{ WinHttpOpenRequest(connect.handle, L"GET", urlPath.c_str(), nullptr,
				WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) };
			if (!request)
			{
				SetSymbolError(locator.fileName, L"WinHttpOpenRequest");
				return false;
			}

			if (!WinHttpSendRequest(request.handle, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
					WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
				|| !WinHttpReceiveResponse(request.handle, nullptr))
			{
				SetSymbolError(locator.fileName, L"WinHttpSendRequest");
				return false;
			}

			DWORD status = 0, statusSize = sizeof(status);
			if (!WinHttpQueryHeaders(request.handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
					WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX))
			{
				SetSymbolError(locator.fileName, L"WinHttpQueryHeaders");
				return false;
			}
			if (status != 200)
			{
				g_symbolError = locator.fileName + L": http " + std::to_wstring(status);
				return false;
			}

			// write beside a name dbghelp never looks at, so a broken download cannot hide a working PDB
			const std::wstring temp = target + L".download";
			HANDLE out = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr,
				CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
			if (out == INVALID_HANDLE_VALUE)
			{
				SetSymbolError(locator.fileName, L"CreateFile");
				return false;
			}

			bool ok = false;
			auto cleanUp = wil::scope_exit([&]
			{
				if (out != INVALID_HANDLE_VALUE)
					CloseHandle(out);
				if (!ok)
					DeleteFileW(temp.c_str());
			});

			for (;;)
			{
				DWORD available = 0;
				if (!WinHttpQueryDataAvailable(request.handle, &available))
				{
					SetSymbolError(locator.fileName, L"WinHttpQueryDataAvailable");
					return false;
				}
				if (available == 0)
					break;

				std::vector<BYTE> buffer(available);
				DWORD read = 0;
				if (!WinHttpReadData(request.handle, buffer.data(), available, &read) || read == 0)
				{
					SetSymbolError(locator.fileName, L"WinHttpReadData");
					return false;
				}
				if (!WriteFile(out, buffer.data(), read, nullptr, nullptr))
				{
					SetSymbolError(locator.fileName, L"WriteFile");
					return false;
				}
			}

			CloseHandle(out);
			out = INVALID_HANDLE_VALUE;

			if (!MoveFileExW(temp.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING))
			{
				SetSymbolError(locator.fileName, L"MoveFileEx");
				return false;
			}
			ok = true;
			return true;
		}

		bool DownloadSymbolFor(const wchar_t* dllName)
		{
			// the same resolution SymbolResolver::Walk uses, so we ask the server for the PDB of
			// the very binary the hooks will later be computed against
			wil::unique_hmodule module{ LoadLibraryExW(dllName, nullptr,
				DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_SEARCH_SYSTEM32) };
			if (!module)
			{
				SetSymbolError(dllName, L"LoadLibraryEx");
				return false;
			}

			wchar_t path[MAX_PATH + 1]{};
			if (GetModuleFileNameW(module.get(), path, MAX_PATH) == 0)
			{
				SetSymbolError(dllName, L"GetModuleFileName");
				return false;
			}

			PdbLocator locator;
			if (!ReadPdbLocator(path, locator))
				return false;

			const std::wstring dir = Utils::GetCurrentDir() + L"\\data\\symbols";
			if (!CreateDirectoryW(dir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
			{
				SetSymbolError(dllName, L"CreateDirectory");
				return false;
			}

			return DownloadPdb(locator, dir + L"\\" + locator.fileName);
		}
	}
#endif

	bool MHostDownloadSymbol()
	{
#if defined(_M_ARM64)
		// dbghelp can only talk to a symbol server through symsrv.dll, and Windows on ARM does
		// not ship it, so grab the two PDB files ourselves and let the local search pick them up.
		g_symbolError.clear();
		for (const wchar_t* dllName : { L"dwmcore.dll", L"uDwm.dll" })
			if (!DownloadSymbolFor(dllName))
				return false;
		return MHostGetSymbolState();
#else
		auto callback = [](PSYMBOL_INFO, ULONG) { return false; };
		HRESULT hr = g_symResolver.Walk(L"dwmcore.dll", "*!*", callback);
		if (FAILED(hr))
			return false;
		hr = g_symResolver.Walk(L"uDwm.dll", "*!*", callback);
		return SUCCEEDED(hr);
#endif
	}

	std::wstring MHostGetSymbolError()
	{
#if defined(_M_ARM64)
		return g_symbolError;
#else
		return {};
#endif
	}

	void OnProcessStart(DWORD id)
	{
		//单独记录每个用户dwm进程的启动间隔状态
		using namespace std::chrono;
		struct sessionData
		{
			steady_clock::duration times = steady_clock::now().time_since_epoch();
			bool init = true;
		};
		static std::unordered_map<DWORD, sessionData> sessionList;

		DWORD sessionId = 0;
		ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

		if(auto iter = sessionList.find(sessionId); iter != sessionList.end())
		{
			bool retry = false;
			//dwm进程不应启动这么频繁 这有可能是频繁崩溃 停止自动加载
			if (!iter->second.init && steady_clock::now().time_since_epoch() - iter->second.times < 10s)
			{
				KillTimer(g_hostMsgWnd, g_timerID);
				auto ret = MessageBoxW(nullptr, L"Checked that the process is suspected to have crashed abnormally and has stopped autoloading.",
					L"DWMBlurGlass Error", MB_ICONERROR | MB_RETRYCANCEL);

				iter->second.times = steady_clock::now().time_since_epoch();

				if (ret != IDRETRY)
					return;
				else
					retry = true;
			}
			iter->second.times = steady_clock::now().time_since_epoch();
			if(!retry)
				iter->second.init = false;
		}
		else
			sessionList.insert(std::make_pair(sessionId, sessionData()));

		std::wstring err;
		if(!LoadDWMExtensionBase(err, id))
		{
			MessageBoxW(0, err.c_str(), L"DWMBlurGlass Error", MB_ICONERROR);
		}
	}

	LRESULT CALLBACK MsgWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
	{
		if(message == WM_APP + 20 && MClientNotifyType::Shutdown == (MClientNotifyType)wParam)
		{
			for(auto& id : g_proclist)
			{
				HWND msgwnd = FindMessageWnd(GetProcessId(L"dwm.exe"));
				if (IsWindow(msgwnd))
					SendMessageW(msgwnd, WM_APP + 20, (WPARAM)MHostNotifyType::Shutdown, 0);

				std::wstring err;
				UnInject(id, Utils::GetCurrentDir() + L"\\DWMBlurGlassExt.dll", err);
			}
		}
		else if(message == WM_APP + 20 && MClientNotifyType::QueryTransparency == (MClientNotifyType)wParam)
		{
			MHostNotify(MHostNotifyType::EnableTransparency, IsEnableTransparency());
		}
		return DefWindowProcW(hWnd, message, wParam, lParam);
	}

	void MHostStartProcess()
	{
		WNDCLASSEXW wx = {};
		wx.cbSize = sizeof(WNDCLASSEX);
		wx.lpfnWndProc = MsgWndProc;
		wx.hInstance = GetModuleHandleW(nullptr);
		wx.lpszClassName = DWMBlurGlassHostNotifyClassName;
		if (!RegisterClassExW(&wx))
			return;

		g_hostMsgWnd = CreateWindowExW(0, wx.lpszClassName, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, nullptr, nullptr);

		g_timerID = SetTimer(g_hostMsgWnd, 1000, 500, [](HWND, UINT, UINT_PTR, DWORD)
		{
			RefreshProcessList();
		});

		MSG msg;
		while (GetMessageW(&msg, nullptr, 0, 0))
		{
			TranslateMessage(&msg);
			DispatchMessageW(&msg);
		}

		KillTimer(g_hostMsgWnd, g_timerID);
		UnregisterClassW(wx.lpszClassName, wx.hInstance);
	}

	void RunMHostProcess()
	{
		STARTUPINFO startupInfo = { 0 };
		PROCESS_INFORMATION processInformation = { nullptr };

		wchar_t param[] = { L" runhost" };
		if (CreateProcessW((Utils::GetCurrentDir() + L"\\DWMBlurGlass.exe").c_str(), param, nullptr,
			nullptr, FALSE, NULL, nullptr, nullptr, &startupInfo, &processInformation))
		{
			CloseHandle(processInformation.hProcess);
			CloseHandle(processInformation.hThread);
		}
	}

	void StopMHostProcess()
	{
		SendMessageW(g_hostMsgWnd, WM_APP + 20, (WPARAM)1, 0);

		if (auto pid = GetProcessId(L"dwmblurglass.exe"))
		{
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
			if (!hProcess)
				return;
			TerminateProcess(hProcess, 0);
			CloseHandle(hProcess);
		}
	}

	bool LoadSymbolOffset()
	{
		g_dwmcoreFunCount = g_udwmFunCount = 0;
		for (auto& list : MDWMBlurGlassExt::g_hookFunList)
		{
			if (list.first == dwmcore)
				g_dwmcoreFunCount++;
			else if (list.first == udwm)
				g_udwmFunCount++;
		}

		std::fill(std::begin(g_hookFunOffsetList), std::end(g_hookFunOffsetList), 0);

		const auto symPath = SymbolResolver::LocalSymbolPath();
		HRESULT hr = g_symResolver.Walk(L"dwmcore.dll", "*!*", symPath, SymCallback_Dwmcore);
		if (FAILED(hr))
			return false;
		hr = g_symResolver.Walk(L"uDwm.dll", "*!*", symPath, SymCallback_uDwm);
		if (FAILED(hr))
			return false;

		// The extension skips every hook it cannot resolve, so a name that is missing from the
		// symbols is a feature that silently stops working. Report it instead of hiding it.
		if (stdout)
		{
			size_t resolved = 0;
			for (size_t i = 0; i < MDWMBlurGlassExt::g_hookFunList.size(); ++i)
			{
				if (g_hookFunOffsetList[i] != 0)
					resolved++;
				else
					std::printf("  symbol not found: %s\n", MDWMBlurGlassExt::g_hookFunList[i].second);
			}
			std::printf("Symbols resolved: %llu/%llu\n", (unsigned long long)resolved,
				(unsigned long long)MDWMBlurGlassExt::g_hookFunList.size());
			std::fflush(stdout);
		}

		return true;
	}

	bool LoadDWMExtensionBase(std::wstring& err, DWORD pid)
	{
		if(!LoadSymbolOffset())
		{
			err = GetBaseLanguageString(L"symloadfail");
			return false;
		}
		const bool ret = Inject(GetProcessId(L"dwm.exe"), Utils::GetCurrentDir() + L"\\DWMBlurGlassExt.dll", err);
		if(ret)
		{
			auto enumproc = [](HWND hWnd, LPARAM _pid) -> BOOL
			{
				DWORD dwPid = 0;
				GetWindowThreadProcessId(hWnd, &dwPid);
				if(_pid == dwPid)
				{
					PostMessageW(hWnd, WM_THEMECHANGED, 0, 0);
					return FALSE;
				}
				return TRUE;
			};
			EnumWindows(enumproc, pid);

			//PostMessageW(FindWindowW(L"Dwm", nullptr), WM_THEMECHANGED, 0, 0);
		}
		return ret;
	}

	void MHostNotify(MHostNotifyType type, LPARAM lParam)
	{
		HWND msgwnd = FindMessageWnd(GetProcessId(L"dwm.exe"));
		if (!IsWindow(msgwnd)) return;

		SendMessageW(msgwnd, WM_APP + 20, (WPARAM)type, lParam);
	}
}

extern "C" __declspec(dllexport) DWORD64 __stdcall GetModuleOffset(size_t index)
{
	using namespace MDWMBlurGlass;
	if (index < sizeof g_hookFunOffsetList)
		return g_hookFunOffsetList[index];
	return 0;
}