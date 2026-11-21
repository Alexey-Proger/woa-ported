/**
 * FileName: HookHelper.cpp
 *
 * Copyright (C) 2024 Maplespe、ALTaleX531
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
#include "HookHelper.h"
#include "DefFunctionList.h"
#include <ImageHlp.h>
#include <winrt.h>
#include <Psapi.h>
#include <atomic>
#pragma comment(lib, "dbghelp.lib")

namespace MDWMBlurGlassExt
{
	std::unordered_map<std::string, void*> g_procAddress;
	bool g_offsetListInited = false;

#if defined(_M_ARM64)
	namespace Diag
	{
		namespace
		{
			constexpr size_t maxMessages = 2000;

			std::atomic_size_t g_messageCount{ 0 };
			std::atomic_bool g_inLog{ false };
			HANDLE g_file = INVALID_HANDLE_VALUE;

			void WriteRaw(std::string_view text)
			{
				if (g_file == INVALID_HANDLE_VALUE)
				{
					const auto dir = Utils::GetCurrentDir() + L"\\data";
					CreateDirectoryW(dir.c_str(), nullptr);

					g_file = CreateFileW((dir + L"\\debug.log").c_str(), FILE_APPEND_DATA,
						FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
						FILE_ATTRIBUTE_NORMAL, nullptr);
					if (g_file == INVALID_HANDLE_VALUE)
						return;
				}

				DWORD written{};
				WriteFile(g_file, text.data(), (DWORD)text.size(), &written, nullptr);
			}
		}

		void Log(std::wstring_view msg)
		{
			// a hook that logs while another thread is logging must not recurse or block DWM
			if (g_messageCount.fetch_add(1) > maxMessages)
				return;
			if (g_inLog.exchange(true))
				return;
			auto clean = RAIIHelper::scope_exit([&] { g_inLog = false; });

			const auto size = WideCharToMultiByte(CP_UTF8, 0, msg.data(), (int)msg.size(),
				nullptr, 0, nullptr, nullptr);
			std::string text(size > 0 ? (size_t)size : 0, '\0');
			if (size > 0)
				WideCharToMultiByte(CP_UTF8, 0, msg.data(), (int)msg.size(),
					text.data(), size, nullptr, nullptr);
			text += "\r\n";

			WriteRaw(text);
		}

		bool Readable(const void* address, size_t size)
		{
			if (!address)
				return false;

			MEMORY_BASIC_INFORMATION mbi{};
			if (!VirtualQuery(address, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT)
				return false;

			switch (mbi.Protect & 0xff)
			{
			case PAGE_READONLY:
			case PAGE_READWRITE:
			case PAGE_WRITECOPY:
			case PAGE_EXECUTE_READ:
			case PAGE_EXECUTE_READWRITE:
			case PAGE_EXECUTE_WRITECOPY:
				break;
			default:
				return false;
			}

			return static_cast<const char*>(address) + size
				<= static_cast<char*>(mbi.BaseAddress) + mbi.RegionSize;
		}

		std::wstring FormatAddress(const void* address)
		{
			static const LPCSTR modules[]{ "dwmcore.dll", "uDwm.dll" };

			const auto value = reinterpret_cast<ULONG64>(address);
			if (!value)
				return L"null";

			for (const auto name : modules)
			{
				const auto base = reinterpret_cast<ULONG64>(GetModuleHandleA(name));
				if (!base || value < base)
					continue;

				MODULEINFO info{};
				if (!K32GetModuleInformation(GetCurrentProcess(), reinterpret_cast<HMODULE>(base),
					&info, sizeof(info)) || value >= base + info.SizeOfImage)
				{
					continue;
				}

				return std::format(L"{}+{:#x}", Text(name), value - base);
			}

			return std::format(L"{:#x}", value);
		}

		BOOL ExceptionFilter(PEXCEPTION_POINTERS pointers, const wchar_t* context)
		{
			const auto record = pointers->ExceptionRecord;
			Log(std::format(L"SEH {} in {}: address={} isRead={}",
				record->ExceptionCode, context, FormatAddress(record->ExceptionAddress),
				record->NumberParameters > 1 ? record->ExceptionInformation[0] : 0));
			return EXCEPTION_EXECUTE_HANDLER;
		}
	}
#endif

	bool MHostLoadProcOffsetList()
	{
		static bool loaded = false;
		if (loaded)
			return true;

		HMODULE hModule = LoadLibraryW((Utils::GetCurrentDir() + L"\\DWMBlurGlass.exe").c_str());
		if (!hModule) 
			return false;

		auto clean = RAIIHelper::scope_exit([&] { FreeLibrary(hModule); });

		const auto GetModuleOffset = (DWORD64(__stdcall*)(size_t))GetProcAddress(hModule, "GetModuleOffset");
		if(!GetModuleOffset)
			return false;

		void* moduleBase_dwmcore = GetModuleHandleW(L"dwmcore.dll");
		void* moduleBase_uDwm = GetModuleHandleW(L"uDwm.dll");
		for (size_t i = 0; i < g_hookFunList.size(); ++i)
		{
			auto& [type, funName] = g_hookFunList[i];
			void* base;
			if (type == dwmcore)
				base = moduleBase_dwmcore;
			else if (type == udwm)
				base = moduleBase_uDwm;
			else
				continue;

			// A name the host could not resolve keeps offset 0: that is the module header, not a
			// function. Leaving it out makes the lookup return nullptr and the hook report
			// MH_ERROR_FUNCTION_NOT_FOUND instead of installing a jump into the PE headers.
			const auto offset = GetModuleOffset(i);
			if (offset == 0)
				continue;

			g_procAddress.insert({ funName, (void*)((DWORD64)base + offset) });
		}

		Diag::LogFormat(L"offset list: {} entries, dwmcore={} udwm={}", g_procAddress.size(),
			Diag::FormatAddress(moduleBase_dwmcore), Diag::FormatAddress(moduleBase_uDwm));

		loaded = true;
		return true;
	}

	PVOID MHostGetProcAddress(LPCSTR pszProcName)
	{
		const auto iter = g_procAddress.find(pszProcName);
		if (iter == g_procAddress.end())
			return nullptr;
		return iter->second;
	}

	bool WriteMemory(PVOID memoryAddress, std::function<void()> callback) try
	{
		if (!memoryAddress || !callback)
		{
			return false;
		}

		MEMORY_BASIC_INFORMATION mbi{};
		winrt::check_bool(
			VirtualQuery(
				memoryAddress,
				&mbi,
				sizeof(MEMORY_BASIC_INFORMATION)
			)
		);
		winrt::check_bool(
			VirtualProtect(
				mbi.BaseAddress,
				mbi.RegionSize,
				PAGE_READWRITE,
				&mbi.Protect
			)
		);
		callback();
		winrt::check_bool(
			VirtualProtect(
				mbi.BaseAddress,
				mbi.RegionSize,
				mbi.Protect,
				&mbi.Protect
			)
		);
		return true;
	}
	catch(...)
	{
		return false;
	}

	void WalkIAT(PVOID baseAddress, std::string_view dllName, std::function<bool(PVOID* functionAddress, LPCSTR functionNameOrOrdinal, BOOL importedByName)> callback) try
	{
		winrt::check_bool(!dllName.empty());
		winrt::check_bool(baseAddress);
		winrt::check_bool(callback);

		ULONG size{ 0ul };
		auto importDescriptor
		{
			static_cast<PIMAGE_IMPORT_DESCRIPTOR>(
				ImageDirectoryEntryToData(
					baseAddress,
					TRUE,
					IMAGE_DIRECTORY_ENTRY_IMPORT,
					&size
				)
			)
		};

		winrt::check_pointer(importDescriptor);

		LPCSTR moduleName{ nullptr };
		while (importDescriptor->Name != 0)
		{
			moduleName = reinterpret_cast<LPCSTR>(reinterpret_cast<UINT_PTR>(baseAddress) + importDescriptor->Name);

			if (!_stricmp(moduleName, dllName.data()))
			{
				break;
			}

			importDescriptor++;
		}

		winrt::check_pointer(moduleName);
		winrt::check_bool(importDescriptor->Name != 0);

		auto thunk{ reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<UINT_PTR>(baseAddress) + importDescriptor->FirstThunk) };
		auto nameThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<UINT_PTR>(baseAddress) + importDescriptor->OriginalFirstThunk);

		bool result{ true };
		while (thunk->u1.Function)
		{
			LPCSTR functionName{ nullptr };
			auto functionAddress = reinterpret_cast<PVOID*>(&thunk->u1.Function);

			BOOL importedByName{ !IMAGE_SNAP_BY_ORDINAL(nameThunk->u1.Ordinal) };
			if (importedByName)
			{
				functionName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<UINT_PTR>(baseAddress) + static_cast<RVA>(nameThunk->u1.AddressOfData))->Name;
			}
			else
			{
				functionName = MAKEINTRESOURCEA(IMAGE_ORDINAL(thunk->u1.Ordinal));
			}

			result = callback(functionAddress, functionName, importedByName);
			if (!result)
			{
				break;
			}

			thunk++;
			nameThunk++;
		}
	}
	catch (...)
	{
	}

	size_t WriteIAT(PVOID baseAddress, std::string_view dllName, std::unordered_map<LPCSTR, PVOID> hookMap)
	{
		size_t result{ hookMap.size() };

		WalkIAT(baseAddress, dllName, [&](PVOID* functionAddress, LPCSTR functionNameOrOrdinal, BOOL importedByName) -> bool
		{
			auto tempHookMap{ hookMap };
			for (auto [targetFunctionNameOrOrdinal, hookFunctionAddress] : tempHookMap)
			{
				if (
					(importedByName == TRUE && !strcmp(functionNameOrOrdinal, targetFunctionNameOrOrdinal)) ||
					(importedByName == FALSE && functionNameOrOrdinal == targetFunctionNameOrOrdinal)
					)
				{
					WriteMemory(functionAddress, [&]()
						{
							InterlockedExchangePointer(functionAddress, hookFunctionAddress);
						});
					hookMap.erase(targetFunctionNameOrOrdinal);

					break;
				}
			}

			if (hookMap.empty())
			{
				return false;
			}

			return true;
		});

		result -= hookMap.size();

		return result;
	}

	PVOID MemSafeSearch(LPCSTR moduleName, PVOID dst, size_t size)
	{
		HMODULE hModule = GetModuleHandleA(moduleName);
		MODULEINFO moduleInfo;
		if (hModule && K32GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(MODULEINFO)))
		{
			PVOID startAddress = hModule;
			PVOID endAddress = PVOID((ULONG64)moduleInfo.lpBaseOfDll + moduleInfo.SizeOfImage);

			while (memcmp(startAddress, dst, size) != 0)
			{
				startAddress = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(startAddress) + 1);
				if (startAddress >= endAddress)
					return nullptr;
			}
			return startAddress;
		}
		return nullptr;
	}

	MinHookImpl::MinHookImpl(LPCSTR pszProcName, void* detour) : m_detour(detour), m_targetName(pszProcName)
	{
		m_status = HookAutoInitializer::status;
	}

	MH_STATUS MinHookImpl::Attach()
	{
		if (HookAutoInitializer::status == MH_OK)
		{
			if(!g_offsetListInited)
			{
				MHostLoadProcOffsetList();
				g_offsetListInited = true;
			}
			if(!m_target)
			{
				const auto iter = g_procAddress.find(m_targetName);
				if (iter == g_procAddress.end())
				{
					m_status = MH_ERROR_FUNCTION_NOT_FOUND;
					Diag::LogFormat(L"hook '{}' NOT RESOLVED", Diag::Text(m_targetName));
					return m_status;
				}

				m_target = iter->second;
			}
			m_status = MH_CreateHook(
				m_target,
				m_detour,
				&m_org
			);

			const auto enable = MH_EnableHook(m_target);
			Diag::LogFormat(L"hook '{}' target={} org={} create={} enable={}", Diag::Text(m_targetName),
				Diag::FormatAddress(m_target), Diag::FormatAddress(m_org), (int)m_status, (int)enable);

			return enable;
		}
		return status;
	}


}