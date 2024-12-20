// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "apphost.windows.h"
#include "error_codes.h"
#include "pal.h"
#include "trace.h"
#include "utils.h"

#include <commctrl.h>
#include <shellapi.h>

#define EMBED_HOST_MISSING_HI_PART_UTF8 "a9259edaaad4b93446260c2986103cda" // SHA-256 of "HOST_MISSING" in UTF-8
#define EMBED_HOST_MISSING_LO_PART_UTF8 "9314b67e35e77149d3f84415c7ce86e3"
#define EMBED_HOST_MISSING_FULL_UTF8    (EMBED_HOST_MISSING_HI_PART_UTF8 EMBED_HOST_MISSING_LO_PART_UTF8) // NUL terminated

#define EMBED_HOST_MISSING_URL_HI_PART_UTF8 "f9d4d2616fb661f40841679b3cd42136" // SHA-256 of "HOST_MISSING_URL" in UTF-8
#define EMBED_HOST_MISSING_URL_LO_PART_UTF8 "faa2585546e66955111e297c764ff0a3"
#define EMBED_HOST_MISSING_URL_FULL_UTF8    (EMBED_HOST_MISSING_URL_HI_PART_UTF8 EMBED_HOST_MISSING_URL_LO_PART_UTF8) // NUL terminated

#define EMBED_NEED_PREREQS_HI_PART_UTF8 "008ee4667a30ee16eea1d63122c94db9" // SHA-256 of "NEED_PREREQS" in UTF-8
#define EMBED_NEED_PREREQS_LO_PART_UTF8 "dea4f5e7a330e123587ce933ce233088"
#define EMBED_NEED_PREREQS_FULL_UTF8    (EMBED_NEED_PREREQS_HI_PART_UTF8 EMBED_NEED_PREREQS_LO_PART_UTF8) // NUL terminated

#define EMBED_NEED_PREREQS_URL_HI_PART_UTF8 "424b3211aeda8117b73dd23713905183" // SHA-256 of "NEED_PREREQS_URL" in UTF-8
#define EMBED_NEED_PREREQS_URL_LO_PART_UTF8 "86163528f78f04027968bac88e919aba"
#define EMBED_NEED_PREREQS_URL_FULL_UTF8    (EMBED_NEED_PREREQS_URL_HI_PART_UTF8 EMBED_NEED_PREREQS_URL_LO_PART_UTF8) // NUL terminated

namespace
{
    pal::string_t g_buffered_errors;
    typedef std::shared_ptr < std::decay_t<decltype(*std::declval<HMODULE>())>> SafeModulePointer;

    bool CheckOSIsNetCoreSupported()
    {
        DWORD dwLoadLibraryFlags = 0;

        SafeModulePointer hModule(LoadLibraryExW(L"kernel32.dll", nullptr, dwLoadLibraryFlags), FreeLibrary);

        if (hModule)
        {
            // SetDefaultDllDirectories and LOAD_LIBRARY_SEARCH_SYSTEM32 flag for LoadLibraryEx were introduced by KB2533623.
            // If this function is present in kernel32.dll, then KB2533623 or equivalent support is present
            auto hFarProc = GetProcAddress(hModule.get(), "SetDefaultDllDirectories");
            return hFarProc != nullptr;
        }

        return false;
    }

    bool is_host_missing_enabled_for_execution(pal::string_t* host_missing_message)
    {
        constexpr int EMBED_SZ = sizeof(EMBED_HOST_MISSING_FULL_UTF8) / sizeof(EMBED_HOST_MISSING_FULL_UTF8[0]);
        constexpr int EMBED_MAX = (EMBED_SZ > 1025 ? EMBED_SZ : 1025); // 1024 DLL name length, 1 NUL

        // Contains the EMBED_HOST_MISSING_FULL_UTF8 value at compile time or the managed DLL name replaced by "dotnet build".
        // Must not be 'const' because std::string(&embed[0]) below would bind to a const string ctor plus length
        // where length is determined at compile time (=64) instead of the actual length of the string at runtime.
        static char embed[EMBED_MAX] = EMBED_HOST_MISSING_FULL_UTF8;     // series of NULs followed by embed hash string

        static const char hi_part[] = EMBED_HOST_MISSING_HI_PART_UTF8;
        static const char lo_part[] = EMBED_HOST_MISSING_LO_PART_UTF8;

        if (!pal::clr_palstring(embed, host_missing_message))
        {
            trace::error(_X("The host_missing_message value could not be retrieved from the executable image."));
            return false;
        }

        // Since the single static string is replaced by editing the executable, a reference string is needed to do the compare.
        // So use two parts of the string that will be unaffected by the edit.
        size_t hi_len = (sizeof(hi_part) / sizeof(hi_part[0])) - 1;
        size_t lo_len = (sizeof(lo_part) / sizeof(lo_part[0])) - 1;

        std::string binding(&embed[0]);
        if ((binding.size() >= (hi_len + lo_len)) &&
            binding.compare(0, hi_len, &hi_part[0]) == 0 &&
            binding.compare(hi_len, lo_len, &lo_part[0]) == 0)
        {
            trace::info(_X("This executable does not binding to host_missing_message yet. The binding value is: '%s'"), host_missing_message->c_str());
            return false;
        }

        trace::info(_X("The host_missing_message binding to this executable is: '%s'"), host_missing_message->c_str());
        return true;
    }

    bool is_host_missing_url_enabled_for_execution(pal::string_t* host_missing_url)
    {
        constexpr int EMBED_SZ = sizeof(EMBED_HOST_MISSING_URL_FULL_UTF8) / sizeof(EMBED_HOST_MISSING_URL_FULL_UTF8[0]);
        constexpr int EMBED_MAX = (EMBED_SZ > 1025 ? EMBED_SZ : 1025); // 1024 DLL name length, 1 NUL

        // Contains the EMBED_HOST_MISSING_URL_FULL_UTF8 value at compile time or the managed DLL name replaced by "dotnet build".
        // Must not be 'const' because std::string(&embed[0]) below would bind to a const string ctor plus length
        // where length is determined at compile time (=64) instead of the actual length of the string at runtime.
        static char embed[EMBED_MAX] = EMBED_HOST_MISSING_URL_FULL_UTF8;     // series of NULs followed by embed hash string

        static const char hi_part[] = EMBED_HOST_MISSING_URL_HI_PART_UTF8;
        static const char lo_part[] = EMBED_HOST_MISSING_URL_LO_PART_UTF8;

        if (!pal::clr_palstring(embed, host_missing_url))
        {
            trace::error(_X("The host_missing_url value could not be retrieved from the executable image."));
            return false;
        }

        // Since the single static string is replaced by editing the executable, a reference string is needed to do the compare.
        // So use two parts of the string that will be unaffected by the edit.
        size_t hi_len = (sizeof(hi_part) / sizeof(hi_part[0])) - 1;
        size_t lo_len = (sizeof(lo_part) / sizeof(lo_part[0])) - 1;

        std::string binding(&embed[0]);
        if ((binding.size() >= (hi_len + lo_len)) &&
            binding.compare(0, hi_len, &hi_part[0]) == 0 &&
            binding.compare(hi_len, lo_len, &lo_part[0]) == 0)
        {
            trace::info(_X("This executable does not binding to host_missing_url yet. The binding value is: '%s'"), host_missing_url->c_str());
            return false;
        }

        trace::info(_X("The host_missing_url binding to this executable is: '%s'"), host_missing_url->c_str());
        return true;
    }

    bool is_need_prereqs_enabled_for_execution(pal::string_t* need_prereqs_message)
    {
        constexpr int EMBED_SZ = sizeof(EMBED_NEED_PREREQS_FULL_UTF8) / sizeof(EMBED_NEED_PREREQS_FULL_UTF8[0]);
        constexpr int EMBED_MAX = (EMBED_SZ > 1025 ? EMBED_SZ : 1025); // 1024 DLL name length, 1 NUL

        // Contains the EMBED_NEED_PREREQS_FULL_UTF8 value at compile time or the managed DLL name replaced by "dotnet build".
        // Must not be 'const' because std::string(&embed[0]) below would bind to a const string ctor plus length
        // where length is determined at compile time (=64) instead of the actual length of the string at runtime.
        static char embed[EMBED_MAX] = EMBED_NEED_PREREQS_FULL_UTF8;     // series of NULs followed by embed hash string

        static const char hi_part[] = EMBED_NEED_PREREQS_HI_PART_UTF8;
        static const char lo_part[] = EMBED_NEED_PREREQS_LO_PART_UTF8;

        if (!pal::clr_palstring(embed, need_prereqs_message))
        {
            trace::error(_X("The need_prereqs_message value could not be retrieved from the executable image."));
            return false;
        }

        // Since the single static string is replaced by editing the executable, a reference string is needed to do the compare.
        // So use two parts of the string that will be unaffected by the edit.
        size_t hi_len = (sizeof(hi_part) / sizeof(hi_part[0])) - 1;
        size_t lo_len = (sizeof(lo_part) / sizeof(lo_part[0])) - 1;

        std::string binding(&embed[0]);
        if ((binding.size() >= (hi_len + lo_len)) &&
            binding.compare(0, hi_len, &hi_part[0]) == 0 &&
            binding.compare(hi_len, lo_len, &lo_part[0]) == 0)
        {
            trace::info(_X("This executable does not binding to need_prereqs_message yet. The binding value is: '%s'"), need_prereqs_message->c_str());
            return false;
        }

        trace::info(_X("The need_prereqs_message binding to this executable is: '%s'"), need_prereqs_message->c_str());
        return true;
    }

    bool is_need_prereqs_url_enabled_for_execution(pal::string_t* need_prereqs_url)
    {
        constexpr int EMBED_SZ = sizeof(EMBED_NEED_PREREQS_URL_FULL_UTF8) / sizeof(EMBED_NEED_PREREQS_URL_FULL_UTF8[0]);
        constexpr int EMBED_MAX = (EMBED_SZ > 1025 ? EMBED_SZ : 1025); // 1024 DLL name length, 1 NUL

        // Contains the EMBED_NEED_PREREQS_URL_FULL_UTF8 value at compile time or the managed DLL name replaced by "dotnet build".
        // Must not be 'const' because std::string(&embed[0]) below would bind to a const string ctor plus length
        // where length is determined at compile time (=64) instead of the actual length of the string at runtime.
        static char embed[EMBED_MAX] = EMBED_NEED_PREREQS_URL_FULL_UTF8;     // series of NULs followed by embed hash string

        static const char hi_part[] = EMBED_NEED_PREREQS_URL_HI_PART_UTF8;
        static const char lo_part[] = EMBED_NEED_PREREQS_URL_LO_PART_UTF8;

        if (!pal::clr_palstring(embed, need_prereqs_url))
        {
            trace::error(_X("The need_prereqs_url value could not be retrieved from the executable image."));
            return false;
        }

        // Since the single static string is replaced by editing the executable, a reference string is needed to do the compare.
        // So use two parts of the string that will be unaffected by the edit.
        size_t hi_len = (sizeof(hi_part) / sizeof(hi_part[0])) - 1;
        size_t lo_len = (sizeof(lo_part) / sizeof(lo_part[0])) - 1;

        std::string binding(&embed[0]);
        if ((binding.size() >= (hi_len + lo_len)) &&
            binding.compare(0, hi_len, &hi_part[0]) == 0 &&
            binding.compare(hi_len, lo_len, &lo_part[0]) == 0)
        {
            trace::info(_X("This executable does not binding to need_prereqs_url yet. The binding value is: '%s'"), need_prereqs_url->c_str());
            return false;
        }

        trace::info(_X("The need_prereqs_url binding to this executable is: '%s'"), need_prereqs_url->c_str());
        return true;
    }


    void __cdecl buffering_trace_writer(const pal::char_t* message)
    {
        // Add to buffer for later use.
        g_buffered_errors.append(message).append(_X("\n"));
        // Also write to stderr immediately
        pal::err_fputs(message);
    }

    // Determines if the current module (apphost executable) is marked as a Windows GUI application
    bool is_gui_application()
    {
        HMODULE module = ::GetModuleHandleW(nullptr);
        assert(module != nullptr);

        // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
        BYTE* bytes = reinterpret_cast<BYTE*>(module);
        UINT32 pe_header_offset = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes)->e_lfanew;
        UINT16 subsystem = reinterpret_cast<IMAGE_NT_HEADERS*>(bytes + pe_header_offset)->OptionalHeader.Subsystem;

        return subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI;
    }

    void write_errors_to_event_log(const pal::char_t* executable_path, const pal::char_t* executable_name)
    {
        // Report errors to the Windows Event Log.
        auto eventSource = ::RegisterEventSourceW(nullptr, _X(".NET Runtime"));
        const DWORD traceErrorID = 1023; // Matches CoreCLR ERT_UnmanagedFailFast
        pal::string_t message;
        message.append(_X("Description: A .NET application failed.\n"));
        message.append(_X("Application: ")).append(executable_name).append(_X("\n"));
        message.append(_X("Path: ")).append(executable_path).append(_X("\n"));
        message.append(_X("Message: ")).append(g_buffered_errors).append(_X("\n"));

        LPCWSTR messages[] = { message.c_str() };
        ::ReportEventW(eventSource, EVENTLOG_ERROR_TYPE, 0, traceErrorID, nullptr, 1, 0, messages, nullptr);
        ::DeregisterEventSource(eventSource);
    }

    bool try_get_url_from_line(const pal::string_t& line, pal::string_t& url)
    {
        const pal::char_t url_prefix[] = DOTNET_CORE_APPLAUNCH_URL _X("?");
        if (utils::starts_with(line, url_prefix, true))
        {
            url.assign(line);
            return true;
        }

        const pal::char_t url_prefix_before_7_0[] = _X("  - ") DOTNET_CORE_APPLAUNCH_URL _X("?");
        if (utils::starts_with(line, url_prefix_before_7_0, true))
        {
            size_t offset = utils::strlen(url_prefix_before_7_0) - utils::strlen(DOTNET_CORE_APPLAUNCH_URL) - 1;
            url.assign(line.substr(offset, line.length() - offset));
            return true;
        }

        return false;
    }

    pal::string_t get_apphost_details_message()
    {
        pal::string_t msg = _X("Architecture: ");
        msg.append(get_current_arch_name());
        msg.append(_X("\n")
            _X("App host version: ") _STRINGIFY(HOST_VERSION) _X("\n\n"));
        return msg;
    }

    void open_url(const pal::char_t* url)
    {
        // Open the URL in default browser
        ::ShellExecuteW(
            nullptr,
            _X("open"),
            url,
            nullptr,
            nullptr,
            SW_SHOWNORMAL);
    }

    bool enable_visual_styles()
    {
        // Create an activation context using a manifest that enables visual styles
        // See https://learn.microsoft.com/windows/win32/controls/cookbook-overview
        // To avoid increasing the size of all applications by embedding a manifest,
        // we just use the WindowsShell manifest.
        pal::char_t buf[MAX_PATH];
        UINT len = ::GetWindowsDirectoryW(buf, MAX_PATH);
        if (len == 0 || len >= MAX_PATH)
        {
            trace::verbose(_X("GetWindowsDirectory failed. Error code: %d"), ::GetLastError());
            return false;
        }

        pal::string_t manifest(buf);
        append_path(&manifest, _X("WindowsShell.Manifest"));

        // Since this is only for errors shown when the process is about to exit, we
        // skip releasing/deactivating the context to minimize impact on apphost size
        ACTCTXW actctx = { sizeof(ACTCTXW), 0, manifest.c_str() };
        HANDLE context_handle = ::CreateActCtxW(&actctx);
        if (context_handle == INVALID_HANDLE_VALUE)
        {
            trace::verbose(_X("CreateActCtxW failed using manifest '%s'. Error code: %d"), manifest.c_str(), ::GetLastError());
            return false;
        }

        ULONG_PTR cookie;
        if (::ActivateActCtx(context_handle, &cookie) == FALSE)
        {
            trace::verbose(_X("ActivateActCtx failed. Error code: %d"), ::GetLastError());
            return false;
        }

        return true;
    }

    void append_hyperlink(pal::string_t& str, const pal::char_t* url)
    {
        str.append(_X("<A HREF=\""));
        str.append(url);
        str.append(_X("\">"));

        // & indicates an accelerator key when in hyperlink text.
        // Replace & with && such that the single ampersand is shown.
        for (size_t i = 0; i < pal::strlen(url); ++i)
        {
            str.push_back(url[i]);
            if (url[i] == _X('&'))
                str.push_back(_X('&'));
        }

        str.append(_X("</A>"));
    }

    bool try_show_error_with_task_dialog(
        const pal::char_t* executable_name,
        const pal::char_t* instruction,
        const pal::char_t* details,
        const pal::char_t* url)
    {
        HMODULE comctl32 = ::LoadLibraryExW(L"comctl32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (comctl32 == nullptr)
            return false;

        typedef HRESULT(WINAPI* task_dialog_indirect)(
            const TASKDIALOGCONFIG* pTaskConfig,
            int* pnButton,
            int* pnRadioButton,
            BOOL* pfVerificationFlagChecked);

        task_dialog_indirect task_dialog_indirect_func = (task_dialog_indirect)::GetProcAddress(comctl32, "TaskDialogIndirect");
        if (task_dialog_indirect_func == nullptr)
        {
            ::FreeLibrary(comctl32);
            return false;
        }

        TASKDIALOGCONFIG config{ 0 };
        config.cbSize = sizeof(TASKDIALOGCONFIG);
        config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_ENABLE_HYPERLINKS | TDF_SIZE_TO_CONTENT | TDF_USE_COMMAND_LINKS;
        config.dwCommonButtons = TDCBF_CLOSE_BUTTON;
        config.pszWindowTitle = executable_name;
        config.pszMainInstruction = instruction;

        // Use the application's icon if available
        HMODULE exe_module = ::GetModuleHandleW(nullptr);
        assert(exe_module != nullptr);
        if (::FindResourceW(exe_module, IDI_APPLICATION, RT_GROUP_ICON) != nullptr)
        {
            config.hInstance = exe_module;
            config.pszMainIcon = IDI_APPLICATION;
        }
        else
        {
            config.pszMainIcon = TD_ERROR_ICON;
        }

        int download_button_id = 1000;
        TASKDIALOG_BUTTON download_button{ download_button_id, _X("Download it now\n") _X("You will need to run the downloaded installer") };
        config.cButtons = 1;
        config.pButtons = &download_button;
        config.nDefaultButton = download_button_id;

        pal::string_t expanded_info(details);
        expanded_info.append(DOC_LINK_INTRO _X("\n"));
        append_hyperlink(expanded_info, DOTNET_APP_LAUNCH_FAILED_URL);
        expanded_info.append(_X("\n\nDownload link:\n"));
        append_hyperlink(expanded_info, url);
        config.pszExpandedInformation = expanded_info.c_str();

        // Callback to handle hyperlink clicks
        config.pfCallback = [](HWND hwnd, UINT uNotification, WPARAM wParam, LPARAM lParam, LONG_PTR lpRefData) -> HRESULT
            {
                if (uNotification == TDN_HYPERLINK_CLICKED && lParam != NULL)
                    open_url(reinterpret_cast<LPCWSTR>(lParam));

                return S_OK;
            };

        int clicked_button;
        bool succeeded = SUCCEEDED(task_dialog_indirect_func(&config, &clicked_button, nullptr, nullptr));
        if (succeeded && clicked_button == download_button_id)
            open_url(url);

        ::FreeLibrary(comctl32);
        return succeeded;
    }

    void show_error_dialog(const pal::char_t* executable_name, int error_code)
    {
        pal::string_t gui_errors_disabled;
        if (pal::getenv(_X("DOTNET_DISABLE_GUI_ERRORS"), &gui_errors_disabled) && pal::xtoi(gui_errors_disabled.c_str()) == 1)
            return;

        bool isMessageEmbedded = false;
        bool isUrlEmbedded = false;
        pal::string_t dialogMsg;
        const pal::char_t* instruction = nullptr;
        pal::string_t details;
        pal::string_t url;
        const pal::string_t url_prefix = _X("  - ") DOTNET_CORE_APPLAUNCH_URL _X("?");
        if (!CheckOSIsNetCoreSupported() && is_need_prereqs_enabled_for_execution(&dialogMsg))
        {
            isMessageEmbedded = true;
            is_need_prereqs_url_enabled_for_execution(&url);
        }
        else if (error_code == StatusCode::CoreHostLibMissingFailure)
        {
            if (!is_host_missing_enabled_for_execution(&dialogMsg))
            {
                dialogMsg = pal::string_t(_X("To run this application, you must install .NET Desktop Runtime "));
                instruction = dialogMsg.c_str();
            }
            else
            {
                isUrlEmbedded = true;
            }

            if (!is_host_missing_url_enabled_for_execution(&url))
            {
                instruction = INSTALL_NET_DESKTOP_ERROR_MESSAGE;
                details = get_apphost_details_message();
                pal::string_t line;
                pal::stringstream_t ss(g_buffered_errors);
                while (std::getline(ss, line, _X('\n')))
                {
                    if (try_get_url_from_line(line, url))
                    {
                        break;
                    }
                }
            }
            else
            {
                isUrlEmbedded = true;
            }
        }
        else if (error_code == StatusCode::FrameworkMissingFailure)
        {
            // We don't have a great way of passing out different kinds of detailed error info across components, so
            // just match the expected error string. See fx_resolver.messages.cpp.
            instruction = INSTALL_OR_UPDATE_NET_ERROR_MESSAGE;
            pal::string_t line;
            pal::stringstream_t ss(g_buffered_errors);
            bool foundCustomMessage = false;
            while (std::getline(ss, line, _X('\n')))
            {
                const pal::char_t prefix[] = _X("Framework: '");
                const pal::char_t prefix_before_7_0[] = _X("The framework '");
                const pal::char_t suffix_before_7_0[] = _X(" was not found.");
                const pal::char_t custom_prefix[] = _X("  _ ");
                bool has_prefix = utils::starts_with(line, prefix, true);
                if (has_prefix
                    || (utils::starts_with(line, prefix_before_7_0, true) && utils::ends_with(line, suffix_before_7_0, true)))
                {
                    details.append(_X("Required: "));
                    if (has_prefix)
                    {
                        details.append(line.substr(utils::strlen(prefix) - 1));
                    }
                    else
                    {
                        size_t prefix_len = utils::strlen(prefix_before_7_0) - 1;
                        details.append(line.substr(prefix_len, line.length() - prefix_len - utils::strlen(suffix_before_7_0)));
                    }

                    details.append(_X("\n\n"));
                    foundCustomMessage = true;
                }
                else if (utils::starts_with(line, custom_prefix, true))
                {
                    details.erase();
                    details.append(line.substr(utils::strlen(custom_prefix)));
                    details.append(_X("\n\n"));
                    foundCustomMessage = true;
                }
                else if (try_get_url_from_line(line, url))
                {
                    break;
                }
            }

            if (!foundCustomMessage)
                details.append(get_apphost_details_message());
        }
        else if (error_code == StatusCode::BundleExtractionFailure)
        {
            pal::string_t line;
            pal::stringstream_t ss(g_buffered_errors);
            while (std::getline(ss, line, _X('\n')))
            {
                if (utils::starts_with(line, _X("Bundle header version compatibility check failed."), true))
                {
                    instruction = INSTALL_NET_DESKTOP_ERROR_MESSAGE;
                    details = get_apphost_details_message();
                    url = get_download_url();
                    url.append(_X("&apphost_version="));
                    url.append(_STRINGIFY(HOST_VERSION));
                }
            }

            if (instruction == nullptr)
                return;
        }
        else
        {
            return;
        }

        if (!isUrlEmbedded)
        {
            assert(url.length() > 0);
            assert(is_gui_application());
            url.append(_X("&gui=true"));
        }
        trace::verbose(_X("Showing error dialog for application: '%s' - error code: 0x%x - url: '%s' - details: %s"), executable_name, error_code, url.c_str(), details.c_str());

        if (enable_visual_styles())
        {
            // Task dialog requires enabling visual styles
            if (try_show_error_with_task_dialog(executable_name, instruction, details.c_str(), url.c_str()))
                return;
        }

        pal::string_t dialog_message(instruction);
        dialog_message.append(_X("\n\n"));
        dialog_message.append(details);
        dialog_message.append(DOC_LINK_INTRO _X("\n") DOTNET_APP_LAUNCH_FAILED_URL _X("\n\n")
            _X("Would you like to download it now?"));
        if (::MessageBoxW(nullptr, dialog_message.c_str(), executable_name, MB_ICONERROR | MB_YESNO) == IDYES)
        {
            open_url(url.c_str());
        }
    }
}

void apphost::buffer_errors()
{
    trace::verbose(_X("Redirecting errors to custom writer."));
    trace::set_error_writer(buffering_trace_writer);
}

void apphost::write_buffered_errors(int error_code)
{
    if (g_buffered_errors.empty())
        return;

    pal::string_t executable_path;
    pal::string_t executable_name;
    if (pal::get_own_executable_path(&executable_path))
    {
        executable_name = get_filename(executable_path);
    }

    write_errors_to_event_log(executable_path.c_str(), executable_name.c_str());

    if (is_gui_application())
        show_error_dialog(executable_name.c_str(), error_code);
}
