#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include <windows.h>

#define wmain ReaderCliMain
#include "../reader/reader.c"
#undef wmain
#include "../common/module_name.h"

static int
CheckFormat (const WCHAR *Expected, const WCHAR *Actual)
{
  if (wcscmp (Expected, Actual) == 0)
    return 0;
  fwprintf (stderr, L"expected: %ls\nactual:   %ls\n", Expected, Actual);
  return 1;
}

int
main (void)
{
  READER_OPTIONS options;
  LOGGER_DRIVER_RECORD record;
  const LOGGER_NAME_ENTRY *name = &g_name_entries[0];
  WCHAR line[512];
  WCHAR expected[512];
  WCHAR stem[WIN_API_LOGGER_MODULE_NAME_CHARS];
  const WCHAR *long_name = L"VeryLongModuleName.dll";
  int failures = 0;

  ZeroMemory (&options, sizeof (options));
  ZeroMemory (&record, sizeof (record));
  record.ProcessId = 123;
  record.ThreadId = 456;
  record.ModuleId = 0;
  record.HookRva = name->hook_rva;
  record.CallerRva = 0x1170B;
  record.CallerModuleChars = 8;
  wcscpy_s (record.CallerModule, _countof (record.CallerModule),
            L"IPHLPAPI");

  swprintf_s (expected, _countof (expected), L"123.456 IPHLPAPI:0x1170B "
              L"called ntdll!%hs", name->canonical_name);
  if (!ReaderFormatRecord (&options, &record, line, _countof (line)))
    ++failures;
  else
    failures += CheckFormat (expected, line);

  options.HasModule = TRUE;
  options.Module = L"ntdll.dll";
  if (!ReaderMatchesFilters (&options, &record, name))
    {
      fwprintf (stderr, L"module filter did not accept ntdll.dll\n");
      ++failures;
    }
  options.Module = L"kernel32";
  if (ReaderMatchesFilters (&options, &record, name))
    {
      fwprintf (stderr, L"module filter accepted kernel32\n");
      ++failures;
    }

  ZeroMemory (&options, sizeof (options));
  record.CallerAddress = 0x7FF6ABCD1234ULL;
  record.CallerRva = 0;
  record.CallerModuleChars = 0;
  swprintf_s (expected, _countof (expected),
              L"123.456 unknown-0x7FF6ABCD1234 called ntdll!%hs",
              name->canonical_name);
  if (!ReaderFormatRecord (&options, &record, line, _countof (line)))
    ++failures;
  else
    failures += CheckFormat (expected, line);

  if (LoggerFormatModuleStem (L"KernelBase.dll",
                              (ULONG)wcslen (L"KernelBase.dll"), stem)
          != 10
      || wcscmp (stem, L"KernelBase") != 0)
    {
      fwprintf (stderr, L"module stem normalization failed: %ls\n", stem);
      ++failures;
    }
  if (LoggerFormatModuleStem (long_name, (ULONG)wcslen (long_name), stem)
          != WIN_API_LOGGER_MODULE_NAME_CHARS - 1
      || wcslen (stem) != WIN_API_LOGGER_MODULE_NAME_CHARS - 1
      || stem[WIN_API_LOGGER_MODULE_NAME_CHARS - 1] != L'\0')
    {
      fwprintf (stderr, L"module stem truncation failed: %ls\n", stem);
      ++failures;
    }

  if (failures == 0)
    {
      printf ("reader format test: PASS\n");
      return 0;
    }
  return 1;
}
