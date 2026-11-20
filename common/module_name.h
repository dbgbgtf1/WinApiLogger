#ifndef WIN_API_LOGGER_MODULE_NAME_H
#define WIN_API_LOGGER_MODULE_NAME_H

static __inline ULONG
LoggerFormatModuleStem (_In_reads_ (SourceChars) const WCHAR *Source,
                        _In_ ULONG SourceChars,
                        _Out_writes_ (WIN_API_LOGGER_MODULE_NAME_CHARS)
                            WCHAR *Destination)
{
  ULONG end = SourceChars;
  ULONG dot = ~0u;
  ULONG length;
  ULONG index;

  for (index = 0; index < WIN_API_LOGGER_MODULE_NAME_CHARS; ++index)
    Destination[index] = UNICODE_NULL;
  if (Source == NULL || SourceChars == 0)
    return 0;

  for (index = 0; index < SourceChars; ++index)
    {
      if (Source[index] == UNICODE_NULL)
        {
          end = index;
          break;
        }
      if (Source[index] == L'.')
        dot = index;
    }
  if (end != 0 && dot != ~0u && dot != 0 && dot + 1 < end)
    end = dot;
  if (end == 0)
    return 0;

  length = end;
  if (length >= WIN_API_LOGGER_MODULE_NAME_CHARS)
    length = WIN_API_LOGGER_MODULE_NAME_CHARS - 1;
  for (index = 0; index < length; ++index)
    Destination[index] = Source[index];
  Destination[length] = UNICODE_NULL;
  return length;
}

#endif
