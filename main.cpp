#include <Windows.h>
#include "wrect.h"
#include "cl_dll.h"
#include "cvardef.h"

cl_enginefunc_t gEngfuncs;

typedef void (*xcommand_t) (void);

typedef enum
{
	src_client,		// came in over a net connection as a clc_stringcmd
					// host_client will be valid during this state.
	src_command		// from the command buffer
} cmd_source_t;

typedef struct cmd_function_s
{
	struct cmd_function_s	*next;
	char					*name;
	xcommand_t				function;
	int					flags;
} cmd_function_t;

//-----------------------------------------------------------------------------
// Finds a string in another string with a case insensitive test
//-----------------------------------------------------------------------------

char const* Q_stristr( char const* pStr, char const* pSearch )
{
	char const* pLetter;

	if (!pStr || !pSearch) 
		return 0;

	pLetter = pStr;

	// Check the entire string
	while (*pLetter != 0)
	{
		// Skip over non-matches
		if (tolower(*pLetter) == tolower(*pSearch))
		{
			// Check for match
			char const* pMatch = pLetter + 1;
			char const* pTest = pSearch + 1;
			while (*pTest != 0)
			{
				// We've run off the end; don't bother.
				if (*pMatch == 0)
					return 0;

				if (tolower(*pMatch) != tolower(*pTest))
					break;

				++pMatch;
				++pTest;
			}

			// Found a match!
			if (*pTest == 0)
				return pLetter;
		}

		++pLetter;
	}

	return 0;
}


//-----------------------------------------------------------------------------
// Purpose: 
//-----------------------------------------------------------------------------
qboolean IsSafeFileToDownload( const char *filename )
{
	char *first, *last;
	char lwrfilename[4096];

	if ( !filename )
		return false;

	if ( !strncmp( filename, "!MD5", 4 ) )
		return true;

	strncpy( lwrfilename, filename, sizeof( lwrfilename ) );
	strlwr( lwrfilename );

	if ( strstr( lwrfilename, "\\" ) || strstr( lwrfilename, ":" ) || 
		strstr( lwrfilename, ".." ) || strstr( lwrfilename, "~" ) )
	{
		return false;
	}

	if ( lwrfilename[0] == '/' )
		return false;

	first = strchr( lwrfilename, '.' );
	last = strrchr( lwrfilename, '.' );

	if ( first == NULL || last == NULL )
		return false;

	if ( first != last )
		return false;

	if ( strlen(first) != 4 )
		return false;

	if ( Q_stristr( lwrfilename, ".cfg" ) || Q_stristr( lwrfilename, ".lst" ) || 
		Q_stristr( lwrfilename, ".exe" ) || Q_stristr( lwrfilename, ".vbs" ) || 
		Q_stristr( lwrfilename, ".com" ) || Q_stristr( lwrfilename, ".bat" ) || 
		Q_stristr( lwrfilename, ".dll" ) || Q_stristr( lwrfilename, ".ini" ) || 
		Q_stristr( lwrfilename, ".log" ) || Q_stristr( lwrfilename, "halflife.wad" ) || 
		Q_stristr( lwrfilename, "pak0.pak" ) || Q_stristr( lwrfilename, "xeno.wad" ) || 
		Q_stristr( lwrfilename, ".so" ) || Q_stristr( lwrfilename, ".dylib" ) || 
		Q_stristr( lwrfilename, ".sys" ) )
	{
		return false;
	}

	return true;
}

xcommand_t gpfnHost_Motd_Write_f;

//-----------------------------------------------------------------------------
// Purpose: 
//-----------------------------------------------------------------------------
void Host_Motd_Write_f( void )
{
	cvar_t *motdfile = gEngfuncs.pfnGetCvarPointer("motdfile");

	if ( IsSafeFileToDownload( motdfile->string ) && strstr( motdfile->string, ".txt" ) )
	{
		gpfnHost_Motd_Write_f();
	}
	else
	{
		gEngfuncs.Con_Printf( "Invalid motdfile name (%s)\n", motdfile->string );
	}
}


static bool DataCompare2( const BYTE* pData, const BYTE* pMask, const char* pszMask )
{
	for ( ; *pszMask; ++pszMask, ++pData, ++pMask )
	{
		if ( *pszMask == 'x' && *pData != *pMask )
		{
			return false;
		}
	}

	return (*pszMask == NULL);
}


LPVOID ScanPartten( PVOID dwStart, SIZE_T dwSize, const char* pSignature, const char* pMask )
{
	int len = (int) strlen( pMask );

	for ( DWORD_PTR dwIndex = 0; (dwIndex + len) < dwSize; dwIndex++ )
	{
		if ( DataCompare2( (const BYTE*)((PUCHAR)dwStart + dwIndex), (const BYTE*)pSignature, pMask ) )
		{
			return (LPVOID)((ULONG_PTR)dwStart + dwIndex);
		}
	}

	return NULL;
}

cmd_function_t **cmd_functions;

int Cmd_AddCommand(char *cmd_name, xcommand_t function)
{
	gEngfuncs.pfnAddCommand(cmd_name, function);
	return 1;
}

cmd_function_t *Cmd_FindCmd(char *cmd_name)
{
	for (cmd_function_t *cmd = *cmd_functions; cmd; cmd = cmd->next)
	{
		if (!strcmp(cmd->name, cmd_name))
			return cmd;
	}

	return NULL;
}

xcommand_t Cmd_HookCmd(char *cmd_name, xcommand_t newfuncs)
{
	cmd_function_t *cmd = Cmd_FindCmd(cmd_name);

	if (!cmd)
	{
		Cmd_AddCommand(cmd_name, newfuncs);
		return newfuncs;
	}

	xcommand_t result = cmd->function;
	cmd->function = newfuncs;
	return result;
}

#ifndef __RVA_TO_VA
#define __RVA_TO_VA(p) ((PVOID)((PCHAR)(p) + *(PLONG)(p) + sizeof(LONG)))
#endif // !__RVA_TO_VA

void Initialize(void)
{
	PUCHAR InitializeFN;
	int i;
	qboolean init=false;
	HMODULE hClientDLL = GetModuleHandle(TEXT("client.dll"));

	InitializeFN = NULL;
	if(hClientDLL != NULL)
	{
		InitializeFN = (PUCHAR)GetProcAddress(hClientDLL, "Initialize");
	}
	else
	{
		InitializeFN = (PUCHAR)ScanPartten((PVOID)0x1901000,
			0x400000, 
			"\x8D\x84\x24\x08\x04\x00\x00\x56\x8B\xB4\x24\x08\x04\x00\x00\x57",
			"xxxxxxxxxxxxxxxx");
		//8D 84 24 08 04 00 00 56 8B B4 24 08 04 00 00 57
	}

	if(!InitializeFN)
		return;

	for(i =0; i < 100; i++)
	{
		if(InitializeFN[i] == 0xBF && InitializeFN[i+5] == 0xF3 && InitializeFN[i+6] == 0xA5)
		{
			cl_enginefunc_t *pengfuncs = *(cl_enginefunc_t **)&InitializeFN[i+1];
			memcpy(&gEngfuncs, pengfuncs, sizeof(cl_enginefunc_t));
			init=true;
			break;
		}
	}

	if(init)
	{
		PUCHAR AddCommand = (PUCHAR)gEngfuncs.pfnAddCommand;
		init = false;
		for(i =0; i< 100;i++)
		{
			if(AddCommand[i] == 0xe8)
			{
				AddCommand = (PUCHAR)__RVA_TO_VA(&AddCommand[i+1]);
				init=true;
				break;
			}
		}

		if(!init)
			return;
		init = false;
		for(i =0; i< 100;i++)
		{
			if(AddCommand[i] == 0xe8)
			{
				AddCommand = (PUCHAR)__RVA_TO_VA(&AddCommand[i+1]);
				init=true;
				break;
			}
		}

		if(!init)
			return;
		
		init = false;
		for(i =0; i< 100;i++)
		{
			if(AddCommand[i] == 0x8B && AddCommand[i+1] == 0x35)
			{
				cmd_functions = *(cmd_function_t***)&AddCommand[i+2];
				init=true;
				break;
			}
		}
		if(!init)
			return;

		gpfnHost_Motd_Write_f = Cmd_HookCmd("motd_write", Host_Motd_Write_f);
	}
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	UNREFERENCED_PARAMETER(lpReserved);

	if( dwReason == DLL_PROCESS_ATTACH )
	{
		Initialize();
	}

	return TRUE;
}