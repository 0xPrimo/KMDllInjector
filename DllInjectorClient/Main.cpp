#include "Header.h"

VOID Banner( )
{
	std::cout << "    ____  ________        _           __            " << std::endl;
	std::cout << "   / __ \\/ / /  _/___    (_)__  _____/ /_____  _____" << std::endl;
	std::cout << "  / / / / / // // __ \\  / / _ \\/ ___/ __/ __ \\/ ___/" << std::endl;
	std::cout << " / /_/ / / // // / / / / /  __/ /__/ /_/ /_/ / /    " << std::endl;
	std::cout << "/_____/_/_/___/_/ /_/_/ /\\___/\\___/\\__/\\____/_/     " << std::endl;
	std::cout << "                   /___/                            " << std::endl;

}

VOID Menu1( PDWORD Index )
{
	system( "cls" );
	Banner( );

	std::wcout << "   [0] APC Hooking Technique (Inject APC into a Process)" << std::endl;
	std::wcout << "   [1] Trampoling Hooking Technique (Inject Shellcode + Hook LdrLoadDll)" << std::endl;
	std::wcout << "   [2] Stop Hooking" << std::endl;
	std::wcout << "   [3] Exit" << std::endl << std::endl;

	std::wcout << "   [>] Enter a Number: ";
	std::wcin >> *Index;

	system( "cls" );
}

VOID Menu2( std::wstring& ProcessName, std::wstring& DllToInject )
{
	Banner( );
	std::wcin.ignore( );

	std::wcout << "   [>] Process Name: ";
	std::getline( std::wcin, ProcessName );

	std::wcout << "   [>] Full Dll Path: ";
	std::getline( std::wcin, DllToInject );
}

int wmain( int ac, wchar_t* av[ ] ) {

	HANDLE hDriver = NULL;
	REQUEST Request;
	SIZE_T RequestSize = sizeof( REQUEST );

	hDriver = CreateFile( DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL );
	if ( hDriver == INVALID_HANDLE_VALUE )
	{
		std::wcout << "   [!] Failed to open handle to the driver." << std::endl;
		return ( 0 );
	}

	do {

		/* Display the menu */
		DWORD Index = -1;
		std::wstring ProcessName;
		std::wstring DllToInject;

		Menu1( &Index );

		if ( Index == -1 )
			continue;

		if ( Index < 2 )
		{
			Menu2( ProcessName, DllToInject );
			if ( !PathFileExistsW( DllToInject.c_str( ) ) )
			{
				std::cout << "   [!] Dll doesn't exist" << std::endl;
				Sleep( 1000 );
				continue;
			}
		}

		switch ( Index )
		{

			case 0:
			{
				// Initialize the request struct
				Request.Technique = HOOK_TECHNIQUE::APC_CALLBACK;
				wcscpy( Request.ProcessToInject, ProcessName.c_str( ) );
				wcscpy( Request.PathToDll, DllToInject.c_str( ) );

				if ( !DeviceIoControl( hDriver, IOCTL_START_HOOKING, &Request, sizeof( REQUEST ), &Request,
									   sizeof( REQUEST ), NULL, NULL ) )
				{
					std::cout << "   [!] DeviceIoControl Failed: " << GetLastError( ) << std::endl;
					Sleep( 2000 );

				}
				break;
			}
			case 1:
			{
				// Initialize the request struct
				Request.Technique = HOOK_TECHNIQUE::TRAMPOLINE;
				wcscpy( Request.ProcessToInject, ProcessName.c_str( ) );
				wcscpy( Request.PathToDll, DllToInject.c_str( ) );

				if ( !DeviceIoControl( hDriver, IOCTL_START_HOOKING, &Request, sizeof( REQUEST ), &Request,
									   sizeof( REQUEST ), NULL, NULL ) )
				{
					std::cout << "   [!] DeviceIoControl Failed: " << GetLastError( ) << std::endl;
					Sleep( 2000 );
				}
				break;
			}
			case 2:
			{
				DeviceIoControl( hDriver, IOCTL_STOP_HOOKING, NULL, 0, NULL, 0, NULL, NULL );
				break;
			}
			case 3:
			{
				ExitProcess( 0 );
				break;
			}
			default:
				break;
		}
	} while ( TRUE );

	return ( 0 );
}