//This project is heavily based on other open-source projects such as:
//   - https://github.com/trustedsec/CS-Remote-OPs-BOF/blob/main/src/Remote/sc_config/entry.c
//   - https://github.com/Cobalt-Strike/bof-vs
//   - many more



#include <Windows.h>
#include "base\helpers.h"
#include "string.h"

/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */
#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {
#include "beacon.h"
    // Define the Dynamic Function Resolution declaration for the GetLastError function
    DFR(KERNEL32, GetLastError);
    #define GetLastError KERNEL32$GetLastError

	// Fix #1: Initialize globals to avoid .bss section
	formatp OutputBuffer = {0};
	char lanmanBinPath[1024] = {0};
	char srv2BinPath[1024] = {0};
	char srvnetBinPath[1024] = {0};

	DWORD ConfigTargetService(const char* Hostname, const char* cpServiceName, const char* binpath, DWORD errmode, DWORD state)
	{

		DWORD dwResult = ERROR_SUCCESS;
		SC_HANDLE scManager = NULL;
		SC_HANDLE scService = NULL;

		// Open the service control manager
        DFR_LOCAL(ADVAPI32, OpenSCManagerA);
        scManager = OpenSCManagerA(Hostname, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT);
		if (NULL == scManager)
		{
			dwResult = GetLastError();
            BeaconPrintf(CALLBACK_OUTPUT, "OpenSCManagerA failed (%lu)\n", dwResult);
			goto config_service_end;
		}

		// Open the service
        DFR_LOCAL(ADVAPI32, OpenServiceA);
		scService = OpenServiceA(scManager, cpServiceName, SERVICE_CHANGE_CONFIG);
		if (NULL == scService)
		{
			dwResult = GetLastError();
             BeaconPrintf(CALLBACK_OUTPUT, "OpenServiceA failed (%lu)\n", dwResult);
			goto config_service_end;
		}

		// Set the service configuration
        DFR_LOCAL(ADVAPI32, ChangeServiceConfigA);
		if (FALSE == ChangeServiceConfigA(
			scService,
			SERVICE_NO_CHANGE,
			state,
			errmode,
			binpath,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		)
			)
		{
			dwResult = GetLastError();
			BeaconPrintf(CALLBACK_OUTPUT, "ChangeServiceConfigA failed (%lu)\n", dwResult);
			goto config_service_end;
		}



	config_service_end:
		DFR_LOCAL(ADVAPI32, CloseServiceHandle);
		if (scService)
		{

			CloseServiceHandle(scService);
			scService = NULL;
		}

		if (scManager)
		{
			CloseServiceHandle(scManager);
			scManager = NULL;
		}

		return dwResult;
	}

	DWORD StopTargetService(const char* Hostname, const char* cpServiceName)
{
    DWORD dwResult = ERROR_SUCCESS;
	SC_HANDLE scManager = NULL;
	SC_HANDLE scService = NULL;
   	SERVICE_STATUS_PROCESS ssp;
	DWORD dwBytesNeeded = 0;


	// Open the service control manager
	DFR_LOCAL(ADVAPI32, OpenSCManagerA);
	scManager = OpenSCManagerA(Hostname, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT);
	if (NULL == scManager)
	{
		dwResult = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_OUTPUT, "OpenSCManagerA failed (%lX)\n", dwResult);
		goto stop_service_end;
	}

	// Open the service
	DFR_LOCAL(ADVAPI32, OpenServiceA);
	scService = OpenServiceA(scManager, cpServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
	if (NULL == scService)
	{
		dwResult = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_OUTPUT, "OpenServiceA failed (%lX)\n", dwResult);
		goto stop_service_end;
	}

    // Get the service status process struct
	DFR_LOCAL(ADVAPI32, QueryServiceStatusEx);
    if ( FALSE == QueryServiceStatusEx(
            scService,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&ssp,
            sizeof(SERVICE_STATUS_PROCESS),
            &dwBytesNeeded
            )
        )
    {
        dwResult = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_OUTPUT, "QueryServiceStatusEx failed (%lX)\n", dwResult);
		goto stop_service_end;
    }

    // Check the current state of the service
    if ( ssp.dwCurrentState == SERVICE_STOPPED )
    {
		//print service name
		BeaconPrintf(CALLBACK_OUTPUT, "Service: %s\n", cpServiceName);
        BeaconPrintf(CALLBACK_OUTPUT, "Service is already stopped.\n");
        goto stop_service_end;
    }

    // If a stop is pending, wait for it
    if ( ssp.dwCurrentState == SERVICE_STOP_PENDING )
    {
        BeaconPrintf(CALLBACK_OUTPUT, "Service stop pending...\n");
        goto stop_service_end;
    }


    // Now we can finally Send a stop code to the service
	DFR_LOCAL(ADVAPI32, ControlService);
    if ( FALSE == ControlService(
            scService,
            SERVICE_CONTROL_STOP,
            (LPSERVICE_STATUS) &ssp
            )
        )
    {
        dwResult = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_OUTPUT, "ControlService failed (%lX)\n", dwResult);
		goto stop_service_end;
    }


	stop_service_end:
		DFR_LOCAL(ADVAPI32, CloseServiceHandle);
		if (scService)
		{
			CloseServiceHandle(scService);
			scService = NULL;
		}

		if (scManager)
		{
			CloseServiceHandle(scManager);
			scManager = NULL;
		}

		return dwResult;
	}

	DWORD StartTargetService(const char* Hostname, const char* cpServiceName)
	{
		DWORD dwResult = ERROR_SUCCESS;
		SC_HANDLE scManager = NULL;
		SC_HANDLE scService = NULL;

		// Open the service control manager
		DFR_LOCAL(ADVAPI32, OpenSCManagerA);
		scManager = OpenSCManagerA(Hostname, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT);
		if (NULL == scManager)
		{
			dwResult = KERNEL32$GetLastError();
			BeaconPrintf(CALLBACK_OUTPUT, "OpenSCManagerA failed (%lX)\n", dwResult);
			goto start_service_end;
		}

		// Open the service
		DFR_LOCAL(ADVAPI32, OpenServiceA);
		scService = OpenServiceA(scManager, cpServiceName, SERVICE_START);
		if (NULL == scService)
		{
			dwResult = KERNEL32$GetLastError();
			BeaconPrintf(CALLBACK_OUTPUT, "OpenServiceA failed (%lX)\n", dwResult);
			goto start_service_end;
		}

		// Start the service
		DFR_LOCAL(ADVAPI32, StartServiceA);
		if( FALSE == StartServiceA(scService, 0, NULL))
		{
			dwResult = KERNEL32$GetLastError();
			BeaconPrintf(CALLBACK_OUTPUT, "StartServiceA failed (%lX)\n", dwResult);
			goto start_service_end;
		}

		start_service_end:
			DFR_LOCAL(ADVAPI32, CloseServiceHandle);
			if (scService)
			{
				CloseServiceHandle(scService);
				scService = NULL;
			}

			if (scManager)
			{
				CloseServiceHandle(scManager);
				scManager = NULL;
			}

		return dwResult;
	}


	// Fix #3: Rewritten CheckServiceStatus with proper goto cleanup and return value
	BOOL CheckServiceStatus(const char* Hostname, const char* cpServiceName) {
		SC_HANDLE scManager = NULL;
		SC_HANDLE scService = NULL;
		SERVICE_STATUS_PROCESS ssp;
		DWORD dwBytesNeeded = 0;
		DWORD dwResult = ERROR_SUCCESS;
		BOOL bRunning = FALSE;

		DFR_LOCAL(ADVAPI32, OpenSCManagerA);
		scManager = OpenSCManagerA(Hostname, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT);
		if (NULL == scManager)
		{
			dwResult = KERNEL32$GetLastError();
			BeaconPrintf(CALLBACK_OUTPUT, "OpenSCManagerA failed (%lX)\n", dwResult);
			goto check_bound_end;
		}

		// Open the service
		DFR_LOCAL(ADVAPI32, OpenServiceA);
		scService = OpenServiceA(scManager, cpServiceName, SERVICE_QUERY_STATUS);
		if (NULL == scService)
		{
			dwResult = KERNEL32$GetLastError();
			BeaconPrintf(CALLBACK_OUTPUT, "OpenServiceA failed (%lX)\n", dwResult);
			goto check_bound_end;
		}

		// Get the service status process struct
		DFR_LOCAL(ADVAPI32, QueryServiceStatusEx);
		if (FALSE == QueryServiceStatusEx(
			scService,
			SC_STATUS_PROCESS_INFO,
			(LPBYTE)&ssp,
			sizeof(SERVICE_STATUS_PROCESS),
			&dwBytesNeeded
		)
			)
		{
			dwResult = KERNEL32$GetLastError();
			BeaconPrintf(CALLBACK_OUTPUT, "QueryServiceStatusEx failed (%lX)\n", dwResult);
			goto check_bound_end;
		}

		// Check the current state of the service
		if (ssp.dwCurrentState == SERVICE_RUNNING)
		{
			bRunning = TRUE;
		}

	check_bound_end:
		DFR_LOCAL(ADVAPI32, CloseServiceHandle);
		if (scService)
		{
			CloseServiceHandle(scService);
			scService = NULL;
		}

		if (scManager)
		{
			CloseServiceHandle(scManager);
			scManager = NULL;
		}

		return bRunning;
	}


	// Fix #2: Rewritten GetServiceStartType with strcmp instead of assignment
	DWORD GetServiceStartType(const char* hostname, const char* serviceName) {
		SC_HANDLE scManager = NULL;
		SC_HANDLE scService = NULL;
		DWORD startType = SERVICE_NO_CHANGE;
		BOOL success = FALSE;
		LPQUERY_SERVICE_CONFIG lpsc = NULL;
		DWORD dwBytesNeeded, cbBufSize, dwError;

		DFR_LOCAL(MSVCRT, strcmp);
		DFR_LOCAL(MSVCRT, strncpy);
		DFR_LOCAL(KERNEL32, LocalAlloc);
		DFR_LOCAL(KERNEL32, LocalFree);
		DFR_LOCAL(ADVAPI32, CloseServiceHandle);

		// Open the service control manager
		DFR_LOCAL(ADVAPI32, OpenSCManagerA);
		scManager = OpenSCManagerA(hostname, NULL, SC_MANAGER_CONNECT);
		if (scManager == NULL) {
			BeaconPrintf(CALLBACK_OUTPUT, "OpenSCManager failed with error: %lX\n", GetLastError());
			return SERVICE_NO_CHANGE;
		}

		// Open the service
		DFR_LOCAL(ADVAPI32, OpenServiceA);
		scService = OpenServiceA(scManager, serviceName, SERVICE_QUERY_CONFIG);
		if (scService == NULL) {
			BeaconPrintf(CALLBACK_OUTPUT, "OpenService failed with error: %lX\n", GetLastError());
			CloseServiceHandle(scManager);
			return SERVICE_NO_CHANGE;
		}

		// Call QueryServiceConfig to find the size of the buffer needed
		DFR_LOCAL(ADVAPI32, QueryServiceConfigA);
		success = QueryServiceConfigA(scService, NULL, 0, &dwBytesNeeded);
		if (!success) {
			dwError = GetLastError();
			if (dwError == ERROR_INSUFFICIENT_BUFFER) {
				cbBufSize = dwBytesNeeded;
				lpsc = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LMEM_FIXED, cbBufSize);
				if (lpsc == NULL) {
					BeaconPrintf(CALLBACK_OUTPUT, "LocalAlloc failed with error: %lX\n", GetLastError());
					CloseServiceHandle(scService);
					CloseServiceHandle(scManager);
					return SERVICE_NO_CHANGE;
				}

				success = QueryServiceConfigA(scService, lpsc, cbBufSize, &dwBytesNeeded);
				if (!success) {
					BeaconPrintf(CALLBACK_OUTPUT, "QueryServiceConfig failed with error: %lX\n", GetLastError());
					LocalFree(lpsc);
					CloseServiceHandle(scService);
					CloseServiceHandle(scManager);
					return SERVICE_NO_CHANGE;
				}

				// Now that we have the configuration, we can check the start type
				startType = lpsc->dwStartType;

				// Fix #2: Use strcmp() instead of = assignment
				if (strcmp(serviceName, "LanmanServer") == 0) {
					strncpy(lanmanBinPath, lpsc->lpBinaryPathName, sizeof(lanmanBinPath) - 1);
					lanmanBinPath[sizeof(lanmanBinPath) - 1] = '\0';
				} else if (strcmp(serviceName, "srv2") == 0) {
					strncpy(srv2BinPath, lpsc->lpBinaryPathName, sizeof(srv2BinPath) - 1);
					srv2BinPath[sizeof(srv2BinPath) - 1] = '\0';
				} else if (strcmp(serviceName, "srvnet") == 0) {
					strncpy(srvnetBinPath, lpsc->lpBinaryPathName, sizeof(srvnetBinPath) - 1);
					srvnetBinPath[sizeof(srvnetBinPath) - 1] = '\0';
				}

			} else {
				BeaconPrintf(CALLBACK_OUTPUT, "QueryServiceConfig failed with error: %lX\n", dwError);
				CloseServiceHandle(scService);
				CloseServiceHandle(scManager);
				return SERVICE_NO_CHANGE;
			}
		}

		// Clean up
		if (lpsc) {
			LocalFree(lpsc);
		}
		CloseServiceHandle(scService);
		CloseServiceHandle(scManager);

		return startType;
	}



	// Fix #4: Rewritten CheckProcessIntegrityLevel with proper cleanup
	DWORD CheckProcessIntegrityLevel() {
		HANDLE hToken = NULL;
		DWORD dwLengthNeeded;
		DWORD dwError = ERROR_SUCCESS;
		PTOKEN_MANDATORY_LABEL pTIL = NULL;
		DWORD dwIntegrityLevel = SECURITY_MANDATORY_LOW_RID;

		DFR_LOCAL(KERNEL32, OpenProcessToken);
		DFR_LOCAL(ADVAPI32, GetTokenInformation);
		DFR_LOCAL(KERNEL32, GetCurrentProcess);
		DFR_LOCAL(KERNEL32, CloseHandle);
		DFR_LOCAL(KERNEL32, LocalAlloc);
		DFR_LOCAL(KERNEL32, LocalFree);
		DFR_LOCAL(ADVAPI32, GetSidSubAuthority);
		DFR_LOCAL(ADVAPI32, GetSidSubAuthorityCount);

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
			BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to open process token for integrity level check.\n");
			return SECURITY_MANDATORY_LOW_RID;
		}

		// Call GetTokenInformation to get the buffer size.
		if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded)) {
			dwError = GetLastError();
			if (dwError != ERROR_INSUFFICIENT_BUFFER) {
				goto integrity_cleanup;
			}

			pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLengthNeeded);
			if (pTIL == NULL) {
				goto integrity_cleanup;
			}

			// Call GetTokenInformation again to get the integrity level.
			if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded)) {
				dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
			}
		}

	integrity_cleanup:
		if (pTIL) {
			LocalFree(pTIL);
		}
		if (hToken) {
			CloseHandle(hToken);
		}

		// Fix #7: Removed duplicate SYSTEM_RID check, return actual level
		if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
			return SECURITY_MANDATORY_SYSTEM_RID;
		} else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
			return SECURITY_MANDATORY_HIGH_RID;
		} else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID) {
			return SECURITY_MANDATORY_MEDIUM_RID;
		} else {
			return SECURITY_MANDATORY_LOW_RID;
		}
	}

    void go(char* args, int len) {
		datap parser;
		BeaconDataParse(&parser, args, len);

		char* hostname = NULL;
		char* action = NULL;
		int hostnameLen = 0;
		int actionLen = 0;

		hostname = BeaconDataExtract(&parser, &hostnameLen);
		action = BeaconDataExtract(&parser, &actionLen);

		// Fix #8: Declare DFR imports once at the top of the function
		DFR_LOCAL(MSVCRT, strcmp);
		DFR_LOCAL(MSVCRT, _stricmp);

		// Normalize localhost/127.0.0.1 to NULL for local SCM access
		if (hostname &&
			(_stricmp(hostname, "localhost") == 0 ||
				strcmp(hostname, "127.0.0.1") == 0)) {
			hostname = NULL;
		}

		if (!action) {
			BeaconPrintf(CALLBACK_OUTPUT, "[!] No action specified. Use: check, start, or stop\n");
			return;
		}

		// Fix #6: Single action dispatch, no debug duplication
		BeaconFormatAlloc(&OutputBuffer, 4096);

		if (strcmp(action, "check") == 0) {
			DWORD lanmanStartType = GetServiceStartType(hostname, "LanmanServer");
			DWORD srv2StartType = GetServiceStartType(hostname, "srv2");
			DWORD srvnetStartType = GetServiceStartType(hostname, "srvnet");
			DWORD lanmanRunning = CheckServiceStatus(hostname, "LanmanServer");
			DWORD srv2Running = CheckServiceStatus(hostname, "srv2");
			DWORD srvnetRunning = CheckServiceStatus(hostname, "srvnet");

			BeaconFormatPrintf(&OutputBuffer, "\n  --------------------CHECKING SERVICES----------------------\n\n");
			BeaconFormatPrintf(&OutputBuffer, "  [*] LanmanServer\n");
			BeaconFormatPrintf(&OutputBuffer, "          |------- state:     %s\n", lanmanRunning ? "Running" : "Stopped");
			BeaconFormatPrintf(&OutputBuffer, "          |------- starttype: %s\n",
				lanmanStartType == SERVICE_DEMAND_START ? "MANUAL" :
				lanmanStartType == SERVICE_AUTO_START ? "AUTO" :
				lanmanStartType == SERVICE_DISABLED ? "DISABLED" : "UNKNOWN");
			BeaconFormatPrintf(&OutputBuffer, "          |------- path:      %s\n\n", lanmanBinPath);
			BeaconFormatPrintf(&OutputBuffer, "  [*] srv2\n");
			BeaconFormatPrintf(&OutputBuffer, "          |------- state:     %s\n", srv2Running ? "Running" : "Stopped");
			BeaconFormatPrintf(&OutputBuffer, "          |------- starttype: %s\n",
				srv2StartType == SERVICE_DEMAND_START ? "MANUAL" :
				srv2StartType == SERVICE_AUTO_START ? "AUTO" :
				srv2StartType == SERVICE_DISABLED ? "DISABLED" : "UNKNOWN");
			BeaconFormatPrintf(&OutputBuffer, "          |------- path:      %s\n\n", srv2BinPath);
			BeaconFormatPrintf(&OutputBuffer, "  [*] srvnet\n");
			BeaconFormatPrintf(&OutputBuffer, "          |------- state:     %s\n", srvnetRunning ? "Running" : "Stopped");
			BeaconFormatPrintf(&OutputBuffer, "          |------- starttype: %s\n",
				srvnetStartType == SERVICE_DEMAND_START ? "MANUAL" :
				srvnetStartType == SERVICE_AUTO_START ? "AUTO" :
				srvnetStartType == SERVICE_DISABLED ? "DISABLED" : "UNKNOWN");
			BeaconFormatPrintf(&OutputBuffer, "          |------- path:      %s\n\n", srvnetBinPath);
			BeaconFormatPrintf(&OutputBuffer, "  ----------------------------------------------------------\n\n\n");

			if (srvnetRunning == TRUE) {
				BeaconFormatPrintf(&OutputBuffer, "  [+] 445/tcp bound - TRUE\n\n");
			} else if (srvnetRunning == FALSE) {
				BeaconFormatPrintf(&OutputBuffer, "  [+] 445/tcp bound - FALSE\n\n");
			} else {
				BeaconFormatPrintf(&OutputBuffer, "  [!] Error occured while checking relevant services...\n\n");
			}

		} else if (strcmp(action, "start") == 0) {
			DWORD integrityLevel = CheckProcessIntegrityLevel();
			if (integrityLevel != SECURITY_MANDATORY_SYSTEM_RID && integrityLevel != SECURITY_MANDATORY_HIGH_RID) {
				BeaconFormatPrintf(&OutputBuffer, "  [!] You should be running at a SYSTEM or HIGH integrity level for this functionality.\n");
				goto go_output;
			}

			DWORD configLanmanResult = ConfigTargetService(hostname, "LanmanServer", NULL, 0, SERVICE_AUTO_START);
			DWORD startLanmanResult = StartTargetService(hostname, "LanmanServer");

			if (configLanmanResult == ERROR_SUCCESS && startLanmanResult == ERROR_SUCCESS) {
				BeaconFormatPrintf(&OutputBuffer, "\n  ----------------RESUME SMB FUNCTIONALITY------------\n\n");
				BeaconFormatPrintf(&OutputBuffer, "  [*] LanmanServer\n");
				BeaconFormatPrintf(&OutputBuffer, "       |--- action: starttype=Auto\n\n");
				BeaconFormatPrintf(&OutputBuffer, "  [*] LanmanServer\n");
				BeaconFormatPrintf(&OutputBuffer, "       |--- action: Started\n\n");
				BeaconFormatPrintf(&OutputBuffer, "  ----------------------------------------------------\n\n\n");
				BeaconFormatPrintf(&OutputBuffer, "  [+] 445/tcp bound - TRUE\n\n");
			}

		} else if (strcmp(action, "stop") == 0) {
			DWORD integrityLevel = CheckProcessIntegrityLevel();
			if (integrityLevel != SECURITY_MANDATORY_SYSTEM_RID && integrityLevel != SECURITY_MANDATORY_HIGH_RID) {
				BeaconFormatPrintf(&OutputBuffer, "  [!] You should be running at a SYSTEM or HIGH integrity level for this functionality.\n");
				goto go_output;
			}

			DWORD configLanmanResult = ConfigTargetService(hostname, "LanmanServer", NULL, 0, SERVICE_DISABLED);
			DWORD stopLanmanResult = StopTargetService(hostname, "LanmanServer");
			DWORD stopSrv2Result = StopTargetService(hostname, "srv2");
			DWORD stopSrvnetResult = StopTargetService(hostname, "srvnet");

			if (configLanmanResult == ERROR_SUCCESS && stopLanmanResult == ERROR_SUCCESS && stopSrv2Result == ERROR_SUCCESS && stopSrvnetResult == ERROR_SUCCESS) {
				BeaconFormatPrintf(&OutputBuffer, "\n  -------------STOPPING SMB FUNCTIONALITY----------\n\n");
				BeaconFormatPrintf(&OutputBuffer, "  [*] LanmanServer\n");
				BeaconFormatPrintf(&OutputBuffer, "       |--- action: starttype=Disabled\n\n");
				BeaconFormatPrintf(&OutputBuffer, "  [*] LanmanServer\n");
				BeaconFormatPrintf(&OutputBuffer, "       |--- action: Stopped\n\n");
				BeaconFormatPrintf(&OutputBuffer, "  [*] srv2\n");
				BeaconFormatPrintf(&OutputBuffer, "       |--- action: Stopped\n\n");
				BeaconFormatPrintf(&OutputBuffer, "  [*] srvnet\n");
				BeaconFormatPrintf(&OutputBuffer, "       |--- action: Stopped\n\n");
				BeaconFormatPrintf(&OutputBuffer, "  ----------------------------------------------------\n\n\n");
				BeaconFormatPrintf(&OutputBuffer, "  [+] 445/tcp bound - FALSE\n\n");
			}

		} else {
			BeaconPrintf(CALLBACK_OUTPUT, "[!] Unknown action: '%s'. Use: check, start, or stop\n", action);
			BeaconFormatFree(&OutputBuffer);
			return;
		}

	// Fix #5: Use BeaconOutput with length instead of BeaconPrintf with %s
	go_output:
		{
			int outlen = 0;
			char* out = BeaconFormatToString(&OutputBuffer, &outlen);
			if (out && outlen > 0) {
				BeaconOutput(CALLBACK_OUTPUT, out, outlen);
			}
		}
		BeaconFormatFree(&OutputBuffer);
    }


}

// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
    bof::runMocked<const char *, const char *>(go, "127.0.0.1", "check");
    return 0;
}

// Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>

TEST(BofTest, Test1) {
    std::vector<bof::output::OutputEntry> got =
        bof::runMocked<>(go);
    std::vector<bof::output::OutputEntry> expected = {
        {CALLBACK_OUTPUT, "System Directory: C:\\Windows\\system32"}
    };
    // It is possible to compare the OutputEntry vectors, like directly
    // ASSERT_EQ(expected, got);
    // However, in this case, we want to compare the output, ignoring the case.
    ASSERT_EQ(expected.size(), got.size());
    ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
}
#endif