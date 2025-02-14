#include <Windows.h>
#include "base\helpers.h"

#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#include "base\mock.h"
#endif

extern "C" {
#include "beacon.h"
#include "known_protocols.h"
#include "known_providers.h"

    FORCEINLINE VOID ToUpperW(IN CONST PWCHAR String)
	{
        for (INT i = 0; String[i] != L'\0'; i++)
        {
            if (String[i] >= L'a' && String[i] <= L'z')
            {
                String[i] -= (L'a' - L'A');
            }
        }
    }

    VOID go(IN PCHAR Arguments, IN INT Length)
	{
        DFR_LOCAL(RPCRT4, RpcStringBindingComposeW);
        DFR_LOCAL(RPCRT4, RpcBindingFromStringBindingW);
        DFR_LOCAL(RPCRT4, RpcBindingToStringBindingW);
        DFR_LOCAL(RPCRT4, RpcStringBindingParseW);
        DFR_LOCAL(RPCRT4, RpcBindingSetAuthInfoW);
        DFR_LOCAL(RPCRT4, RpcMgmtEpEltInqBegin);
        DFR_LOCAL(RPCRT4, RpcMgmtEpEltInqNextW);
        DFR_LOCAL(RPCRT4, RpcMgmtInqIfIds);
        DFR_LOCAL(RPCRT4, RpcIfIdVectorFree);
        DFR_LOCAL(RPCRT4, RpcStringFreeW);
        DFR_LOCAL(RPCRT4, RpcBindingFree);
        DFR_LOCAL(RPCRT4, UuidToStringW);

        //
        // Extract the arguments
        //

        PARSER Parser{};

        BeaconDataParse(&Parser, Arguments, Length);

        CONST AUTO   Server{ reinterpret_cast<RPC_WSTR>(BeaconDataExtract(&Parser, nullptr)) };
        CONST USHORT Port  { static_cast<USHORT>(BeaconDataShort(&Parser)) };

        RPC_WSTR ProtocolSequence{};

        switch (Port)
        {
			case 445:
	        case 139:
	        {
                ProtocolSequence = (RPC_WSTR)L"ncacn_np";
                break;
	        }

			case 443:
            case 593:
            {
                ProtocolSequence = (RPC_WSTR)L"ncacn_http";
                break;
            }

			case 135:
			default:
            {
                ProtocolSequence = (RPC_WSTR)L"ncacn_ip_tcp";
                break;
            }
        }

        //
        // Compose the string binding
        //

        RPC_WSTR   StringBinding{};
        RPC_STATUS Status       { RpcStringBindingComposeW(nullptr, ProtocolSequence, Server, nullptr, nullptr, &StringBinding) };

        if (Status != RPC_S_OK)
        {
            BeaconPrintf(CALLBACK_ERROR, "RpcStringBindingCompose failed composing a string binding: %d\n", Status);
            return;
        }

        RPC_BINDING_HANDLE BindingHandle{};

        do
        {
            //
			// Create the real binding
			//

            Status = RpcBindingFromStringBindingW(StringBinding, &BindingHandle);

            if (Status != RPC_S_OK)
            {
                BeaconPrintf(CALLBACK_ERROR, "RpcBindingFromStringBindingW failed creating a binding to the specified server: %d\n", Status);
                break;
            }

            //
            // Authenticate using the current identity. Not needed for port 135 and 593
            //

            if (Port != 135 && Port != 493)
            {
            	Status = RpcBindingSetAuthInfoW(BindingHandle, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_WINNT, nullptr, RPC_C_AUTHZ_NONE);

                if (Status != RPC_S_OK)
                {
                    BeaconPrintf(CALLBACK_ERROR, "RpcBindingSetAuthInfoW failed setting the binding handle's authentication: %d\n", Status);
                    break;
                }
            }

            //
            // Begin enumerating RPC endpoints
            //

            RPC_EP_INQ_HANDLE InquiryHandle{};

            Status = RpcMgmtEpEltInqBegin(BindingHandle, RPC_C_EP_ALL_ELTS, nullptr, 0, nullptr, &InquiryHandle);
            	
        	if (Status != RPC_S_OK)
        	{
        		BeaconPrintf(CALLBACK_ERROR, "RpcMgmtEpEltInqBegin enumerating RPC endpoints: %d\n", Status);
        		break;
        	}

            //
            // Query information about each element in the endpoint map
            //

            RPC_STATUS EnumerationStatus{};

            do
            {
                RPC_IF_ID          InterfaceId       {};
                RPC_BINDING_HANDLE EnumerationBinding{};
                UUID               Uuid              {};
                RPC_WSTR           Annotation        {};

            	EnumerationStatus = RpcMgmtEpEltInqNextW(InquiryHandle, &InterfaceId, &EnumerationBinding, &Uuid, &Annotation);

                if (EnumerationStatus != RPC_S_OK)
                {
                    continue;
                }

            	RPC_WSTR String{};

            	//
            	// Print the UUID
            	//

                Status = UuidToStringW(&InterfaceId.Uuid, &String);

                if (Status == RPC_S_OK && Annotation != nullptr)
                {
                    LPCWSTR CurrentProtocol{};
                    LPCSTR  CurrentProvider{};

                    ToUpperW(reinterpret_cast<PWCHAR>(String));

                    //
                    // Not the most efficient approach, but I cba
                    //

                    for (CONST AUTO& Protocol : KNOWN_PROTOCOLS)
                    {
                        if (__builtin_memcmp(Protocol[0], String, UUID_STRING_SIZE) == 0)
                        {
                            CurrentProtocol = Protocol[1];
                            break;
                        }
                    }

                    for (CONST AUTO& Provider : KNOWN_PROVIDERS)
                    {
	                    if (__builtin_memcmp(Provider[0], &InterfaceId.Uuid, sizeof(UUID) + sizeof(UNICODE_NULL) + 1) == 0)
	                    {
                            CurrentProvider = Provider[1];
                            break;
	                    }
                    }

            		BeaconPrintf(CALLBACK_OUTPUT, "Protocol: %lS\nProvider: %hS\nUUID: %ws v%d.%d %ws", CurrentProtocol, CurrentProvider, String, InterfaceId.VersMajor, InterfaceId.VersMinor, Annotation);

            		RpcStringFreeW(&Annotation);
            		RpcStringFreeW(&String);
            	}

            	//
            	// Print binding
            	//

                Status = RpcBindingToStringBindingW(EnumerationBinding, &String);

                if (Status == RPC_S_OK)
                {
                    BeaconPrintf(CALLBACK_OUTPUT, "Binding: %ws\n", String);
                }
                else
                {
                    BeaconPrintf(CALLBACK_ERROR, "RpcBindingToStringBindingW failed to convert the enumeration binding to a string: %d\n", Status);
                }

                RpcStringFreeW(&String);
            	RpcBindingFree(&EnumerationBinding);

            } while (EnumerationStatus != RPC_X_NO_MORE_ENTRIES);

        } while (FALSE);

        RpcStringFreeW(&StringBinding);

        if (BindingHandle != nullptr)
        {
            RpcBindingFree(&BindingHandle);
        }
	}
}

//
// Define a main function for the debug build
//

#if defined(_DEBUG) && !defined(_GTEST)
#pragma comment(lib, "rpcrt4.lib")

INT wmain(INT argc, PWCHAR argv[])
{
    bof::runMocked(go, argv[1], static_cast<USHORT>(_wtoi(argv[2])));
    return 0;
}

#endif