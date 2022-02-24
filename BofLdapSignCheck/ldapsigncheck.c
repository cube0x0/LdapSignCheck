#define SECURITY_WIN32
#include <windows.h>
#include <security.h>
#include "lib/libc.h"
#include "lib/beacon.h"
#include <winldap.h>

DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$AcquireCredentialsHandleW(SEC_WCHAR*, SEC_WCHAR*, ULONG, PLUID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$InitializeSecurityContextW(PCredHandle, PCtxtHandle, SEC_WCHAR*, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$FreeCredentialsHandle(PCredHandle);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT int WINAPI MSVCRT$snprintf(char * s, size_t n, const char* fmt, ...);
WINBASEAPI int WINAPI KERNEL32$lstrlenA(LPCSTR);
WINBASEAPI int WINAPI KERNEL32$lstrlenW(LPCWSTR);
DECLSPEC_IMPORT int WINAPI MSVCRT$wcscmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int WINAPI MSVCRT$swprintf_s(wchar_t*, size_t, const wchar_t*, ...);

DECLSPEC_IMPORT LDAP *LDAPAPI WLDAP32$ldap_initW(const PWSTR HostName, ULONG PortNumber);
DECLSPEC_IMPORT LDAP *LDAPAPI WLDAP32$ldap_initA(const PSTR HostName, ULONG PortNumber);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_unbind_s(LDAP *ld);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_connect(LDAP *ld, LDAP_TIMEVAL *timeout);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_set_optionW(LDAP *ld, int option, const void *invalue);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_get_optionW(LDAP *ld, int option,  void *invalue);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_sasl_bind_sW(LDAP *ld, const PCHAR dn, const PCHAR mechanism, const BERVAL *cred, PLDAPControlA *serverctrls, PLDAPControlA *clientctrls, PBERVAL *serverdata);

VERIFYSERVERCERT ServerCertCallback;
BOOLEAN _cdecl ServerCertCallback (PLDAP Connection, PCCERT_CONTEXT pServerCert)
{
	return TRUE;
}

BOOL checkLDAP(PCHAR dc, wchar_t* spn, BOOL ssl)
{
	CredHandle hCredential;
	TimeStamp tsExpiry;
	SECURITY_STATUS getHandle = SECUR32$AcquireCredentialsHandleW(
		NULL,
		L"NTLM",
		SECPKG_CRED_OUTBOUND,
		NULL,
		NULL, 
		NULL,
		NULL,
		&hCredential,
		&tsExpiry
	);

	if (hCredential.dwLower == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "[-] AcquireCredentialsHandleW failed: %S\n", getHandle);
		return FALSE;
	}

	//ldap
	ULONG result;
	LDAP* pLdapConnection = NULL;

	if(ssl == TRUE){
		pLdapConnection = WLDAP32$ldap_initW(dc, 636);
	}else{
		pLdapConnection = WLDAP32$ldap_initW(dc, 389);
	}
	if (pLdapConnection == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "[-] Failed to establish LDAP connection");
		return FALSE;
	}

	const int version = LDAP_VERSION3;
	result = WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_VERSION, (void*)&version);
	
	if(ssl == TRUE){
        WLDAP32$ldap_get_optionW(pLdapConnection, LDAP_OPT_SSL, &result);  //LDAP_OPT_SSL
        if (result == 0)
            WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_SSL, LDAP_OPT_ON);

        WLDAP32$ldap_get_optionW(pLdapConnection, LDAP_OPT_SIGN, result);  //LDAP_OPT_SIGN
        if (result == 0)
            WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_SIGN, LDAP_OPT_ON);

        WLDAP32$ldap_get_optionW(pLdapConnection, LDAP_OPT_ENCRYPT, result);  //LDAP_OPT_ENCRYPT
        if (result == 0)
            WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_ENCRYPT, LDAP_OPT_ON);

        WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_SERVER_CERTIFICATE, (void*)&ServerCertCallback ); //LDAP_OPT_SERVER_CERTIFICATE
	}

	result = WLDAP32$ldap_connect(pLdapConnection, NULL);
	if (result != LDAP_SUCCESS)
	{
		BeaconPrintf(CALLBACK_ERROR, "[-] ldap_connect failed:");
		return FALSE;
	}

	ULONG res;
	struct berval* servresp = NULL;

	SecBufferDesc InBuffDesc;
	SecBuffer InSecBuff;

	SECURITY_STATUS initSecurity;
	CtxtHandle newContext;

	SecBuffer secbufPointer = { 0, SECBUFFER_TOKEN, NULL };
	SecBufferDesc output = { SECBUFFER_VERSION, 1, &secbufPointer };

	SecBuffer secbufPointer3 = { 0, SECBUFFER_TOKEN, NULL };
	SecBufferDesc output2 = { SECBUFFER_VERSION, 1, &secbufPointer };

	ULONG contextAttr;
	TimeStamp expiry;

	PSecBuffer ticket;
	int count = 0;
	//loop
	do {
		if(count > 5){
			BeaconPrintf(CALLBACK_ERROR, "[-] stuck in loop");
			break;
		}
		count++;
		if (servresp == NULL) {
			initSecurity = SECUR32$InitializeSecurityContextW(
				&hCredential,
				NULL,
				(SEC_WCHAR*)spn,
				ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MUTUAL_AUTH | ISC_REQ_DELEGATE,
				0,
				SECURITY_NATIVE_DREP,
				NULL,
				0,
				&newContext,
				&output,
				&contextAttr,
				&expiry);

			ticket = output.pBuffers;
			//BeaconPrintf(CALLBACK_OUTPUT, "[-] size : %d\n", (DWORD)ticket->cbBuffer);

			if (ticket->pvBuffer == NULL) {
				BeaconPrintf(CALLBACK_ERROR, "[-] InitializeSecurityContextW failed: %S\n", initSecurity);
				return FALSE;
			}

		}
		else {
			SecBuffer secbufPointer2 = { servresp->bv_len, SECBUFFER_TOKEN, servresp->bv_val };
			SecBufferDesc input = { SECBUFFER_VERSION, 1, &secbufPointer2 };

			initSecurity = SECUR32$InitializeSecurityContextW(
				&hCredential,
				&newContext, //pass cred handle
				(SEC_WCHAR*)spn,
				ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MUTUAL_AUTH | ISC_REQ_DELEGATE,
				0,
				SECURITY_NATIVE_DREP,
				&input, //pass Sec Buffer
				0,
				&newContext,
				&output2,
				&contextAttr,
				&expiry);
			
			ticket = output2.pBuffers;
			//BeaconPrintf(CALLBACK_OUTPUT, "[-] size : %d\n", (DWORD)ticket->cbBuffer);

			if (ticket->pvBuffer == NULL) {
				BeaconPrintf(CALLBACK_ERROR, "[-] InitializeSecurityContextW failed: %S\n", initSecurity);
				return FALSE;
			}
		}

		struct berval cred;
		cred.bv_len = ticket->cbBuffer;
		cred.bv_val = (char*)ticket->pvBuffer;

		//connect
		WLDAP32$ldap_sasl_bind_sW(
			pLdapConnection, // Session Handle
			L"",    // Domain DN
			L"GSSAPI", //auth type
			&cred, //auth
			NULL, //ctrl
			NULL,  //ctrl
			&servresp); // response
		WLDAP32$ldap_get_optionW(pLdapConnection, LDAP_OPT_ERROR_NUMBER, &res);

		// take token from ldap_sasl_bind_sW
		if(servresp->bv_val != NULL){
			output.pBuffers->cbBuffer = servresp->bv_len;
			output.pBuffers->pvBuffer = servresp->bv_val;
		}else{
			BeaconPrintf(CALLBACK_ERROR, "[-] no token back from ldap_sasl_bind_sW");
			return FALSE;
		}

		//BeaconPrintf(CALLBACK_OUTPUT, "ldap_sasl_bind: %D", result);
		//BeaconPrintf(CALLBACK_OUTPUT, "LDAP_OPT_ERROR_NUMBER: %d\n", res);

		if(ssl == TRUE){
			if (res == LDAP_INVALID_CREDENTIALS)
			{
				BeaconPrintf(CALLBACK_OUTPUT, "[-] LDAPS://%S has signing enabled or required", dc);
				WLDAP32$ldap_unbind_s(pLdapConnection);
				return TRUE;
			}
			else if (res == LDAP_SUCCESS)
			{
				BeaconPrintf(CALLBACK_OUTPUT, "[+] LDAPS://%S has not signing enabled", dc);
				WLDAP32$ldap_unbind_s(pLdapConnection);
				return FALSE;
			}
			else if (res == LDAP_SASL_BIND_IN_PROGRESS)
			{
				continue;
			}
			else{
				BeaconPrintf(CALLBACK_ERROR, "[-] Unknown issue");
				return FALSE;
			}
		}else{
			if (res == LDAP_STRONG_AUTH_REQUIRED)
			{
				BeaconPrintf(CALLBACK_OUTPUT, "[-] LDAP://%S has signing required", dc);
				WLDAP32$ldap_unbind_s(pLdapConnection);
				return TRUE;
			}
			else if (res == LDAP_SUCCESS)
			{
				BeaconPrintf(CALLBACK_OUTPUT, "[+] LDAP://%S has not signing required", dc);
				WLDAP32$ldap_unbind_s(pLdapConnection);
				return FALSE;
			}
			else if (res == LDAP_SASL_BIND_IN_PROGRESS)
			{
				continue;
			}
			else{
				BeaconPrintf(CALLBACK_ERROR, "[-] Unknown issue");
				return FALSE;
			}
		}

	} while (res == LDAP_SASL_BIND_IN_PROGRESS);

	return TRUE;
}

void go(char* args, int len)
{
	datap parser;
	
	BeaconDataParse(&parser, args, len);
	
	wchar_t* targetSPN = (wchar_t*)BeaconDataExtract(&parser, NULL);
	wchar_t* targetDC = (wchar_t*)BeaconDataExtract(&parser, NULL);
	
	//BeaconPrintf(CALLBACK_OUTPUT,"[+] Target DC: %S", targetDC);
	//BeaconPrintf(CALLBACK_OUTPUT,"[+] Target SPN: %S\n", targetSPN);

	KERNEL32$LoadLibraryA("WLDAP32");
	checkLDAP(targetDC, targetSPN, FALSE);
	checkLDAP(targetDC, targetSPN, TRUE);
}
