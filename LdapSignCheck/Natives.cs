using System;
using System.Runtime.InteropServices;

namespace LdapSignCheck
{
    internal class Natives
    {
        //import
        [DllImport("secur32.dll", SetLastError = true)]
        public static extern int InitializeSecurityContext(
                    ref SECURITY_HANDLE phCredential,//PCredHandle
                    IntPtr phContext, //PCtxtHandle
                    string pszTargetName,
                    int fContextReq,
                    int Reserved1,
                    int TargetDataRep,
                    IntPtr pInput, //PSecBufferDesc SecBufferDesc
                    int Reserved2,
                    out SECURITY_HANDLE phNewContext, //PCtxtHandle
                    out SecBufferDesc pOutput, //PSecBufferDesc SecBufferDesc
                    out uint pfContextAttr, //managed ulong == 64 bits!!!
                    out SECURITY_INTEGER ptsExpiry  //PTimeStamp
                );

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern int InitializeSecurityContext(
                    ref SECURITY_HANDLE phCredential,//PCredHandle
                    ref SECURITY_HANDLE phContext, //PCtxtHandle
                    string pszTargetName,
                    int fContextReq,
                    int Reserved1,
                    int TargetDataRep,
                    ref SecBufferDesc pInput, //PSecBufferDesc SecBufferDesc
                    int Reserved2,
                    out SECURITY_HANDLE phNewContext, //PCtxtHandle
                    out SecBufferDesc pOutput, //PSecBufferDesc SecBufferDesc
                    out uint pfContextAttr, //managed ulong == 64 bits!!!
                    out SECURITY_INTEGER ptsExpiry  //PTimeStamp
                );

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int AcquireCredentialsHandle(
            string pszPrincipal, //SEC_CHAR*
            string pszPackage, //SEC_CHAR* //"Kerberos","NTLM","Negotiative"
            int fCredentialUse,
            IntPtr PAuthenticationID, //_LUID AuthenticationID,//pvLogonID,//PLUID
            ref SEC_WINNT_AUTH_IDENTITY pAuthData,//PVOID
            IntPtr pGetKeyFn, //SEC_GET_KEY_FN
            IntPtr pvGetKeyArgument, //PVOID
            ref SECURITY_HANDLE phCredential, //SecHandle //PCtxtHandle ref
            IntPtr ptsExpiry  //PTimeStamp //TimeStamp ref
        );

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_HANDLE
        {
            public IntPtr LowPart;
            public IntPtr HighPart;

            public SECURITY_HANDLE(int dummy)
            {
                LowPart = HighPart = IntPtr.Zero;
            }
        };

        public enum SecBufferType
        {
            SECBUFFER_VERSION = 0,
            SECBUFFER_EMPTY = 0,
            SECBUFFER_DATA = 1,
            SECBUFFER_TOKEN = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SecBuffer : IDisposable
        {
            public int cbBuffer;
            public int bufferType;
            public IntPtr pvBuffer;

            public SecBuffer(int bufferSize)
            {
                cbBuffer = bufferSize;
                bufferType = (int)SecBufferType.SECBUFFER_TOKEN;
                if (bufferSize > 0)
                {
                    pvBuffer = Marshal.AllocHGlobal(bufferSize);
                }
                else
                {
                    pvBuffer = IntPtr.Zero;
                }
            }

            public SecBuffer(byte[] secBufferBytes)
            {
                cbBuffer = secBufferBytes.Length;
                bufferType = (int)SecBufferType.SECBUFFER_TOKEN;
                pvBuffer = Marshal.AllocHGlobal(cbBuffer);
                Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
            }

            public SecBuffer(byte[] secBufferBytes, SecBufferType bufferType)
            {
                cbBuffer = secBufferBytes.Length;
                this.bufferType = (int)bufferType;
                pvBuffer = Marshal.AllocHGlobal(cbBuffer);
                Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
            }

            public void Dispose()
            {
                if (pvBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pvBuffer);
                    pvBuffer = IntPtr.Zero;
                }
            }

            public byte[] GetBytes()
            {
                byte[] buffer = null;
                if (cbBuffer > 0)
                {
                    buffer = new byte[cbBuffer];
                    Marshal.Copy(pvBuffer, buffer, 0, cbBuffer);
                }
                return buffer;
            }

            public byte[] GetBytes2()
            {
                byte[] buffer = null;
                if (cbBuffer > 0)
                {
                    buffer = new byte[cbBuffer + 2048];
                    Marshal.Copy(pvBuffer, buffer, 0, cbBuffer + 2048);
                }
                return buffer;
            }

            public byte[] GetBytes(int bytes)
            {
                byte[] buffer = null;
                if (cbBuffer > 0)
                {
                    buffer = new byte[cbBuffer + bytes];
                    Marshal.Copy(pvBuffer, buffer, 0, cbBuffer + bytes);
                }
                return buffer;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SecBufferDesc : IDisposable
        {
            public int ulVersion;
            public int cBuffers;
            public IntPtr pBuffers; //Point to SecBuffer

            public SecBufferDesc(int bufferSize)
            {
                ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
                cBuffers = 1;
                SecBuffer secBuffer = new SecBuffer(bufferSize);
                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(secBuffer));
                Marshal.StructureToPtr(secBuffer, pBuffers, false);
            }

            public SecBufferDesc(byte[] secBufferBytes)
            {
                ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
                cBuffers = 1;
                SecBuffer secBuffer = new SecBuffer(secBufferBytes);
                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(secBuffer));
                Marshal.StructureToPtr(secBuffer, pBuffers, false);
            }

            public void Dispose()
            {
                if (pBuffers != IntPtr.Zero)
                {
                    SecBuffer secBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
                    secBuffer.Dispose();
                    Marshal.FreeHGlobal(pBuffers);
                    pBuffers = IntPtr.Zero;
                }
            }

            public SecBuffer GetSecBuffer()
            {
                if (pBuffers == IntPtr.Zero)
                    throw new ObjectDisposedException("SecBufferDesc");
                SecBuffer secBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
                return secBuffer;
            }
        }

        [Flags]
        public enum InitializeContextReqFlags
        {
            None = 0,
            Delegate = 0x00000001,
            MutualAuth = 0x00000002,
            ReplayDetect = 0x00000004,
            SequenceDetect = 0x00000008,
            Confidentiality = 0x00000010,
            UseSessionKey = 0x00000020,
            PromptForCreds = 0x00000040,
            UseSuppliedCreds = 0x00000080,
            AllocateMemory = 0x00000100,
            UseDCEStyle = 0x00000200,
            Datagram = 0x00000400,
            Connection = 0x00000800,
            CallLevel = 0x00001000,
            FragmentSupplied = 0x00002000,
            ExtendedError = 0x00004000,
            Stream = 0x00008000,
            Integrity = 0x00010000,
            Identify = 0x00020000,
            NullSession = 0x00040000,
            ManualCredValidation = 0x00080000,
            Reserved1 = 0x00100000,
            FragmentToFit = 0x00200000,
            ForwardCredentials = 0x00400000,
            NoIntegrity = 0x00800000,
            UseHttpStyle = 0x01000000,
            UnverifiedTargetName = 0x20000000,
            ConfidentialityOnly = 0x40000000,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_INTEGER
        {
            public uint LowPart;
            public int HighPart;

            public SECURITY_INTEGER(int dummy)
            {
                LowPart = 0;
                HighPart = 0;
            }
        };

        [StructLayout(LayoutKind.Sequential)]
        internal sealed class berval
        {
            public int bv_len;
            public IntPtr bv_val = IntPtr.Zero;

            public berval()
            { }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct SEC_WINNT_AUTH_IDENTITY
        {
            public SEC_WINNT_AUTH_IDENTITY(string domain, string user, string password)
            {
                User = user;
                UserLength = (uint)user.Length;
                Domain = domain;
                DomainLength = (uint)domain.Length;
                Password = password;
                PasswordLength = (uint)password.Length;
                Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
            }

            //private const uint SEC_WINNT_AUTH_IDENTITY_ANSI = 0x1;
            private const uint SEC_WINNT_AUTH_IDENTITY_UNICODE = 0x2;
            private readonly String User;
            private readonly uint UserLength;
            private readonly String Domain;
            private readonly uint DomainLength;
            private readonly String Password;
            private readonly uint PasswordLength;
            private readonly uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public sealed class LDAP_TIMEVAL
        {
            public int tv_sec;
            public int tv_usec;
        }

        public enum LdapStatus
        {
            LDAP_SUCCESS = 0,

            //LDAP_OPERATIONS_ERROR = 1,
            //LDAP_PROTOCOL_ERROR = 2,
            LDAP_TIMELIMIT_EXCEEDED = 3,

            LDAP_SIZELIMIT_EXCEEDED = 4,

            //LDAP_COMPARE_FALSE = 5,
            //LDAP_COMPARE_TRUE = 6,
            LDAP_AUTH_METHOD_NOT_SUPPORTED = 7,

            LDAP_STRONG_AUTH_REQUIRED = 8,

            //LDAP_REFERRAL = 9,
            //LDAP_ADMIN_LIMIT_EXCEEDED = 11,
            //LDAP_UNAVAILABLE_CRITICAL_EXTENSION = 12,
            //LDAP_CONFIDENTIALITY_REQUIRED = 13,
            LDAP_SASL_BIND_IN_PROGRESS = 14,

            LDAP_NO_SUCH_ATTRIBUTE = 16,
            LDAP_UNDEFINED_TYPE = 17,

            //LDAP_INAPPROPRIATE_MATCHING = 18,
            LDAP_CONSTRAINT_VIOLATION = 19,

            LDAP_TYPE_OR_VALUE_EXISTS = 20,
            LDAP_INVALID_SYNTAX = 21,

            LDAP_NO_SUCH_OBJECT = 32,

            //LDAP_ALIAS_PROBLEM = 33,
            LDAP_INVALID_DN_SYNTAX = 34,

            //LDAP_IS_LEAF = 35,
            //LDAP_ALIAS_DEREF_PROBLEM = 36,

            //LDAP_INAPPROPRIATE_AUTH = 48,
            LDAP_INVALID_CREDENTIALS = 49,

            LDAP_INSUFFICIENT_ACCESS = 50,
            LDAP_BUSY = 51,
            LDAP_UNAVAILABLE = 52,
            LDAP_UNWILLING_TO_PERFORM = 53,
            //LDAP_LOOP_DETECT = 54,

            //LDAP_NAMING_VIOLATION = 64,
            LDAP_OBJECT_CLASS_VIOLATION = 65,

            LDAP_NOT_ALLOWED_ON_NONLEAF = 66,

            //LDAP_NOT_ALLOWED_ON_RDN = 67,
            LDAP_ALREADY_EXISTS = 68,

            //LDAP_NO_OBJECT_CLASS_MODS = 69,
            //LDAP_RESULTS_TOO_LARGE = 70,
            //LDAP_AFFECTS_MULTIPLE_DSAS = 71,
            //LDAP_OTHER = 80,

            LDAP_SERVER_DOWN = -1,
            //LDAP_LOCAL_ERROR = -2,
            //LDAP_ENCODING_ERROR = -3,
            //LDAP_DECODING_ERROR = -4,
            //LDAP_TIMEOUT = -5,
            //LDAP_AUTH_UNKNOWN = -6,
            //LDAP_FILTER_ERROR = -7,
            //LDAP_USER_CANCELLED = -8,
            //LDAP_PARAM_ERROR = -9,
            //LDAP_NO_MEMORY = -10,
            //LDAP_CONNECT_ERROR = -11,
            //LDAP_NOT_SUPPORTED = -12,
            //LDAP_CONTROL_NOT_FOUND = -13,
            //LDAP_NO_RESULTS_RETURNED = -14,
            //LDAP_MORE_RESULTS_TO_RETURN = -15,

            //LDAP_CLIENT_LOOP = -16,
            //LDAP_REFERRAL_LIMIT_EXCEEDED = -17,
        }

        [DllImport("wldap32", EntryPoint = "ldap_sasl_bind_sA", CharSet = CharSet.Ansi)]
        public static extern int ldap_sasl_bind(
            [In] IntPtr ld,
            string dn, string mechanism,
            IntPtr cred,
            IntPtr serverctrls,
            IntPtr clientctrls,
            out IntPtr msgidp);

        [DllImport("wldap32", EntryPoint = "ldap_get_optionW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int ldap_get_option(IntPtr ld, int option, out int value);

        [DllImport("wldap32", EntryPoint = "ldap_connect", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern uint ldap_connect(IntPtr ld, LDAP_TIMEVAL timeout);

        [DllImport("wldap32", EntryPoint = "ldap_initA", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr ldap_init(string hostname, uint port);

        [DllImport("wldap32", EntryPoint = "ldap_set_optionW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint ldap_set_option(IntPtr ld, uint option, ref uint invalue);

        [DllImport("wldap32", EntryPoint = "ldap_set_optionW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint ldap_set_option(IntPtr ld, uint option, IntPtr pointer);

        [DllImport("wldap32", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int ldap_unbind_s(IntPtr ld);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate bool VERIFYSERVERCERT(
            IntPtr connection,
            IntPtr pServerCert);
    }
}