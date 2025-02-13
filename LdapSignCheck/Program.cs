using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using DnsClient;
using static LdapSignCheck.Natives;

namespace LdapSignCheck
{
    internal class Program
    {
        public static bool ldapCheck(string dc, string username, string password, bool ssl)
        {
            var ldap_phCredential = new SECURITY_HANDLE();
            var ldap_ptsExpiry = new SECURITY_INTEGER();

            SEC_WINNT_AUTH_IDENTITY ident;
            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
            {
                ident = new SEC_WINNT_AUTH_IDENTITY("", username, password);
            }
            else
            {
                ident = new SEC_WINNT_AUTH_IDENTITY();
            }

            var status = AcquireCredentialsHandle(
                null,
                "NTLM",
                2, // Client will use the credentials.
                IntPtr.Zero, // Do not specify LOGON id.
                ref ident, // User information.
                IntPtr.Zero,
                IntPtr.Zero,
                ref ldap_phCredential,
                IntPtr.Zero);

            var timeout = new LDAP_TIMEVAL
            {
                tv_sec = (int)(new TimeSpan(0, 0, 30).Ticks / TimeSpan.TicksPerSecond)
            };
            uint version = 3;
            uint LDAP_OPT_ON = 1;
            IntPtr ld = IntPtr.Zero;

            if (ssl)
            {
                ld = ldap_init(dc, 636);
            }
            else
            {
                ld = ldap_init(dc, 389);
            }
            if (ld == IntPtr.Zero)
            {
                Console.WriteLine("ldap_init failed");
                return false;
            }

            ldap_set_option(ld, 0x0011, ref version);

            if (ssl)
            {
                ldap_get_option(ld, 0x0a, out int lv);  //LDAP_OPT_SSL
                if (lv == 0)
                    ldap_set_option(ld, 0x0a, ref LDAP_OPT_ON);

                ldap_get_option(ld, 0x0095, out lv);  //LDAP_OPT_SIGN
                if (lv == 0)
                    ldap_set_option(ld, 0x0095, ref LDAP_OPT_ON);

                ldap_get_option(ld, 0x0096, out lv);  //LDAP_OPT_ENCRYPT
                if (lv == 0)
                    ldap_set_option(ld, 0x0096, ref LDAP_OPT_ON);

                ldap_set_option(ld, 0x81, //LDAP_OPT_SERVER_CERTIFICATE
                    Marshal.GetFunctionPointerForDelegate<VERIFYSERVERCERT>((connection, serverCert) => true));
            }
            uint res;
            res = ldap_connect(ld, timeout);
            if ((LdapStatus)res != LdapStatus.LDAP_SUCCESS)
            {
                Console.WriteLine("ldap_connect failed: {0}", (LdapStatus)res);
                return false;
            }

            var ldap_ClientToken = new SecBufferDesc(12288);
            var ldap_ClientToken2 = new SecBufferDesc(1288);
            var ldap_ClientToken3 = new SecBufferDesc(12288);
            var ldap_ClientContext = new SECURITY_HANDLE();
            uint ldap_ClientContextAttributes = 0;
            var ldap_ClientLifeTime = new SECURITY_INTEGER();
            var ticket = new SecBuffer();
            var servresp = IntPtr.Zero;
            var Iret = 0;
            int count = 0;

            while (true)
            {
                if (servresp == IntPtr.Zero)
                {
                    if (count >= 3)
                    {
                        ldap_unbind_s(ld);
                        return false;
                    }
                    count++;
                    Iret = InitializeSecurityContext(
                        ref ldap_phCredential,
                        IntPtr.Zero,
                        $"LDAP/{dc}",
                        (int)(InitializeContextReqFlags.AllocateMemory | InitializeContextReqFlags.Delegate | InitializeContextReqFlags.MutualAuth),
                        0,
                        0x00000010,
                        IntPtr.Zero,
                        0,
                        out ldap_ClientContext,
                        out ldap_ClientToken,
                        out ldap_ClientContextAttributes,
                        out ldap_ClientLifeTime);

                    ticket = ldap_ClientToken.GetSecBuffer();
                }
                else
                {
                    Iret = InitializeSecurityContext(
                        ref ldap_phCredential,
                        ref ldap_ClientContext,
                        String.Format("LDAP/{0}", dc),
                        (int)(InitializeContextReqFlags.Connection | InitializeContextReqFlags.Delegate | InitializeContextReqFlags.MutualAuth),
                        0,
                        0x00000010,
                        ref ldap_ClientToken,
                        0,
                        out ldap_ClientContext,
                        out ldap_ClientToken2,
                        out ldap_ClientContextAttributes,
                        out ldap_ClientLifeTime);

                    ticket = ldap_ClientToken2.GetSecBuffer();
                }

                var berval = new berval
                {
                    bv_len = ticket.cbBuffer,
                    bv_val = ticket.pvBuffer
                };
                var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(berval));
                Marshal.StructureToPtr(berval, ptr, false);
                var bind = ldap_sasl_bind(
                    ld,
                    "",
                    "GSSAPI", // GSS-SPNEGO / GSSAPI
                    ptr,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out servresp);
                Marshal.FreeHGlobal(ptr);
                ldap_get_option(ld, 0x0031, out int value);
                //Console.WriteLine("ldap_get_option: {0}", (LdapStatus)value);

                //take token from ldap_sasl_bind
                if (servresp != IntPtr.Zero)
                {
                    berval msgidp2 = (berval)Marshal.PtrToStructure(servresp, typeof(berval));
                    byte[] msgidbytes = new byte[msgidp2.bv_len];
                    Marshal.Copy(msgidp2.bv_val, msgidbytes, 0, msgidp2.bv_len);
                    ldap_ClientToken = new SecBufferDesc(msgidbytes);
                }
                else
                {
                    ldap_ClientToken = new SecBufferDesc(12880);
                }

                if (ssl)
                {
                    if ((LdapStatus)value == LdapStatus.LDAP_INVALID_CREDENTIALS)
                    {
                        Console.WriteLine("[-] LDAPS://{0} has signing enabled or required", dc);
                        ldap_unbind_s(ld);
                        return true;
                    }
                    else if ((LdapStatus)value == LdapStatus.LDAP_SUCCESS)
                    {
                        Console.WriteLine("[+] LDAPS://{0} has not signing enabled", dc);
                        ldap_unbind_s(ld);
                        return false;
                    }
                    else if ((LdapStatus)value == LdapStatus.LDAP_SASL_BIND_IN_PROGRESS)
                    {
                        continue;
                    }
                    else
                    {
                        Console.WriteLine("Unknown error: {0}", (LdapStatus)value);
                        ldap_unbind_s(ld);
                        return false;
                    }
                }
                else
                {
                    if ((LdapStatus)value == LdapStatus.LDAP_STRONG_AUTH_REQUIRED)
                    {
                        Console.WriteLine("[-] LDAP://{0} has signing required", dc);
                        ldap_unbind_s(ld);
                        return true;
                    }
                    else if ((LdapStatus)value == LdapStatus.LDAP_SUCCESS)
                    {
                        Console.WriteLine("[+] LDAP://{0} has not signing required", dc);
                        ldap_unbind_s(ld);
                        return false;
                    }
                    else if ((LdapStatus)value == LdapStatus.LDAP_SASL_BIND_IN_PROGRESS)
                    {
                        continue;
                    }
                    else
                    {
                        Console.WriteLine("Unknown error: {0}", (LdapStatus)value);
                        ldap_unbind_s(ld);
                        return false;
                    }
                }
            }
        }

        public static uint ConvertFromIpAddressToInteger(string ipAddress)
        {
            var address = IPAddress.Parse(ipAddress);
            byte[] bytes = address.GetAddressBytes();

            return BitConverter.ToUInt32(bytes, 0);
        }

        public static LookupClient client = null;
        public static Dictionary<string, string> getDCs(string domain, string username, string password, string domainController)
        {
            Dictionary<string, string> list = new Dictionary<string, string>();
            string endpoint = "";
            if (string.IsNullOrEmpty(domainController))
            {
                endpoint = domain;
            }
            else
            {
                endpoint = domainController;
            }
            DirectoryEntry directoryEntry = new DirectoryEntry(String.Concat("LDAP://", endpoint), username, password);
            DirectorySearcher searcher = new DirectorySearcher(directoryEntry);
            searcher.Filter = "(&(objectCategory=computer)(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";
            searcher.PropertiesToLoad.AddRange(new string[] { "dnshostname" });
            foreach (SearchResult result in searcher.FindAll())
            {
                DirectoryEntry entry = result.GetDirectoryEntry();
                string ipv4 = "";
                string hostname = entry.Properties["dnshostname"].Value.ToString();
                
                if (client != null)
                {
                    var a = client.Query(hostname, QueryType.A);
                    if (a.Answers.Count() > 0 && a.Answers.ARecords().Count() > 0 && !string.IsNullOrEmpty(a.Answers.ARecords().FirstOrDefault().Address.ToString()))
                        ipv4 = a.Answers.ARecords().FirstOrDefault().Address.ToString();
                }

                list.Add(hostname, ipv4);
            }
            return list;
        }

        public static Dictionary<string, string> getDCs()
        {
            Dictionary<string, string> list = new Dictionary<string, string>();

            Domain domain = Domain.GetCurrentDomain();

            foreach (DomainController dc in domain.DomainControllers)
            {
                list.Add(dc.Name, dc.IPAddress);
            }
            return list;
        }

        public static void showHelp()
        {
            Console.WriteLine();
            Console.WriteLine("LdapSignScan");
            Console.WriteLine("By @Cube0x0");
            Console.WriteLine();
            Console.WriteLine("Examples: ");
            Console.WriteLine("LdapSignScan.exe");
            Console.WriteLine("LdapSignScan.exe -domain lab.local -user domain_user -password Password123! -dc-ip 192.168.1.10");
        }

        private static void Main(string[] args)
        {
            string domain = "";
            string username = "";
            string password = "";
            string domainController = "";
            Dictionary<string, string> DCs = new Dictionary<string, string>();

            foreach (var entry in args.Select((value, index) => new { index, value }))
            {
                string argument = entry.value.ToUpper();

                switch (argument)
                {
                    case "-DOMAIN":
                    case "/DOMAIN":
                        domain = args[entry.index + 1];
                        break;

                    case "-USER":
                    case "/USER":
                        username = args[entry.index + 1];
                        break;

                    case "-PASSWORD":
                    case "/PASSWORD":
                        password = args[entry.index + 1];
                        break;
                    case "-DC-IP":
                    case "/DC-IP":
                        domainController = args[entry.index + 1];
                        break;
                    case "-H":
                    case "/H":
                        showHelp();
                        return;
                }
            }

            if (!string.IsNullOrEmpty(domainController))
            {
                client = new LookupClient(new IPEndPoint(ConvertFromIpAddressToInteger(domainController), 53));
                client.UseTcpOnly = true;
                client.UseCache = false;
            }

            if (!string.IsNullOrEmpty(domain) && !string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                DCs = getDCs(domain, username, password, domainController);
            else
                DCs = getDCs();

            foreach (var dc in DCs)
            {
                Console.WriteLine("[*] Checking LDAP signing on {0} - {1}", dc.Key, dc.Value);
                if (!string.IsNullOrEmpty(dc.Value))
                {
                    ldapCheck(dc.Value, username, password, false);
                    ldapCheck(dc.Value, username, password, true);
                }
                else
                {
                    ldapCheck(dc.Key, username, password, false);
                    ldapCheck(dc.Key, username, password, true);
                }
                int a = 5; 
                int b = 10;
                int sum = a + b;
                Console.WriteLine($"The sum of a and b is: {sum}.");
                Console.WriteLine();
            }
        }
    }
}
