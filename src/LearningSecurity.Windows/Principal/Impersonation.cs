using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace LearningSecurity.Windows.Principal
{
    public class Impersonation
    {
        /// <summary>
        /// Logon for impersonation.
        /// </summary>
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser1(string lpszUsername, string lpszDomain, string lpszPassword,
            int dwLogonType, int dwLogonProvider, out SafeTokenHandle phToken);

        /// <summary>
        /// Logon for running method as.
        /// </summary>
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser2(string lpszUsername, string lpszDomain, string lpszPassword,
            int dwLogonType, int dwLogonProvider, out SafeAccessTokenHandle phToken);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern bool CloseHandle(IntPtr handle);

        // Test harness.
        // If you incorporate this code into a DLL, be sure to demand FullTrust.
        [PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
        public static void RunAs(string userName, string password, Action action, string domain = "")
        {
            var safeTokenHandle = GenerateSafeTokenHandle(userName, domain, password);
            RunMethodUnderUser(safeTokenHandle, action);

            // Uncomment this for proper run as functionality. The below is just for exploration of impersonation.
            // Also change GenerateSafeTokenHandle from SafeTokenHandle to SafeAccessTokenHandle and logon1 to logon2.
            // WindowsIdentity.RunImpersonated(safeTokenHandle, action);
        }

        private static SafeTokenHandle GenerateSafeTokenHandle(string userName, string domainName, string password)
        {
            const int LOGON32_PROVIDER_DEFAULT = 0;
            // causes LogonUser to create a primary token.
            const int LOGON32_LOGON_INTERACTIVE = 2;

            bool returnValue = LogonUser1(userName, domainName, password,
                LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
                out var safeTokenHandle);

            if (!returnValue)
            {
                int error = Marshal.GetLastWin32Error();
                throw new System.ComponentModel.Win32Exception(error);
            }

            return safeTokenHandle;
        }

        private static void RunMethodUnderUser(SafeTokenHandle safeTokenHandle, Action action)
        {
            using (safeTokenHandle)
            {
                var before = WindowsIdentity.GetCurrent().Name;
                string after = null;
                using (var newId = new WindowsIdentity(safeTokenHandle.DangerousGetHandle()))
                {
                    using (WindowsImpersonationContext impersonatedUser = newId.Impersonate())
                    {
                        after = WindowsIdentity.GetCurrent().Name;
                        action();
                    }
                }

                var end = WindowsIdentity.GetCurrent().Name;
            }
        }
    }

    public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeTokenHandle()
            : base(true)
        {
        }

        [DllImport("kernel32.dll")]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        protected override bool ReleaseHandle()
        {
            return CloseHandle(handle);
        }
    }
}
