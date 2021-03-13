using System;
using System.Diagnostics;
using System.Security.Permissions;
using System.Security.Principal;
using System.Threading;

namespace LearningSecurity.Windows.Principal
{
    public static class AccessControl
    {
        public static void Require(Role role)
        {
            AppDomain.CurrentDomain.SetPrincipalPolicy(PrincipalPolicy.WindowsPrincipal);
            // var roleName = Enum.GetName(typeof(Role), role);
            var roleName = "Authenticated Users";

            PrincipalPermission principalPerm = new PrincipalPermission(null, roleName);
            
            IPrincipal threadPrincipal = Thread.CurrentPrincipal;
            WindowsIdentity windowsIdentity = WindowsIdentity.GetCurrent();
            foreach (var windowsIdentityGroup in windowsIdentity.Groups)
            {
                Debug.WriteLine(windowsIdentityGroup.Value);
            }

            principalPerm.Demand();
        }

        public enum Role
        {
            Administrators,
            Anonymous
        }
    }


}
