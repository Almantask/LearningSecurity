using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using LearningSecurity.Windows.Principal;
using Xunit;

namespace LearningSecurity.Windows.Tests
{
    public class ImpersonationTests
    {
        public class RunAs
        {
            [Fact(Skip = "Requires a specific user credentials")]
            public void DoesNotThrow_WhenImpersonatedAsAdmin_GivenMethodRequiresAdmin()
            {
                void RequireAdmin() => AccessControl.Require(AccessControl.Role.Administrators);

                Action impersonate = () => Impersonation.RunAs("****", "*****", RequireAdmin);

                impersonate.Should().NotThrow();
            }
        }
    }
}
