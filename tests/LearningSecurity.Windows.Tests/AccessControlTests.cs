using System;
using System.Security;
using FluentAssertions;
using Xunit;
using static LearningSecurity.Windows.Principal.AccessControl;

namespace LearningSecurity.Windows.Tests
{
    public class AccessControlTests
    {
        public class Require
        {
            [Fact(Skip = "Unable to impersonate on a non-administrative account")]
            public void ThrowsSecurityException_GivenAnonymous_WhenRequiredAdministrators()
            {
                Action action = () => Require(Role.Administrators);

                action.Should().Throw<SecurityException>();
            }

            [Fact(Skip = "Unable to impersonate on a non-administrative account")]
            public void DoesNotThrow_GivenNoLogin_WhenRequiredAnonymous()
            {
                Action action = () => Require(Role.Anonymous);

                action.Should().NotThrow();
            }

            [Fact(Skip = "Unable to impersonate on a non-administrative account")]
            public void DoesNotThrow_GivenImpersonatedAdmin_WhenRequiredAnonymous()
            {
                Action action = () => Require(Role.Anonymous);

                action.Should().NotThrow();
            }
        }
    }
}