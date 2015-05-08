using System.Security.Principal;

namespace SampleWCFApiHost
{
    public interface IAuthorizationProvider
    {
        /// <summary>
        /// Evaluates the specified authority against the specified context.
        /// 
        /// </summary>
        /// <param name="principal">Must be an <see cref="T:System.Security.Principal.IPrincipal"/> object.</param><param name="context">Name of the rule to evaluate.</param>
        /// <returns>
        /// <strong>True</strong> if the expression evaluates to true,
        ///             otherwise <strong>false</strong>.
        /// </returns>
        bool Authorize(IPrincipal principal, string context);
    }

    public class CustomAuthorizationProvider : IAuthorizationProvider
    {
        /// <summary>
        /// Evaluates the specified authority against the specified context.
        /// 
        /// </summary>
        /// <param name="principal">Must be an <see cref="T:System.Security.Principal.IPrincipal"/> object.</param><param name="context">Name of the rule to evaluate.</param>
        /// <returns>
        /// <strong>True</strong> if the expression evaluates to true,
        ///             otherwise <strong>false</strong>.
        /// </returns>
        public bool Authorize(IPrincipal principal, string context)
        {

            return false;
        }
    }
}