using System.Linq;
using Microsoft.Extensions.Logging;
using PlexSSO.Model;
using PlexSSO.Service.Config;
using PlexSSO.Service.PlexClient;
using static PlexSSO.Service.Config.PlexSsoConfig;

namespace PlexSSO.Service.Auth
{
    public class AuthenticationValidator : IAuthValidator
    {
        private readonly IConfigurationService _configurationService;
        private readonly ILogger<AuthenticationValidator> _logger;

        public AuthenticationValidator(IConfigurationService configurationService,
                                       ILogger<AuthenticationValidator> logger)
        {
            this._configurationService = configurationService;
            this._logger = logger;
        }

        public SsoResponse ValidateAuthenticationStatus(
            AccessTier accessTier,
            bool loggedIn,
            string serviceName,
            string serviceUri,
            string userName
        )
        {
            if (string.IsNullOrWhiteSpace(serviceName) ||
                string.IsNullOrWhiteSpace(serviceUri) ||
                string.IsNullOrWhiteSpace(userName))
            {
                _logger.LogWarning("Some properties which should not be null/empty were null/empty.\n" +
                    "Did you forget to add a header in your reverse proxy?\n" +
                    $"\tserviceName = {serviceName}\n" +
                    $"\tserviceUri = {serviceUri}\n" +
                    $"\tuserName = {userName}");
            }

            var rules = _configurationService.GetAccessControls(serviceName)
                .Where(rule => rule.Path == null || serviceUri.StartsWith(rule.Path));

            var numRules = 0;
            foreach (var rule in rules)
            {
                var block = rule.ControlType == ControlType.Allow ?
                    accessTier.IsHigherTierThan(rule.MinimumAccessTier ?? AccessTier.Failure) :
                    accessTier.IsLowerTierThan(rule.MinimumAccessTier ?? AccessTier.NoAccess);
                
                if (rule.Exempt.Contains(userName))
                {
                    block = !block;
                }

                if (block) {
                    return new SsoResponse(
                        true,
                        loggedIn,
                        true,
                        AccessTier.NoAccess
                    );
                }

                numRules++;
            }

            return new SsoResponse(
                true,
                loggedIn,
                numRules == 0 ? accessTier == AccessTier.NoAccess : false,
                accessTier
            );
        }
    }

    public static class AccessTierExtensions
    {
        public static bool IsLowerTierThan(this AccessTier currentAccess, AccessTier accessTier)
        {
            return currentAccess > accessTier;
        }
        
        public static bool IsHigherTierThan(this AccessTier currentAccess, AccessTier accessTier)
        {
            return currentAccess < accessTier;
        }
    }
}
