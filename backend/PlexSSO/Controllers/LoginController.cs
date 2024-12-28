using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using PlexSSO.Model;
using PlexSSO.Model.API;
using PlexSSO.Model.Types;
using PlexSSO.Service.Auth;
using PlexSSO.Service.PlexClient;

namespace PlexSSO.Controllers
{
    [ApiController]
    [Route(Constants.ControllerPath)]
    public class LoginController : CommonAuthController
    {
        private readonly ILogger<LoginController> _logger;
        private readonly IPlexClient _plexClient;
        private readonly IAuthValidator _authValidator;

        public LoginController(ILogger<LoginController> logger,
                               IPlexClient plexClient,
                               IAuthValidator authValidator)
        {
            _logger = logger;
            _plexClient = plexClient;
            _authValidator = authValidator;
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<SsoResponse> Login([FromBody] LoginPost data)
        {
            try
            {
                Identity.AccessToken = new AccessToken(data.Token);

                // Hardcoded server identifiers
                var primaryServerId = "90244d9a956da3afad32f85d6b24a9c24649d681";
                var secondaryServerId = "c6448117a95874f18274f31495ff5118fd291089";

                bool isAuthenticated = false;

                // Check both server identifiers
                var serverIdsToCheck = new[] { primaryServerId, secondaryServerId };
                foreach (var serverId in serverIdsToCheck)
                {
                    var serverIdentifier = new ServerIdentifier(serverId);
                    Identity.AccessTier = await _plexClient.GetAccessTier(serverIdentifier, Identity.AccessToken);

                    if (Identity.AccessTier != AccessTier.NoAccess && Identity.AccessTier != AccessTier.Failure)
                    {
                        Identity.ServerIdentifier = serverIdentifier;
                        isAuthenticated = true;
                        break; // Exit loop once authenticated
                    }
                }

                if (!isAuthenticated)
                {
                    Identity.AccessTier = AccessTier.NoAccess;
                    Identity.IsAuthenticated = false;
                    return GetErrorResponse();
                }

                var user = await _plexClient.GetUserInfo(Identity.AccessToken);
                Identity.Email = user.Email;
                Identity.Username = user.Username;
                Identity.Thumbnail = user.Thumbnail;

                Identity.IsAuthenticated = true;

                var identity = new ClaimsIdentity(
                    Identity.AsClaims(),
                    CookieAuthenticationDefaults.AuthenticationScheme
                );

                var authProperties = new AuthenticationProperties
                {
                    AllowRefresh = true,
                    IsPersistent = true
                };

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(identity),
                    authProperties
                );

                var response = _authValidator.ValidateAuthenticationStatus(Identity, ServiceName, ServiceUri);
                Response.StatusCode = response.Status;
                return response;
            }
            catch (Exception e)
            {
                _logger.LogError("Failed to log user in: {e}", e);
                Identity.AccessTier = AccessTier.NoAccess;
                Identity.IsAuthenticated = false;
                return GetErrorResponse();
            }
        }

        private SsoResponse GetErrorResponse()
        {
            Response.StatusCode = 400;
            return new SsoResponse(false,
                Identity.IsAuthenticated,
                true,
                AccessTier.NoAccess,
                400,
                "An error occurred");
        }
    }
}
