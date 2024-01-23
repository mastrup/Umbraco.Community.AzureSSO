using System.IO;
using System.Linq;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Umbraco.Cms.Core;
using Umbraco.Cms.Core.IO;
using Umbraco.Cms.Core.Models.Membership;
using Umbraco.Cms.Core.Security;
using Umbraco.Cms.Core.Services;
using Umbraco.Cms.Web.BackOffice.Security;
using Umbraco.Community.AzureSSO.Settings;
using Umbraco.Extensions;
using System.Security.Cryptography;

namespace Umbraco.Community.AzureSSO
{
	public class MicrosoftAccountBackOfficeExternalLoginProviderOptions : IConfigureNamedOptions<BackOfficeExternalLoginProviderOptions>
	{
		public const string SchemeName = "MicrosoftAccount";

		private readonly AzureSsoSettings _settings;
		private readonly IUserService _userService;
		private readonly MediaFileManager _mediaFileManager;

		public MicrosoftAccountBackOfficeExternalLoginProviderOptions(AzureSsoSettings settings, IUserService userService, MediaFileManager mediaFileManager)
		{
			_settings = settings;
			_userService = userService;
			_mediaFileManager = mediaFileManager;
		}

		public void Configure(string? name, BackOfficeExternalLoginProviderOptions options)
		{
			if (name != $"{Constants.Security.BackOfficeExternalAuthenticationTypePrefix}{SchemeName}")
			{
				return;
			}

			Configure(options);
		}

		public void Configure(BackOfficeExternalLoginProviderOptions options)
		{
			options.ButtonStyle = _settings.ButtonStyle;
			options.Icon = _settings.Icon;
			options.AutoLinkOptions = new ExternalSignInAutoLinkOptions(
					// must be true for auto-linking to be enabled
					autoLinkExternalAccount: true,

					// Optionally specify default user group, else
					// assign in the OnAutoLinking callback
					// (default is editor)
					defaultUserGroups: System.Array.Empty<string>(),

					// Optionally specify the default culture to create
					// the user as. If null it will use the default
					// culture defined in the web.config, or it can
					// be dynamically assigned in the OnAutoLinking
					// callback.
					defaultCulture: null,

					// Optionally you can disable the ability to link/unlink
					// manually from within the back office. Set this to false
					// if you don't want the user to unlink from this external
					// provider.
					allowManualLinking: false
			)
			{
				// Optional callback
				OnAutoLinking = (autoLoginUser, loginInfo) =>
				{
					if (!autoLoginUser.IsApproved)
					{
						SetGroups(autoLoginUser, loginInfo);
						SetName(autoLoginUser, loginInfo);
						if (_settings.SyncUserAvatar)
						{
							SetUserAvatar(autoLoginUser, loginInfo);
						}
					}
				},
				OnExternalLogin = (user, loginInfo) =>
				{
					if (_settings.SetGroupsOnLogin)
					{
						SetGroups(user, loginInfo);
					}
					SetName(user, loginInfo);

					if (_settings.SyncUserAvatar)
					{
						SetUserAvatar(user, loginInfo);
					}

					return true; //returns a boolean indicating if sign in should continue or not.
				}
			};

			// Optionally you can disable the ability for users
			// to login with a username/password. If this is set
			// to true, it will disable username/password login
			// even if there are other external login providers installed.
			options.DenyLocalLogin = _settings.DenyLocalLogin;

			// Optionally choose to automatically redirect to the
			// external login provider so the user doesn't have
			// to click the login button.
			options.AutoRedirectLoginToExternalProvider = _settings.AutoRedirectLoginToExternalProvider;
		}

		private void SetGroups(BackOfficeIdentityUser user, ExternalLoginInfo loginInfo)
		{
			user.Roles.Clear();

			var groups = loginInfo.Principal.Claims.Where(c => _settings.GroupLookup.ContainsKey(c.Value));
			foreach (var group in groups)
			{
				var umbracoGroups = _settings.GroupLookup[group.Value].Split(',');
				foreach (var umbracoGroupAlias in umbracoGroups)
				{
					user.AddRole(umbracoGroupAlias);
				}
			}

			foreach (var group in _settings.DefaultGroups)
			{
				user.AddRole(group);
			}
		}

		private void SetName(BackOfficeIdentityUser user, ExternalLoginInfo loginInfo)
		{
			if (loginInfo.Principal?.Identity?.Name != null)
			{
				user.Name = DisplayName(loginInfo.Principal, defaultValue: loginInfo.Principal.Identity.Name);
				user.UserName = loginInfo.Principal.Identity.Name;
			}
			user.IsApproved = true;
		}

		private void SetUserAvatar(BackOfficeIdentityUser user, ExternalLoginInfo loginInfo)
		{
			if (loginInfo.AuthenticationTokens?.FirstOrDefault(t => t.Name.Equals("access_token"))?.Value is string accessToken)
			{
				using (var httpClient = new HttpClient())
				{
					httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
					var pictureResult = httpClient.GetAsync($"{_settings.MicrosoftGraphEndpoint}/v1.0/me/photo/$value").Result;

					if (pictureResult.IsSuccessStatusCode)
					{
						if (_userService.GetByUsername(user.UserName) is User u && pictureResult.Headers.ETag is EntityTagHeaderValue etag)
						{
							//etag : identifier for a specific version of a resource
							u.Avatar = $"UserAvatars/{etag.ToString().GenerateHash<SHA1>()}.jpg";

							if (u.IsDirty())
							{
								using (var fs = pictureResult.Content.ReadAsStream())
								{
									_mediaFileManager.FileSystem.AddFile(u.Avatar, fs, true);
								}

								_userService.Save(u);
							}
						}
					}

				}
			}
		}

		private string DisplayName(ClaimsPrincipal claimsPrincipal, string defaultValue)
		{
			var displayName = claimsPrincipal.FindFirstValue("name");

			return !string.IsNullOrWhiteSpace(displayName) ? displayName : defaultValue;
		}
	}
}
