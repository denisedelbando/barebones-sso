using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using barebones_sso.Models;
using Sustainsys.Saml2;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.Owin;
using Sustainsys.Saml2.WebSso;
using System;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Web.Hosting;
using System.Configuration;

namespace barebones_sso
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context, user manager and signin manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            app.UseSaml2Authentication(CreateSaml2Options());
        }

        private static Saml2AuthenticationOptions CreateSaml2Options()
        {
            var spOptions = new SPOptions
            {
                EntityId = new EntityId(ConfigurationManager.AppSettings["local_id"]),
                ReturnUrl = new Uri(ConfigurationManager.AppSettings["url_callback"])
            };
            var Saml2Options = new Saml2AuthenticationOptions(false)
            {
                SPOptions = spOptions
            };

            var idp = new IdentityProvider(new EntityId(ConfigurationManager.AppSettings["idp_entityid"]), spOptions)
            {
                LoadMetadata = true, 
                MetadataLocation = HostingEnvironment.MapPath(ConfigurationManager.AppSettings["idp_metadatalocation"])
            };

            idp.SigningKeys.AddConfiguredKey(
                new X509Certificate2(
                    HostingEnvironment.MapPath(ConfigurationManager.AppSettings["cert_path"])));

            Saml2Options.IdentityProviders.Add(idp);

            return Saml2Options;
        }

        private static SPOptions CreateSPOptions()
        {
            var swedish = "sv-se";

            var organization = new Organization();
            organization.Names.Add(new LocalizedName("Sustainsys", swedish));
            organization.DisplayNames.Add(new LocalizedName("Sustainsys AB", swedish));
            organization.Urls.Add(new LocalizedUri(new Uri("http://www.Sustainsys.se"), swedish));

            var spOptions = new SPOptions
            {
                EntityId = new EntityId("https://localhost:44303/Saml2"),
                ReturnUrl = new Uri("https://localhost:44303/Account/ExternalLoginCallback"),
                DiscoveryServiceUrl = new Uri("https://localhost:44300/DiscoveryService"),
                Organization = organization
            };

            var techContact = new ContactPerson
            {
                Type = ContactType.Technical
            };
            techContact.EmailAddresses.Add("Saml2@example.com");
            spOptions.Contacts.Add(techContact);

            var supportContact = new ContactPerson
            {
                Type = ContactType.Support
            };
            supportContact.EmailAddresses.Add("support@example.com");
            spOptions.Contacts.Add(supportContact);

            var attributeConsumingService = new AttributeConsumingService
            {
                IsDefault = true,
                ServiceNames = { new LocalizedName("Saml2", "en") }
            };

            attributeConsumingService.RequestedAttributes.Add(
                new RequestedAttribute("urn:someName")
                {
                    FriendlyName = "Some Name",
                    IsRequired = true,
                    NameFormat = RequestedAttribute.AttributeNameFormatUri
                });

            attributeConsumingService.RequestedAttributes.Add(
                new RequestedAttribute("Minimal"));

            spOptions.AttributeConsumingServices.Add(attributeConsumingService);

            spOptions.ServiceCertificates.Add(new X509Certificate2(
                AppDomain.CurrentDomain.SetupInformation.ApplicationBase + "/App_Data/Sustainsys.Saml2.Tests.pfx"));

            return spOptions;
        }
    }
}