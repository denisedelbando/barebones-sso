using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(barebones_sso.Startup))]

namespace barebones_sso
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }

    }
}