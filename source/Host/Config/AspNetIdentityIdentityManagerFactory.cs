using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using Thinktecture.IdentityManager;

namespace Thinktecture.IdentityManager.Host
{
    public class AspNetIdentityIdentityManagerFactory
    {
        static AspNetIdentityIdentityManagerFactory()
        {
            System.Data.Entity.Database.SetInitializer(new System.Data.Entity.DropCreateDatabaseIfModelChanges<IdentityDbContext>());

            //System.Data.Entity.Database.SetInitializer(new System.Data.Entity.DropCreateDatabaseIfModelChanges<CustomDbContext>());
        }

        string connString;
        public AspNetIdentityIdentityManagerFactory(string connString)
        {
            this.connString = connString;
        }
        
        public IIdentityManagerService Create()
        {
            var db = new IdentityDbContext<IdentityUser>(this.connString);
            var userStore = new UserStore<IdentityUser>(db);
            var userMgr = new Microsoft.AspNet.Identity.UserManager<IdentityUser>(userStore);
            var roleStore = new RoleStore<IdentityRole>(db);
            var roleMgr = new Microsoft.AspNet.Identity.RoleManager<IdentityRole>(roleStore);

            Thinktecture.IdentityManager.AspNetIdentity.AspNetIdentityManagerService<IdentityUser, string, IdentityRole, string> svc = null;
            svc = new Thinktecture.IdentityManager.AspNetIdentity.AspNetIdentityManagerService<IdentityUser, string, IdentityRole, string>(userMgr, roleMgr, () =>
            {
                var meta = svc.GetStandardMetadata();
                meta.UserMetadata.UpdateProperties =
                    meta.UserMetadata.UpdateProperties.Union(new PropertyMetadata[]{
                        svc.GetMetadataForClaim(Constants.ClaimTypes.Name, "Name")
                    });
                return Task.FromResult(meta);
            });

            return new DisposableIdentityManagerService(svc, db);

            //var db = new CustomDbContext("CustomAspId");
            //var store = new CustomUserStore(db);
            //var mgr = new CustomUserManager(store);
            //return new Thinktecture.IdentityManager.AspNetIdentity.UserManager<CustomUser, int, CustomUserLogin, CustomUserRole, CustomUserClaim>(mgr, db);
        }
    }
}