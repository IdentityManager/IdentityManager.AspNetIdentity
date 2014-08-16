/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license
 */

using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Thinktecture.IdentityManager;

namespace Thinktecture.IdentityManager.AspNetIdentity
{
    public class AspNetIdentityManagerService<TUser, TKey> : IIdentityManagerService
        where TUser : class, IUser<TKey>, new()
        where TKey : IEquatable<TKey>
    {
        protected Microsoft.AspNet.Identity.UserManager<TUser, TKey> userManager;
        protected Func<string, TKey> ConvertSubjectToKey;
        Func<Task<IdentityManagerMetadata>> metadataFunc;

        AspNetIdentityManagerService(UserManager<TUser, TKey> userManager)
        {
            if (userManager == null) throw new ArgumentNullException("userManager");

            if (!userManager.SupportsQueryableUsers)
            {
                throw new InvalidOperationException("UserManager must support queryable users.");
            }

            this.userManager = userManager;

            if (userManager.UserTokenProvider == null)
            {
                userManager.UserTokenProvider = new TokenProvider<TUser, TKey>();
            }

            var keyType = typeof(TKey);
            if (keyType == typeof(string)) ConvertSubjectToKey = subject => (TKey)ParseString(subject);
            else if (keyType == typeof(int)) ConvertSubjectToKey = subject => (TKey)ParseInt(subject);
            else if (keyType == typeof(long)) ConvertSubjectToKey = subject => (TKey)ParseLong(subject);
            else if (keyType == typeof(Guid)) ConvertSubjectToKey = subject => (TKey)ParseGuid(subject);
            else
            {
                throw new InvalidOperationException("Key type not supported");
            }
        }
        
        public AspNetIdentityManagerService(
            UserManager<TUser, TKey> userManager,
            bool includeAccountProperties = true)
            :this(userManager)
        {
            this.metadataFunc = () => Task.FromResult(GetStandardMetadata(includeAccountProperties));
        }

        public AspNetIdentityManagerService(
           UserManager<TUser, TKey> userManager,
           IdentityManagerMetadata metadata)
            : this(userManager, ()=>Task.FromResult(metadata))
        {
        }
        
        public AspNetIdentityManagerService(
           UserManager<TUser, TKey> userManager,
           Func<Task<IdentityManagerMetadata>> metadataFunc)
            : this(userManager)
        {
            this.metadataFunc = metadataFunc;
        }

        object ParseString(string sub)
        {
            return sub;
        }
        object ParseInt(string sub)
        {
            int key;
            if (!Int32.TryParse(sub, out key)) return 0;
            return key;
        }
        object ParseLong(string sub)
        {
            long key;
            if (!Int64.TryParse(sub, out key)) return 0;
            return key;
        }
        object ParseGuid(string sub)
        {
            Guid key;
            if (!Guid.TryParse(sub, out key)) return Guid.Empty;
            return key;
        }

        public IdentityManagerMetadata GetStandardMetadata(bool includeAccountProperties = true)
        {
            var update = new List<PropertyMetadata>();
            if (this.userManager.SupportsUserPassword)
            {
                update.Add(PropertyMetadata.FromFunctions<TUser, string>(Constants.ClaimTypes.Password, x => null, SetPassword, name: "Password", dataType: PropertyDataType.Password, required: true));
            }
            if (this.userManager.SupportsUserEmail)
            {
                update.Add(PropertyMetadata.FromFunctions<TUser, string>(Constants.ClaimTypes.Email, GetEmail, SetEmail, name: "Email", dataType: PropertyDataType.Email));
            }
            if (this.userManager.SupportsUserPhoneNumber)
            {
                update.Add(PropertyMetadata.FromFunctions<TUser, string>(Constants.ClaimTypes.Phone, GetPhone, SetPhone, name: "Phone", dataType: PropertyDataType.String));
            }

            update.Add(PropertyMetadata.FromFunctions<TUser, string>(Constants.ClaimTypes.Name, GetName, SetName, name: "Name", dataType: PropertyDataType.String));

            if (includeAccountProperties)
            {
                update.AddRange(PropertyMetadata.FromType<TUser>());
            }

            var create = new List<PropertyMetadata>();
            create.Add(PropertyMetadata.FromProperty<TUser>(x => x.UserName, type:Constants.ClaimTypes.Username, required:true));
            create.Add(PropertyMetadata.FromFunctions<TUser, string>(Constants.ClaimTypes.Password, x => null, SetPassword, name: "Password", dataType: PropertyDataType.Password, required: true));

            var user = new UserMetadata
            {
                SupportsCreate = true,
                SupportsDelete = true,
                SupportsClaims = this.userManager.SupportsUserClaim,
                CreateProperties = create,
                UpdateProperties = update
            };

            var meta = new IdentityManagerMetadata
            {
                UserMetadata = user
            };
            return meta;
        }

        protected void SetPassword(TUser user, string password)
        {
            var token = this.userManager.GeneratePasswordResetToken(user.Id);
            this.userManager.ResetPassword(user.Id, token, password);
        }

        protected string GetEmail(TUser user)
        {
            return userManager.GetEmail(user.Id);
        }
        protected void SetEmail(TUser user, string email)
        {
            this.userManager.SetEmail(user.Id, email);
            if (!String.IsNullOrWhiteSpace(email))
            {
                var token = this.userManager.GenerateEmailConfirmationToken(user.Id);
                this.userManager.ConfirmEmail(user.Id, token);
            }
        }

        protected string GetPhone(TUser user)
        {
            return userManager.GetPhoneNumber(user.Id);
        }
        protected void SetPhone(TUser user, string phone)
        {
            this.userManager.SetPhoneNumber(user.Id, phone);
            if (!String.IsNullOrWhiteSpace(phone))
            {
                var token = this.userManager.GenerateChangePhoneNumberToken(user.Id, phone);
                this.userManager.ChangePhoneNumberAsync(user.Id, phone, token);
            }
        }

        protected string GetName(TUser user)
        {
            return userManager.GetClaims(user.Id).Where(x => x.Type == Constants.ClaimTypes.Name).Select(x => x.Value).FirstOrDefault();
        }
        protected void SetName(TUser user, string name)
        {
            var claims = this.userManager.GetClaims(user.Id).Where(x => x.Type == Constants.ClaimTypes.Name).ToArray();
            foreach (var claim in claims)
            {
                this.userManager.RemoveClaim(user.Id, claim);
            }
            if (!String.IsNullOrWhiteSpace(name))
            {
                this.userManager.AddClaim(user.Id, new Claim(Constants.ClaimTypes.Name, name));
            }
        }

        public Task<IdentityManagerMetadata> GetMetadataAsync()
        {
            return this.metadataFunc();
        }

        public Task<IdentityManagerResult<QueryResult>> QueryUsersAsync(string filter, int start, int count)
        {
            var query =
                from user in userManager.Users
                orderby user.UserName
                select user;

            if (!String.IsNullOrWhiteSpace(filter))
            {
                query =
                    from user in query
                    where user.UserName.Contains(filter)
                    orderby user.UserName
                    select user;
            }

            int total = query.Count();
            var users = query.Skip(start).Take(count).ToArray();

            var result = new QueryResult();
            result.Start = start;
            result.Count = count;
            result.Total = total;
            result.Filter = filter;
            result.Users = users.Select(x =>
            {
                var user = new UserResult
                {
                    Subject = x.Id.ToString(),
                    Username = x.UserName,
                    Name = DisplayNameFromUser(x)
                };

                return user;
            }).ToArray();

            return Task.FromResult(new IdentityManagerResult<QueryResult>(result));
        }

        protected virtual string DisplayNameFromUser(TUser user)
        {
            if (userManager.SupportsUserClaim)
            {
                var claims = userManager.GetClaims(user.Id);
                var name = claims.Where(x => x.Type == Thinktecture.IdentityManager.Constants.ClaimTypes.Name).Select(x => x.Value).FirstOrDefault();
                if (!String.IsNullOrWhiteSpace(name))
                {
                    return name;
                }
            }
            return null;
        }

        public async Task<IdentityManagerResult<CreateResult>> CreateUserAsync(IEnumerable<Thinktecture.IdentityManager.UserClaim> properties)
        {
            var usernameClaim = properties.Single(x => x.Type == Constants.ClaimTypes.Username);
            var passwordClaim = properties.Single(x => x.Type == Constants.ClaimTypes.Password);

            var username = usernameClaim.Value;
            var password = passwordClaim.Value;

            string[] exclude = new string[] { Constants.ClaimTypes.Username, Constants.ClaimTypes.Password };
            var otherProperties = properties.Where(x => !exclude.Contains(x.Type)).ToArray();

            var metadata = await GetMetadataAsync();
            var createProps = metadata.UserMetadata.GetCreateProperties();

            TUser user = new TUser { UserName = username };
            foreach (var prop in otherProperties)
            {
                SetProperty(createProps, user, prop.Type, prop.Value);
            }
            
            var result = await this.userManager.CreateAsync(user, password);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult<CreateResult>(result.Errors.ToArray());
            }

            return new IdentityManagerResult<CreateResult>(new CreateResult { Subject = user.Id.ToString() });
        }

        public async Task<IdentityManagerResult> DeleteUserAsync(string subject)
        {
            TKey key = ConvertSubjectToKey(subject);
            var user = await this.userManager.FindByIdAsync(key);
            if (user == null)
            {
                return new IdentityManagerResult("Invalid subject");
            }

            var result = await this.userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult<CreateResult>(result.Errors.ToArray());
            }

            return IdentityManagerResult.Success;
        }

        public async Task<IdentityManagerResult<UserDetail>> GetUserAsync(string subject)
        {
            TKey key = ConvertSubjectToKey(subject);
            var user = await this.userManager.FindByIdAsync(key);
            if (user == null)
            {
                return new IdentityManagerResult<UserDetail>((UserDetail)null);
            }

            var result = new UserDetail
            {
                Subject = subject,
                Username = user.UserName,
                Name = DisplayNameFromUser(user),
            };

            var metadata = await GetMetadataAsync();

            var props =
                from prop in metadata.UserMetadata.UpdateProperties
                select new UserClaim
                {
                    Type = prop.Type,
                    Value = GetProperty(prop, user)
                };
            result.Properties = props.ToArray();
            
            if (userManager.SupportsUserClaim)
            {
                var userClaims = await userManager.GetClaimsAsync(key);
                var claims = new List<Thinktecture.IdentityManager.UserClaim>();
                if (userClaims != null)
                {
                    claims.AddRange(userClaims.Select(x => new Thinktecture.IdentityManager.UserClaim { Type = x.Type, Value = x.Value }));
                }
                result.Claims = claims.ToArray();
            }

            return new IdentityManagerResult<UserDetail>(result);
        }

        public async Task<IdentityManagerResult> SetPropertyAsync(string subject, string type, string value)
        {
            TKey key = ConvertSubjectToKey(subject);
            var user = await this.userManager.FindByIdAsync(key);
            if (user == null)
            {
                return new IdentityManagerResult<UserDetail>((UserDetail)null);
            }

            var errors = ValidateProperty(type, value);
            if (errors.Any())
            {
                return new IdentityManagerResult(errors.ToArray());
            }

            var metadata = await GetMetadataAsync();
            SetProperty(metadata.UserMetadata.UpdateProperties, user, type, value);
            
            var result = userManager.Update(user);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult<CreateResult>(result.Errors.ToArray());
            }

            return IdentityManagerResult.Success;
        }

        public async Task<IdentityManagerResult> AddClaimAsync(string subject, string type, string value)
        {
            TKey key = ConvertSubjectToKey(subject);
            var user = await this.userManager.FindByIdAsync(key);
            if (user == null)
            {
                return new IdentityManagerResult("Invalid subject");
            } 
            
            var existingClaims = await userManager.GetClaimsAsync(key);
            if (!existingClaims.Any(x => x.Type == type && x.Value == value))
            {
                var result = await this.userManager.AddClaimAsync(key, new System.Security.Claims.Claim(type, value));
                if (!result.Succeeded)
                {
                    return new IdentityManagerResult<CreateResult>(result.Errors.ToArray());
                }
            }

            return IdentityManagerResult.Success;
        }

        public async Task<IdentityManagerResult> RemoveClaimAsync(string subject, string type, string value)
        {
            TKey key = ConvertSubjectToKey(subject);
            var user = await this.userManager.FindByIdAsync(key);
            if (user == null)
            {
                return new IdentityManagerResult("Invalid subject");
            } 
            
            var result = await this.userManager.RemoveClaimAsync(key, new System.Security.Claims.Claim(type, value));
            if (!result.Succeeded)
            {
                return new IdentityManagerResult<CreateResult>(result.Errors.ToArray());
            }

            return IdentityManagerResult.Success;
        }

        private IEnumerable<string> ValidateProperty(string type, string value)
        {
            return Enumerable.Empty<string>();
        }

        private string GetProperty(PropertyMetadata propMetadata, TUser user)
        {
            string val;
            if (propMetadata.TryGet(user, out val))
            {
                return val;
            }

            throw new Exception("Invalid property type " + propMetadata.Type);
        }

        private void SetProperty(IEnumerable<PropertyMetadata> propsMeta, TUser user, string type, string value)
        {
            if (propsMeta.TrySet(user, type, value))
            {
                return;
            }

            throw new Exception("Invalid property type " + type);
        }
    }
}
