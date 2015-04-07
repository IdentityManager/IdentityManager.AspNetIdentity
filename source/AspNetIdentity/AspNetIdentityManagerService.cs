/*
 * Copyright 2014 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityManager;

namespace IdentityManager.AspNetIdentity
{
    public class AspNetIdentityManagerService<TUser, TUserKey, TRole, TRoleKey> : IIdentityManagerService
        where TUser : class, IUser<TUserKey>, new()
        where TUserKey : IEquatable<TUserKey>
        where TRole : class, IRole<TRoleKey>, new()
        where TRoleKey : IEquatable<TRoleKey>
    {
        public string RoleClaimType { get; set; }

        protected Microsoft.AspNet.Identity.UserManager<TUser, TUserKey> userManager;
        protected Func<string, TUserKey> ConvertUserSubjectToKey;

        protected Microsoft.AspNet.Identity.RoleManager<TRole, TRoleKey> roleManager;
        protected Func<string, TRoleKey> ConvertRoleSubjectToKey;

        Func<Task<IdentityManagerMetadata>> metadataFunc;

        AspNetIdentityManagerService(UserManager<TUser, TUserKey> userManager, RoleManager<TRole, TRoleKey> roleManager, Func<string, TUserKey> parseUserSubject = null, Func<string, TRoleKey> parseRoleSubject = null)
        {
            if (userManager == null) throw new ArgumentNullException("userManager");
            if (roleManager == null) throw new ArgumentNullException("roleManager");

            if (!userManager.SupportsQueryableUsers)
            {
                throw new InvalidOperationException("UserManager must support queryable users.");
            }

            this.userManager = userManager;
            this.roleManager = roleManager;

            if (userManager.UserTokenProvider == null)
            {
                userManager.UserTokenProvider = new TokenProvider<TUser, TUserKey>();
            }

            if (parseUserSubject != null)
            {
                ConvertUserSubjectToKey = parseUserSubject;
            }
            else
            {
                var keyType = typeof (TUserKey);
                if (keyType == typeof (string)) ConvertUserSubjectToKey = subject => (TUserKey) ParseString(subject);
                else if (keyType == typeof (int)) ConvertUserSubjectToKey = subject => (TUserKey) ParseInt(subject);
                else if (keyType == typeof (uint)) ConvertUserSubjectToKey = subject => (TUserKey) ParseUInt32(subject);
                else if (keyType == typeof (long)) ConvertUserSubjectToKey = subject => (TUserKey) ParseLong(subject);
                else if (keyType == typeof (Guid)) ConvertUserSubjectToKey = subject => (TUserKey) ParseGuid(subject);
                else
                {
                    throw new InvalidOperationException("User Key type not supported");
                }
            }

            if (parseRoleSubject != null)
            {
                ConvertRoleSubjectToKey = parseRoleSubject;
            }
            else
            {
                var keyType = typeof (TRoleKey);
                if (keyType == typeof (string)) ConvertRoleSubjectToKey = subject => (TRoleKey) ParseString(subject);
                else if (keyType == typeof (int)) ConvertRoleSubjectToKey = subject => (TRoleKey) ParseInt(subject);
                else if (keyType == typeof (uint)) ConvertRoleSubjectToKey = subject => (TRoleKey) ParseUInt32(subject);
                else if (keyType == typeof (long)) ConvertRoleSubjectToKey = subject => (TRoleKey) ParseLong(subject);
                else if (keyType == typeof (Guid)) ConvertRoleSubjectToKey = subject => (TRoleKey) ParseGuid(subject);
                else
                {
                    throw new InvalidOperationException("Role Key type not supported");
                }
            }

            this.RoleClaimType = Constants.ClaimTypes.Role;
        }

        public AspNetIdentityManagerService(
            UserManager<TUser, TUserKey> userManager,
            RoleManager<TRole, TRoleKey> roleManager,
            bool includeAccountProperties = true,
            Func<string, TUserKey> parseUserSubject = null, Func<string, TRoleKey> parseRoleSubject = null)
            : this(userManager, roleManager, parseUserSubject, parseRoleSubject)
        {
            this.metadataFunc = () => Task.FromResult(GetStandardMetadata(includeAccountProperties));
        }

        public AspNetIdentityManagerService(
           UserManager<TUser, TUserKey> userManager,
           RoleManager<TRole, TRoleKey> roleManager,
           IdentityManagerMetadata metadata,
           Func<string, TUserKey> parseUserSubject = null, Func<string, TRoleKey> parseRoleSubject = null)
            : this(userManager, roleManager, () => Task.FromResult(metadata), parseUserSubject, parseRoleSubject)
        {
        }

        public AspNetIdentityManagerService(
           UserManager<TUser, TUserKey> userManager,
           RoleManager<TRole, TRoleKey> roleManager,
           Func<Task<IdentityManagerMetadata>> metadataFunc,
           Func<string, TUserKey> parseUserSubject = null, Func<string, TRoleKey> parseRoleSubject = null)
            : this(userManager, roleManager, parseUserSubject, parseRoleSubject)
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
        object ParseUInt32(string sub)
        {
            uint key;
            if (!UInt32.TryParse(sub, out key)) return 0;
            return key;
        }

        public virtual IdentityManagerMetadata GetStandardMetadata(bool includeAccountProperties = true)
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
            if (this.userManager.SupportsUserTwoFactor)
            {
                update.Add(PropertyMetadata.FromFunctions<TUser, bool>("two_factor", GetTwoFactorEnabled, SetTwoFactorEnabled, name: "Two Factor Enabled", dataType: PropertyDataType.Boolean));
            }
            if (this.userManager.SupportsUserLockout)
            {
                update.Add(PropertyMetadata.FromFunctions<TUser, bool>("locked_enabled", GetLockoutEnabled, SetLockoutEnabled, name: "Lockout Enabled", dataType: PropertyDataType.Boolean));
                update.Add(PropertyMetadata.FromFunctions<TUser, bool>("locked", GetLockedOut, SetLockedOut, name: "Locked Out", dataType: PropertyDataType.Boolean));
            }

            if (includeAccountProperties)
            {
                update.AddRange(PropertyMetadata.FromType<TUser>());
            }

            var create = new List<PropertyMetadata>();
            create.Add(PropertyMetadata.FromProperty<TUser>(x => x.UserName, type: Constants.ClaimTypes.Username, required: true));
            create.Add(PropertyMetadata.FromFunctions<TUser, string>(Constants.ClaimTypes.Password, x => null, SetPassword, name: "Password", dataType: PropertyDataType.Password, required: true));

            var user = new UserMetadata
            {
                SupportsCreate = true,
                SupportsDelete = true,
                SupportsClaims = this.userManager.SupportsUserClaim,
                CreateProperties = create,
                UpdateProperties = update
            };

            var role = new RoleMetadata
            {
                RoleClaimType = this.RoleClaimType,
                SupportsCreate = true,
                SupportsDelete = true,
                CreateProperties = new PropertyMetadata[] {
                    PropertyMetadata.FromProperty<TRole>(x=>x.Name, type:Constants.ClaimTypes.Name, required:true),
                }
            };

            var meta = new IdentityManagerMetadata
            {
                UserMetadata = user,
                RoleMetadata = role
            };
            return meta;
        }

        public virtual PropertyMetadata GetMetadataForClaim(string type, string name = null, PropertyDataType dataType = PropertyDataType.String, bool required = false)
        {
            return PropertyMetadata.FromFunctions<TUser, string>(type, GetForClaim(type), SetForClaim(type), name, dataType, required);
        }
        public virtual Func<TUser, string> GetForClaim(string type)
        {
            return user => userManager.GetClaims(user.Id).Where(x => x.Type == type).Select(x => x.Value).FirstOrDefault();
        }
        public virtual Func<TUser, string, IdentityManagerResult> SetForClaim(string type)
        {
            return (user, value) =>
            {
                var claims = this.userManager.GetClaims(user.Id).Where(x => x.Type == type).ToArray();
                foreach (var claim in claims)
                {
                    var result = this.userManager.RemoveClaim(user.Id, claim);
                    if (!result.Succeeded)
                    {
                        return new IdentityManagerResult(result.Errors.First());
                    }
                }
                if (!String.IsNullOrWhiteSpace(value))
                {
                    var result = this.userManager.AddClaim(user.Id, new Claim(type, value));
                    if (!result.Succeeded)
                    {
                        return new IdentityManagerResult(result.Errors.First());
                    }
                }
                return IdentityManagerResult.Success;
            };
        }

        public virtual IdentityManagerResult SetPassword(TUser user, string password)
        {
            var token = this.userManager.GeneratePasswordResetToken(user.Id);
            var result = this.userManager.ResetPassword(user.Id, token, password);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult(result.Errors.First());
            }
            return IdentityManagerResult.Success;
        }

        public virtual string GetEmail(TUser user)
        {
            return userManager.GetEmail(user.Id);
        }
        public virtual IdentityManagerResult SetEmail(TUser user, string email)
        {
            var result = this.userManager.SetEmail(user.Id, email);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult(result.Errors.First());
            }
            
            if (!String.IsNullOrWhiteSpace(email))
            {
                var token = this.userManager.GenerateEmailConfirmationToken(user.Id);
                result = this.userManager.ConfirmEmail(user.Id, token);
                if (!result.Succeeded)
                {
                    return new IdentityManagerResult(result.Errors.First());
                }
            }
            
            return IdentityManagerResult.Success;
        }

        public virtual string GetPhone(TUser user)
        {
            return userManager.GetPhoneNumber(user.Id);
        }
        public virtual IdentityManagerResult SetPhone(TUser user, string phone)
        {
            var result = this.userManager.SetPhoneNumber(user.Id, phone);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult(result.Errors.First());
            }
            
            if (!String.IsNullOrWhiteSpace(phone))
            {
                var token = this.userManager.GenerateChangePhoneNumberToken(user.Id, phone);
                result = this.userManager.ChangePhoneNumber(user.Id, phone, token);
                if (!result.Succeeded)
                {
                    return new IdentityManagerResult(result.Errors.First());
                }
            }
            
            return IdentityManagerResult.Success;
        }

        public virtual bool GetTwoFactorEnabled(TUser user)
        {
            return userManager.GetTwoFactorEnabled(user.Id);
        }
        public virtual IdentityManagerResult SetTwoFactorEnabled(TUser user, bool enabled)
        {
            var result = userManager.SetTwoFactorEnabled(user.Id, enabled);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult(result.Errors.First());
            }

            return IdentityManagerResult.Success;
        }

        public virtual bool GetLockoutEnabled(TUser user)
        {
            return userManager.GetLockoutEnabled(user.Id);
        }
        public virtual IdentityManagerResult SetLockoutEnabled(TUser user, bool enabled)
        {
            var result = userManager.SetLockoutEnabled(user.Id, enabled);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult(result.Errors.First());
            }

            return IdentityManagerResult.Success;
        }

        public virtual bool GetLockedOut(TUser user)
        {
            return userManager.GetLockoutEndDate(user.Id) > DateTimeOffset.UtcNow;
        }
        public virtual IdentityManagerResult SetLockedOut(TUser user, bool locked)
        {
            if (locked)
            {
                var result = userManager.SetLockoutEndDate(user.Id, DateTimeOffset.MaxValue);
                if (!result.Succeeded)
                {
                    return new IdentityManagerResult(result.Errors.First());
                }
            }
            else
            {
                var result = userManager.SetLockoutEndDate(user.Id, DateTimeOffset.MinValue);
                if (!result.Succeeded)
                {
                    return new IdentityManagerResult(result.Errors.First());
                }
            }

            return IdentityManagerResult.Success;
        }

        public virtual Task<IdentityManagerMetadata> GetMetadataAsync()
        {
            return this.metadataFunc();
        }

        public virtual Task<IdentityManagerResult<QueryResult<UserSummary>>> QueryUsersAsync(string filter, int start, int count)
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

            var result = new QueryResult<UserSummary>();
            result.Start = start;
            result.Count = count;
            result.Total = total;
            result.Filter = filter;
            result.Items = users.Select(x =>
            {
                var user = new UserSummary
                {
                    Subject = x.Id.ToString(),
                    Username = x.UserName,
                    Name = DisplayNameFromUser(x)
                };

                return user;
            }).ToArray();

            return Task.FromResult(new IdentityManagerResult<QueryResult<UserSummary>>(result));
        }

        protected virtual string DisplayNameFromUser(TUser user)
        {
            if (userManager.SupportsUserClaim)
            {
                var claims = userManager.GetClaims(user.Id);
                var name = claims.Where(x => x.Type == IdentityManager.Constants.ClaimTypes.Name).Select(x => x.Value).FirstOrDefault();
                if (!String.IsNullOrWhiteSpace(name))
                {
                    return name;
                }
            }
            return null;
        }

        public virtual async Task<IdentityManagerResult<CreateResult>> CreateUserAsync(IEnumerable<IdentityManager.PropertyValue> properties)
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
                var propertyResult = SetUserProperty(createProps, user, prop.Type, prop.Value);
                if (!propertyResult.IsSuccess)
                {
                    return new IdentityManagerResult<CreateResult>(propertyResult.Errors.ToArray());
                }
            }

            var result = await this.userManager.CreateAsync(user, password);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult<CreateResult>(result.Errors.ToArray());
            }

            return new IdentityManagerResult<CreateResult>(new CreateResult { Subject = user.Id.ToString() });
        }

        public virtual async Task<IdentityManagerResult> DeleteUserAsync(string subject)
        {
            TUserKey key = ConvertUserSubjectToKey(subject);
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

        public virtual async Task<IdentityManagerResult<UserDetail>> GetUserAsync(string subject)
        {
            TUserKey key = ConvertUserSubjectToKey(subject);
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
                select new PropertyValue
                {
                    Type = prop.Type,
                    Value = GetUserProperty(prop, user)
                };
            result.Properties = props.ToArray();

            if (userManager.SupportsUserClaim)
            {
                var userClaims = await userManager.GetClaimsAsync(key);
                var claims = new List<IdentityManager.ClaimValue>();
                if (userClaims != null)
                {
                    claims.AddRange(userClaims.Select(x => new IdentityManager.ClaimValue { Type = x.Type, Value = x.Value }));
                }
                result.Claims = claims.ToArray();
            }

            return new IdentityManagerResult<UserDetail>(result);
        }

        public virtual async Task<IdentityManagerResult> SetUserPropertyAsync(string subject, string type, string value)
        {
            TUserKey key = ConvertUserSubjectToKey(subject);
            var user = await this.userManager.FindByIdAsync(key);
            if (user == null)
            {
                return new IdentityManagerResult("Invalid subject");
            }

            var errors = ValidateUserProperty(type, value);
            if (errors.Any())
            {
                return new IdentityManagerResult(errors.ToArray());
            }

            var metadata = await GetMetadataAsync();
            var propResult = SetUserProperty(metadata.UserMetadata.UpdateProperties, user, type, value);
            if (!propResult.IsSuccess)
            {
                return propResult;
            }

            var result = await userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult(result.Errors.ToArray());
            }

            return IdentityManagerResult.Success;
        }

        public virtual async Task<IdentityManagerResult> AddUserClaimAsync(string subject, string type, string value)
        {
            TUserKey key = ConvertUserSubjectToKey(subject);
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

        public virtual async Task<IdentityManagerResult> RemoveUserClaimAsync(string subject, string type, string value)
        {
            TUserKey key = ConvertUserSubjectToKey(subject);
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

        protected virtual IEnumerable<string> ValidateUserProperty(string type, string value)
        {
            return Enumerable.Empty<string>();
        }

        protected virtual string GetUserProperty(PropertyMetadata propMetadata, TUser user)
        {
            string val;
            if (propMetadata.TryGet(user, out val))
            {
                return val;
            }

            throw new Exception("Invalid property type " + propMetadata.Type);
        }

        protected virtual IdentityManagerResult SetUserProperty(IEnumerable<PropertyMetadata> propsMeta, TUser user, string type, string value)
        {
            IdentityManagerResult result;
            if (propsMeta.TrySet(user, type, value, out result))
            {
                return result;
            }

            throw new Exception("Invalid property type " + type);
        }


        protected virtual void ValidateSupportsRoles()
        {
            if (roleManager == null)
            {
                throw new InvalidOperationException("Roles Not Supported");
            }
        }

        public virtual async Task<IdentityManagerResult<CreateResult>> CreateRoleAsync(IEnumerable<PropertyValue> properties)
        {
            ValidateSupportsRoles();

            var nameClaim = properties.Single(x => x.Type == Constants.ClaimTypes.Name);

            var name = nameClaim.Value;

            string[] exclude = new string[] { Constants.ClaimTypes.Name };
            var otherProperties = properties.Where(x => !exclude.Contains(x.Type)).ToArray();

            var metadata = await GetMetadataAsync();
            var createProps = metadata.RoleMetadata.GetCreateProperties();

            TRole role = new TRole() { Name = name };
            foreach (var prop in otherProperties)
            {
                var roleResult = SetRoleProperty(createProps, role, prop.Type, prop.Value);
                if (!roleResult.IsSuccess)
                {
                    return new IdentityManagerResult<CreateResult>(roleResult.Errors.ToArray());
                }
            }

            var result = await this.roleManager.CreateAsync(role);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult<CreateResult>(result.Errors.ToArray());
            }

            return new IdentityManagerResult<CreateResult>(new CreateResult { Subject = role.Id.ToString() });
        }

        public virtual async Task<IdentityManagerResult> DeleteRoleAsync(string subject)
        {
            ValidateSupportsRoles();

            TRoleKey key = ConvertRoleSubjectToKey(subject);
            var role = await this.roleManager.FindByIdAsync(key);
            if (role == null)
            {
                return new IdentityManagerResult("Invalid subject");
            }

            var result = await this.roleManager.DeleteAsync(role);
            if (!result.Succeeded)
            {
                return new IdentityManagerResult<CreateResult>(result.Errors.ToArray());
            }

            return IdentityManagerResult.Success;
        }

        public virtual async Task<IdentityManagerResult<RoleDetail>> GetRoleAsync(string subject)
        {
            ValidateSupportsRoles();

            TRoleKey key = ConvertRoleSubjectToKey(subject);
            var role = await this.roleManager.FindByIdAsync(key);
            if (role == null)
            {
                return new IdentityManagerResult<RoleDetail>((RoleDetail)null);
            }

            var result = new RoleDetail
            {
                Subject = subject,
                Name = role.Name,
                // Description
            };

            var metadata = await GetMetadataAsync();

            var props =
                from prop in metadata.RoleMetadata.UpdateProperties
                select new PropertyValue
                {
                    Type = prop.Type,
                    Value = GetRoleProperty(prop, role)
                };
            result.Properties = props.ToArray();

            return new IdentityManagerResult<RoleDetail>(result);
        }

        public virtual Task<IdentityManagerResult<QueryResult<RoleSummary>>> QueryRolesAsync(string filter, int start, int count)
        {
            ValidateSupportsRoles();

            if (start < 0) start = 0;
            if (count < 0) count = Int32.MaxValue;

            var query =
                from role in roleManager.Roles
                orderby role.Name
                select role;

            if (!String.IsNullOrWhiteSpace(filter))
            {
                query =
                    from role in query
                    where role.Name.Contains(filter)
                    orderby role.Name
                    select role;
            }

            int total = query.Count();
            var roles = query.Skip(start).Take(count).ToArray();

            var result = new QueryResult<RoleSummary>();
            result.Start = start;
            result.Count = count;
            result.Total = total;
            result.Filter = filter;
            result.Items = roles.Select(x =>
            {
                var user = new RoleSummary
                {
                    Subject = x.Id.ToString(),
                    Name = x.Name,
                    // Description
                };

                return user;
            }).ToArray();

            return Task.FromResult(new IdentityManagerResult<QueryResult<RoleSummary>>(result));
        }

        public virtual async Task<IdentityManagerResult> SetRolePropertyAsync(string subject, string type, string value)
        {
            ValidateSupportsRoles();

            TRoleKey key = ConvertRoleSubjectToKey(subject);
            var role = await this.roleManager.FindByIdAsync(key);
            if (role == null)
            {
                return new IdentityManagerResult("Invalid subject");
            }

            var errors = ValidateRoleProperty(type, value);
            if (errors.Any())
            {
                return new IdentityManagerResult(errors.ToArray());
            }

            var metadata = await GetMetadataAsync();
            var result = SetRoleProperty(metadata.RoleMetadata.UpdateProperties, role, type, value);
            if (!result.IsSuccess)
            {
                return result;
            }

            var updateResult = await roleManager.UpdateAsync(role);
            if (!updateResult.Succeeded)
            {
                return new IdentityManagerResult(result.Errors.ToArray());
            }

            return IdentityManagerResult.Success;
        }

        protected virtual IEnumerable<string> ValidateRoleProperties(IEnumerable<PropertyValue> properties)
        {
            return properties.Select(x => ValidateRoleProperty(x.Type, x.Value)).Aggregate((x, y) => x.Concat(y));
        }

        protected virtual IEnumerable<string> ValidateRoleProperty(string type, string value)
        {
            return Enumerable.Empty<string>();
        }

        protected virtual string GetRoleProperty(PropertyMetadata propMetadata, TRole role)
        {
            string val;
            if (propMetadata.TryGet(role, out val))
            {
                return val;
            }

            throw new Exception("Invalid property type " + propMetadata.Type);
        }

        protected virtual IdentityManagerResult SetRoleProperty(IEnumerable<PropertyMetadata> propsMeta, TRole role, string type, string value)
        {
            IdentityManagerResult result;
            if (propsMeta.TrySet(role, type, value, out result))
            {
                return result;
            }

            throw new Exception("Invalid property type " + type);
        }
    }
}
