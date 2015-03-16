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
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityManager.AspNetIdentity
{
    class TokenProvider<TUser, TKey> : IUserTokenProvider<TUser, TKey>
        where TUser : class, IUser<TKey>
        where TKey : System.IEquatable<TKey>
    {
        public Task<string> GenerateAsync(string purpose, Microsoft.AspNet.Identity.UserManager<TUser, TKey> manager, TUser user)
        {
            return Task.FromResult(purpose + user.Id);
        }

        public Task<bool> IsValidProviderForUserAsync(Microsoft.AspNet.Identity.UserManager<TUser, TKey> manager, TUser user)
        {
            return Task.FromResult(true);
        }

        public Task NotifyAsync(string token, Microsoft.AspNet.Identity.UserManager<TUser, TKey> manager, TUser user)
        {
            return Task.FromResult(0);
        }

        public Task<bool> ValidateAsync(string purpose, string token, Microsoft.AspNet.Identity.UserManager<TUser, TKey> manager, TUser user)
        {
            return Task.FromResult((purpose + user.Id) == token);
        }
    }
}
