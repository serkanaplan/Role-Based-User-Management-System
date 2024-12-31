﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;


namespace Authorization;

// program.cs dosyasında dmin ve user politikalarını eklemek yerine dinamik olarak gelen role göre ya admin yada user policy oluşacak 
public class DynamicPolicyProvider(IOptions<AuthorizationOptions> options) : IAuthorizationPolicyProvider
{
    private DefaultAuthorizationPolicyProvider BackupPolicyProvider { get; } = new DefaultAuthorizationPolicyProvider(options);

    public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => BackupPolicyProvider.GetDefaultPolicyAsync();
    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() => BackupPolicyProvider.GetFallbackPolicyAsync();


    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (policyName.StartsWith("Role", StringComparison.OrdinalIgnoreCase))
        {
            var role = policyName["Role".Length..];
            var policy = new AuthorizationPolicyBuilder();
            policy.AddRequirements(new DynamicRoleRequirement(role));
            return Task.FromResult<AuthorizationPolicy?>(policy.Build());
        }
        return BackupPolicyProvider.GetPolicyAsync(policyName);
    }
}
