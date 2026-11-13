using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Sentomaru.AspNetCore;

/// <summary>
/// 4.19.0: startup check (ValidateOnStart, every environment) that each <see cref="SentomaruIntegrityAttribute.OperationRules"/>
/// on an MVC action, its controller or the global filters names a set of <see cref="SentomaruClientOptions.OperationRules"/>.
/// Without MVC registered there is nothing to check (the filter still refuses an unknown set with 503). The shape of the
/// sets themselves is checked by <see cref="SentomaruClientOptions.Validate"/>.
/// </summary>
public sealed class SentomaruOperationRulesValidator(IServiceProvider services) : IValidateOptions<SentomaruClientOptions>
{
    public ValidateOptionsResult Validate(string? name, SentomaruClientOptions options)
    {
        var actions = services.GetService<IActionDescriptorCollectionProvider>()?.ActionDescriptors.Items;
        if (actions is null) return ValidateOptionsResult.Success;
        var errors = new List<string>();
        foreach (var action in actions)
        {
            var attributes = action.FilterDescriptors.Select(f => f.Filter)
                .Concat(action.EndpointMetadata ?? [])
                .OfType<SentomaruIntegrityAttribute>()
                .Where(a => a.OperationRules is not null)
                .Distinct();
            foreach (var attribute in attributes)
            {
                if (SentomaruOperationRules.FindSet(options, attribute.OperationRules!) is { Count: > 0 }) continue;
                var error = $"Sentomaru:OperationRules has no set '{attribute.OperationRules}' (referenced by " +
                            $"[SentomaruIntegrity(\"{attribute.Operation}\", OperationRules = \"{attribute.OperationRules}\")] on {action.DisplayName}).";
                if (!errors.Contains(error)) errors.Add(error);
            }
        }
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
