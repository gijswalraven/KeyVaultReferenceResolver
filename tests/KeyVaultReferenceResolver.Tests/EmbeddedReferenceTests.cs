using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace KeyVaultReferenceResolver.Tests;

/// <summary>
/// References are substituted in place rather than replacing the whole configuration value.
/// </summary>
/// <remarks>
/// Previously the resolved secret replaced the entire value, so
/// "Server=db;Password=@Microsoft.KeyVault(...)" silently collapsed to just the password -
/// producing a malformed connection string - and a value containing two references resolved
/// only the first.
/// </remarks>
public class EmbeddedReferenceTests
{
    private const string PasswordUri = "https://myvault.vault.azure.net/secrets/db-password";
    private const string UserUri = "https://myvault.vault.azure.net/secrets/db-user";
    private const string PasswordRef = "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/db-password)";
    private const string UserRef = "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/db-user)";

    private static IConfigurationRoot Resolve(
        Dictionary<string, string?> settings,
        MockSecretResolver resolver,
        KeyVaultReferenceResolverOptions? options = null)
    {
        var builder = new ConfigurationBuilder().AddInMemoryCollection(settings);
        builder.AddKeyVaultReferenceResolver(resolver, options);
        return builder.Build();
    }

    [Fact]
    public void ReferenceEmbeddedInLiteralText_PreservesSurroundingText()
    {
        // Arrange
        var resolver = new MockSecretResolver().AddSecret(PasswordUri, "p@ssw0rd");

        // Act
        var config = Resolve(
            new Dictionary<string, string?>
            {
                ["ConnectionStrings:Db"] = $"Server=db;User Id=sa;Password={PasswordRef};Encrypt=true"
            },
            resolver);

        // Assert
        Assert.Equal(
            "Server=db;User Id=sa;Password=p@ssw0rd;Encrypt=true",
            config["ConnectionStrings:Db"]);
    }

    [Fact]
    public void TwoReferencesInOneValue_ResolvesBoth()
    {
        // Arrange
        var resolver = new MockSecretResolver()
            .AddSecret(UserUri, "sa")
            .AddSecret(PasswordUri, "p@ssw0rd");

        // Act
        var config = Resolve(
            new Dictionary<string, string?>
            {
                ["ConnectionStrings:Db"] = $"Server=db;User Id={UserRef};Password={PasswordRef}"
            },
            resolver);

        // Assert
        Assert.Equal("Server=db;User Id=sa;Password=p@ssw0rd", config["ConnectionStrings:Db"]);
    }

    [Fact]
    public void SameReferenceTwiceInOneValue_ResolvesBothOccurrences()
    {
        // Arrange
        var resolver = new MockSecretResolver().AddSecret(PasswordUri, "p@ssw0rd");

        // Act
        var config = Resolve(
            new Dictionary<string, string?> { ["Doubled"] = $"{PasswordRef}|{PasswordRef}" },
            resolver);

        // Assert
        Assert.Equal("p@ssw0rd|p@ssw0rd", config["Doubled"]);
    }

    [Fact]
    public void WholeValueIsAReference_StillResolvesToJustTheSecret()
    {
        // Arrange
        var resolver = new MockSecretResolver().AddSecret(PasswordUri, "p@ssw0rd");

        // Act
        var config = Resolve(
            new Dictionary<string, string?> { ["Password"] = PasswordRef },
            resolver);

        // Assert - the common case must be unchanged
        Assert.Equal("p@ssw0rd", config["Password"]);
    }

    [Fact]
    public void OneOfTwoReferencesFails_WholeValueIsNull()
    {
        // Arrange - only the user secret exists
        var resolver = new MockSecretResolver(
            new Dictionary<string, string> { [UserUri] = "sa" },
            throwOnMissing: true);
        var options = new KeyVaultReferenceResolverOptions { ThrowOnResolveFailure = false };

        // Act
        var config = Resolve(
            new Dictionary<string, string?>
            {
                ["ConnectionStrings:Db"] = $"Server=db;User Id={UserRef};Password={PasswordRef}"
            },
            resolver,
            options);

        // Assert - fail closed for the whole value. A partially substituted connection string
        // would otherwise be handed to the application with an empty password.
        Assert.Null(config["ConnectionStrings:Db"]);
    }

    [Fact]
    public void MixedFormatsInOneValue_ResolvesBoth()
    {
        // Arrange
        var resolver = new MockSecretResolver()
            .AddSecret(UserUri, "sa")
            .AddSecret(PasswordUri, "p@ssw0rd");

        // Act - SecretUri format alongside VaultName format
        var config = Resolve(
            new Dictionary<string, string?>
            {
                ["ConnectionStrings:Db"] =
                    $"User Id={UserRef};Password=@Microsoft.KeyVault(VaultName=myvault;SecretName=db-password)"
            },
            resolver);

        // Assert
        Assert.Equal("User Id=sa;Password=p@ssw0rd", config["ConnectionStrings:Db"]);
    }

    [Fact]
    public void SharedSecretAcrossKeys_IsResolvedForEachKey()
    {
        // Arrange
        var resolver = new MockSecretResolver().AddSecret(PasswordUri, "p@ssw0rd");

        // Act - the same URI referenced from two keys is fetched once but applied to both
        var config = Resolve(
            new Dictionary<string, string?>
            {
                ["First"] = PasswordRef,
                ["Second"] = $"prefix-{PasswordRef}"
            },
            resolver);

        // Assert
        Assert.Equal("p@ssw0rd", config["First"]);
        Assert.Equal("prefix-p@ssw0rd", config["Second"]);
    }
}
