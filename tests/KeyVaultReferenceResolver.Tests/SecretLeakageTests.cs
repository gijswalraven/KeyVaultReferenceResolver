using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Xunit;

namespace KeyVaultReferenceResolver.Tests;

/// <summary>
/// Guards the property that matters most for a secrets library: no secret value, and no
/// secret name, may reach a log sink or an exception surface.
/// </summary>
/// <remarks>
/// These are regression tests for real defects. The resolvers previously logged the secret
/// name unmasked at Information, and the resolution exceptions carried the unmasked reference
/// on a public property. Both were found by review rather than by a failing test.
/// </remarks>
public class SecretLeakageTests
{
    // Distinctive sentinels: a substring match on these cannot succeed by accident.
    private const string SecretValueSentinel = "S3CRET-VALUE-SENTINEL-8f21";
    private const string SecretNameSentinel = "secret-name-sentinel-4c7e";

    private static readonly string SecretUri =
        $"https://myvault.vault.azure.net/secrets/{SecretNameSentinel}";

    private static readonly string Reference =
        $"@Microsoft.KeyVault(SecretUri={SecretUri})";

    [Fact]
    public void Resolution_DoesNotWriteSecretValueOrNameToTheLog()
    {
        // Arrange
        var logger = new CapturingLogger();
        var resolver = new MockSecretResolver().AddSecret(SecretUri, SecretValueSentinel);

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

        // Act - resolve at every level the library emits, so Debug records are captured too
        builder.AddKeyVaultReferenceResolver(resolver, options: null, logger: logger);
        var config = builder.Build();

        // Assert - the secret did resolve, so this test is exercising the success path
        Assert.Equal(SecretValueSentinel, config["Db:Password"]);

        Assert.DoesNotContain(SecretValueSentinel, logger.AllText);

        // The secret name is permitted at Debug but must not appear at Information or above,
        // which is what ships to an aggregated log store by default.
        var shipped = logger.TextAtOrAbove(LogLevel.Information);
        Assert.DoesNotContain(SecretValueSentinel, shipped);
        Assert.DoesNotContain(SecretNameSentinel, shipped);
    }

    [Fact]
    public void FailedResolution_DoesNotWriteSecretNameToTheLogOrTheException()
    {
        // Arrange - an empty resolver that throws, so every failure path runs
        var logger = new CapturingLogger();
        var resolver = new MockSecretResolver(new Dictionary<string, string>(), throwOnMissing: true);

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

        // Act
        var ex = Assert.Throws<KeyVaultReferenceResolutionException>(
            () => builder.AddKeyVaultReferenceResolver(resolver, options: null, logger: logger));

        // Assert - the exception identifies the vault and the config key, not the secret
        Assert.DoesNotContain(SecretNameSentinel, ex.SecretUri);
        Assert.DoesNotContain(SecretNameSentinel, ex.Message);
        Assert.Equal("Db:Password", ex.ConfigurationKey);

        // ToString() covers the inner exception and anything a log sink renders by default
        Assert.DoesNotContain(SecretValueSentinel, ex.ToString());

        Assert.DoesNotContain(SecretValueSentinel, logger.AllText);
        Assert.DoesNotContain(SecretNameSentinel, logger.TextAtOrAbove(LogLevel.Information));
    }

    [Fact]
    public void CachedResolution_DoesNotWriteSecretValueToTheLog()
    {
        // Arrange
        var logger = new CapturingLogger();
        var resolver = new MockSecretResolver().AddSecret(SecretUri, SecretValueSentinel);

        // Act - resolve twice so the cache-hit path is exercised
        for (var i = 0; i < 2; i++)
        {
            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });
            builder.AddKeyVaultReferenceResolver(resolver, options: null, logger: logger);
            builder.Build();
        }

        // Assert
        Assert.DoesNotContain(SecretValueSentinel, logger.AllText);
    }

    [Fact]
    public void MaskSecretUri_RemovesTheSecretName()
    {
        // Act
        var masked = KeyVaultReferenceResolutionException.MaskSecretUri(SecretUri);

        // Assert
        Assert.Equal("https://myvault.vault.azure.net/secrets/***", masked);
        Assert.DoesNotContain(SecretNameSentinel, masked);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void MaskSecretUri_EmptyInput_ReturnsEmpty(string? input)
    {
        Assert.Equal(string.Empty, KeyVaultReferenceResolutionException.MaskSecretUri(input));
    }

    /// <summary>
    /// Minimal <see cref="ILogger"/> that records the rendered message of every entry,
    /// including the exception text, so tests can assert on what a sink would receive.
    /// </summary>
    private sealed class CapturingLogger : ILogger
    {
        private readonly ConcurrentQueue<(LogLevel Level, string Text)> _entries = new();

        public string AllText => string.Join("\n", _entries.Select(e => e.Text));

        public string TextAtOrAbove(LogLevel minimum) =>
            string.Join("\n", _entries.Where(e => e.Level >= minimum).Select(e => e.Text));

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        // Enabled for every level: a logger that filters would hide records this test exists
        // to inspect.
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var text = formatter(state, exception);
            if (exception != null)
                text += "\n" + exception;

            _entries.Enqueue((logLevel, text));
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }
}
