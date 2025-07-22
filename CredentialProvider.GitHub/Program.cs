using System.CommandLine;
using System.CommandLine.Help;
using System.Reflection;
using CredentialProvider.GitHub;
using Microsoft.Extensions.Logging;
using NReco.Logging.File;
using NuGet.Protocol.Plugins;


var pluginOption = new Option<bool>("-Plugin") { Aliases = { "-P" }, Description = "Used by nuget to run the credential helper in plugin mode" };
var uriOption = new Option<Uri>("-Uri") { Aliases = { "-U" }, Description = "The package source URI for which credentials will be filled", CustomParser = a =>
    {
        if (a.Tokens[0] is { } token && Uri.TryCreate(token.Value, UriKind.Absolute, out var uri))
        {
            return uri;
        }
        
        return null;
    }
};
var nonInteractiveOption = new Option<bool>("-NonInteractive") { Aliases = { "-N" }, Description = "If present and true, providers will not issue interactive prompts" };
var isRetryOption = new Option<bool>("-IsRetry") { Aliases = { "-I" }, Description = "If false / unset, INVALID CREDENTIALS MAY BE RETURNED. The caller is required to validate returned credentials themselves, and if invalid, should call the credential provider again with -IsRetry set. If true, the credential provider will obtain new credentials instead of returning potentially invalid credentials from the cache." };
var verbosityOption = new Option<LogLevel>("-Verbosity") { Aliases = { "-V" }, Description = "Display this amount of detail in the output", DefaultValueFactory = _ => LogLevel.Information };
var redactPasswordOption = new Option<bool>("-RedactPassword") { Aliases = { "-R" }, Description = "Prevents writing the password to standard output (for troubleshooting purposes)" };
var canShowDialogOption = new Option<bool>("-CanShowDialog") { Aliases = { "-C" }, Description = "If true, user can be prompted with credentials through UI, if false, device flow must be used", DefaultValueFactory = _ => true };
var outputFormatOption = new Option<OutputFormat>("-OutputFormat") { Aliases = { "-F" }, Description = "In standalone mode, format the results for human readability or as JSON. If JSON is selected, then logging (which may include Device Code instructions) will be logged to standard error instead of standard output" };

var rootCommand = new RootCommand
{
    pluginOption,
    uriOption,
    nonInteractiveOption,
    isRetryOption,
    verbosityOption,
    redactPasswordOption,
    canShowDialogOption,
    outputFormatOption,
};

var helpOption = rootCommand.Options.OfType<HelpOption>().Single();
helpOption.Aliases.Add("-Help");

rootCommand.SetAction(async (parseResult, cancellationToken) =>
{
    var filterOptionsMonitor = new Program.FilterOptionsMonitor();
    var loggerBuilder = new Microsoft.Extensions.Logging.LoggerFactory([Microsoft.Extensions.Logging.Abstractions.NullLoggerProvider.Instance], filterOptionsMonitor);
    if (GetFileLoggerProvider() is { } fileLoggerProvider)
    {
        loggerBuilder.AddProvider(fileLoggerProvider);
    }
    
    ILogger? logger = null;
    var getLogger = () => logger ??= loggerBuilder.CreateLogger<Program>();
    NuGet.Protocol.Plugins.RequestHandlers requestHandlers = new();
    requestHandlers.AddOrUpdate(MessageMethod.GetAuthenticationCredentials, () => new Program.GetAuthenticationCredentialsRequestHandler(getLogger), x => x);
    requestHandlers.AddOrUpdate(MessageMethod.Initialize, () => new Program.InitializeRequestHandler(getLogger), x => x);
    requestHandlers.AddOrUpdate(MessageMethod.GetOperationClaims, () => new Program.GetOperationClaimsRequestHandler(getLogger), x => x);
    requestHandlers.AddOrUpdate(MessageMethod.SetLogLevel, () => new Program.SetLogLevelRequestHandler(getLogger, filterOptionsMonitor), x => x);
    requestHandlers.AddOrUpdate(MessageMethod.SetCredentials, () => new Program.SetCredentialsRequestHandler(getLogger), x => x);
    
    // Plug-in mode
    if (parseResult.GetValue(pluginOption))
    {
        // plugin mode
        try
        {
            using var plugin = await PluginFactory.CreateFromCurrentProcessAsync(requestHandlers, ConnectionOptions.CreateDefault(), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            loggerBuilder.AddProvider(new Program.PluginConnectionLoggerProvider(plugin.Connection));
            var pluginLogger = getLogger();
            await WaitForPluginExitAsync(plugin, pluginLogger, TimeSpan.FromMinutes(2)).ConfigureAwait(false);
            pluginLogger.LogTrace(Resources.RunningInPlugin);
            pluginLogger.LogTrace(string.Format(Resources.CommandLineArgs, GetProgramVersion(), Environment.CommandLine));
                
            await WaitForPluginExitAsync(plugin, pluginLogger, TimeSpan.FromMinutes(2)).ConfigureAwait(continueOnCapturedContext: false);
        }
        catch (OperationCanceledException ex)
        {
            // When restoring from multiple sources, one of the sources will throw an unhandled TaskCanceledException
            // if it has been restored successfully from a different source.

            // This is probably more confusing than interesting to users, but may be helpful in debugging,
            // so log the exception but not to the console.
            loggerBuilder.CreateLogger<Program>().LogTrace(ex, "Failed to complete plugin");
        }

        return 0;
    }
    
    // Stand-alone mode
    if (requestHandlers.TryGet(MessageMethod.GetAuthenticationCredentials, out var requestHandler) &&
        requestHandler is Program.GetAuthenticationCredentialsRequestHandler getFromGithubCliRequestHandler)
    {
        var current = filterOptionsMonitor.CurrentValue;
        current.MinLevel = parseResult.GetRequiredValue(verbosityOption);
        filterOptionsMonitor.UpdateOptions(current);

        var outputFormat = parseResult.GetValue(outputFormatOption);
        loggerBuilder.AddProvider(new Program.OutputLoggerProvider(outputFormat is OutputFormat.Json ? Console.Error : Console.Out));

        var standAloneLogger = getFromGithubCliRequestHandler.Logger;
        
        var request = new GetAuthenticationCredentialsRequest(parseResult.GetRequiredValue(uriOption), parseResult.GetValue(isRetryOption), parseResult.GetValue(nonInteractiveOption), parseResult.GetValue(canShowDialogOption));
        var response = await getFromGithubCliRequestHandler.HandleRequestAsync(request);
        
        
        // Fail if credentials are not found
        if (response.ResponseCode != MessageResponseCode.Success)
        {
            return 2;
        }
        
        var resultUsername = response.Username;
        var resultPassword = parseResult.GetValue(redactPasswordOption) ? Resources.Redacted : response.Password;
        if (outputFormat is OutputFormat.Json)
        {
             // Manually write the JSON output, since we don't use ConsoleLogger in JSON mode (see above)
             Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new Program.CredentialResult(resultUsername, resultPassword)));
        }
        else
        {
            standAloneLogger.LogInformation($"{Resources.Username}: {{Username}}", resultUsername);
            standAloneLogger.LogInformation($"{Resources.Password_}: {{Password}}", resultPassword);
        }
        return 0;
    }

    return -1;
});

var configuration = new CommandLineConfiguration(rootCommand);

await configuration.InvokeAsync(args);

static ILoggerProvider? GetFileLoggerProvider()
{
    if (Environment.GetEnvironmentVariable("GITHUB_CREDENTIALPROVIDER_LOG_PATH") is { } logPath)
    {
        return new FileLoggerProvider(logPath);
    }

    return null;
}

enum OutputFormat
{
    HumanReadable = 0,
    Json = 1
}

partial class Program
{
    private static bool shuttingDown;

    private static string? programVersion;
    
    private static AssemblyName CurrentAssemblyName => typeof(Program).Assembly.GetName();
            
    private static bool IsShuttingDown => Volatile.Read(ref shuttingDown);
    
    static string? GetProgramVersion()
    {
        return programVersion ??= System.Reflection.Assembly
            .GetEntryAssembly()?
            .GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? CurrentAssemblyName.Version?.ToString();
    }

    private static async Task WaitForPluginExitAsync(IPlugin plugin, Microsoft.Extensions.Logging.ILogger logger,
        TimeSpan shutdownTimeout)
    {
        var beginShutdownTaskSource = new TaskCompletionSource<object?>();
        var endShutdownTaskSource = new TaskCompletionSource<object?>();

        plugin.Connection.Faulted += (_, a) =>
        {
            logger.LogError(a.Exception, Resources.FaultedOnMessage, $"{a.Message?.Type} {a.Message?.Method} {a.Message?.RequestId}");
        };

        plugin.BeforeClose += (_, _) =>
        {
            Volatile.Write(ref shuttingDown, true);
            beginShutdownTaskSource.TrySetResult(null);
        };

        plugin.Closed += (_, _) =>
        {
            // beginShutdownTaskSource should already be set in BeforeClose, but just in case do it here too
            beginShutdownTaskSource.TrySetResult(null);

            endShutdownTaskSource.TrySetResult(null);
        };

        await beginShutdownTaskSource.Task;
        var timer = new Timer(_ => endShutdownTaskSource.TrySetCanceled(), null, shutdownTimeout, TimeSpan.FromMilliseconds(-1));
        await using (timer.ConfigureAwait(false))
        {
            await endShutdownTaskSource.Task;
        }

        if (endShutdownTaskSource.Task.IsCanceled)
        {
            logger.LogError(Resources.PluginTimedOut);
        }
    }

    private class PluginConnectionLoggerProvider(IConnection connection) : Microsoft.Extensions.Logging.ILoggerProvider
    {
        public void Dispose()
        {
        }

        public ILogger CreateLogger(string categoryName)
        {
            return new PluginConnectionLogger(connection);
        }

        private class PluginConnectionLogger(IConnection connection) : Microsoft.Extensions.Logging.ILogger
        {
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                // intentionally not awaiting here -- don't want to block forward progress just because we tried to log.
                connection.SendRequestAndReceiveResponseAsync<LogRequest, LogResponse>(
                        MessageMethod.Log,
                        new LogRequest(FromExtensions(logLevel), $"    {formatter(state, exception)}"),
                        CancellationToken.None)
                    // "observe" any exceptions to avoid unobserved exception escalation, which may terminate the process
                    .ContinueWith(x => x.Exception, TaskContinuationOptions.OnlyOnFaulted);

                static NuGet.Common.LogLevel FromExtensions(Microsoft.Extensions.Logging.LogLevel logLevel)
                {
                    return logLevel switch
                    {
                        Microsoft.Extensions.Logging.LogLevel.Critical or Microsoft.Extensions.Logging.LogLevel.Error => NuGet.Common.LogLevel.Error,
                        Microsoft.Extensions.Logging.LogLevel.Warning => NuGet.Common.LogLevel.Warning,
                        Microsoft.Extensions.Logging.LogLevel.Information => NuGet.Common.LogLevel.Information,
                        Microsoft.Extensions.Logging.LogLevel.Debug => NuGet.Common.LogLevel.Debug,
                        Microsoft.Extensions.Logging.LogLevel.Trace => NuGet.Common.LogLevel.Verbose,
                        Microsoft.Extensions.Logging.LogLevel.None => NuGet.Common.LogLevel.Minimal,
                        _ => throw new InvalidOperationException(),
                    };
                }
            }

            public bool IsEnabled(LogLevel logLevel)
            {
                return true;
            }

            public IDisposable? BeginScope<TState>(TState state) where TState : notnull
            {
                return null;
            }
        }
    }

    private abstract class RequestHandlerBase<TRequest, TResponse>(Func<ILogger> loggerFactory) : IRequestHandler where TResponse : class
    {
        private ILogger? logger;
        
        public virtual CancellationToken CancellationToken { get; private set; } = CancellationToken.None;

        public ILogger Logger => logger ??= loggerFactory();

        public IConnection? Connection { get; private set; }

        public async Task HandleResponseAsync(
            IConnection connection,
            Message message,
            IResponseHandler responseHandler,
            CancellationToken cancellationToken)
        {
            var start = System.Diagnostics.Stopwatch.GetTimestamp();

            this.Connection = connection;
            this.CancellationToken = cancellationToken;
            var request = MessageUtilities.DeserializePayload<TRequest>(message);
            try
            {
                this.Logger.LogDebug("Sending message type {Type} and method {Method} with request {Payload}", message.Type, message.Method, message.Payload);
                TResponse response;
                try
                {
                    response = await this.HandleRequestAsync(request).ConfigureAwait(false);
                }
                catch (Exception ex) when (cancellationToken.IsCancellationRequested)
                {
                    this.Logger.LogError(ex, "Canceling while processing request: {Message}", ex.ToString());
                    return;
                }

                this.Logger.LogDebug("Sending message type {Type} and method {Method} in {Milliseconds} milliseconds.", message.Type, message.Method, System.Diagnostics.Stopwatch.GetElapsedTime(start).Milliseconds);
                await responseHandler.SendResponseAsync(message, response, CancellationToken.None).ConfigureAwait(false);
                this.Logger.LogDebug("Processed message type {Type} and method {Method} in {Milliseconds} milliseconds.", message.Type, message.Method, System.Diagnostics.Stopwatch.GetElapsedTime(start).Milliseconds);
            }
            catch (Exception ex)
            {
                if ((ex is not OperationCanceledException ? 0 : IsShuttingDown ? 1 : 0) != 0)
                {
                    this.Logger.LogDebug("Canceling during shutdown");
                }

                this.Logger.LogError(ex, message: null);
                throw;
            }
        }

        internal abstract Task<TResponse> HandleRequestAsync(TRequest request);
    }

    private sealed class InitializeRequestHandler(Func<ILogger> loggerFactory) : RequestHandlerBase<InitializeRequest, InitializeResponse>(loggerFactory)
    {
        private static readonly InitializeResponse Success = new(MessageResponseCode.Success);
        internal override Task<InitializeResponse> HandleRequestAsync(InitializeRequest request) => Task.FromResult(Success);
    }

    private sealed class GetOperationClaimsRequestHandler(Func<ILogger> loggerFactory) : RequestHandlerBase<GetOperationClaimsRequest, GetOperationClaimsResponse>(loggerFactory)
    {
        private static readonly GetOperationClaimsResponse CanProvideCredentialsResponse = new([OperationClaim.Authentication]);
        private static readonly GetOperationClaimsResponse EmptyGetOperationClaimsResponse = new([]);

        internal override Task<GetOperationClaimsResponse> HandleRequestAsync(GetOperationClaimsRequest request) => Task.FromResult(ResolvePath("gh") is not null ? CanProvideCredentialsResponse : EmptyGetOperationClaimsResponse);
        
        private static string? ResolvePath(string filename) => typeof(System.Diagnostics.Process).GetMethod(nameof(ResolvePath), System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)?.Invoke(null, [filename]) as string;
    }

    private sealed class SetLogLevelRequestHandler(Func<ILogger> loggerFactory, ManualOptionsMonitor<LoggerFilterOptions> optionsMonitor) : RequestHandlerBase<SetLogLevelRequest, SetLogLevelResponse>(loggerFactory)
    {
        private static readonly SetLogLevelResponse Success = new(MessageResponseCode.Success);
        
        internal override Task<SetLogLevelResponse> HandleRequestAsync(SetLogLevelRequest request)
        {
            var current = optionsMonitor.CurrentValue;
            current.MinLevel = request.LogLevel switch
            {
                NuGet.Common.LogLevel.Verbose =>  LogLevel.Trace,
                NuGet.Common.LogLevel.Debug =>  LogLevel.Debug,
                NuGet.Common.LogLevel.Information =>  LogLevel.Information,
                NuGet.Common.LogLevel.Warning =>  LogLevel.Warning,
                NuGet.Common.LogLevel.Error =>  LogLevel.Error,
                NuGet.Common.LogLevel.Minimal =>  LogLevel.Critical,
                _ => throw new InvalidOperationException(),
            };
                
            optionsMonitor.UpdateOptions(current);
            return Task.FromResult(Success);
        }
    }

    private sealed class SetCredentialsRequestHandler(Func<ILogger> loggerFactory) : RequestHandlerBase<SetCredentialsRequest, SetCredentialsResponse>(loggerFactory)
    {
        private static readonly SetCredentialsResponse Success = new(MessageResponseCode.Success);
        internal override Task<SetCredentialsResponse> HandleRequestAsync(SetCredentialsRequest request) => Task.FromResult(Success);
    }

    private partial class GetAuthenticationCredentialsRequestHandler(Func<ILogger> loggerFactory) : RequestHandlerBase<GetAuthenticationCredentialsRequest, GetAuthenticationCredentialsResponse>(loggerFactory)
    {
        private static readonly System.Text.RegularExpressions.Regex IndexRegex = IndexRegexFunc();
        private static readonly System.Text.RegularExpressions.Regex PackageRegex = PackageRegexFunc();
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> authorizationTokenCache = new();
            
        internal override async Task<GetAuthenticationCredentialsResponse> HandleRequestAsync(GetAuthenticationCredentialsRequest request)
        {
            this.Logger.LogDebug($"Handling {nameof(GetAuthenticationCredentialsRequest)}");
            var uri = request.Uri;
            if (uri is null)
            {
                return new GetAuthenticationCredentialsResponse(username: null, password: null, message: "Request URI null", authenticationTypes: null, responseCode: MessageResponseCode.Error);
            }
            
            this.Logger.LogInformation("Processing {Uri}", uri);
            if (TryGetName(uri, out var name))
            {
                string? token= null;
                if (!request.IsRetry && authorizationTokenCache.TryGetValue(name, out token))
                {
                    return new GetAuthenticationCredentialsResponse(
                        username: name,
                        password: token,
                        message: null,
                        authenticationTypes: ["Basic"],
                        MessageResponseCode.Success);
                }
                
                this.Logger.LogInformation("Getting GH token for {Name}", name);

                // get the password from GH
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo("gh")
                    {
                        ArgumentList = { "auth", "token" },
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden,
                    }
                };

                process.OutputDataReceived += (_, e) =>
                {
                    if (token is null && e.Data is not null)
                    {
                        token = e.Data;
                    }
                };

                if (process.Start())
                {
                    process.BeginOutputReadLine();
                    await process.WaitForExitAsync(this.CancellationToken).ConfigureAwait(false);
                }

                if (token is not null)
                {
                    this.authorizationTokenCache.TryAdd(name, token);
                    return new GetAuthenticationCredentialsResponse(
                        username: name,
                        password: token,
                        message: null,
                        authenticationTypes: ["Basic"],
                        MessageResponseCode.Success);
                }

                return new GetAuthenticationCredentialsResponse(
                    username: null,
                    password: null,
                    message: "Failed to create process",
                    authenticationTypes: null,
                    responseCode: MessageResponseCode.NotFound);
            }

            // not valid for us
            return new GetAuthenticationCredentialsResponse(username: null, password: null, message: null, authenticationTypes: null, responseCode: MessageResponseCode.NotFound);
        }

        private static bool TryGetName(Uri uri, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? value)
        {
            var uriString = uri.ToString();
            return TryGetNameRegex(IndexRegex, uriString, out value) || TryGetNameRegex(PackageRegex, uriString, out value);

            static bool TryGetNameRegex(System.Text.RegularExpressions.Regex regex, string uri, out string? value)
            {
                if (regex.Match(uri) is { Success: true, Groups: var indexGroups })
                {
                    value = indexGroups["name"].Value;
                    return true;
                }

                value = null;
                return false;
            }
        }

        [System.Text.RegularExpressions.GeneratedRegex("""https:\/\/nuget\.pkg\.github\.com\/(?<name>[a-zA-Z]+)\/index\.json""")]
        private static partial System.Text.RegularExpressions.Regex IndexRegexFunc();
        
        [System.Text.RegularExpressions.GeneratedRegex("""https:\/\/nuget\.pkg\.github\.com\/(?<name>[a-zA-Z]+)\/(?<package>[a-zA-z.]+)\/index\.json""")]
        private static partial System.Text.RegularExpressions.Regex PackageRegexFunc();
    }

    private sealed class FilterOptionsMonitor() : ManualOptionsMonitor<LoggerFilterOptions>(new LoggerFilterOptions { MinLevel = LogLevel.None });

    private class ManualOptionsMonitor<TOptions>(TOptions options) : Microsoft.Extensions.Options.IOptionsMonitor<TOptions>
    {
        private readonly List<Action<TOptions, string>> listeners = [];

        public TOptions CurrentValue { get; private set; } = options;
        
        public TOptions Get(string? name) => CurrentValue;

        public IDisposable OnChange(Action<TOptions, string> listener)
        {
            listeners.Add(listener);
            return new ActionDisposable(() => listeners.Remove(listener));
        }

        public void UpdateOptions(TOptions options)
        {
            CurrentValue = options;
            listeners.ForEach(listener => listener(options, string.Empty));
        }
    
        public sealed class ActionDisposable(Action action) : IDisposable
        {
            public void Dispose() => action();
        } 
    }
    
    private sealed class OutputLoggerProvider(TextWriter writer) : ILoggerProvider
    {
        private readonly ILogger logger = new OutputLogger(writer);
        
        private sealed class OutputLogger(TextWriter writer) : ILogger
        {
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                writer.WriteLine(formatter(state, exception));
            }

            public bool IsEnabled(LogLevel logLevel)
            {
                return true;
            }

            public IDisposable? BeginScope<TState>(TState state) where TState : notnull
            {
                return null;
            }
        }

        public void Dispose()
        {
        }

        public ILogger CreateLogger(string categoryName) => this.logger;
    }
    
    [System.Runtime.Serialization.DataContract]
    public class CredentialResult(string username, string password)
    {
        [System.Runtime.Serialization.DataMember]
        public string Username { get; } = username;

        [System.Runtime.Serialization.DataMember]
        public string Password { get; } = password;
    }
}