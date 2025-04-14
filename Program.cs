using AltShare.Models;
using AltShare.Services;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using MongoDB.Driver;
using System.Security.Cryptography;
using Microsoft.OpenApi.Models;
using System.Net;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddEnvironmentVariables();

builder.Services.AddControllersWithViews();
builder.Services.AddSwaggerGen(option =>
{
    option.SwaggerDoc("v1", new OpenApiInfo { Title = "Account Sharing", Version = "v1" });
    option.TagActionsBy(api => new[] { api.GroupName ?? api.ActionDescriptor.RouteValues["controller"] });
    option.AddSecurityDefinition(
        "Bearer",
        new OpenApiSecurityScheme
        {
            In = ParameterLocation.Header,
            Description = "Please enter a valid token",
            Name = "Authorization",
            Type = SecuritySchemeType.Http,
            BearerFormat = "JWT",
            Scheme = "Bearer"
        }
    );
    option.AddSecurityRequirement(
        new OpenApiSecurityRequirement
        {
            {
                new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference
                    {
                        Type = ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    }
                },
                new string[] { }
            }
        }
    );
});

builder.Services.Configure<AccountDatabaseSettings>(settings =>
{
    settings.ConnectionString = builder.Configuration["Mongo:ConnectionString"] ??
        throw new InvalidOperationException("MongoDB connection string is missing");
    settings.DatabaseName = builder.Configuration["Mongo:DatabaseName"] ?? "AccountShare";
    settings.UserCollectionName = builder.Configuration["Mongo:UserCollectionName"] ?? "UserAccount";
    settings.AccountCollectionName = builder.Configuration["Mongo:AccountCollectionName"] ?? "SharedAccount";
});

builder.Services.Configure<AltShare.Models.Argon2Settings>(
    builder.Configuration.GetSection("Argon2Settings"));

var mongoConnectionString = builder.Configuration["Mongo:ConnectionString"];
if (string.IsNullOrEmpty(mongoConnectionString))
{
    throw new InvalidOperationException(
        "MongoDB connection string is missing. Please check your secrets.json file."
    );
}

MongoClient mongoClient;
try
{
    mongoClient = new MongoClient(mongoConnectionString);
    mongoClient.ListDatabaseNames().First();
    Console.WriteLine("Successfully connected to MongoDB Atlas");
}
catch (Exception ex)
{
    throw new InvalidOperationException(
        $"Failed to connect to MongoDB. Please check your connection string and ensure MongoDB is running. Error: {ex.Message}",
        ex
    );
}

builder.Services.AddSingleton(mongoClient);

var database = mongoClient.GetDatabase(
    builder.Configuration["Mongo:DatabaseName"] ?? "AccountShare");

builder.Services.AddSingleton(database.GetCollection<EncryptedSharedAccount>(
    builder.Configuration["Mongo:AccountCollectionName"] ?? "SharedAccount"));
builder.Services.AddSingleton(database.GetCollection<SharedAccountMapping>(
    nameof(SharedAccountMapping)));

// Register services
builder.Services.AddSingleton<UserAccountService>();
builder.Services.AddSingleton<SharedAccountService>();
builder.Services.AddSingleton<PasswordHasherService>();

builder.Services.AddHttpClient();

bool IsRunningInKubernetes()
{
    return !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("KUBERNETES_SERVICE_HOST"));
}

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var publicKeyPath =
            IsRunningInKubernetes()
                ? "/run/secrets/altshare/public_key.pem"
                : "public_key.pem";

        if (!File.Exists(publicKeyPath))
        {
            throw new InvalidOperationException("JWT public key file not found.");
        }

        var publicKeyPem = File.ReadAllText(publicKeyPath).Trim();

        RSA publicKey = RSA.Create();
        publicKey.ImportFromPem(publicKeyPem.ToCharArray());

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            IssuerSigningKey = new RsaSecurityKey(publicKey)
        };

        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var accessToken = context.Request.Query["access_token"];

                var path = context.HttpContext.Request.Path;
                if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/api/hub"))
                {
                    context.Token = accessToken;
                }
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddSignalR(options => { options.EnableDetailedErrors = true; });

// Add CORS configuration
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(builder =>
    {
        builder
            .WithOrigins("https://asher.local:5173", "https://asher.local:7006", "https://localhost:5173", "https://share.3xjn.dev")
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials()
            .WithExposedHeaders("Content-Disposition");
    });
});

var app = builder.Build();

ServicePointManager.ServerCertificateValidationCallback +=
(sender, cert, chain, sslPolicyErrors) => { return true; };

app.UseHttpsRedirection();

app.UseRouting();

app.UseWebSockets();

app.UseCors(); // Add CORS middleware

app.UseAuthentication();
app.UseAuthorization();

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "AltShare v1");
    c.RoutePrefix = "swagger";
});

// Map endpoints after UseRouting and UseCors
app.MapHub<SignalingHub>("/api/hub");
app.MapControllers();

if (app.Environment.IsProduction())
{
    app.UseExceptionHandler(config =>
    {
        config.Run(async context =>
        {
            context.Response.StatusCode = 500;
            context.Response.ContentType = "application/json";

            var errorDetails = new
            {
                message = "An unexpected error occurred. Please try again later."
            };

            var errorJson = JsonSerializer.Serialize(errorDetails);
            await context.Response.WriteAsync(errorJson);
        });
    });
}
else
{
    app.UseDeveloperExceptionPage();
}

app.Run();
