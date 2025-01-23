using AltShare.Models;
using AltShare.Services;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using System.Security.Cryptography;
using Microsoft.OpenApi.Models;
using AltShare.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddSwaggerGen(option =>
{
    option.SwaggerDoc("v1", new OpenApiInfo { Title = "Account Sharing", Version = "v1" });
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

IConfiguration config = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json", true, true)
    .AddJsonFile("local.appsettings.json", true, true)
    .AddUserSecrets<Program>(optional: true)
    .AddEnvironmentVariables()
    .Build();


builder.Services.Configure<AccountDatabaseSettings>(
    config.GetSection("Mongo")
);

builder.Services.Configure<Argon2Options>(
    config.GetSection("Argon2")
);

builder.Services.AddSingleton(serviceProvider =>
{
    var settings = serviceProvider.GetRequiredService<IOptions<AccountDatabaseSettings>>().Value;
    Console.WriteLine($"Connecting to with string of {settings.ConnectionString.Length} length");
    return new MongoClient(settings.ConnectionString);
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var publicKey = config["Jwt:PublicKey"].Replace("\r\n", "");
        if (string.IsNullOrEmpty(publicKey))
        {
            throw new InvalidOperationException("JWT public key is not configured.");
        }

        var rsa = RSA.Create();
        rsa.ImportFromPem(publicKey);

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = config["Jwt:Issuer"],
            IssuerSigningKey = new RsaSecurityKey(rsa)
        };
    });

builder.Services.AddSingleton<UserAccountService>();
builder.Services.AddSingleton<SharedAccountService>();
builder.Services.AddSingleton<PasswordHasherService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();


app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthorization();

//app.MapControllerRoute(
//    name: "default",
//    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapControllers();

app.Run();
