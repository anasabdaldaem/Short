using System;
using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using LiteDB;
using Microsoft.AspNetCore.WebUtilities;
using ClientsideEncryption;
var host = Host.CreateDefaultBuilder(args)
    .ConfigureWebHostDefaults(builder =>
    {
        builder.UseWebRoot("C:\\Users\\ANAS\\Downloads\\Compressed\\fast-aspnet-samples-main\\fast-aspnet-samples-main\\url-shortener\\wwwroot");
        builder.ConfigureServices(services =>
        {
            
            services.AddSingleton<ILiteDatabase, LiteDatabase>((sp) =>
            {
                var db = new LiteDatabase("shortener.db");
                var collection = db.GetCollection<ShortLink>(BsonAutoId.Int32);
                collection.EnsureIndex(p => p.Url);
                collection.Upsert(new ShortLink
                {
                    Id = 100_000,
                    Url = "https://www.google.com/",
                    Chunk = "google",
                    create = DateTime.Now,
                    count = 0,
                    user = "sys",
                    password="123"
                });
                return db;
            });
            services.AddRouting();
        })
        .Configure(app =>
        {

            app.UseRouting();
            app.UseEndpoints((endpoints) =>
            {
                endpoints.MapPost("/shorten", HandleShortenUrl);
                endpoints.MapPost("/Find", FindShortenUrl);
                endpoints.MapPost("/Signup", SignUp);
                endpoints.MapGet("/ViewAll", ViewALLData);
                endpoints.MapFallback(HandleUrl);
               
            });
        });
    })
    .Build();

await host.RunAsync();

static Task SignUp(HttpContext context)
{
    var db = context.RequestServices.GetService<ILiteDatabase>();
    var collection = db.GetCollection<ShortLink>(nameof(ShortLink));
    ShortLink entry;
    context.Request.Form.TryGetValue("user", out var formData);
    var user=formData.ToString();
    context.Request.Form.TryGetValue("Password", out formData);
    var password=formData.ToString();
    entry=collection.Find(p => p.user == user).FirstOrDefault();
    if(entry is null)
    {
        entry= new ShortLink();
        
            entry.user=user;
            entry.password=password;
            entry.Url = "https://www.google.com/";
            entry.create = DateTime.Now;
            entry.count = 0;
        
        collection.Insert(entry);
        entry.Chunk = entry.GetUrlChunk();
        collection.Update(entry);
    }
    else
    {
        context.Response.WriteAsync("<script language='javascript'>alert('User is exist use another.');window.location.href = '/';</script>");
        return Task.CompletedTask;
    }
    context.Response.WriteAsync("<script language='javascript'>alert('Now You Have Account With Us enjoy.');window.location.href = '/';</script>");
    return Task.CompletedTask;
}
static Task HandleShortenUrl(HttpContext context)
{
    // Retrieve our dependencies
    var db = context.RequestServices.GetService<ILiteDatabase>();
    var collection = db.GetCollection<ShortLink>(nameof(ShortLink));
    ShortLink entry;
    string urlChunk;
    string password;
    // Perform basic form validation
    if (!context.Request.HasFormContentType || !context.Request.Form.ContainsKey("url"))
    {
        context.Response.WriteAsync("<script language='javascript'>alert('Cannot process request.');window.location.href = '/';</script>");
        return Task.CompletedTask;
    }
    else
    {
        context.Request.Form.TryGetValue("url", out var formData);
        var requestedUrl = formData.ToString();
        context.Request.Form.TryGetValue("shortcode", out formData);
        var requestedshortcode = formData.ToString();
        context.Request.Form.TryGetValue("user", out formData);
        var user = formData.ToString();
        context.Request.Form.TryGetValue("password", out formData);
        password = formData.ToString();
        
        String chunk;
        entry = collection.Find(p => p.user == user && p.password==password).FirstOrDefault();
        if (entry is null)
        {
            context.Response.WriteAsync("<script language='javascript'>alert('Your User or Password is invalid');window.location.href = '/';</script>");
            return Task.CompletedTask;
        }
        else
        {
            if (requestedshortcode.Trim() != "")
            {
                chunk = requestedshortcode.Trim();
                if (chunk.Length > 4)
                {
                    context.Response.WriteAsync("<script language='javascript'>alert('shortcodes must be at least 4 characters');window.location.href = '/';</script>");
                    return Task.CompletedTask;
                }
                entry = collection.Find(p => p.Chunk == chunk).FirstOrDefault();
                if (entry != null)
                {
                    context.Response.WriteAsync("<script language='javascript'>alert('The Shortcode URL is Used');window.location.href = '/';</script>");
                    return Task.CompletedTask;
                }
                else
                {
                    // Test our URL
                    if (!Uri.TryCreate(requestedUrl, UriKind.Absolute, out Uri result))
                    {
                        context.Response.WriteAsync("<script language='javascript'>alert('Could not understand URL');window.location.href = '/';</script>");
                        return Task.CompletedTask;
                    }

                    var url = result.ToString();
                    entry = collection.Find(p => p.Url == url && p.user == user && p.password==password).FirstOrDefault();

                    if (entry is null)
                    {
                        entry = new ShortLink
                        {
                            Url = url,
                            Chunk = chunk,
                            user = user,
                            create = DateTime.Now,
                            count = 0,
                            password=password
                        };
                        collection.Insert(entry);
                    }
                    else
                    {
                        entry.Chunk = chunk;
                        collection.Update(entry);
                    }
                }
            }
            else
            {
                if (!Uri.TryCreate(requestedUrl, UriKind.Absolute, out Uri result))
                {
                    context.Response.WriteAsync("<script language='javascript'>alert('Could not understand URL');window.location.href = '/';</script>");
                    return Task.CompletedTask;
                }

                var url = result.ToString();
                entry = collection.Find(p => p.Url == url && p.user == user && p.password==password).FirstOrDefault();

                if (entry is null)
                {
                    entry = new ShortLink();

                    entry.Url = url;
                    collection.Insert(entry);
                    entry.user = user;
                    entry.password= password;
                    entry.create = DateTime.Now;
                    entry.count = 0;
                    entry.Chunk = entry.GetUrlChunk();
                    collection.Update(entry);
                }

            }
        }
        urlChunk = entry.Chunk;

    }
    var responseUri = $"{context.Request.Scheme}://{context.Request.Host}/{entry.user}/{urlChunk}";
    context.Response.Redirect($"/#{responseUri}");
    return Task.CompletedTask;
}



static Task FindShortenUrl(HttpContext context)
{
    context.Request.Form.TryGetValue("shortcode", out var CH);
    if (CH.ToString().Trim() == "")
    {
        // Retrieve our dependencies
        var db = context.RequestServices.GetService<ILiteDatabase>();
        var collection = db.GetCollection<ShortLink>(nameof(ShortLink));

        // Perform basic form validation
        if (!context.Request.HasFormContentType || !context.Request.Form.ContainsKey("url"))
        {
            context.Response.WriteAsync("<script language='javascript'>alert('Cannot process request.');window.location.href = '/';</script>");
            return Task.CompletedTask;
        }
        else
        {
            context.Request.Form.TryGetValue("url", out var formData);
            var requestedUrl = formData.ToString();
            context.Request.Form.TryGetValue("user", out formData);
            var user = formData.ToString();
            context.Request.Form.TryGetValue("password", out formData);
            var password=formData.ToString();
            var entry = collection.Find(p => p.user == user && p.password==password).FirstOrDefault();

            if (entry is null)
            {
                context.Response.WriteAsync("<script language='javascript'>alert('Your User or Password is invalid');window.location.href = '/';</script>");
                return Task.CompletedTask;
            }
            else
            {
                if (!Uri.TryCreate(requestedUrl, UriKind.Absolute, out Uri result))
                {
                    context.Response.WriteAsync("<script language='javascript'>alert('Could not understand URL');window.location.href = '/';</script>");
                    return Task.CompletedTask;
                }

                var url = result.ToString();
                entry = collection.Find(p => p.Url == url && p.user == user && p.password == password).FirstOrDefault();
                if (entry is null)
                {
                    context.Response.WriteAsync("<script language='javascript'>alert('Could not Find the URL');window.location.href = '/';</script>");
                    return Task.CompletedTask;
                }
                else
                {
                    var urlChunk = entry.Chunk;
                    var responseUri = $"{context.Request.Scheme}://{context.Request.Host}/{entry.user}/{urlChunk}";
                    context.Response.Redirect($"/#{responseUri}");
                    return Task.CompletedTask;
                }
            }
        }
    }
    else
    {
        context.Response.WriteAsync("<script language='javascript'>alert('Shortcode must be empty to find URL');window.location.href = '/';</script>");
        return Task.CompletedTask;
    }
}
static Task ViewALLData(HttpContext context)
{

    var db = context.RequestServices.GetService<ILiteDatabase>();
    var collection = db.GetCollection<ShortLink>();
    context.Request.Query.TryGetValue("user", out var formData1);
    var username = formData1.ToString();
    context.Request.Query.TryGetValue("password", out formData1);
    var pass=formData1.ToString();
    var user = AESEncrytDecry.DecryptStringAES(username);
    var password = AESEncrytDecry.DecryptStringAES(pass);
    if (user != "keyError" && password != "keyError")
    {
        var entry = collection.Find(p => p.user == user && p.password==password);
        if (entry is null)
        {
            context.Response.WriteAsync("<script language='javascript'>alert('Your User or Password is invalid or empty');window.location.href = '/';</script>");
            return Task.CompletedTask;
        }
        else
        {


            context.Response.WriteAsJsonAsync(entry);
            return Task.CompletedTask;
        }
    }
    else
    {
        context.Response.WriteAsync("<script language='javascript'>alert('Not vaild login');window.location.href = '/';</script>");
        return Task.CompletedTask;
    }
}

static Task HandleUrl(HttpContext context)
{
    if (context.Request.Path == "/")
    {
        return context.Response.SendFileAsync("wwwroot/index.htm");;
    }

    // Default to home page if no matching url.
    var redirect = "/";

    var db = context.RequestServices.GetService<ILiteDatabase>();
    var collection = db.GetCollection<ShortLink>();

    var path = context.Request.Path.ToUriComponent();
    if (path.Contains("user"))
        redirect = path;
    else
    {
        if(path.Contains("ViewAll"))
        redirect=path;
        var z = path.Trim('/').Split('/');
        if (z.Length == 2)
        {
            var user = z[0];
            var chunk = z[1];
            var entry = collection.Find(p => p.Chunk == chunk && p.user == user).SingleOrDefault();

            if (entry is not null)
            {
                redirect = entry.Url;
                entry.count += 1;
                entry.lastacc = DateTime.Now;
                collection.Update(entry);
            }
        }
    }


    context.Response.Redirect(redirect);
    return Task.CompletedTask;
}

// Classes

public class ShortLink
{
    public  string GetUrlChunk()
    { 
        return Chunk=WebEncoders.Base64UrlEncode(BitConverter.GetBytes(Id));
    }

    public int GetId(string urlChunk)
    {
        return Id;
    }

    public string user { get; set; }
    public string password { get; set; }
    public string Chunk { get; set; }
    public int Id { get; set; }
    public DateTime create { get; set; }
    public DateTime lastacc { get; set; }

    public int count { get; set; }

    public string Url { get; set; }
}