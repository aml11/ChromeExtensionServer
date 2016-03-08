using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Ionic.Zip;
using Newtonsoft.Json;
using NLog;
using NLog.Config;

namespace ChromeExtensionServer
{
	internal static class ExtUri
	{
		private static readonly Logger Log = LogManager.GetCurrentClassLogger();

		public static Dictionary<string, string> GetQueryCollection(this Uri uri)
		{
			var ret = new Dictionary<string, string>();
			try
			{
				var queryString = uri.Query;
				var queryCollection = System.Web.HttpUtility.ParseQueryString(queryString);

				foreach (var queryParamKey in queryCollection.AllKeys)
				{
					ret[queryParamKey] = queryCollection[queryParamKey];
				}
			}
			catch (Exception e)
			{
				Log.Error(string.Format("The url is invalid ({0}).", uri.PathAndQuery), e);
			}
			return ret;
		}
	}


	public class CrxFileStructure
	{
		public readonly byte[] MagicNumber;
		public readonly byte[] CrxVersion;
		public readonly byte[] KeyLength;
		public readonly byte[] SignatureLength;
		public readonly byte[] PublicKeyStructure;
		public readonly byte[] Signature;
		public readonly byte[] ZipBytes;

		public CrxFileStructure(string fileName)
		{
			using (var file = File.OpenRead(fileName))
			{
				MagicNumber = new byte[4];
				file.Read(MagicNumber, 0, MagicNumber.Length);

				//Verify magic
				if (!Encoding.UTF8.GetBytes("Cr24").SequenceEqual(MagicNumber))
				{
					throw new ArgumentException(string.Format("File {0} has a bad magic number, was:{1}.", fileName, string.Join(",", MagicNumber)));
				}

				CrxVersion = new byte[4];
				file.Read(CrxVersion, 0, CrxVersion.Length);

				if (BitConverter.ToInt32(CrxVersion, 0) != 2)
				{
					throw new ArgumentException(string.Format("File {0} has a bad version number, was:{1} (we only support 2).", fileName, string.Join(",", CrxVersion)));
				}

				KeyLength = new byte[4];
				file.Read(KeyLength, 0, KeyLength.Length);

				SignatureLength = new byte[4];
				file.Read(SignatureLength, 0, SignatureLength.Length);

				var keyLen = BitConverter.ToInt32(KeyLength, 0);
				PublicKeyStructure = new byte[keyLen];
				file.Read(PublicKeyStructure, 0, PublicKeyStructure.Length);

				var sigLen = BitConverter.ToInt32(SignatureLength, 0);
				Signature = new byte[sigLen];
				file.Read(Signature, 0, Signature.Length);

				ZipBytes = new byte[file.Length - file.Position];
				file.Read(ZipBytes, 0, ZipBytes.Length);

				var magicZip = ZipBytes.Take(4).ToArray();
				if (!magicZip.SequenceEqual(new byte[] { 0x50, 0x4b, 0x03, 0x04 }))
				{
					throw new ArgumentException(string.Format("File {0} has a bad zip magic number, was:{1} (we only support 2).", fileName, string.Join(",", magicZip)));
				}
			}
		}

	}


	class Program
	{
		private static readonly Logger Log = LogManager.GetCurrentClassLogger();


		private static string readJsonManifestFromCrx(string fileName)
		{
			try
			{
				var crx = new CrxFileStructure(fileName);
				using (var ms = new MemoryStream(crx.ZipBytes))
				using (var z = ZipFile.Read(ms))
				{
					var manifestEntry = z.Entries.First(entry => entry.FileName.Equals("manifest.json", StringComparison.OrdinalIgnoreCase));
					using (var streamReader = new StreamReader(manifestEntry.OpenReader()))
					{
						var json = streamReader.ReadToEnd();
						return json;
					}
				}

			}
			catch (Exception e)
			{
				Log.Error(e, "Couldn't get the manifest version from {0}.", fileName);
			}
			return "";
		}



		private static void writeFile(HttpListenerContext ctx, string path)
		{
			var response = ctx.Response;
			using (var fs = File.OpenRead(path))
			{
				var filename = Path.GetFileName(path);
				//response is HttpListenerContext.Response...
				response.ContentLength64 = fs.Length;
				response.SendChunked = false;
				response.ContentType = System.Net.Mime.MediaTypeNames.Application.Octet;
				response.AddHeader("Content-disposition", "attachment; filename=" + filename);

				byte[] buffer = new byte[64*1024];
				using (var bw = new BinaryWriter(response.OutputStream))
				{
					int read;
					while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
					{
						bw.Write(buffer, 0, read);
						bw.Flush(); //seems to have no effect
					}

					bw.Close();
				}

				response.StatusCode = (int) HttpStatusCode.OK;
				response.StatusDescription = "OK";
				response.OutputStream.Close();
				Log.Info("Success writing {0} bytes from the file {1}.", fs.Length, path);
			}
		}

		// ReSharper disable once InconsistentNaming
		static void Main(string[] args)
		{
			var assemblyFolder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
			LogManager.Configuration = new XmlLoggingConfiguration(assemblyFolder + "\\NLog.config", true);
			Log.Info("Starting ChromeExtensionServer");
			
			var listener = new HttpListener();
			listener.Prefixes.Add("http://*:80/");
			listener.Start();
			Log.Info("Listening...");
			for (;;)
			{
				try
				{
					var ctx = listener.GetContext();
					Log.Info("Got a new request: {0} from: {1}.", ctx.Request.Url, ctx.Request.RemoteEndPoint);
					Task.Factory.StartNew(() =>
					{
						try
						{
							if (ctx.Request.Url.LocalPath == "/")
							{
								var query = ctx.Request.Url.GetQueryCollection();
								Log.Info("Query string:{0}", String.Join(",", query.Select(kvp => string.Format("{0}={1}", kvp.Key, kvp.Value))));
								if (query.ContainsKey("x"))
								{
									var id = System.Web.HttpUtility.ParseQueryString(query["x"])["id"];
									var fileName = string.Format("{0}.crx", id);
									var realFileName = Path.Combine(Directory.GetCurrentDirectory(), "files\\" + fileName);
									Log.Info("Trying to get {0}.", realFileName);
									if (File.Exists(realFileName))
									{
										var baseUrl = ctx.Request.Url.GetComponents(UriComponents.SchemeAndServer | UriComponents.UserInfo, UriFormat.Unescaped);
										var version = getVersionFromCrx(realFileName);
										Log.Info("Offerring version {0} for id {1}.", version, id);
										var retXml = Resource1.RetXml
											.Replace(Resource1.hashToReplace, id)
											.Replace(Resource1.urlToReplace, string.Format("{0}/{1}", baseUrl, fileName))
											.Replace(Resource1.versionToReplace, version);
										Log.Info("Replying with {0}.", retXml);
										var buffer = Encoding.UTF8.GetBytes(retXml);
										ctx.Response.OutputStream.Write(buffer, 0, buffer.Length);
									}
									else
									{
										Log.Error("We aren't serving an extension with the id:{0}.", id);
									}
								}
								else
								{
									Log.Warn("Bad query string.");
								}
								ctx.Response.StatusCode = (int) HttpStatusCode.OK;
							}
							else
							{
								Log.Info("Try to get {0}.", ctx.Request.Url.LocalPath);
								var path = Directory.GetCurrentDirectory() + "\\files" + ctx.Request.Url.LocalPath;
								if (!File.Exists(path))
								{
									Log.Warn("We aren't serving {0}", ctx.Request.Url.LocalPath);
								}
								else
								{
									writeFile(ctx, path);
								}
							}
						}
						catch (Exception e)
						{
							Log.Error(e, "Exception during response build.");
						}
						finally
						{
							ctx.Response.Close();
						}
					});
				}
				catch (Exception e)
				{
					Log.Error(e, "Exception during http run.");
				}
			}
		}

		private static string getVersionFromCrx(string fileName)
		{
			var jsonStr = readJsonManifestFromCrx(fileName);
			var jsonDic = JsonConvert.DeserializeObject<Dictionary<string, object>>(jsonStr);
			return jsonDic["version"] as string;
		}
	}
}
