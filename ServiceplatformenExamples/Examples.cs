using Xunit;
using System.Text.Json;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Net.Http.Headers;
using Digst.OioIdws.OioWsTrustCore;
using Digst.OioIdws.WscCore.OioWsTrust;
using ConnectedServices_PersonBaseDataExtendedService;
using ConnectedServices_SKATForwardEIndkomstService;
using ConnectedServices_YdelseListeHentService;
using static Digst.OioIdws.SoapCore.FederatedChannelFactoryExtensions;
using static Digst.OioIdws.WscCore.OioWsTrust.TokenServiceConfigurationFactory;
using Xunit.Sdk;
using System;
using Microsoft.Win32.SafeHandles;

namespace ServiceplatformenExamples;

public class Examples
{
    [Fact]
    public async Task SF1520CprReplikaOpslagExample()
    {
        WriteClientCert();

        var cpr = "0101001234";

        var data = await SF1520PersonLookup(cpr);

        JsonSerializerOptions options = new() { WriteIndented = true, IncludeFields = true };
        Console.WriteLine(JsonSerializer.Serialize(data, options));
    }

    
    [Fact]
    public async Task SF0770ASkatIndkomstOpslagPersonoplysningerExample()
    {
        WriteClientCert();
        var cpr = "0101001234";
        var startMonth = "202510"; // YYYYMM
        var endMonth = "202510";  // YYYYMM

        var data = await SF0770AIndkomstoplysningerLaes(cpr, startMonth, endMonth);

        JsonSerializerOptions options = new() { WriteIndented = true, IncludeFields = true };
        Console.WriteLine(JsonSerializer.Serialize(data, options));
    }

    [Fact]
    public async Task SF1491HentYdelserFraEgensektorExample()
    {
        WriteClientCert();

        var cpr = "0101001234";

        var data = await SF1491EffektueringHent(cpr);

        JsonSerializerOptions options = new() { WriteIndented = true, IncludeFields = true };
        Console.WriteLine(JsonSerializer.Serialize(data, options));
    }

    [Fact]
    public async Task SF1516HentAccessTokenExample()
    {
        WriteClientCert();

        var result = await SF1516AccessTokenDemo(true);

        Console.WriteLine(result);
    }
    
    [Fact]
    public async Task SF1475HentSagerFraDUBUExample()
    {
        WriteClientCert();

        var result = await SF1475HentSagerFraDUBU();

        Console.WriteLine(result);
    }

    public static string GetAccessToken(string base64SamlToken, string clientCertificatePath, string tokenUrl, string? datarekvirentType = null, string? datarekvirentIdentifier = null)
    {
        var handler = new HttpClientHandler();
        var clientCert = new Certificate { FilePath = clientCertificatePath, FromFileSystem = true };
        X509Certificate2 clientCertificate = CertificateUtil.GetCertificate(clientCert);
        handler.ClientCertificates.Add(clientCertificate);

        using var httpClient = new HttpClient(handler);

        var parameters = new Dictionary<string, string>
        {
            { "saml-token", base64SamlToken },
        };

        bool hasType = !string.IsNullOrEmpty(datarekvirentType);
        bool hasIdentifier = !string.IsNullOrEmpty(datarekvirentIdentifier);

        if (hasType && hasIdentifier)
        {
            var allowedTypes = new[] { "CPR", "CVR", "PNummer", "OrgEnhed" };
            if (!allowedTypes.Contains(datarekvirentType))
                throw new ArgumentException("datarekvirentType must be one of: CPR, CVR, PNummer, OrgEnhed");

            parameters["datarekvirent-type"] = datarekvirentType!;
            parameters["datarekvirent-identifier"] = datarekvirentIdentifier!;
        }
        else if (hasType || hasIdentifier)
        {
            throw new ArgumentException("Both datarekvirentType and datarekvirentIdentifier must be provided together, or both must be null.");
        }

        var content = new FormUrlEncodedContent(parameters);

        var response = httpClient.PostAsync(tokenUrl, content).Result;

        try
        {
            response.EnsureSuccessStatusCode();
        }
        catch (HttpRequestException)
        {
            var errorContent = response.Content.ReadAsStringAsync().Result;
            Console.WriteLine($"Error Response: {errorContent}");
            throw;
        }

        var result = response.Content.ReadAsStringAsync().Result;

        using var doc = JsonDocument.Parse(result);
        string? accessToken = doc.RootElement.TryGetProperty("access_token", out var tokenElement) && tokenElement.GetString() != null
            ? tokenElement.GetString()
            : null;

        if (accessToken is null)
            throw new InvalidOperationException("access_token property is missing or null in the response.");

        return accessToken;
    }

    public static class Config
    {
        const string basePath = "../../../Certificates/";
        public const string
            // Kommunens CVR-nummer
            MunicipalityCvr = "29189668",

            // Client certificate paths - production
            PRODClientCertPublicKeyPath = basePath + "Client/clientPROD.cer",
            PRODClientCertPrivateKeyPath = basePath + "Client/clientPROD.pem",
            PRODP12Path = basePath + "Client/clientCertPROD.p12",

            // Client certificate paths - test
            TESTClientCertPublicKeyPath = basePath + "Client/clientTEST.cer",
            TESTClientCertPrivateKeyPath = basePath + "Client/clientTEST.pem",
            TESTP12Path = basePath + "Client/clientCertTEST.p12",

            // Service certificates paths
            PRODServiceplatformenCertificateFilePath = basePath + "Services/SP_PROD_Signing_1.cer",
            TESTServiceplatformenCertificateFilePath = basePath + "Services/SP_EXTTEST_Signing_1.cer",
            PRODYdelsesindeksCertificateFilePath = basePath + "Services/YDI_PROD_Ydelsesindeks_1.cer",
            TESTYdelsesindeksCertificateFilePath = basePath + "Services/YDI_EXTTEST_Ydelsesindeks_1.cer",

            // STS certificates path
            // PRODStsCertificateFilePath = basePath + "STS/ADG_PROD_Adgangsstyring_2.cer",
            PRODStsCertificateFilePath = basePath + "STS/ADG_PROD_Adgangsstyring_2_with_chain.cer",
            TESTStsCertificateFilePath = basePath + "STS/ADG_EXTTEST_Adgangsstyring_1.cer",

            // Sts endpoints
            PRODStsEndpoint = "https://n2adgangsstyring.stoettesystemerne.dk/runtime/services/kombittrust/14/certificatemixed",
            PRODStsEndpointId = "http://saml.n2adgangsstyring.stoettesystemerne.dk/runtime",
            TESTStsEndpoint = "https://n2adgangsstyring.eksterntest-stoettesystemerne.dk/runtime/services/kombittrust/14/certificatemixed",
            TESTStsEndpointId = "http://saml.n2adgangsstyring.eksterntest-stoettesystemerne.dk/runtime";
    }

    static void WriteClientCert()
    {
        // Handle PROD certificate
        if (!File.Exists(Config.PRODP12Path))
        {
            var prodCert = X509Certificate2.CreateFromPemFile(Config.PRODClientCertPublicKeyPath, Config.PRODClientCertPrivateKeyPath);
            byte[] prodPfxBytes = prodCert.Export(X509ContentType.Pfx);
            File.WriteAllBytes(Config.PRODP12Path, prodPfxBytes);
        }

        // Handle TEST certificate
        if (!File.Exists(Config.TESTP12Path))
        {
            var testCert = X509Certificate2.CreateFromPemFile(Config.TESTClientCertPublicKeyPath, Config.TESTClientCertPrivateKeyPath);
            byte[] testPfxBytes = testCert.Export(X509ContentType.Pfx);
            File.WriteAllBytes(Config.TESTP12Path, testPfxBytes);
        }
    }

    static StsTokenServiceConfiguration CreateStsConfig(string serviceCertificatePath,
                                    string serviceEndpoint,
                                    string serviceEndpointId,
                                    bool includeLibertyHeader = true,
                                    string wspSoapVersion = "1.1",
                                    bool isTest = false) =>
        CreateConfiguration(new OioIdwsWcfConfigurationSection()
        {
            StsCertificate = new Certificate { FilePath = isTest ? Config.TESTStsCertificateFilePath : Config.PRODStsCertificateFilePath, FromFileSystem = true },
            StsEndpointAddress = isTest ? Config.TESTStsEndpoint : Config.PRODStsEndpoint,
            StsEntityIdentifier = isTest ? Config.TESTStsEndpointId : Config.PRODStsEndpointId,
            ServiceCertificate = new Certificate { FilePath = serviceCertificatePath, FromFileSystem = true, },
            WspEndpoint = serviceEndpoint,
            WspEndpointID = serviceEndpointId,
            ClientCertificate = new Certificate { FilePath = isTest ? Config.TESTP12Path : Config.PRODP12Path, FromFileSystem = true },
            Cvr = Config.MunicipalityCvr,
            TokenLifeTimeInMinutes = 60,
            IncludeLibertyHeader = includeLibertyHeader,
            MaxReceivedMessageSize = 256000,
            DebugMode = false,
            WspSoapVersion = wspSoapVersion
        });


    static StsTokenServiceConfiguration TESTCreateStsConfig(string serviceCertificatePath,
                                    string serviceEndpoint,
                                    string serviceEndpointId,
                                    // string stsCertificateFilePath = Config.StsCertificateFilePath2,
                                    bool includeLibertyHeader = true,
                                    string wspSoapVersion = "1.1") =>
        CreateConfiguration(new OioIdwsWcfConfigurationSection()
        {
            StsCertificate = new Certificate { FilePath = Config.TESTStsCertificateFilePath, FromFileSystem = true },
            StsEndpointAddress = Config.TESTStsEndpoint,
            StsEntityIdentifier = Config.TESTStsEndpointId,
            ServiceCertificate = new Certificate { FilePath = serviceCertificatePath, FromFileSystem = true, },
            WspEndpoint = serviceEndpoint,
            WspEndpointID = serviceEndpointId,
            ClientCertificate = new Certificate { FilePath = Config.TESTP12Path, FromFileSystem = true },
            Cvr = Config.MunicipalityCvr,
            TokenLifeTimeInMinutes = 60,
            IncludeLibertyHeader = includeLibertyHeader,
            // IncludeLibertyHeader = true,
            MaxReceivedMessageSize = 256000,
            DebugMode = false,
            WspSoapVersion = wspSoapVersion //"1.2", //Delete if you want to use 1.1
        });

    static async Task<PersonLookupResponseType> SF1520PersonLookup(string cpr, bool isTest = false)
    {
        string serviceCertificatePath, serviceEndpoint, serviceEndpointId;

        if (isTest)
        {
            serviceCertificatePath = Config.TESTServiceplatformenCertificateFilePath;
            serviceEndpoint = "https://exttest.serviceplatformen.dk/service/CPR/PersonBaseDataExtended/5";
            serviceEndpointId = "http://cpr.serviceplatformen.dk/service/personbasedataextended/5";
        }
        else
        {
            serviceCertificatePath = Config.PRODServiceplatformenCertificateFilePath;
            serviceEndpoint = "https://prod.serviceplatformen.dk/service/CPR/PersonBaseDataExtended/5";
            serviceEndpointId = "http://cpr.serviceplatformen.dk/service/personbasedataextended/5";
        }

        var config = CreateStsConfig(serviceCertificatePath, serviceEndpoint, serviceEndpointId, isTest: isTest);

        GenericXmlSecurityToken token;
        token = (GenericXmlSecurityToken)new StsTokenService(config).GetToken();

        var client = CreateChannelWithIssuedToken<PersonBaseDataExtendedPortType>(token, config);
        var request = new PersonLookupRequest(new PersonLookupRequestType { PNR = cpr });
        var response = await client.PersonLookupAsync(request);
        return response.PersonLookupResponse1;
    }

    static async Task<IndkomstOplysningPersonHent1> SF0770AIndkomstoplysningerLaes(string cpr, string startMonth, string endMonth, bool isTest = false)
    {
        string serviceCertificatePath, serviceEndpoint, serviceEndpointId;

        if (isTest)
        {
            serviceCertificatePath = Config.TESTServiceplatformenCertificateFilePath;
            serviceEndpoint = "https://exttest.serviceplatformen.dk/service/SKAT/EIndkomst/4";
            serviceEndpointId = "http://entityid.kombit.dk/service/sp/skatforwardeindkomstservice/4";
        }
        else
        {
            serviceCertificatePath = Config.PRODServiceplatformenCertificateFilePath;
            serviceEndpoint = "https://prod.serviceplatformen.dk/service/SKAT/EIndkomst/4";
            serviceEndpointId = "http://entityid.kombit.dk/service/sp/skatforwardeindkomstservice/4";
        }

        var config = CreateStsConfig(serviceCertificatePath, serviceEndpoint, serviceEndpointId, isTest: isTest);

        GenericXmlSecurityToken token;
        token = (GenericXmlSecurityToken)new StsTokenService(config).GetToken();

        // Abonnement information
        var SENummer = "13392714";
        var AbonnementTypeKode = "3154";
        var AbonnentTypeKode = "0784";
        var AdgangFormaalTypeKode = "272";

        var client = CreateChannelWithIssuedToken<SKATForwardEIndkomstServiceServicePortType>(token, config);
        var request = new IndkomstOplysningPersonHent
        {
            IndkomstOplysningPersonHent_I = new IndkomstOplysningPersonHent_I
            {
                HovedOplysninger = new ConnectedServices_SKATForwardEIndkomstService.HovedOplysningerType { TransaktionsId = Guid.NewGuid().ToString(), TransaktionsTid = DateTime.UtcNow },
                IndkomstOplysningPersonInddata = new IndkomstOplysningPersonInddataType
                {
                    AbonnentAdgangStruktur = new AbonnentAdgangStrukturType { AbonnementTypeKode = AbonnementTypeKode, AbonnentTypeKode = AbonnentTypeKode, AdgangFormaalTypeKode = AdgangFormaalTypeKode },
                    AbonnentStruktur = new AbonnentStrukturType { AbonnentVirksomhedStruktur = new AbonnentVirksomhedStrukturType { AbonnentVirksomhed = new AbonnentVirksomhedStrukturTypeAbonnentVirksomhed { VirksomhedSENummerIdentifikator = SENummer } } },
                    IndkomstOplysningValg = new IndkomstOplysningPersonInddataTypeIndkomstOplysningValg
                    {
                        Item = new IndkomstOplysningPersonInddataTypeIndkomstOplysningValgIndkomstPersonSamling
                        {
                            PersonIndkomstSoegeStruktur =
                            [
                                new PersonIndkomstSoegeStrukturType { PersonCivilRegistrationIdentifier = cpr, SoegeAarMaanedLukketStruktur = new SoegeAarMaanedLukketStrukturType { SoegeAarMaanedFraKode = startMonth, SoegeAarMaanedTilKode = endMonth}},
                            ]
                        }
                    }
                }
            }
        };
        var response = await client.SF0770_A_IndkomstoplysningerLaes_IndkomstoplysningerLaesAsync(request);
        return response;
    }

    static async Task<EffektueringHentRequest1> SF1491EffektueringHent(string cpr, bool isTest = false)
    {
        string serviceCertificatePath, serviceEndpoint, serviceEndpointId;

        if (isTest)
        {
            serviceCertificatePath = Config.TESTYdelsesindeksCertificateFilePath;
            serviceEndpoint = "https://ydelsesindeks-exttest.stoettesystemerne.dk/ydelselistehent/2";
            serviceEndpointId = "http://entityid.kombit.dk/service/ydelselistehent/1";
        }
        else
        {
            serviceCertificatePath = Config.PRODYdelsesindeksCertificateFilePath;
            serviceEndpoint = "https://ydelsesindeks.stoettesystemerne.dk/ydelselistehent/2";
            serviceEndpointId = "http://entityid.kombit.dk/service/ydelselistehent/1";
        }

        var config = CreateStsConfig(serviceCertificatePath, serviceEndpoint, serviceEndpointId, includeLibertyHeader: false, wspSoapVersion: "1.2", isTest: isTest);

        GenericXmlSecurityToken token;
        token = (GenericXmlSecurityToken)new StsTokenService(config).GetToken();

        var client = CreateChannelWithIssuedToken<YdelseListeHentServicePortType>(token, config);
        var request = new EffektueringHentRequest
        {
            EffektueringHent_I = new EffektueringHent_I
            {
                HovedOplysninger = new ConnectedServices_YdelseListeHentService.HovedOplysningerType { TransaktionsId = Guid.NewGuid().ToString(), TransaktionsTid = DateTime.UtcNow },
                Kriterie = new EffektueringHent_ITypeKriterie { Item = cpr, ItemElementName = ItemChoiceType1.PartCPRNummer },
                RettighedListe = [new EffektueringHent_ITypeBevillingDataAfgrGruppe { }]
            }

        };
        var response = await client.EffektueringHentAsync(request);
        return response;
    }

    static async Task<String> SF1475HentSagerFraDUBU(bool isTest = false)
    {
        string clientCertificatePath, serviceCertificatePath, serviceEndpoint, serviceEndpointId, tokenUrl;

        if (isTest)
        {
            clientCertificatePath = Config.TESTP12Path;
            serviceCertificatePath = Config.TESTServiceplatformenCertificateFilePath;
            serviceEndpoint = "https://test-dataudstilling.dubu.dk/services/DUBUSagHent_1";
            serviceEndpointId = "http://test-dataudstilling.dubu.dk/service/dataudstilling/1";
            tokenUrl = "https://test-dataudstilling.dubu.dk/accesstoken";
        }
        else
        {
            clientCertificatePath = Config.PRODP12Path;
            serviceCertificatePath = Config.PRODServiceplatformenCertificateFilePath;
            serviceEndpoint = "https://dataudstilling.dubu.dk/services/DUBUSagHent_1";
            serviceEndpointId = "http://dataudstilling.dubu.dk/service/dataudstilling/1";
            tokenUrl = "https://dataudstilling.dubu.dk/accesstoken";
        }

        var config = CreateStsConfig(serviceCertificatePath, serviceEndpoint, serviceEndpointId, isTest: isTest);

        GenericXmlSecurityToken saml_token;
        saml_token = (GenericXmlSecurityToken)new StsTokenService(config).GetToken();

        var tokenXml = saml_token.TokenXml.OuterXml;
        var tokenBytes = System.Text.Encoding.UTF8.GetBytes(tokenXml);
        var base64token = Convert.ToBase64String(tokenBytes);

        
        var accessToken = GetAccessToken(base64token, clientCertificatePath, tokenUrl, "CVR", Config.MunicipalityCvr);

        var handler = new HttpClientHandler();
        var clientCert = new Certificate { FilePath = clientCertificatePath, FromFileSystem = true };
        X509Certificate2 clientCertificate = CertificateUtil.GetCertificate(clientCert);
        handler.ClientCertificates.Add(clientCertificate);
        using var httpClient = new HttpClient(handler);
        
        // Prepare GET request to /SagListe
        using var getRequest = new HttpRequestMessage(HttpMethod.Get, $"{serviceEndpoint}/SagListe");

        // Add Authorization header
        getRequest.Headers.Authorization = new AuthenticationHeaderValue("Holder-of-key", accessToken);

        // Add required headers
        getRequest.Headers.Add("x-TransaktionsId", Guid.NewGuid().ToString());
        getRequest.Headers.Add("x-TransaktionsTid", DateTime.UtcNow.ToString("o"));
        getRequest.Headers.Add("x-OnBehalfOfUser", "Digitalisering - Automatisering");

        // Send request and read response
        var getResponse = await httpClient.SendAsync(getRequest);
        var responseData = await getResponse.Content.ReadAsStringAsync();

        // Get first SagListe from response
        using var sagListeDoc = JsonDocument.Parse(responseData);
        var sagArray = sagListeDoc.RootElement.GetProperty("SagListeHent_O").GetProperty("SagListe");

        // Find the test Sag (part name contains "kartoffel")
        JsonElement testSag = default;
        bool foundTestSag = false;
        foreach (var sag in sagArray.EnumerateArray())
        {
            if (sag.TryGetProperty("SagSimpel", out var sagSimpel) &&
            sagSimpel.TryGetProperty("SagPrimaerPart", out var primaerPart) &&
            primaerPart.TryGetProperty("PartFuldtNavn", out var navn) &&
            navn.GetString() is string fuldtNavn &&
            fuldtNavn.Contains("kartoffel", StringComparison.OrdinalIgnoreCase))
            {
            testSag = sag;
            foundTestSag = true;
            break;
            }
        }
        if (!foundTestSag)
            throw new InvalidOperationException("No Sag found with PartFuldtNavn containing 'kartoffel'.");

        // Extract SagId
        var sagId = testSag.GetProperty("SagSimpel").GetProperty("SagUUID").GetString();

        // Prepare GET request to /Sag/{sagId}
        using var getRequest2 = new HttpRequestMessage(HttpMethod.Get, $"{serviceEndpoint}/Sag/{sagId}?PrimaerPartsNetvaerkMarkering=true&DokumenterMarkering=true");

        getRequest2.Headers.Authorization = new AuthenticationHeaderValue("Holder-of-key", accessToken);

        getRequest2.Headers.Add("x-TransaktionsId", Guid.NewGuid().ToString());
        getRequest2.Headers.Add("x-TransaktionsTid", DateTime.UtcNow.ToString("o"));
        getRequest2.Headers.Add("x-OnBehalfOfUser", "Digitalisering - Automatisering");

        // Send request and read response
        getResponse = await httpClient.SendAsync(getRequest2);
        responseData = await getResponse.Content.ReadAsStringAsync();;

        return responseData;
    }

    static async Task<String> SF1516AccessTokenDemo(bool isTest = false)
    {
        string clientCertificatePath, serviceCertificatePath, serviceEndpoint, serviceEndpointId, tokenUrl;

        if (isTest)
        {
            clientCertificatePath = Config.TESTP12Path;
            serviceCertificatePath = Config.TESTServiceplatformenCertificateFilePath;
            serviceEndpoint = "https://exttest.serviceplatformen.dk/service/AccessTokenDemo_1/callDemoService/";
            serviceEndpointId = "http://entityid.kombit.dk/service/demoservicerest/1";
            tokenUrl = "https://exttest.serviceplatformen.dk/service/AccessTokenService_1/token";
        }
        else
        {
            // Does not work - ServiceplatformAccessTokenDemo does not exist in PROD
            clientCertificatePath = Config.PRODP12Path;
            serviceCertificatePath = Config.PRODServiceplatformenCertificateFilePath;
            serviceEndpoint = "https://prod.serviceplatformen.dk/service/AccessTokenDemo_1/callDemoService/";
            serviceEndpointId = "http://entityid.kombit.dk/service/demoservicerest/1";
            tokenUrl = "https://prod.serviceplatformen.dk/service/AccessTokenService_1/token";
        }

        var config = CreateStsConfig(serviceCertificatePath, serviceEndpoint, serviceEndpointId, isTest: isTest);

        GenericXmlSecurityToken saml_token;
        saml_token = (GenericXmlSecurityToken)new StsTokenService(config).GetToken();

        var tokenXml = saml_token.TokenXml.OuterXml;
        var tokenBytes = System.Text.Encoding.UTF8.GetBytes(tokenXml);
        var base64token = Convert.ToBase64String(tokenBytes);

        var accessToken = GetAccessToken(base64token, clientCertificatePath, tokenUrl);

        if (accessToken is null)
            throw new InvalidOperationException("No access token");

        var handler = new HttpClientHandler();
        var clientCert = new Certificate { FilePath = clientCertificatePath, FromFileSystem = true };
        X509Certificate2 clientCertificate = CertificateUtil.GetCertificate(clientCert);
        handler.ClientCertificates.Add(clientCertificate);

        using var httpClient = new HttpClient(handler);
        
        string message = "HejVerden";
        string errorMessage = "Fejl";

        string demoServiceUrl = serviceEndpoint + message;

        var demoServiceUri = new UriBuilder(demoServiceUrl) { Query = $"errogrMessage={Uri.EscapeDataString(errorMessage)}" };

        using var getRequest = new HttpRequestMessage(HttpMethod.Get, demoServiceUri.Uri);
        getRequest.Headers.Add("Authorization", "Holder-of-key " + accessToken);
        getRequest.Headers.Add("x-TransaktionsId", Guid.NewGuid().ToString());
        getRequest.Headers.Add("x-TransaktionsTid", DateTime.UtcNow.ToString("o"));

        var getResponse = await httpClient.SendAsync(getRequest);

        getResponse.EnsureSuccessStatusCode();
        var responseData = await getResponse.Content.ReadAsStringAsync();

        // Parse responseData to get AdvisTekst
        using var responseDoc = JsonDocument.Parse(responseData);
        string? advisTekst = responseDoc.RootElement
            .GetProperty("svarreaktion")
            .GetProperty("HovedoplysningerSvarREST")[0]
            .GetProperty("SvarReaktion")
            .GetProperty("Advis")
            .GetProperty("AdvisTekst")
            .GetString();

        return $"Message sent: {message}, Message received: {advisTekst}";
    }
}
