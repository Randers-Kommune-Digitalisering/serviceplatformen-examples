using Xunit;
using System.Text.Json;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using Digst.OioIdws.OioWsTrustCore;
using Digst.OioIdws.WscCore.OioWsTrust;
using ConnectedServices_PersonBaseDataExtendedService;
using ConnectedServices_SKATForwardEIndkomstService;
using ConnectedServices_YdelseListeHentService;
using static Digst.OioIdws.SoapCore.FederatedChannelFactoryExtensions;
using static Digst.OioIdws.WscCore.OioWsTrust.TokenServiceConfigurationFactory;

namespace ServiceplatformenExamples;

public class Examples
{
    [Fact]
    public async Task SF1520CprReplikaOpslagExample()
    {
        WriteClientCert();

        var cpr = "<cpr>";

        var data = await SF1520PersonLookup(cpr);

        JsonSerializerOptions options = new() { WriteIndented = true, IncludeFields = true };
        Console.WriteLine(JsonSerializer.Serialize(data, options));
    }

    [Fact]
    public async Task SF0770ASkatIndkomstOpslagPersonoplysningerExample()
    {
        WriteClientCert();

        var cpr = "<cpr>";
        var startMonth = "202411"; //formay YYYYMM, e.g. "202401"
        var endMonth = "202412"; //format YYYYMM, e.g. "202412"

        var data = await SF0770AIndkomstoplysningerLaes(cpr, startMonth, endMonth);

        JsonSerializerOptions options = new() { WriteIndented = true, IncludeFields = true };
        Console.WriteLine(JsonSerializer.Serialize(data, options));
    }

    [Fact]
    public async Task SF1491HentYdelserFraEgenSektorExample()
    {
        WriteClientCert();

        var cpr = "<cpr>";

        var data = await SF1491EffektueringHent(cpr);

        JsonSerializerOptions options = new() { WriteIndented = true, IncludeFields = true };
        Console.WriteLine(JsonSerializer.Serialize(data, options));
    }

    // [Fact]
    // public async Task SF1475HentHentSagerFraDUBUExample()
    // {
    //     WriteClientCert();

    //     // var cpr = "<cpr>";

    //     // var data = await SF1475HentSagerFraDUBU(cpr);

    //     // JsonSerializerOptions options = new() { WriteIndented = true, IncludeFields = true };
    //     // Console.WriteLine(JsonSerializer.Serialize(data, options));
    // }

    public static class Config {
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
            PRODStsCertificateFilePath = basePath + "STS/ADG_PROD_Adgangsstyring_2.cer",
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
                RettighedListe = [ new EffektueringHent_ITypeBevillingDataAfgrGruppe {} ]
            }

        };
        var response = await client.EffektueringHentAsync(request);
        return response;
    }
}
