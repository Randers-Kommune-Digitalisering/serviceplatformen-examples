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
        var startMonth = "<start month>"; //formay YYYYMM, e.g. "202401"
        var endMonth = "<end month>"; //format YYYYMM, e.g. "202412"

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

     public static class Config {
        const string basePath = "../../../Certificates/";
        public const string 
            // Kommunens CVR-nummer
            MunicipalityCvr = "29189668",

            // Client certificate paths
            ClientCertPublicKeyPath = basePath + "Client/<client public key name>.cer",
            ClientCertPrivateKeyPath = basePath + "Client/<client private key name>.pem",
            P12Path = basePath + "Client/clientCert.p12",

            // Service certificates paths
            ServiceplatformenCertificateFilePath = basePath + "Services/SP_PROD_Signing_1.cer",
            YdelsesindeksCertificateFilePath = basePath + "Services/YDI_PROD_Ydelsesindeks_1.cer",
            
            // STS certificates path
            StsCertificateFilePath = basePath + "STS/ADG_PROD_Adgangsstyring_1.cer",

            // Sts endpoints
            StsEndpoint = "https://adgangsstyring.stoettesystemerne.dk/runtime/services/kombittrust/14/certificatemixed",
            StsEndpointId = "http://saml.n2adgangsstyring.stoettesystemerne.dk/runtime";
    }

    static void WriteClientCert()
    {
        if (File.Exists(Config.P12Path))
        {
            return;
        } else {
            var clientCertificate = X509Certificate2.CreateFromPemFile(Config.ClientCertPublicKeyPath, Config.ClientCertPrivateKeyPath);
            byte[] pfxBytes = clientCertificate.Export(X509ContentType.Pfx);
            File.WriteAllBytes(Config.P12Path, pfxBytes);            
        }
    }

    static StsTokenServiceConfiguration CreateStsConfig(string serviceCertificatePath,
                                    string serviceEndpoint,
                                    string serviceEndpointId,
                                    // string stsCertificateFilePath = Config.StsCertificateFilePath2,
                                    bool includeLibertyHeader = true,
                                    string wspSoapVersion = "1.1") =>
        CreateConfiguration(new OioIdwsWcfConfigurationSection()
        {
            StsCertificate = new Certificate { FilePath = Config.StsCertificateFilePath, FromFileSystem = true },
            StsEndpointAddress = Config.StsEndpoint,
            StsEntityIdentifier = Config.StsEndpointId,
            ServiceCertificate = new Certificate { FilePath = serviceCertificatePath, FromFileSystem = true, },
            WspEndpoint = serviceEndpoint, 
            WspEndpointID = serviceEndpointId,
            ClientCertificate = new Certificate { FilePath = Config.P12Path, FromFileSystem = true },
            Cvr = Config.MunicipalityCvr,
            TokenLifeTimeInMinutes = 60,
            IncludeLibertyHeader = includeLibertyHeader,
            // IncludeLibertyHeader = true,
            MaxReceivedMessageSize = 256000,
            DebugMode = false,
            WspSoapVersion = wspSoapVersion //"1.2", //Delete if you want to use 1.1
        });

    static async Task<PersonLookupResponseType> SF1520PersonLookup(string cpr)
    {
        var serviceCertificatePath = Config.ServiceplatformenCertificateFilePath;
        var serviceEndpoint = "https://prod.serviceplatformen.dk/service/CPR/PersonBaseDataExtended/5";
        var serviceEndpointId = "http://cpr.serviceplatformen.dk/service/personbasedataextended/5";

        var config = CreateStsConfig(serviceCertificatePath, serviceEndpoint, serviceEndpointId);

        GenericXmlSecurityToken token;
        token = (GenericXmlSecurityToken)new StsTokenService(config).GetToken();

        var client = CreateChannelWithIssuedToken<PersonBaseDataExtendedPortType>(token, config);
        var request = new PersonLookupRequest(new PersonLookupRequestType { PNR = cpr });
        var response = await client.PersonLookupAsync(request);
        return response.PersonLookupResponse1;
    }

    static async Task<IndkomstOplysningPersonHent1> SF0770AIndkomstoplysningerLaes(string cpr, string startMonth, string endMonth)
    {
        var serviceCertificatePath = Config.ServiceplatformenCertificateFilePath;
        var serviceEndpoint = "https://prod.serviceplatformen.dk/service/SKAT/EIndkomst/4";
        var serviceEndpointId = "http://entityid.kombit.dk/service/sp/skatforwardeindkomstservice/4";

        var config = CreateStsConfig(serviceCertificatePath, serviceEndpoint, serviceEndpointId);

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

    static async Task<EffektueringHentRequest1> SF1491EffektueringHent(string cpr)
    {
        var serviceCertificatePath = Config.YdelsesindeksCertificateFilePath;
        var serviceEndpoint = "https://ydelsesindeks.stoettesystemerne.dk/ydelselistehent/2";
        var serviceEndpointId = "http://entityid.kombit.dk/service/ydelselistehent/1";

        var config = CreateStsConfig(serviceCertificatePath, serviceEndpoint, serviceEndpointId, false, "1.2");

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