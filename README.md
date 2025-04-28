# serviceplatformen-examples

Taken from [KvalitetsIT's SF1520 example](https://github.com/KvalitetsIT/kombit-sf1520-example). Examples added for SF0770A (Oplysninger fra SKAT) and SF1491 (Oplysniger om ydelser fra egen sektor)

## How to use
* Copy client public (.cer) and private (.pem) keys into the dirextory ServiceplatformenExamples/Certificates/Client
* In Examples.cs change the path for the keys to the correct file names. (\<client public key name\> and \<client private key name\>)
* Set the variables in the test cases. (\<cpr\>, \<start month\> and \<end month\>)
* Make sure you have dotnet installed and run the tests with `dotnet test` in the ServiceplatformenExamples directory