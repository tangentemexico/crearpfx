// Program.cs
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

class Program
{
    static void Main(string[] args)
    {

        string certDerPath = @"c:\tmp\fiel_ajx\00001000000702661841.cer";
        string keyDerPath = @"c:\tmp\fiel_ajx\Claveprivada_FIEL_20230925_045208.key";
        string keyPassword = "Desd-2020";
        string pfxPassword = "Desda-220";
        var outputPfxPath = CrearPFX(certDerPath, keyDerPath, keyPassword, pfxPassword);
        Console.WriteLine($"PFX generado en: {outputPfxPath}");
        Console.WriteLine("Presiona cualquier tecla para salir...");
        Console.ReadKey();
    }

    static string CrearPFX(string certDerPath, string keyDerPath, string keyPassword, string pfxPassword )
    {
        string outputPfxPath = certDerPath + ".pfx"; 

        // 1) Leer certificado DER
        byte[] certDer = File.ReadAllBytes(certDerPath);
        var cert = new X509Certificate2(certDer);

        // 2) Leer clave privada PKCS#8 DER (cifrada con password)
        byte[] keyDer = File.ReadAllBytes(keyDerPath);
        using RSA rsa = RSA.Create();

        // ImportEncryptedPkcs8PrivateKey: descifra el PKCS#8 usando tu password
        rsa.ImportEncryptedPkcs8PrivateKey(
            keyPassword,           // passphrase que usaste en OpenSSL (-passin)
            keyDer,                // bytes del archivo .key (DER)
            out _                  // bytes consumidos (puedes ignorar)
        );

        // 3) Combinar cert + clave
        var certWithKey = cert.CopyWithPrivateKey(rsa);

        // 4) Exportar a PFX
        byte[] pfxBytes = certWithKey.Export(
            X509ContentType.Pfx,
            pfxPassword           // pass: Desde202022 en tu ejemplo
        );
        File.WriteAllBytes(outputPfxPath, pfxBytes);

        return outputPfxPath;
    }
}
