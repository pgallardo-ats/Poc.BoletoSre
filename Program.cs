using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Poc.BoletoSre.Gateways;
using Serilog;

namespace Poc.BoletoSre {

    internal static class Program {

        static IHost host;

        /// <summary>
        ///  The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main() {

            ApplicationConfiguration.Initialize();

            var builder  = Host.CreateDefaultBuilder();

            builder.ConfigureServices((context, services) => {
                
                    services.AddSingleton<Form1>();
                    services.AddScoped<ISegurancaGateway, SegurancaGateway>();
                    services.AddScoped<IIntegracaoBancariaGateway, IntegracaoBancariaGateway>();

                });

            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .Enrich.FromLogContext()
                .WriteTo.Debug(outputTemplate: "[{Timestamp:dd-MM-yyyy HH:mm:ss.fff} {Level:u3}] {Message:lj}{NewLine}{Exception}")
                .CreateLogger();
            
            builder.ConfigureLogging(logging => {
                logging.ClearProviders();
                logging.AddSerilog(Log.Logger);
            });

            host = builder.Build();

            var meuForm = host.Services.GetService<Form1>();
            Application.Run(meuForm);
        }
    }
}