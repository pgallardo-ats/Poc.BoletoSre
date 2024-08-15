using Microsoft.Extensions.Logging;
using Poc.BoletoSre.Modelos;
using SsegSegurancaClient;
using System.ServiceModel;
using System.ServiceModel.Channels;
using Client = SreIntBancClient;

namespace Poc.BoletoSre.Gateways {

    /// <inheritdoc cref="IIntegracaoBancariaGateway"/>
    public class IntegracaoBancariaGateway : IDisposable, IIntegracaoBancariaGateway {

        #region Campos...

        Client.IntegracaoBancariaClient _integracaoBancariaClient;
        private bool disposed = false;
        private readonly ILogger<IntegracaoBancariaGateway> _log;
        private readonly string _sistemaId = "SISTEMA";

        #endregion

        #region Construtor...

        /// <summary>
        /// Construtor básico da classe...
        /// </summary>
        /// <param name="logger">Instância de Logger para fazer logs de operações...</param>
        public IntegracaoBancariaGateway(ILogger<IntegracaoBancariaGateway> logger) {

            _log = logger;

            try {
                // URL do endpoint do serviço. Atualizar conforme o ambiente a ser utilizado.
                string endpointUrl = "http://TesteAppSre/SVC_RegistroDeComercio/IntegracaoBancaria.svc";
                long timeoutEnvio = 25;

                System.ServiceModel.Channels.Binding genericoBinding;

                genericoBinding = new CustomBinding {
                    Elements = { new HttpTransportBindingElement {
                            MaxBufferSize = int.MaxValue,
                            MaxReceivedMessageSize = int.MaxValue }
                        },
                    SendTimeout = TimeSpan.FromSeconds(timeoutEnvio),
                };

                // Instânciando o cliente WCF...
                _integracaoBancariaClient = new Client.IntegracaoBancariaClient(genericoBinding, new EndpointAddress(endpointUrl));

                _log.LogInformation("IntegracaoBancariaGateway Iniciada com sucesso...");
            }
            catch (Exception xabu) {
                _log.LogError(xabu, "Erro ao iniciar IntegracaoBancariaGateway...");
            }
        }

        #endregion

        #region Métodos principais...

        /// <inheritdoc/>
        public async Task<Client.BoletoBancarioAvulso> CriarBoletoAvulsoAsync(DadosBoletoBancarioCriacao dadosBoleto, TicketAutenticacao ticket, string ipChamador, CancellationToken cancellationToken = default) {

            Client.BoletoBancarioAvulso retorno = null;

            try {
                Client.AtoEventoTipoJuridicoPorteEmpresarial atoEventTipoJurPorteEmpr = new Client.AtoEventoTipoJuridicoPorteEmpresarial() {
                    AtoEvento = new Client.AtoEvento() {
                        AtoId = dadosBoleto.AtoId,
                        EventoId = dadosBoleto.EventoId,
                    },
                    TipoJuridicoPorteEmpresarial = new Client.TipoJuridicoPorteEmpresarial() {
                        TipoJuridicoId = 0, // Aqui pode variar conforme a necessidade.
                        PorteEmpresarialId = 0, // Aqui pode variar conforme a necessidade.
                    },
                };
                List<Client.BoletoBancarioAtoEvento> boletoAtoEventoLista = new List<Client.BoletoBancarioAtoEvento> {
                    new Client.BoletoBancarioAtoEvento() {
                        ModoPersistencia = Client.ModoPersistenciaEnumerado.Adicionado,
                        AtoEventoId = dadosBoleto.AtoEventoId,
                        QuantidadeEventos = 1, // Aqui pode variar conforme a necessidade.
                    }
                };

                Client.BoletoBancarioAvulso boletoClient = new Client.BoletoBancarioAvulso() {
                    ModoPersistencia = Client.ModoPersistenciaEnumerado.Adicionado,
                    CpfCnpjSolicitante = dadosBoleto.CpfCnpjSolicitante,
                    NomeSolicitante = dadosBoleto.NomeSolicitante,
                    AtoEventoTipoJuridicoPorteEmpresarial = atoEventTipoJurPorteEmpr,
                    Boleto = new Client.BoletoBancario() {
                        ModoPersistencia = Client.ModoPersistenciaEnumerado.Adicionado,
                        ValorAtoEvento = dadosBoleto.ValorAtoEvento,
                        ValorBoleto = dadosBoleto.ValorBoleto,
                        ValorReconhecimentoFacial = 0, // Aqui pode variar conforme a necessidade.
                        QuantidadeReconhecimentoFacial = 0, // Aqui pode variar conforme a necessidade.
                        Avulso = true,
                        ConvenioId = null,
                        DataEmissao = DateTime.Now,
                        TipoJuridicoId = null, // Aqui pode variar conforme a necessidade.
                        PorteEmpresarialId = null, // Aqui pode variar conforme a necessidade.
                        AtoEventos = boletoAtoEventoLista.ToArray(),
                    },
                    UsuarioId = ticket.UsuarioId,
                };

                Task<Client.BoletoBancarioAvulso> boletoBancarioAvulsoTask;
                using (OperationContextScope contextScope = new OperationContextScope(_integracaoBancariaClient.InnerChannel)) {

                    // Injetar dados do ticket no contexto WCF...
                    DefinirWcfComAutenticacaoJucerja(ticket, ipChamador);

                    // Chamar integração...
                    boletoBancarioAvulsoTask = _integracaoBancariaClient.GerarBoletoAvulsoAsync(boletoClient);
                }
                Client.BoletoBancarioAvulso boletoAvulsoClient = await boletoBancarioAvulsoTask.WaitAsync(cancellationToken);

                retorno = boletoAvulsoClient;
            }
            catch (FaultException<Client.SegurancaSessaoFaultContract> xabu) {
                _log.LogError(xabu, "Erro ao se autenticar durante comunicação com integração");
            }
            catch (Exception xabu) {
                _log.LogError(xabu, "Erro inesperado em CriarBoletoAvulsoAsync...");
            }

            return retorno;
        }

        /// <inheritdoc/>
        public async Task<Client.BoletoBancarioAvulso> ObterBoletoBancarioAvulsoPorIdAsync(int boletoId, TicketAutenticacao ticket, string ipChamador, CancellationToken cancellationToken) {

            Client.BoletoBancarioAvulso boletoClient = null;

            try {
                Task<Client.BoletoBancarioAvulso> boletoBancarioTask;
                using (OperationContextScope contextScope = new OperationContextScope(_integracaoBancariaClient.InnerChannel)) {

                    // Injetar dados do ticket no contexto WCF...
                    DefinirWcfComAutenticacaoJucerja(ticket, ipChamador);

                    // Chamar integração...
                    boletoBancarioTask = _integracaoBancariaClient.ObterBoletoBancarioAvulsoPeloBoleteoIdAsync(boletoId);
                }
                boletoClient = await boletoBancarioTask.WaitAsync(cancellationToken);
            }
            catch (FaultException<Client.SegurancaSessaoFaultContract> xabu) {
                _log.LogError(xabu, "Erro ao se autenticar durante comunicação com integração");
            }
            catch (Exception xabu) {
                _log.LogError(xabu, "Erro inesperado em ObterBoletoBancarioAvulsoPorIdAsync...");
            }

            return boletoClient;
        }

        /// <inheritdoc/>
        public async Task<Client.BoletoBancarioAvulso> ObterBoletoBancarioPorNumeroAsync(string numeroBoleto, TicketAutenticacao ticket, string ipChamador, CancellationToken cancellationToken = default) {

            Client.BoletoBancarioAvulso boletoAvulsoClient = null;

            try {
                Task<Client.BoletoBancario> boletoBancarioTask;
                using (OperationContextScope contextScope = new OperationContextScope(_integracaoBancariaClient.InnerChannel)) {

                    // Injetar dados do ticket no contexto WCF...
                    DefinirWcfComAutenticacaoJucerja(ticket, ipChamador);

                    // Chamar integração...
                    boletoBancarioTask = _integracaoBancariaClient.ObterBoletoBancarioParaWebAsync(numeroBoleto);
                }
                Client.BoletoBancario boletoClient = await boletoBancarioTask.WaitAsync(cancellationToken);

                if (boletoClient == null) { return null; }
                int boletoId = boletoClient.Id;

                boletoAvulsoClient = await ObterBoletoBancarioAvulsoPorIdAsync(boletoId, ticket, ipChamador, cancellationToken).ConfigureAwait(false);
            }
            catch (FaultException<Client.SegurancaSessaoFaultContract> xabu) {
                _log.LogError(xabu, "Erro ao se autenticar durante comunicação com integração");
            }
            catch (Exception xabu) {
                _log.LogError(xabu, "Erro inesperado em ObterBoletoBancarioPorNumeroAsync...");
            }

            return boletoAvulsoClient;
        }

        #endregion

        #region Métodos de apoio...

        /// <summary>
        /// Define um valor para um heder no contexto de comunicação do WCF...
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="contexto"></param>
        /// <param name="conteudo"></param>
        /// <param name="nomeHeader"></param>
        private void DefinirWcfHeader<T>(OperationContext contexto, T conteudo, string nomeHeader) {

            if (contexto != null && contexto.OutgoingMessageHeaders != null && conteudo != null) {
                MessageHeader<T> messageHeader = new MessageHeader<T>(conteudo);
                contexto.OutgoingMessageHeaders.Add(messageHeader.GetUntypedHeader(nomeHeader, "ns"));
            }
        }

        private void DefinirWcfComAutenticacaoJucerja(TicketAutenticacao ticket, string ipChamador) {

            // Injetar no header WCF o IP do chamador...
            DefinirWcfHeader(OperationContext.Current, ipChamador, "origemIP");

            // Injetar no header WCF o ticket baseado na integração...
            DefinirWcfHeader(OperationContext.Current, ticket, "ticket");

            // Injetar no header WCF o nome do sistema de origem...
            DefinirWcfHeader(OperationContext.Current, _sistemaId, "sistemaOrigem");
        }

        public void Dispose() {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public void Dispose(bool disposing) {

            if (disposed) { return; }

            if (disposing && _integracaoBancariaClient != null) {
                try {
                    // Tentar fechar o client...
                    _integracaoBancariaClient.Close();
                }
                catch (Exception) {
                    // Abortar a comunicação e colocar o client no estado Fechado...
                    _integracaoBancariaClient.Abort();
                }
            }

            disposed = true;
        }

        #endregion
    }
}
