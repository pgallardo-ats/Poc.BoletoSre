using Microsoft.Extensions.Logging;
using System.ServiceModel;
using Client = SsegSegurancaClient;

namespace Poc.BoletoSre.Gateways {

    /// <inheritdoc cref="ISegurancaGateway"/>
    public class SegurancaGateway : IDisposable, ISegurancaGateway {

        #region Campos...

        Client.SegurancaClient _segurancaClient;
        private bool disposed = false;
        private readonly ILogger<SegurancaGateway> _log;
        // Substituir o _sistemaId com o código do sistema correto, conforme a utilização...
        private readonly string _sistemaId = "SISTEMA";

        #endregion

        #region Construtor...
                
        /// <summary>
        /// Construtor clássico da integração...
        /// </summary>
        /// <param name="logger">Instãncia de Logger para fazer logs de operações...</param>
        public SegurancaGateway(ILogger<SegurancaGateway> logger) {

            _log = logger;

            try {
                // URL do endpoint do serviço. Atualizar conforme o ambiente a ser utilizado.
                string endpointUrl = "https://testeappsre/SVC_Seguranca/Seguranca.svc";
                long timeoutEnvio = 25;

                var wsHttpBiding = new WSHttpBinding() {
                    Security = new WSHttpSecurity() {
                        Mode = SecurityMode.Transport, // Para suporte ao WCF se comunicar com um endpoint utilizando HTTPS...
                    },
                    SendTimeout = TimeSpan.FromSeconds(timeoutEnvio),
                    MaxBufferPoolSize = int.MaxValue,
                    MaxReceivedMessageSize = int.MaxValue,
                };

                // Instânciando o cliente WCF...
                _segurancaClient = new Client.SegurancaClient(wsHttpBiding, new EndpointAddress(endpointUrl));

                _log.LogInformation("SegurancaGateway Iniciado com sucesso...");
            }
            catch(Exception xabu) {
                _log.LogError(xabu, "Erro ao iniciar SegurancaGeteway...");
            }
        }

        #endregion

        #region Métodos principais...

        /// <inheritdoc/>
        public async Task<SsegSegurancaClient.TicketAutenticacao> RealizarLoginAsync(string login, string senha, string ipChamador, CancellationToken cancellationToken = default) {

            Client.TicketAutenticacao ticketClient = null;

            try {
                Task<Client.TicketAutenticacao> loginTask;

                // Abrir contexto de conexão para chamada segura com dados no header da chamada wcf...
                using (OperationContextScope contextScope = new OperationContextScope(_segurancaClient.InnerChannel)) {

                    // Injetar no header WCF o nome do sistema de origem...
                    DefinirWcfHeader<string>(OperationContext.Current, _sistemaId, "sistemaOrigem");
                    // Injetar no header WCF o IP do chamador...
                    DefinirWcfHeader<string>(OperationContext.Current, ipChamador, "origemIP");

                    // Chamar WCF Client e realizar o login...
                    loginTask = _segurancaClient.LoginAsync(login, senha);
                }
                ticketClient = await loginTask.WaitAsync(cancellationToken);

            }
            catch (FaultException<Client.SegurancaSessaoFaultContract> xabu) {
                string mensagem = "Falha ao tentar fazer login.";
                if (xabu.Message.ToUpper().Contains("SSEG_E026")) { mensagem = "Credencial já autenticada para outro endereço."; }
                if (xabu.Message.ToUpper().Contains("SSEG_E029")) { mensagem = "Login / Senha inválidos."; }
                _log.LogError(xabu, "Erro em RealizarLoginAsync: {mensagem}", mensagem);
            }
            catch (Exception xabu) {
                _log.LogError(xabu, "Erro em RealizarLoginAsync...");
            }   

            return ticketClient;
        }

        #endregion

        #region Métodos de apoio...

        /// <summary>
        /// Define um valor para um heder no contexto de comunicação do WCF...
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="contexto">Contexto de operação do WCF.</param>
        /// <param name="conteudo">Conteúdo a ser adicionado no contexto.</param>
        /// <param name="nomeHeader">Nome do header do contexto a ser utilizado.</param>
        protected void DefinirWcfHeader<T>(OperationContext contexto, T conteudo, string nomeHeader) {

            if (contexto != null && contexto.OutgoingMessageHeaders != null && conteudo != null) {
                MessageHeader<T> messageHeader = new MessageHeader<T>(conteudo);
                contexto.OutgoingMessageHeaders.Add(messageHeader.GetUntypedHeader(nomeHeader, "ns"));
            }
        }


        public void Dispose() {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public void Dispose(bool disposing) {

            if (disposed) { return; }

            if (disposing && _segurancaClient != null) {
                try {
                    // Tentar fechar o client...
                    _segurancaClient.Close();
                }
                catch (Exception) {
                    // Abortar a comunicação e colocar o client no estado Fechado...
                    _segurancaClient.Abort();
                }
            }

            disposed = true;
        }

        #endregion
    }
}
