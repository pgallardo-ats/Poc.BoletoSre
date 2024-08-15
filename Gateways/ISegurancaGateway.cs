using SsegSegurancaClient;

namespace Poc.BoletoSre.Gateways {
    
    /// <summary>
    /// Integração com serviço de segurança a JUCERJA (JUCERJA-SSEG)...
    /// </summary>
    public interface ISegurancaGateway {

        /// <summary>
        /// Relizar login e obter um ticket de autenticação, com base em um login + senha...
        /// </summary>
        /// <param name="login">Login de usuário da JUCERJA.</param>
        /// <param name="senha">Senha de um usuário da JUCERJA.</param>
        /// <param name="ipChamador">Texto como endereço IPv4 do chamador da operação.</param>
        /// <param name="cancellationToken">Token de cancelamento da operação.</param>
        /// <returns>Instância de <see cref="TicketAutenticacao"/></returns>
        Task<TicketAutenticacao> RealizarLoginAsync(string login, string senha, string ipChamador, CancellationToken cancellationToken = default);
    }
}