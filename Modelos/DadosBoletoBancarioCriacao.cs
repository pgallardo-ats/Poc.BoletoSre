namespace Poc.BoletoSre.Modelos {

    public class DadosBoletoBancarioCriacao {

        #region Propriedades...

        /// <summary>
        /// 
        /// </summary>
        public int AtoId { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public int EventoId { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public int AtoEventoId { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public decimal ValorAtoEvento { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public decimal ValorBoleto { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public string CpfCnpjSolicitante { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public string NomeSolicitante { get; set; }

        #endregion
    }
}
