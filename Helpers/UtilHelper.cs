namespace Poc.BoletoSre.Helpers {

    public static class UtilHelper {

        #region Campos....

        private static Random randomNumber = null;

        #endregion

        public static string GerarCpf() {

            // Gerar 9 números aleatórios de 0 a 9
            // Calcular esses números, achar os 2 dígitos
            // Colocar esses 11 números no maskedTextBox

            Random rnd = new Random();
            int n1 = rnd.Next(0, 10);
            int n2 = rnd.Next(0, 10);
            int n3 = rnd.Next(0, 10);
            int n4 = rnd.Next(0, 10);
            int n5 = rnd.Next(0, 10);
            int n6 = rnd.Next(0, 10);
            int n7 = rnd.Next(0, 10);
            int n8 = rnd.Next(0, 10);
            int n9 = rnd.Next(0, 10);

            int soma1 = n1 * 10 + n2 * 9 + n3 * 8 + n4 * 7 + n5 * 6 + n6 * 5 + n7 * 4 + n8 * 3 + n9 * 2;
            int dv1 = soma1 % 11;

            if (dv1 < 2) {
                dv1 = 0;
            }
            else {
                dv1 = 11 - dv1;
            }

            int soma2 = n1 * 11 + n2 * 10 + n3 * 9 + n4 * 8 + n5 * 7 + n6 * 6 + n7 * 5 + n8 * 4 + n9 * 3 + dv1 * 2;
            int dv2 = soma2 % 11;

            if (dv2 < 2) {
                dv2 = 0;
            }
            else {
                dv2 = 11 - dv2;
            }

            return n1.ToString() + n2 + n3 + n4 + n5 + n6 + n7 + n8 + n9 + dv1 + dv2;
        }

        public static string ObterStringAleatoria(int tamanho, bool somenteNumeros = false) {

            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            const string numeros = "0123456789";

            string conteudo = (somenteNumeros) ? numeros : chars;

            if (randomNumber == null) { randomNumber = new Random((int)DateTime.Now.Ticks); }
            return new string(Enumerable.Repeat(conteudo, tamanho).Select(s => s[randomNumber.Next(s.Length)]).ToArray());
        }

    }
}
