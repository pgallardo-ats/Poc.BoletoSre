namespace Poc.BoletoSre {
    partial class Form1 {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing) {
            if (disposing && (components != null)) {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent() {
            flowLayoutPanel1 = new FlowLayoutPanel();
            label1 = new Label();
            txtBoxLogin = new TextBox();
            label2 = new Label();
            txtBoxSenha = new TextBox();
            flowLayoutPanel2 = new FlowLayoutPanel();
            btnGerarBoleto = new Button();
            progressBar1 = new ProgressBar();
            txtBoxMensagens = new TextBox();
            flowLayoutPanel1.SuspendLayout();
            flowLayoutPanel2.SuspendLayout();
            SuspendLayout();
            // 
            // flowLayoutPanel1
            // 
            flowLayoutPanel1.Controls.Add(label1);
            flowLayoutPanel1.Controls.Add(txtBoxLogin);
            flowLayoutPanel1.Controls.Add(label2);
            flowLayoutPanel1.Controls.Add(txtBoxSenha);
            flowLayoutPanel1.FlowDirection = FlowDirection.TopDown;
            flowLayoutPanel1.Location = new Point(12, 12);
            flowLayoutPanel1.Name = "flowLayoutPanel1";
            flowLayoutPanel1.Size = new Size(496, 103);
            flowLayoutPanel1.TabIndex = 8;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new Point(3, 0);
            label1.Name = "label1";
            label1.Size = new Size(40, 15);
            label1.TabIndex = 3;
            label1.Text = "Login:";
            // 
            // txtBoxLogin
            // 
            txtBoxLogin.Font = new Font("Courier New", 11F, FontStyle.Bold);
            txtBoxLogin.Location = new Point(3, 18);
            txtBoxLogin.Name = "txtBoxLogin";
            txtBoxLogin.PlaceholderText = "Login de usuário da JUCERJA";
            txtBoxLogin.Size = new Size(388, 24);
            txtBoxLogin.TabIndex = 4;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Location = new Point(3, 45);
            label2.Name = "label2";
            label2.Size = new Size(42, 15);
            label2.TabIndex = 5;
            label2.Text = "Senha:";
            // 
            // txtBoxSenha
            // 
            txtBoxSenha.Font = new Font("Courier New", 10F, FontStyle.Bold);
            txtBoxSenha.Location = new Point(3, 63);
            txtBoxSenha.Name = "txtBoxSenha";
            txtBoxSenha.PasswordChar = '*';
            txtBoxSenha.PlaceholderText = "Senha de usuário da JUCERJA";
            txtBoxSenha.Size = new Size(388, 23);
            txtBoxSenha.TabIndex = 6;
            txtBoxSenha.UseSystemPasswordChar = true;
            // 
            // flowLayoutPanel2
            // 
            flowLayoutPanel2.AutoSize = true;
            flowLayoutPanel2.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            flowLayoutPanel2.Controls.Add(btnGerarBoleto);
            flowLayoutPanel2.Controls.Add(progressBar1);
            flowLayoutPanel2.Controls.Add(txtBoxMensagens);
            flowLayoutPanel2.FlowDirection = FlowDirection.TopDown;
            flowLayoutPanel2.Location = new Point(12, 118);
            flowLayoutPanel2.Name = "flowLayoutPanel2";
            flowLayoutPanel2.Size = new Size(809, 234);
            flowLayoutPanel2.TabIndex = 9;
            // 
            // btnGerarBoleto
            // 
            btnGerarBoleto.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            btnGerarBoleto.AutoSize = true;
            btnGerarBoleto.Location = new Point(3, 3);
            btnGerarBoleto.Name = "btnGerarBoleto";
            btnGerarBoleto.Size = new Size(803, 55);
            btnGerarBoleto.TabIndex = 5;
            btnGerarBoleto.Text = "Gerar Boleto";
            btnGerarBoleto.UseVisualStyleBackColor = true;
            btnGerarBoleto.Click += btnGerarBoleto_Click;
            // 
            // progressBar1
            // 
            progressBar1.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            progressBar1.Location = new Point(3, 64);
            progressBar1.Name = "progressBar1";
            progressBar1.Size = new Size(803, 11);
            progressBar1.TabIndex = 7;
            progressBar1.Value = 100;
            progressBar1.Visible = false;
            // 
            // txtBoxMensagens
            // 
            txtBoxMensagens.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            txtBoxMensagens.Font = new Font("Courier New", 11F);
            txtBoxMensagens.Location = new Point(3, 81);
            txtBoxMensagens.Multiline = true;
            txtBoxMensagens.Name = "txtBoxMensagens";
            txtBoxMensagens.ReadOnly = true;
            txtBoxMensagens.ScrollBars = ScrollBars.Both;
            txtBoxMensagens.Size = new Size(803, 150);
            txtBoxMensagens.TabIndex = 8;
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(828, 361);
            Controls.Add(flowLayoutPanel2);
            Controls.Add(flowLayoutPanel1);
            FormBorderStyle = FormBorderStyle.Fixed3D;
            MaximizeBox = false;
            Name = "Form1";
            Text = "Boleto SRE ";
            FormClosed += Form1_FormClosed;
            Load += Form1_Load;
            flowLayoutPanel1.ResumeLayout(false);
            flowLayoutPanel1.PerformLayout();
            flowLayoutPanel2.ResumeLayout(false);
            flowLayoutPanel2.PerformLayout();
            ResumeLayout(false);
            PerformLayout();
        }



        #endregion
        private FlowLayoutPanel flowLayoutPanel1;
        private Label label1;
        private TextBox txtBoxLogin;
        private Label label2;
        private TextBox txtBoxSenha;
        private FlowLayoutPanel flowLayoutPanel2;
        private Button btnGerarBoleto;
        private ProgressBar progressBar1;
        private TextBox txtBoxMensagens;
    }
}
