using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Media;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace FireCrypt2
{
    public partial class Form1 : Form
    {
        public readonly byte[] salt = new byte[8] { 0x50, 0x3f, 0xc8, 0xa4, 0xf1, 0xf0, 0xab, 0x45 }; // Must be at least eight bytes.  MAKE THIS SALTIER!
        public const int iterations = 2048; // Recommendation is >= 1000.
        public string sourceFilename;
        public string destinationFilename;
        public string password;
        public string realEx;
        public string ext;
        public bool Encrypt;

        private GifImage gifImage = null;
        private string filePath = @"";

        public Form1()
        {
            InitializeComponent();
            button2.Enabled = false;
            pictureBox1.Visible = false;
            filePath = pictureBox1.ImageLocation;
        }

        private void linkLabel1_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            System.Diagnostics.Process.Start("https://www.github.com/Foxxite");
        }

        private void button1_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog1 = new OpenFileDialog();
            openFileDialog1.Filter = "All files (*.*)|*.*|Encrypted Files (*.🦊🔒)|*.🦊🔒";
            openFileDialog1.Title = "Open an Encrypted/Decerpted File";
            openFileDialog1.ShowDialog();

            sourceFilename = openFileDialog1.FileName;

            this.button1.Text = "Selected File:\n" + sourceFilename;

            ext = Path.GetExtension(openFileDialog1.FileName);

            if (ext == ".🦊🔒")
            {
                label1.Text = "Status: Ready to decrypt file";
                button2.Enabled = true;
                button2.Text = "Decrypt File";
                Encrypt = false;
            }
            else
            {
                button2.Enabled = true;
                button2.Text = "Encrypt File";
                label1.Text = "Status: Ready to encrypt file";
                Encrypt = true;
            }
        }

        private async void button2_Click(object sender, EventArgs e)
        {
            if (!String.IsNullOrEmpty(textBox1.Text))
            {
                password = textBox1.Text;
                if(Encrypt)
                {
                    button1.Enabled = false;
                    button2.Enabled = false;
                    timer1.Enabled = true;
                    pictureBox1.Visible = true;
                    label1.Text = "Status: Encrypting file...";
                    try
                    {
                        destinationFilename = sourceFilename + ".🦊🔒";
                        await EncryptFile(sourceFilename, destinationFilename, password, salt, iterations);
                        File.Delete(sourceFilename);
                    }
                    catch (Exception ex)
                    {
                        SystemSounds.Exclamation.Play();
                        MessageBox.Show(ex.Message, "FileCrypt 2.0 | Error");
                    }
                    timer1.Enabled = false;
                    pictureBox1.Visible = false;
                    SystemSounds.Hand.Play();
                    MessageBox.Show("Your file: `" + sourceFilename + "`\nhas been successfully encrypted to: `" + sourceFilename + ".🦊🔒`", "FileCrypt 2.0 | Success");
                    button1.Enabled = true;
                    button1.Text = "Choose File";
                    label1.Text = "Status: Idle";
                    sourceFilename = null;
                }
                else
                {
                    destinationFilename = sourceFilename;

                    string NewDestinationFilename = destinationFilename;

                    int index = NewDestinationFilename.IndexOf(".🦊🔒");

                    if (index != -1)
                    {
                        NewDestinationFilename = NewDestinationFilename.Remove(index);
                    }

                    destinationFilename = NewDestinationFilename;

                    button1.Enabled = false;
                    button2.Enabled = false;
                    timer1.Enabled = true;
                    pictureBox1.Visible = true;
                    label1.Text = "Status: Decrypting file...";
                    try
                    {
                        await DecryptFile(sourceFilename, destinationFilename, password, salt, iterations);
                        File.Delete(sourceFilename);
                    }
                    catch (Exception ex)
                    {
                        SystemSounds.Exclamation.Play();
                        MessageBox.Show(ex.Message, "FileCrypt 2.0 | Error");
                    }
                    timer1.Enabled = false;
                    pictureBox1.Visible = false;
                    SystemSounds.Hand.Play();
                    MessageBox.Show("Your file: `" + sourceFilename + "`\nhas been successfully decrypted to: `" + destinationFilename + "`", "FileCrypt 2.0 | Success");
                    button1.Enabled = true;
                    button1.Text = "Choose File";
                    label1.Text = "Status: Idle";
                    sourceFilename = null;
                }
            }
            else
            {
                SystemSounds.Exclamation.Play();
                MessageBox.Show("You forgot to enter a password", "FileCrypt 2.0 | No Password");
            }
            

        }

        public async Task DecryptFile(string sourceFilename, string destinationFilename, string password, byte[] salt, int iterations)
        {
            AesManaged aes = new AesManaged();
            aes.BlockSize = aes.LegalBlockSizes[0].MaxSize;
            aes.KeySize = aes.LegalKeySizes[0].MaxSize;
            // NB: Rfc2898DeriveBytes initialization and subsequent calls to   GetBytes   must be eactly the same, including order, on both the encryption and decryption sides.
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, salt, iterations);
            aes.Key = key.GetBytes(aes.KeySize / 8);
            aes.IV = key.GetBytes(aes.BlockSize / 8);
            aes.Mode = CipherMode.CBC;
            ICryptoTransform transform = aes.CreateDecryptor(aes.Key, aes.IV);

            using (FileStream destination = new FileStream(destinationFilename, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                using (CryptoStream cryptoStream = new CryptoStream(destination, transform, CryptoStreamMode.Write))
                {
                    try
                    {
                        using (FileStream source = new FileStream(sourceFilename, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            source.CopyTo(cryptoStream);
                        }
                    }
                    catch (CryptographicException exception)
                    {
                        if (exception.Message == "Padding is invalid and cannot be removed.")
                            throw new ApplicationException("Universal Microsoft Cryptographic Exception (Not to be believed!)", exception);
                        else
                            throw;
                    }
                }
            }
        }

        public async Task EncryptFile(string sourceFilename, string destinationFilename, string password, byte[] salt, int iterations)
        {
            AesManaged aes = new AesManaged();
            aes.BlockSize = aes.LegalBlockSizes[0].MaxSize;
            aes.KeySize = aes.LegalKeySizes[0].MaxSize;
            // NB: Rfc2898DeriveBytes initialization and subsequent calls to   GetBytes   must be eactly the same, including order, on both the encryption and decryption sides.
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, salt, iterations);
            aes.Key = key.GetBytes(aes.KeySize / 8);
            aes.IV = key.GetBytes(aes.BlockSize / 8);
            aes.Mode = CipherMode.CBC;
            ICryptoTransform transform = aes.CreateEncryptor(aes.Key, aes.IV);

            using (FileStream destination = new FileStream(destinationFilename, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                using (CryptoStream cryptoStream = new CryptoStream(destination, transform, CryptoStreamMode.Write))
                {
                    try
                    {
                        using (FileStream source = new FileStream(sourceFilename, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            source.CopyTo(cryptoStream);
                        }
                    }
                    catch (CryptographicException exception)
                    {
                        if (exception.Message == "Padding is invalid and cannot be removed.")
                            throw new ApplicationException("Universal Microsoft Cryptographic Exception (Not to be believed!)", exception);
                        else
                            throw;
                    }
                }
            }
        }

        public void timer1_Tick(object sender, EventArgs e)
        {
            pictureBox1.Image = gifImage.GetNextFrame();
        }

    }
}
