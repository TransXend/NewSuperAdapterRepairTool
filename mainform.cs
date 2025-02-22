using System;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace NetSuperAdapterTool
{
    public class MainForm : Form
    {
        private MenuStrip menuStrip;
        private ToolStripMenuItem modeMenu;
        private ToolStripMenuItem basicModeMenuItem;
        private ToolStripMenuItem advancedModeMenuItem;
        private Panel contentPanel;
        private Button toggleThemeButton;
        private RichTextBox logViewer;
        private bool darkMode = false;

        public MainForm()
        {
            this.Text = "Net Super Adapter Tool";
            this.Size = new Size(800, 600);
            InitializeComponents();
        }

        private void InitializeComponents()
        {
            // Setup Menu
            menuStrip = new MenuStrip();
            modeMenu = new ToolStripMenuItem("Mode");
            basicModeMenuItem = new ToolStripMenuItem("Basic", null, OnBasicMode);
            advancedModeMenuItem = new ToolStripMenuItem("Advanced", null, OnAdvancedMode);
            modeMenu.DropDownItems.Add(basicModeMenuItem);
            modeMenu.DropDownItems.Add(advancedModeMenuItem);
            menuStrip.Items.Add(modeMenu);
            this.MainMenuStrip = menuStrip;
            this.Controls.Add(menuStrip);

            // Theme Toggle Button
            toggleThemeButton = new Button();
            toggleThemeButton.Text = "Toggle Dark/Light Mode";
            toggleThemeButton.Location = new Point(10, 30);
            toggleThemeButton.Click += ToggleThemeButton_Click;
            this.Controls.Add(toggleThemeButton);

            // Content Panel
            contentPanel = new Panel();
            contentPanel.Location = new Point(10, 70);
            contentPanel.Size = new Size(760, 200);
            this.Controls.Add(contentPanel);

            // Log Viewer
            logViewer = new RichTextBox();
            logViewer.Location = new Point(10, 280);
            logViewer.Size = new Size(760, 270);
            logViewer.ReadOnly = true;
            this.Controls.Add(logViewer);

            // Default Mode
            SetMode("Basic");
        }

        private void ToggleThemeButton_Click(object sender, EventArgs e)
        {
            darkMode = !darkMode;
            if (darkMode)
            {
                this.BackColor = Color.FromArgb(45, 45, 48);
                logViewer.BackColor = Color.Black;
                logViewer.ForeColor = Color.White;
            }
            else
            {
                this.BackColor = SystemColors.Control;
                logViewer.BackColor = Color.White;
                logViewer.ForeColor = Color.Black;
            }
            Log("Theme toggled.");
        }

        private void OnBasicMode(object sender, EventArgs e)
        {
            SetMode("Basic");
            Log("Switched to Basic Mode.");
        }

        private void OnAdvancedMode(object sender, EventArgs e)
        {
            SetMode("Advanced");
            Log("Switched to Advanced Mode.");
        }

        private void SetMode(string mode)
        {
            // Clear previous controls
            contentPanel.Controls.Clear();

            if (mode == "Basic")
            {
                // Basic Mode: Quick Fix
                Button btnQuickFix = new Button();
                btnQuickFix.Text = "Quick Fix";
                btnQuickFix.Size = new Size(150, 30);
                btnQuickFix.Location = new Point(10, 10);
                btnQuickFix.Click += (s, e) => RunQuickFix();
                contentPanel.Controls.Add(btnQuickFix);
            }
            else if (mode == "Advanced")
            {
                // Advanced Mode: Deep Troubleshooting
                Button btnDeepTroubleshoot = new Button();
                btnDeepTroubleshoot.Text = "Deep Troubleshoot";
                btnDeepTroubleshoot.Size = new Size(150, 30);
                btnDeepTroubleshoot.Location = new Point(10, 10);
                btnDeepTroubleshoot.Click += (s, e) => RunDeepTroubleshoot();
                contentPanel.Controls.Add(btnDeepTroubleshoot);
            }
        }

        private void RunQuickFix()
        {
            Log("Quick fix initiated.");
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c ipconfig /release && ipconfig /renew")
                {
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                Process process = Process.Start(psi);
                process.WaitForExit();
                Log("Quick fix executed: IP release and renew.");
            }
            catch (Exception ex)
            {
                Log("Error during quick fix: " + ex.Message);
            }
        }

        private void RunDeepTroubleshoot()
        {
            Log("Deep troubleshoot initiated.");
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c netsh int ip reset")
                {
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                Process process = Process.Start(psi);
                process.WaitForExit();
                Log("Deep troubleshoot executed: TCP/IP stack reset.");
            }
            catch (Exception ex)
            {
                Log("Error during deep troubleshoot: " + ex.Message);
            }
        }

        private void Log(string message)
        {
            logViewer.AppendText($"{DateTime.Now}: {message}\n");
        }
    }
}
