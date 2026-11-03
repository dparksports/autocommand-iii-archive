using System.Windows;

using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Sitedoctor.Core;

namespace AutoCommand.Views
{
    /// <summary>
    /// Confirmation for firewall blocks from the Process Monitor. MessageBox
    /// cannot host a checkbox, so this window carries the class-specific
    /// warning plus the "don't ask again" check-off (a ConfirmPrefs key).
    /// Frequent blockers use the checkbox to stop the prompt interrupting
    /// every block; the choice is per warning class — silencing the routine
    /// IP confirm never silences the svchost warning — and reversible from
    /// the Blocked popup's reset button.
    /// </summary>
    public partial class BlockConfirmWindow : Window
    {
        public bool Confirmed { get; private set; }
        public bool Suppress => SuppressCheck.IsChecked == true;

        /// <summary>True when the user ticked "also close the running
        /// instances" — the per-action consent for sever-on-block. The
        /// checkbox only appears when killable instances exist (never-tier
        /// is excluded upstream and never listed), so a tick here IS the
        /// explicit consent for every instance the panel listed, Windows
        /// components included.</summary>
        public bool AlsoSever => SeverCheck.IsChecked == true;

        /// <summary>ConfirmPrefs key the checkbox silences (null → no checkbox shown).</summary>
        public string SuppressKey { get; }

        public BlockConfirmWindow(string headline, string warning, string detail,
                                  string suppressKey, string suppressLabel,
                                  string severLabel = null, string severCandidates = null)
        {
            InitializeComponent();
            HeadText.Text = headline;
            WarningText.Text = warning;
            WarningBorder.Visibility = string.IsNullOrEmpty(warning) ? Visibility.Collapsed : Visibility.Visible;
            DetailText.Text = detail;
            SuppressKey = suppressKey;
            if (string.IsNullOrEmpty(suppressLabel))
            {
                SuppressCheck.Visibility = Visibility.Collapsed;
            }
            else
            {
                SuppressCheck.Content = suppressLabel;
            }

            // Sever-on-block consent panel: shown only when the caller found
            // killable instances. Unchecked by default — blocking alone is
            // the safe default; killing is an explicit add-on, per action,
            // never persisted and never silenced by the don't-ask prefs.
            if (string.IsNullOrEmpty(severLabel))
            {
                SeverBorder.Visibility = Visibility.Collapsed;
            }
            else
            {
                SeverCheck.Content = severLabel;
                SeverCandidatesText.Text = severCandidates;
                SeverBorder.Visibility = Visibility.Visible;
            }
        }

        private void BlockBtn_Click(object sender, RoutedEventArgs e)
        {
            Confirmed = true;
            DialogResult = true;
        }
    }
}
