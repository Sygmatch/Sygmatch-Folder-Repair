#Requires -Version 5.1
<#
.SYNOPSIS
    Sygmatch Folder Repair 4.0 - Reparación segura de permisos, propiedad y herencia de carpetas.

.DESCRIPTION
    Soluciona el típico "Error de permisos / Acceso denegado" que aparece en carpetas tras reinstalar
    Windows (SID huérfanos, propietario antiguo, herencia rota) y limpia restos del virus de acceso
    directo en USB. Compatible con Windows 10 y Windows 11 (Windows PowerShell 5.1).

    Seguridad:
      * Pide permisos de administrador automáticamente (UAC).
      * Bloquea rutas del sistema, raíces de unidad, perfiles de usuario y AppData.
      * No sigue enlaces simbólicos/uniones (junctions); si los encuentra dentro de la carpeta, aborta.
      * Siempre crea una copia de seguridad de los permisos ANTES de modificar nada.
      * Nunca modifica la carpeta padre ni borra archivos: lo sospechoso va a CUARENTENA (recuperable).
      * Elimina únicamente SID huérfanos reales (S-1-5-21-* que Windows no puede resolver y que no
        pertenecen a este equipo ni a tu dominio).

.PARAMETER Path
    Carpeta que se mostrará al abrir. Por defecto: la carpeta donde está este script.

.NOTES
    Autor : Sygmatch  |  https://github.com/Sygmatch
#>
[CmdletBinding()]
param([string]$Path)

$script:AppName   = 'Sygmatch Folder Repair'
$script:AppVer    = '4.0'
$script:GitHubUrl = 'https://github.com/Sygmatch'

# ============================================================================
#  1) ELEVACION AUTOMATICA (UAC) + FORZAR WINDOWS POWERSHELL 5.1 (STA)
# ============================================================================
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-CmdArg([string]$p) {
    $p = $p.TrimEnd('\')
    if ($p.Length -eq 2 -and $p[1] -eq ':') { $p += '\\' }
    return '"' + $p + '"'
}

$script:IsAdmin = Test-IsAdmin
if ((-not $script:IsAdmin) -or ($PSVersionTable.PSEdition -eq 'Core')) {
    $self = $PSCommandPath
    if (-not $self) { $self = $MyInvocation.MyCommand.Path }
    Add-Type -AssemblyName System.Windows.Forms
    if (-not $self) {
        [void][System.Windows.Forms.MessageBox]::Show("Guarda este archivo como .ps1 y ejecútalo de nuevo (clic derecho > Ejecutar con PowerShell).", $script:AppName, 'OK', 'Information')
        exit
    }
    $psExe   = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $argLine = '-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "{0}"' -f $self
    if ($Path) { $argLine += ' -Path ' + (ConvertTo-CmdArg $Path) }
    try {
        if ($script:IsAdmin) { Start-Process -FilePath $psExe -ArgumentList $argLine }
        else                 { Start-Process -FilePath $psExe -ArgumentList $argLine -Verb RunAs }
    } catch {
        [void][System.Windows.Forms.MessageBox]::Show("Esta herramienta necesita permisos de administrador para reparar permisos y propiedad.`r`n`r`nAcepta el aviso de UAC para continuar.", $script:AppName, 'OK', 'Warning')
    }
    exit
}

# ============================================================================
#  2) ENSAMBLADOS, DPI Y CONTROLES MODERNOS (C#)
# ============================================================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch {}

$script:CsSource = @'
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace Sygmatch.UI
{
    [ComImport, Guid("DC1C5A9C-E88A-4dde-A5A1-60F82A20AEF7")]
    internal class FileOpenDialogRCW { }

    [ComImport, Guid("43826d1e-e718-42ee-bc55-a1e261c37bfe"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IShellItem
    {
        void BindToHandler(IntPtr pbc, ref Guid bhid, ref Guid riid, out IntPtr ppv);
        void GetParent(out IShellItem ppsi);
        void GetDisplayName(uint sigdnName, [MarshalAs(UnmanagedType.LPWStr)] out string ppszName);
        void GetAttributes(uint sfgaoMask, out uint psfgaoAttribs);
        void Compare(IShellItem psi, uint hint, out int piOrder);
    }

    [ComImport, Guid("d57c7288-d4ad-4768-be02-9d969532d960"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IFileOpenDialog
    {
        [PreserveSig] int Show(IntPtr parent);
        void SetFileTypes(uint cFileTypes, IntPtr rgFilterSpec);
        void SetFileTypeIndex(uint iFileType);
        void GetFileTypeIndex(out uint piFileType);
        void Advise(IntPtr pfde, out uint pdwCookie);
        void Unadvise(uint dwCookie);
        void SetOptions(uint fos);
        void GetOptions(out uint pfos);
        void SetDefaultFolder(IShellItem psi);
        void SetFolder(IShellItem psi);
        void GetFolder(out IShellItem ppsi);
        void GetCurrentSelection(out IShellItem ppsi);
        void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string pszName);
        void GetFileName([MarshalAs(UnmanagedType.LPWStr)] out string pszName);
        void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string pszTitle);
        void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string pszText);
        void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string pszLabel);
        void GetResult(out IShellItem ppsi);
    }

    public static class Native
    {
        [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
        [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr hWnd, IntPtr hAfter, int x, int y, int cx, int cy, uint flags);
        [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int val, int size);
        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)] static extern int SetWindowTheme(IntPtr hwnd, string app, string ids);
        [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
        static extern void SHCreateItemFromParsingName(string path, IntPtr pbc, ref Guid riid, out IShellItem ppv);

        static Dictionary<string, bool> _fonts = new Dictionary<string, bool>();

        public static void TrySetDpiAware()
        {
            try { SetProcessDPIAware(); } catch (Exception) { }
        }

        public static void SetDarkTitleBar(IntPtr h, bool dark)
        {
            try
            {
                int v = dark ? 1 : 0;
                if (DwmSetWindowAttribute(h, 20, ref v, 4) != 0) { DwmSetWindowAttribute(h, 19, ref v, 4); }
                SetWindowPos(h, IntPtr.Zero, 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0004 | 0x0010 | 0x0020);
            }
            catch (Exception) { }
        }

        public static void SetControlTheme(IntPtr h, bool dark)
        {
            try { SetWindowTheme(h, dark ? "DarkMode_Explorer" : "Explorer", null); } catch (Exception) { }
        }

        public static bool HasFont(string name)
        {
            bool r;
            if (_fonts.TryGetValue(name, out r)) return r;
            r = false;
            try
            {
                using (InstalledFontCollection c = new InstalledFontCollection())
                {
                    foreach (FontFamily f in c.Families)
                    {
                        if (string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase)) { r = true; break; }
                    }
                }
            }
            catch (Exception) { }
            _fonts[name] = r;
            return r;
        }

        // Selector de carpetas moderno (IFileOpenDialog con FOS_PICKFOLDERS). Devuelve null si se cancela.
        public static string PickFolder(IntPtr owner, string title, string initial)
        {
            IFileOpenDialog dlg = null;
            try
            {
                dlg = (IFileOpenDialog)(object)new FileOpenDialogRCW();
                uint opts;
                dlg.GetOptions(out opts);
                dlg.SetOptions(opts | 0x20u | 0x40u | 0x800u);
                if (!string.IsNullOrEmpty(title)) dlg.SetTitle(title);
                if (!string.IsNullOrEmpty(initial) && System.IO.Directory.Exists(initial))
                {
                    Guid iid = new Guid("43826d1e-e718-42ee-bc55-a1e261c37bfe");
                    IShellItem si;
                    SHCreateItemFromParsingName(initial, IntPtr.Zero, ref iid, out si);
                    dlg.SetFolder(si);
                }
                int hr = dlg.Show(owner);
                if (hr != 0) return null;
                IShellItem res;
                dlg.GetResult(out res);
                string path;
                res.GetDisplayName(0x80058000u, out path);
                return path;
            }
            finally
            {
                if (dlg != null) { try { Marshal.ReleaseComObject(dlg); } catch (Exception) { } }
            }
        }
    }

    public static class Gfx
    {
        public static GraphicsPath RoundRect(RectangleF r, float radius)
        {
            GraphicsPath p = new GraphicsPath();
            float d = radius * 2f;
            if (d > r.Width) d = r.Width;
            if (d > r.Height) d = r.Height;
            if (d <= 1f) { p.AddRectangle(r); return p; }
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        public static GraphicsPath Pill(RectangleF r)
        {
            return RoundRect(r, r.Height / 2f);
        }

        public static Color Lerp(Color a, Color b, float t)
        {
            if (t < 0f) t = 0f;
            if (t > 1f) t = 1f;
            return Color.FromArgb(
                (int)(a.A + (b.A - a.A) * t),
                (int)(a.R + (b.R - a.R) * t),
                (int)(a.G + (b.G - a.G) * t),
                (int)(a.B + (b.B - a.B) * t));
        }

        public static float Scale(Graphics g)
        {
            return g.DpiX / 96f;
        }

        public static void ClearBack(Graphics g, Control c)
        {
            if (c.BackColor.A == 255) g.Clear(c.BackColor);
        }
    }

    // ---------------------------------------------------------------- Cabecera con degradado
    public class GradientPanel : Panel
    {
        public Color ColorA = Color.FromArgb(124, 58, 237);
        public Color ColorB = Color.FromArgb(37, 99, 235);
        public Color ColorC = Color.FromArgb(236, 72, 153);

        public GradientPanel()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            if (ClientRectangle.Width < 2 || ClientRectangle.Height < 2) return;
            using (LinearGradientBrush br = new LinearGradientBrush(ClientRectangle, ColorA, ColorC, 0f))
            {
                ColorBlend cb = new ColorBlend();
                cb.Colors = new Color[] { ColorA, ColorB, ColorC };
                cb.Positions = new float[] { 0f, 0.55f, 1f };
                br.InterpolationColors = cb;
                e.Graphics.FillRectangle(br, ClientRectangle);
            }
        }
    }

    // ---------------------------------------------------------------- Panel redondeado
    public class RoundedPanel : Panel
    {
        public Color Fill = Color.White;
        public Color Border = Color.Silver;
        public float Radius = 12f;
        public float BorderWidth = 1f;

        public RoundedPanel()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            if (Width < 4 || Height < 4) return;
            Graphics g = e.Graphics;
            float s = Gfx.Scale(g);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            Gfx.ClearBack(g, this);
            RectangleF r = new RectangleF(0.5f, 0.5f, Width - 2f, Height - 2f);
            using (GraphicsPath p = Gfx.RoundRect(r, Radius * s))
            using (SolidBrush b = new SolidBrush(Fill))
            using (Pen pen = new Pen(Border, BorderWidth))
            {
                g.FillPath(b, p);
                g.DrawPath(pen, p);
            }
        }
    }

    // ---------------------------------------------------------------- Interruptor (modo sol/luna o normal)
    public class ToggleSwitch : Control
    {
        bool _checked;
        float _t;
        Timer _timer;
        public bool SunMoon = false;
        public Color OnColor = Color.FromArgb(124, 58, 237);
        public Color OffColor = Color.FromArgb(160, 160, 175);
        public event EventHandler CheckedChanged;

        public ToggleSwitch()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.Selectable | ControlStyles.StandardClick | ControlStyles.SupportsTransparentBackColor, true);
            TabStop = true;
            Cursor = Cursors.Hand;
            Size = new Size(64, 32);
            _timer = new Timer();
            _timer.Interval = 15;
            _timer.Tick += new EventHandler(OnTick);
        }

        public bool Checked
        {
            get { return _checked; }
            set
            {
                if (_checked == value) return;
                _checked = value;
                _timer.Start();
                if (CheckedChanged != null) CheckedChanged(this, EventArgs.Empty);
            }
        }

        public void SetCheckedSilent(bool v)
        {
            _checked = v;
            _t = v ? 1f : 0f;
            _timer.Stop();
            Invalidate();
        }

        void OnTick(object sender, EventArgs e)
        {
            float target = _checked ? 1f : 0f;
            float step = 0.12f;
            if (_t < target) { _t += step; if (_t >= target) { _t = target; _timer.Stop(); } }
            else if (_t > target) { _t -= step; if (_t <= target) { _t = target; _timer.Stop(); } }
            else { _timer.Stop(); }
            Invalidate();
        }

        protected override void OnClick(EventArgs e)
        {
            base.OnClick(e);
            Checked = !_checked;
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            base.OnKeyDown(e);
            if (e.KeyCode == Keys.Space || e.KeyCode == Keys.Enter) { Checked = !_checked; e.Handled = true; }
        }

        protected override bool IsInputKey(Keys keyData)
        {
            if (keyData == Keys.Space || keyData == Keys.Enter) return true;
            return base.IsInputKey(keyData);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _timer != null) { _timer.Stop(); _timer.Dispose(); _timer = null; }
            base.Dispose(disposing);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            if (Width < 8 || Height < 8) return;
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            Gfx.ClearBack(g, this);
            float w = Width - 2f, h = Height - 2f;
            RectangleF tr = new RectangleF(1f, 1f, w, h);
            float eased = _t * _t * (3f - 2f * _t);
            Color fill = Gfx.Lerp(OffColor, OnColor, eased);
            using (GraphicsPath p = Gfx.Pill(tr))
            using (SolidBrush b = new SolidBrush(fill))
            {
                g.FillPath(b, p);
            }
            float pad = h * 0.13f;
            float d = h - 2f * pad;
            float x0 = tr.X + pad;
            float x1 = tr.Right - pad - d;
            float kx = x0 + (x1 - x0) * eased;
            RectangleF knob = new RectangleF(kx, tr.Y + pad, d, d);
            if (SunMoon)
            {
                PaintSunMoon(g, tr, knob, eased);
            }
            else
            {
                using (SolidBrush sh = new SolidBrush(Color.FromArgb(45, 0, 0, 0)))
                    g.FillEllipse(sh, knob.X, knob.Y + 1.5f, knob.Width, knob.Height);
                using (SolidBrush kb = new SolidBrush(Color.White))
                    g.FillEllipse(kb, knob);
            }
        }

        void PaintSunMoon(Graphics g, RectangleF tr, RectangleF knob, float t)
        {
            float u = tr.Height;
            int starA = (int)(255 * t);
            int cloudA = (int)(215 * (1f - t));
            using (SolidBrush sb = new SolidBrush(Color.FromArgb(starA, 255, 255, 255)))
            {
                g.FillEllipse(sb, tr.X + u * 0.28f, tr.Y + u * 0.26f, u * 0.10f, u * 0.10f);
                g.FillEllipse(sb, tr.X + u * 0.50f, tr.Y + u * 0.60f, u * 0.07f, u * 0.07f);
                g.FillEllipse(sb, tr.X + u * 0.72f, tr.Y + u * 0.24f, u * 0.06f, u * 0.06f);
            }
            using (SolidBrush cb = new SolidBrush(Color.FromArgb(cloudA, 255, 255, 255)))
            {
                float cx = tr.Right - u * 1.05f;
                float cy = tr.Y + u * 0.56f;
                g.FillEllipse(cb, cx, cy, u * 0.34f, u * 0.20f);
                g.FillEllipse(cb, cx + u * 0.14f, cy - u * 0.14f, u * 0.28f, u * 0.28f);
                g.FillEllipse(cb, cx + u * 0.30f, cy, u * 0.30f, u * 0.20f);
            }
            using (SolidBrush sh = new SolidBrush(Color.FromArgb(50, 0, 0, 0)))
                g.FillEllipse(sh, knob.X, knob.Y + 1.5f, knob.Width, knob.Height);
            Color baseC = Gfx.Lerp(Color.FromArgb(255, 193, 37), Color.FromArgb(226, 229, 244), t);
            using (SolidBrush kb = new SolidBrush(baseC))
                g.FillEllipse(kb, knob);

            float r = knob.Width / 2f;
            float cxk = knob.X + r;
            float cyk = knob.Y + r;
            if (t < 0.99f)
            {
                int a = (int)(255 * (1f - t));
                using (Pen rp = new Pen(Color.FromArgb(a, 255, 236, 150), Math.Max(1.5f, r * 0.13f)))
                {
                    rp.StartCap = LineCap.Round;
                    rp.EndCap = LineCap.Round;
                    for (int i = 0; i < 8; i++)
                    {
                        double ang = i * Math.PI / 4.0;
                        float ca = (float)Math.Cos(ang);
                        float sa = (float)Math.Sin(ang);
                        g.DrawLine(rp, cxk + ca * r * 0.56f, cyk + sa * r * 0.56f, cxk + ca * r * 0.82f, cyk + sa * r * 0.82f);
                    }
                }
                using (SolidBrush core = new SolidBrush(Color.FromArgb(a, 255, 246, 196)))
                    g.FillEllipse(core, cxk - r * 0.36f, cyk - r * 0.36f, r * 0.72f, r * 0.72f);
            }
            if (t > 0.01f)
            {
                int a2 = (int)(255 * t);
                using (SolidBrush cr = new SolidBrush(Color.FromArgb(a2, 188, 193, 216)))
                {
                    g.FillEllipse(cr, cxk - r * 0.55f, cyk - r * 0.30f, r * 0.42f, r * 0.42f);
                    g.FillEllipse(cr, cxk + r * 0.10f, cyk + r * 0.20f, r * 0.34f, r * 0.34f);
                    g.FillEllipse(cr, cxk + r * 0.05f, cyk - r * 0.58f, r * 0.24f, r * 0.24f);
                }
            }
        }
    }

    // ---------------------------------------------------------------- Boton redondeado
    public class RoundButton : Control
    {
        public Color FillA = Color.FromArgb(124, 58, 237);
        public Color FillB = Color.FromArgb(79, 70, 229);
        public Color TextColor = Color.White;
        public Color BorderColor = Color.Transparent;
        public float Radius = 10f;
        bool _hover, _down;

        public RoundButton()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.Selectable | ControlStyles.StandardClick | ControlStyles.SupportsTransparentBackColor, true);
            TabStop = true;
            Cursor = Cursors.Hand;
            Font = new Font("Segoe UI Semibold", 9.5f, FontStyle.Regular, GraphicsUnit.Point);
            Size = new Size(120, 36);
        }

        protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { _hover = false; _down = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { if (e.Button == MouseButtons.Left) { _down = true; Focus(); Invalidate(); } base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { _down = false; Invalidate(); base.OnMouseUp(e); }
        protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }
        protected override void OnTextChanged(EventArgs e) { Invalidate(); base.OnTextChanged(e); }
        protected override bool IsInputKey(Keys keyData) { if (keyData == Keys.Space || keyData == Keys.Enter) return true; return base.IsInputKey(keyData); }
        protected override void OnKeyDown(KeyEventArgs e)
        {
            base.OnKeyDown(e);
            if (e.KeyCode == Keys.Space || e.KeyCode == Keys.Enter) { e.Handled = true; OnClick(EventArgs.Empty); }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            if (Width < 8 || Height < 8) return;
            Graphics g = e.Graphics;
            float s = Gfx.Scale(g);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            Gfx.ClearBack(g, this);
            RectangleF r = new RectangleF(0.5f, 0.5f, Width - 2f, Height - 2f);
            Color back = BackColor.A == 255 ? BackColor : Color.FromArgb(128, 128, 128);
            Color a = FillA, b = FillB;
            if (!Enabled) { a = Gfx.Lerp(a, back, 0.65f); b = Gfx.Lerp(b, back, 0.65f); }
            else if (_down) { a = Gfx.Lerp(a, Color.Black, 0.18f); b = Gfx.Lerp(b, Color.Black, 0.18f); }
            else if (_hover) { a = Gfx.Lerp(a, Color.White, 0.14f); b = Gfx.Lerp(b, Color.White, 0.14f); }
            using (GraphicsPath p = Gfx.RoundRect(r, Radius * s))
            {
                if (a.ToArgb() == b.ToArgb())
                {
                    using (SolidBrush sb = new SolidBrush(a)) g.FillPath(sb, p);
                }
                else
                {
                    using (LinearGradientBrush lb = new LinearGradientBrush(r, a, b, 0f)) g.FillPath(lb, p);
                }
                if (BorderColor.A > 0)
                {
                    using (Pen pen = new Pen(BorderColor, 1f)) g.DrawPath(pen, p);
                }
            }
            Color tc = Enabled ? TextColor : Gfx.Lerp(TextColor, back, 0.5f);
            TextRenderer.DrawText(g, Text, Font, ClientRectangle, tc,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine | TextFormatFlags.NoPadding);
            if (Focused && ShowFocusCues)
            {
                RectangleF fr = new RectangleF(3f * s, 3f * s, Width - 7f * s, Height - 7f * s);
                using (Pen fp = new Pen(Color.FromArgb(140, tc), 1f))
                {
                    fp.DashStyle = DashStyle.Dot;
                    using (GraphicsPath fpth = Gfx.RoundRect(fr, Math.Max(2f, Radius * s - 3f * s))) g.DrawPath(fp, fpth);
                }
            }
        }
    }

    // ---------------------------------------------------------------- Tarjeta de accion
    public class ActionCard : Control
    {
        public string Title = "";
        public string Desc = "";
        public string Glyph = "";
        public string Badge = "";
        public bool ShowInfo = true;
        public Color AccentA = Color.FromArgb(124, 58, 237);
        public Color AccentB = Color.FromArgb(79, 70, 229);
        public Color CardBack = Color.White;
        public Color CardBorder = Color.Gainsboro;
        public Color TitleColor = Color.Black;
        public Color DescColor = Color.Gray;
        public event EventHandler InfoClick;
        bool _hover, _down, _overInfo, _swallow;
        Rectangle _info = Rectangle.Empty;
        Font _fTitle, _fDesc, _fInfo;

        public ActionCard()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.Selectable | ControlStyles.StandardClick | ControlStyles.SupportsTransparentBackColor, true);
            TabStop = true;
            Cursor = Cursors.Hand;
            Size = new Size(380, 76);
            _fTitle = new Font("Segoe UI Semibold", 10.5f, FontStyle.Regular, GraphicsUnit.Point);
            _fDesc = new Font("Segoe UI", 8.5f, FontStyle.Regular, GraphicsUnit.Point);
            _fInfo = new Font("Segoe UI Semibold", 8.5f, FontStyle.Regular, GraphicsUnit.Point);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_fTitle != null) { _fTitle.Dispose(); _fTitle = null; }
                if (_fDesc != null) { _fDesc.Dispose(); _fDesc = null; }
                if (_fInfo != null) { _fInfo.Dispose(); _fInfo = null; }
            }
            base.Dispose(disposing);
        }

        protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { _hover = false; _down = false; _overInfo = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }
        protected override void OnMouseMove(MouseEventArgs e)
        {
            bool oi = ShowInfo && !_info.IsEmpty && _info.Contains(e.Location);
            if (oi != _overInfo) { _overInfo = oi; Invalidate(); }
            base.OnMouseMove(e);
        }
        protected override void OnMouseDown(MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left)
            {
                _down = true;
                _swallow = _overInfo;
                Focus();
                Invalidate();
            }
            base.OnMouseDown(e);
        }
        protected override void OnMouseUp(MouseEventArgs e)
        {
            bool wasDown = _down;
            _down = false;
            Invalidate();
            if (wasDown && _swallow && _overInfo && InfoClick != null) InfoClick(this, EventArgs.Empty);
            base.OnMouseUp(e);
        }
        protected override void OnClick(EventArgs e)
        {
            if (_swallow) { _swallow = false; return; }
            base.OnClick(e);
        }
        protected override bool IsInputKey(Keys keyData) { if (keyData == Keys.Space || keyData == Keys.Enter) return true; return base.IsInputKey(keyData); }
        protected override void OnKeyDown(KeyEventArgs e)
        {
            base.OnKeyDown(e);
            if (e.KeyCode == Keys.Space || e.KeyCode == Keys.Enter) { e.Handled = true; _swallow = false; OnClick(EventArgs.Empty); }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            if (Width < 60 || Height < 40) return;
            Graphics g = e.Graphics;
            float s = Gfx.Scale(g);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
            Gfx.ClearBack(g, this);
            Color back0 = BackColor.A == 255 ? BackColor : CardBack;
            RectangleF r = new RectangleF(1f, 1f, Width - 3f, Height - 3f);
            float rad = 14f * s;
            Color back = CardBack;
            if (!Enabled) back = Gfx.Lerp(CardBack, back0, 0.45f);
            else if (_down) back = Gfx.Lerp(CardBack, AccentA, 0.18f);
            else if (_hover) back = Gfx.Lerp(CardBack, AccentA, 0.08f);
            using (GraphicsPath p = Gfx.RoundRect(r, rad))
            {
                using (SolidBrush b = new SolidBrush(back)) g.FillPath(b, p);
                if ((_hover || Focused) && Enabled)
                {
                    using (LinearGradientBrush lb = new LinearGradientBrush(r, AccentA, AccentB, 0f))
                    using (Pen pen = new Pen(lb, 2f)) g.DrawPath(pen, p);
                }
                else
                {
                    using (Pen pen = new Pen(CardBorder, 1f)) g.DrawPath(pen, p);
                }
            }

            float pad = 14f * s;
            float dia = 46f * s;
            RectangleF ic = new RectangleF(r.X + pad, r.Y + (r.Height - dia) / 2f, dia, dia);
            Color ia = Enabled ? AccentA : Gfx.Lerp(AccentA, back0, 0.55f);
            Color ib = Enabled ? AccentB : Gfx.Lerp(AccentB, back0, 0.55f);
            using (LinearGradientBrush lb2 = new LinearGradientBrush(ic, ia, ib, 45f))
                g.FillEllipse(lb2, ic);
            using (StringFormat sf = new StringFormat())
            {
                sf.Alignment = StringAlignment.Center;
                sf.LineAlignment = StringAlignment.Center;
                g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
                if (!string.IsNullOrEmpty(Glyph) && Native.HasFont("Segoe MDL2 Assets"))
                {
                    using (Font gf = new Font("Segoe MDL2 Assets", 17f, FontStyle.Regular, GraphicsUnit.Point))
                    using (SolidBrush wb = new SolidBrush(Color.White))
                        g.DrawString(Glyph, gf, wb, ic, sf);
                }
                else
                {
                    using (Font bf = new Font("Segoe UI", 15f, FontStyle.Bold, GraphicsUnit.Point))
                    using (SolidBrush wb = new SolidBrush(Color.White))
                        g.DrawString(Badge, bf, wb, ic, sf);
                }
            }

            int infoD = (int)(20f * s);
            _info = new Rectangle((int)(r.Right - pad - infoD + 4f * s), (int)(r.Y + 10f * s), infoD, infoD);
            float tx = ic.Right + 14f * s;
            float tw = (ShowInfo ? _info.X - 6f * s : r.Right - pad) - tx;
            if (tw < 40f) tw = 40f;
            Color tcol = Enabled ? TitleColor : Gfx.Lerp(TitleColor, back0, 0.5f);
            Color dcol = Enabled ? DescColor : Gfx.Lerp(DescColor, back0, 0.5f);
            Rectangle tRect = new Rectangle((int)tx, (int)(r.Y + 11f * s), (int)tw, (int)(22f * s));
            Rectangle dRect = new Rectangle((int)tx, (int)(r.Y + 34f * s), (int)(r.Right - pad - tx), (int)(r.Height - 34f * s - 8f * s));
            TextRenderer.DrawText(g, Title, _fTitle, tRect, tcol, TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine | TextFormatFlags.NoPadding);
            TextRenderer.DrawText(g, Desc, _fDesc, dRect, dcol, TextFormatFlags.Left | TextFormatFlags.Top | TextFormatFlags.WordBreak | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);

            if (ShowInfo)
            {
                Color ic2 = _overInfo ? AccentA : Gfx.Lerp(DescColor, back0, 0.25f);
                RectangleF infoF = new RectangleF(_info.X, _info.Y, _info.Width, _info.Height);
                using (Pen ip = new Pen(ic2, 1.4f)) g.DrawEllipse(ip, infoF);
                TextRenderer.DrawText(g, "i", _fInfo, _info, ic2, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding | TextFormatFlags.SingleLine);
            }
        }
    }

    // ---------------------------------------------------------------- Boton con mascara (icono GitHub)
    public class MaskButton : Control
    {
        public Bitmap Mask;
        public Color Tint = Color.White;
        public Color HoverFill = Color.FromArgb(55, 255, 255, 255);
        public float IconScale = 0.62f;
        bool _hover, _down;

        public MaskButton()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.Selectable | ControlStyles.StandardClick | ControlStyles.SupportsTransparentBackColor, true);
            TabStop = true;
            Cursor = Cursors.Hand;
            Size = new Size(40, 40);
        }

        protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { _hover = false; _down = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { if (e.Button == MouseButtons.Left) { _down = true; Invalidate(); } base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { _down = false; Invalidate(); base.OnMouseUp(e); }
        protected override bool IsInputKey(Keys keyData) { if (keyData == Keys.Space || keyData == Keys.Enter) return true; return base.IsInputKey(keyData); }
        protected override void OnKeyDown(KeyEventArgs e)
        {
            base.OnKeyDown(e);
            if (e.KeyCode == Keys.Space || e.KeyCode == Keys.Enter) { e.Handled = true; OnClick(EventArgs.Empty); }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            if (Width < 8 || Height < 8) return;
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            Gfx.ClearBack(g, this);
            RectangleF full = new RectangleF(1f, 1f, Width - 3f, Height - 3f);
            if (_hover || _down || Focused)
            {
                int a = _down ? Math.Min(255, HoverFill.A + 40) : HoverFill.A;
                using (SolidBrush hb = new SolidBrush(Color.FromArgb(a, HoverFill.R, HoverFill.G, HoverFill.B)))
                    g.FillEllipse(hb, full);
            }
            if (Mask == null) return;
            float sz = Math.Min(Width, Height) * IconScale;
            if (_hover) sz *= 1.05f;
            Rectangle dest = new Rectangle((int)((Width - sz) / 2f), (int)((Height - sz) / 2f), (int)sz, (int)sz);
            float cr = Tint.R / 255f, cg = Tint.G / 255f, cb = Tint.B / 255f;
            ColorMatrix cm = new ColorMatrix(new float[][] {
                new float[] { 0, 0, 0, 0, 0 },
                new float[] { 0, 0, 0, 0, 0 },
                new float[] { 0, 0, 0, 0, 0 },
                new float[] { 0, 0, 0, 1, 0 },
                new float[] { cr, cg, cb, 0, 1 } });
            using (ImageAttributes ia = new ImageAttributes())
            {
                ia.SetColorMatrix(cm);
                ia.SetWrapMode(WrapMode.TileFlipXY);
                g.DrawImage(Mask, dest, 0, 0, Mask.Width, Mask.Height, GraphicsUnit.Pixel, ia);
            }
        }
    }

    // ---------------------------------------------------------------- Barra de progreso con degradado
    public class GradientProgress : Control
    {
        int _v;
        bool _marquee;
        float _m;
        Timer _timer;
        public Color Track = Color.FromArgb(40, 44, 66);
        public Color ColorA = Color.FromArgb(167, 139, 250);
        public Color ColorB = Color.FromArgb(56, 189, 248);

        public GradientProgress()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
            Size = new Size(300, 8);
            _timer = new Timer();
            _timer.Interval = 20;
            _timer.Tick += new EventHandler(OnTick);
        }

        public int Value
        {
            get { return _v; }
            set { int n = value; if (n < 0) n = 0; if (n > 100) n = 100; _v = n; Invalidate(); }
        }

        public bool Marquee
        {
            get { return _marquee; }
            set
            {
                if (_marquee == value) return;
                _marquee = value;
                if (_marquee) _timer.Start(); else { _timer.Stop(); Invalidate(); }
            }
        }

        void OnTick(object sender, EventArgs e)
        {
            _m += 0.018f;
            if (_m > 1.3f) _m = -0.3f;
            Invalidate();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _timer != null) { _timer.Stop(); _timer.Dispose(); _timer = null; }
            base.Dispose(disposing);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            if (Width < 8 || Height < 3) return;
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            Gfx.ClearBack(g, this);
            RectangleF tr = new RectangleF(0f, 0f, Width - 1f, Height - 1f);
            using (GraphicsPath p = Gfx.Pill(tr))
            using (SolidBrush tb = new SolidBrush(Track))
                g.FillPath(tb, p);
            float x, w;
            if (_marquee) { w = tr.Width * 0.30f; x = tr.X + tr.Width * _m; }
            else { w = tr.Width * _v / 100f; x = tr.X; }
            if (w < 1f) return;
            float x2 = x + w;
            if (x < tr.X) x = tr.X;
            if (x2 > tr.Right) x2 = tr.Right;
            if (x2 - x < 2f) return;
            RectangleF fr = new RectangleF(x, tr.Y, x2 - x, tr.Height);
            using (GraphicsPath fp = Gfx.Pill(fr))
            using (LinearGradientBrush lb = new LinearGradientBrush(new RectangleF(fr.X - 1f, fr.Y, fr.Width + 2f, fr.Height), ColorA, ColorB, 0f))
                g.FillPath(lb, fp);
        }
    }
}
'@

if (-not ('Sygmatch.UI.Native' -as [type])) {
    Add-Type -ReferencedAssemblies 'System.Windows.Forms', 'System.Drawing' -TypeDefinition $script:CsSource -Language CSharp
}
[Sygmatch.UI.Native]::TrySetDpiAware()

$script:Scale = 1.0
try {
    $gScr = [System.Drawing.Graphics]::FromHwnd([IntPtr]::Zero)
    $script:Scale = [math]::Round($gScr.DpiX / 96.0, 2)
    $gScr.Dispose()
} catch {}
if ($script:Scale -lt 1.0) { $script:Scale = 1.0 }

function px([double]$v)            { return [int][math]::Round($v * $script:Scale) }
function PT([double]$x, [double]$y){ return [System.Drawing.Point]::new((px $x), (px $y)) }
function SZ([double]$w, [double]$h){ return [System.Drawing.Size]::new((px $w), (px $h)) }
function RGB([int]$r, [int]$g, [int]$b) { return [System.Drawing.Color]::FromArgb(255, $r, $g, $b) }

# ============================================================================
#  3) CARPETAS DE DATOS (copias de seguridad, cuarentena, registros) Y AJUSTES
# ============================================================================
$script:DataDir      = Join-Path $env:LOCALAPPDATA 'Sygmatch\Folder Repair'
$script:BackupDir    = Join-Path $script:DataDir 'Backups'
$script:QuarDir      = Join-Path $script:DataDir 'Quarantine'
$script:LogDir       = Join-Path $script:DataDir 'Logs'
$script:SettingsFile = Join-Path $script:DataDir 'settings.json'
foreach ($d in @($script:DataDir, $script:BackupDir, $script:QuarDir, $script:LogDir)) {
    if (-not (Test-Path -LiteralPath $d)) { try { [void](New-Item -ItemType Directory -Force -Path $d) } catch {} }
}
$script:LogFile = Join-Path $script:LogDir ((Get-Date -Format 'yyyyMMdd') + '.log')

function Get-Setting([string]$Name, $Default) {
    try {
        if (Test-Path -LiteralPath $script:SettingsFile) {
            $j = Get-Content -LiteralPath $script:SettingsFile -Raw -ErrorAction Stop | ConvertFrom-Json
            if ($null -ne $j.$Name) { return $j.$Name }
        }
    } catch {}
    return $Default
}

function Set-Setting([string]$Name, $Value) {
    try {
        $h = @{}
        if (Test-Path -LiteralPath $script:SettingsFile) {
            $j = Get-Content -LiteralPath $script:SettingsFile -Raw -ErrorAction Stop | ConvertFrom-Json
            foreach ($p in $j.PSObject.Properties) { $h[$p.Name] = $p.Value }
        }
        $h[$Name] = $Value
        ($h | ConvertTo-Json) | Set-Content -LiteralPath $script:SettingsFile -Encoding UTF8
    } catch {}
}

# ============================================================================
#  4) MOTOR COMPARTIDO (se carga en la ventana Y en el hilo de trabajo)
# ============================================================================
$script:WorkerPrelude = @'
function Get-ProtectedReason {
    param([string]$Path, [bool]$AllowDriveRoot = $false)
    if ([string]::IsNullOrWhiteSpace($Path)) { return 'No has indicado ninguna carpeta.' }
    try { $full = [System.IO.Path]::GetFullPath($Path) } catch { return 'La ruta no es válida.' }
    if ($full.StartsWith('\\')) { return 'No se admiten rutas de red (UNC). Usa una carpeta local.' }
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { return 'La carpeta no existe.' }
    $norm = $full.TrimEnd('\')
    if ($norm -match '^[A-Za-z]:$') {
        if ($AllowDriveRoot) { return $null }
        return 'No se permite reparar la raíz completa de una unidad. Selecciona una carpeta concreta.'
    }
    $sysDrive = $env:SystemDrive
    $roots = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432, $env:ProgramData,
               "$sysDrive\Recovery", "$sysDrive\Boot", "$sysDrive\PerfLogs", "$sysDrive\Documents and Settings",
               "$sysDrive\Config.Msi", "$sysDrive\`$Recycle.Bin", "$sysDrive\System Volume Information") | Where-Object { $_ }
    foreach ($b in $roots) {
        $bn = ([string]$b).TrimEnd('\')
        if ($norm -ieq $bn -or $norm.StartsWith($bn + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            return "Ruta protegida del sistema: $bn"
        }
    }
    if ($norm -imatch '^[A-Za-z]:\\(Windows|Program Files|Program Files \(x86\)|ProgramData)(\\|$)') { return 'Es una carpeta de sistema (Windows, Program Files o ProgramData).' }
    if ($norm -imatch '(^|\\)(System Volume Information|\$Recycle\.Bin|\$WinREAgent|\$Windows\.~BT|\$Windows\.~WS)(\\|$)') { return 'Es una carpeta interna del sistema.' }
    if ($norm -imatch '^[A-Za-z]:\\Users$') { return 'Es la carpeta Users completa. Elige una subcarpeta concreta.' }
    if ($norm -imatch '^[A-Za-z]:\\Users\\[^\\]+$') { return 'Es la carpeta personal completa de un usuario. Elige una subcarpeta (Documentos, Imágenes, etc.).' }
    if ($norm -imatch '^[A-Za-z]:\\Users\\[^\\]+\\AppData(\\|$)') { return 'AppData contiene datos internos de programas y no debe repararse en bloque.' }
    if ($env:USERPROFILE -and ($norm -ieq $env:USERPROFILE.TrimEnd('\'))) { return 'Es tu carpeta personal completa. Elige una subcarpeta.' }
    try {
        $di = New-Object System.IO.DirectoryInfo($norm)
        $lt = ''
        try { $lt = [string]$di.LinkType } catch {}
        if ($lt -eq 'Junction' -or $lt -eq 'SymbolicLink') { return 'La carpeta seleccionada es un enlace/unión. Selecciona la carpeta real.' }
    } catch {}
    return $null
}

function Get-SafeName([string]$s) {
    if (-not $s) { return '' }
    return ($s -replace '[^A-Za-z0-9._-]', '_')
}

function Invoke-Tool {
    param([string]$Exe, [string]$Arguments)
    $r = [pscustomobject]@{ ExitCode = -1; Output = ''; Cancelled = $false }
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Exe
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $enc = [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
        $psi.StandardOutputEncoding = $enc
        $psi.StandardErrorEncoding = $enc
        $p = [System.Diagnostics.Process]::Start($psi)
        $tOut = $p.StandardOutput.ReadToEndAsync()
        $tErr = $p.StandardError.ReadToEndAsync()
        while (-not $p.WaitForExit(250)) {
            if ($Ctx.State.Cancel) { try { $p.Kill() } catch {}; $r.Cancelled = $true; break }
        }
        if (-not $r.Cancelled) { $p.WaitForExit() }
        if ($r.Cancelled) { $r.ExitCode = -1 } else { $r.ExitCode = $p.ExitCode }
        $r.Output = [string]$tOut.Result + "`n" + [string]$tErr.Result
        $p.Dispose()
    } catch { $r.Output = 'ERROR: ' + $_.Exception.Message }
    return $r
}

function Get-ToolStats {
    param([string]$Output)
    $res = [pscustomobject]@{ Processed = -1; Failed = -1; Samples = @() }
    if (-not $Output) { return $res }
    $lines = @($Output -split "\r?\n" | Where-Object { $_ -and $_.Trim() })
    if ($lines.Count -eq 0) { return $res }
    $idx = -1
    for ($i = $lines.Count - 1; $i -ge 0; $i--) {
        $mm = [regex]::Match($lines[$i], '^\D*(\d+)\D+(\d+)\D*$')
        if ($mm.Success -and -not [regex]::IsMatch($lines[$i], '[A-Za-z]:\\')) {
            $res.Processed = [int]$mm.Groups[1].Value; $res.Failed = [int]$mm.Groups[2].Value; $idx = $i; break
        }
    }
    $others = @()
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($i -ne $idx) { $others += $lines[$i].Trim() } }
    $res.Samples = @($others | Select-Object -First 5)
    return $res
}

function Resolve-SidName([string]$Sid) {
    try { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return "(huérfano) $Sid" }
}

# Un SID es "huérfano" solo si: es del tipo S-1-5-21-*, Windows no puede traducirlo a una cuenta
# y su dominio NO es el de este equipo, ni el de tu usuario/grupos (evita borrar cuentas de dominio
# cuando estás sin conexión).
function Test-OrphanSid([string]$Sid) {
    if (-not $script:SidCache) { $script:SidCache = @{} }
    if ($script:SidCache.ContainsKey($Sid)) { return $script:SidCache[$Sid] }
    $res = $false
    if ($Sid -match '^(S-1-5-21-\d+-\d+-\d+)-\d+$') {
        $prefix = $Matches[1]
        if (@($Ctx.KnownPrefixes) -notcontains $prefix) {
            try { [void](New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]) }
            catch {
                $ex = $_.Exception
                if ($ex.InnerException) { $ex = $ex.InnerException }
                if ($ex -is [System.Security.Principal.IdentityNotMappedException]) { $res = $true }
            }
        }
    }
    $script:SidCache[$Sid] = $res
    return $res
}

function Get-AclInfo {
    param($Item)
    $info = [pscustomobject]@{ Ok = $false; Owner = $null; OwnerOrphan = $false; Protected = $false; Orphans = (New-Object System.Collections.ArrayList) }
    try {
        $sec = $Item.GetAccessControl([System.Security.AccessControl.AccessControlSections]'Access,Owner')
        $info.Ok = $true
        $o = $sec.GetOwner([System.Security.Principal.SecurityIdentifier])
        if ($o) { $info.Owner = $o.Value; $info.OwnerOrphan = (Test-OrphanSid $o.Value) }
        $info.Protected = [bool]$sec.AreAccessRulesProtected
        $seen = @{}
        foreach ($r in $sec.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $v = $r.IdentityReference.Value
            if (-not $seen.ContainsKey($v)) { $seen[$v] = $true; if (Test-OrphanSid $v) { [void]$info.Orphans.Add($v) } }
        }
    } catch { $info.Ok = $false }
    return $info
}

# Recorre la carpeta SIN seguir enlaces simbólicos ni uniones.
function Scan-Folder {
    param([string]$Root, [bool]$Recurse = $true, [bool]$CheckAcl = $false, [int]$MaxAcl = 0)
    $res = [pscustomobject]@{
        Dirs = 0; Files = 0; FileLinks = 0; Unreadable = 0; AclRead = 0; AclDenied = 0; OwnerOther = 0; OwnerOrphan = 0
        DirLinks = (New-Object System.Collections.ArrayList)
        Hidden   = (New-Object System.Collections.ArrayList)
        Orphans  = @{}
        Cancelled = $false
    }
    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($Root)
    $n = 0
    $hs = 6
    while ($stack.Count -gt 0) {
        if ($Ctx.State.Cancel) { $res.Cancelled = $true; break }
        $dir = $stack.Pop()
        $entries = $null
        try { $entries = (New-Object System.IO.DirectoryInfo($dir)).EnumerateFileSystemInfos() } catch { $res.Unreadable++; continue }
        try {
            foreach ($e in $entries) {
                $n++
                $attr = [int]$e.Attributes
                $isDir = (($attr -band 16) -ne 0)
                if (($attr -band 1024) -ne 0) {
                    $lt = ''
                    try { $lt = [string]$e.LinkType } catch {}
                    if ($lt -eq 'Junction' -or $lt -eq 'SymbolicLink') {
                        if ($isDir) { [void]$res.DirLinks.Add($e.FullName) } else { $res.FileLinks++ }
                        continue
                    }
                }
                if ($isDir) { $res.Dirs++; if ($Recurse) { $stack.Push($e.FullName) } } else { $res.Files++ }
                if (($attr -band $hs) -eq $hs) { [void]$res.Hidden.Add([pscustomobject]@{ Path = $e.FullName; IsDir = $isDir }) }
                if ($CheckAcl -and $res.AclRead -lt $MaxAcl) {
                    $res.AclRead++
                    $ai = Get-AclInfo $e
                    if (-not $ai.Ok) { $res.AclDenied++ }
                    else {
                        foreach ($s in $ai.Orphans) { if ($res.Orphans.ContainsKey($s)) { $res.Orphans[$s] = $res.Orphans[$s] + 1 } else { $res.Orphans[$s] = 1 } }
                        if ($ai.OwnerOrphan) { $res.OwnerOrphan++ }
                        elseif ($ai.Owner -and (@($Ctx.ExpectedOwners) -notcontains $ai.Owner)) { $res.OwnerOther++ }
                    }
                }
                if (($n % 2000) -eq 0) {
                    Prog -1 ('Analizando... {0:N0} elementos' -f $n)
                    if ($Ctx.State.Cancel) { break }
                }
            }
        } catch { $res.Unreadable++ }
    }
    return $res
}
'@

# Cargar el motor tambien en la ventana (Invoke-Tool, Get-ProtectedReason...) con un contexto minimo.
$script:Ctx = @{ State = @{ Cancel = $false }; KnownPrefixes = @(); ExpectedOwners = @() }
$Ctx = $script:Ctx
. ([scriptblock]::Create($script:WorkerPrelude))

# ============================================================================
#  5) OPERACIONES EN SEGUNDO PLANO
# ============================================================================
$script:WorkerHeader = @'
$ErrorActionPreference = 'Continue'
function Say([string]$m, [string]$lvl = 'info') { $Ctx.Q.Enqueue([pscustomobject]@{ T = 'log'; Text = $m; Level = $lvl }) }
function Prog([int]$p, [string]$m) { $Ctx.Q.Enqueue([pscustomobject]@{ T = 'prog'; Pct = $p; Text = $m }) }
function Done($r) { $Ctx.Q.Enqueue([pscustomobject]@{ T = 'done'; Result = $r }) }
function Cancelled { return [bool]$Ctx.State.Cancel }
function Step-Check { if (Cancelled) { throw 'CANCELLED' } }
'@

# ---------------------------------------------------------------- NIVEL 1: REPARAR
$script:OpRepair = @'
$t        = [string]$Ctx.Target
$rec      = [bool]$Ctx.Recurse
$unhide   = [bool]$Ctx.Unhide
$icacls   = Join-Path $env:SystemRoot 'System32\icacls.exe'
$takeown  = Join-Path $env:SystemRoot 'System32\takeown.exe'
$tflag    = ''
if ($rec) { $tflag = ' /t' }
$R = [ordered]@{ Ok = $false; Cancelled = $false; Message = ''; Backup = $null; OrphansFound = 0; OrphansLeft = 0; Unhidden = 0; Warnings = 0; WriteTest = $false; ResetFailed = 0; Dirs = 0; Files = 0 }

try {
    Prog 2 'Validando carpeta...'
    $why = Get-ProtectedReason -Path $t
    if ($why) { throw "ABORT:$why" }

    Prog 4 'Analizando contenido (sin seguir enlaces)...'
    $scan = Scan-Folder -Root $t -Recurse $rec
    Step-Check
    $R.Dirs = $scan.Dirs; $R.Files = $scan.Files
    Say ('Contenido: {0:N0} carpetas y {1:N0} archivos.' -f $scan.Dirs, $scan.Files)
    if ($scan.FileLinks -gt 0) { Say ('{0} enlaces simbólicos a archivos: se tratan como enlaces, no se sigue su destino.' -f $scan.FileLinks) 'warn' }
    if ($scan.DirLinks.Count -gt 0) {
        Say 'Se encontraron enlaces simbólicos/uniones a carpetas dentro de la selección:' 'warn'
        foreach ($l in ($scan.DirLinks | Select-Object -First 8)) { Say ('    ' + $l) 'warn' }
        throw 'ABORT:La carpeta contiene uniones o enlaces simbólicos hacia otras ubicaciones. Para proteger el sistema NO se repara de forma recursiva (podría tocar carpetas fuera de la seleccionada). Quita o mueve esos enlaces, o repara las subcarpetas por separado.'
    }

    # ---- copia de seguridad (obligatoria) ----
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $name = Get-SafeName ([System.IO.Path]::GetFileName($t))
    if (-not $name) { $name = 'carpeta' }
    $bk = Join-Path $Ctx.BackupDir ('{0}_{1}.acl' -f $stamp, $name)
    Prog 8 'Guardando copia de seguridad de los permisos...'
    $x = Invoke-Tool $icacls ('"{0}" /save "{1}"{2} /c /q /L' -f $t, $bk, $tflag)
    Step-Check
    if (-not (Test-Path -LiteralPath $bk) -or ((Get-Item -LiteralPath $bk).Length -lt 8)) {
        throw 'ABORT:No se pudo crear la copia de seguridad de permisos. No se ha modificado nada.'
    }
    $meta = [ordered]@{ Target = $t; Parent = (Split-Path -Path $t -Parent); Created = (Get-Date).ToString('s'); User = $env:USERNAME; Recurse = $rec; Tool = 'Sygmatch Folder Repair 4.0' }
    ($meta | ConvertTo-Json) | Set-Content -LiteralPath ([System.IO.Path]::ChangeExtension($bk, 'json')) -Encoding UTF8
    $R.Backup = $bk
    Say ('Copia de seguridad creada: ' + $bk) 'ok'

    # ---- 1) tomar posesión ----
    Prog 20 'Tomando posesión (takeown)...'
    $lang = (Get-UICulture).TwoLetterISOLanguageName
    $yes = 'Y'
    switch ($lang) { 'es' { $yes = 'S' } 'pt' { $yes = 'S' } 'it' { $yes = 'S' } 'fr' { $yes = 'O' } 'de' { $yes = 'J' } 'nl' { $yes = 'J' } }
    $ta = '/f "{0}"' -f $t
    if ($rec) { $ta += ' /r /skipsl' }
    $x = Invoke-Tool $takeown ($ta + ' /d ' + $yes)
    if ($x.ExitCode -ne 0 -and $yes -ne 'Y') { $x = Invoke-Tool $takeown ($ta + ' /d Y') }
    Step-Check
    if ($x.ExitCode -ne 0) { Say 'takeown terminó con avisos (algunos elementos pueden estar bloqueados).' 'warn'; $R.Warnings += 1 }

    # ---- 2) propietario = tu usuario ----
    Prog 34 'Asignando propietario...'
    $x = Invoke-Tool $icacls ('"{0}" /setowner *{1}{2} /c /q /L' -f $t, $Ctx.OwnerSid, $tflag)
    Step-Check
    $st = Get-ToolStats $x.Output
    if ($st.Failed -gt 0) { Say ('Propietario: {0} elementos no se pudieron cambiar.' -f $st.Failed) 'warn'; $R.Warnings += 1 }

    # ---- 3) reset: permisos por defecto heredados (quita ACEs explícitas, incl. SID huérfanos) ----
    Prog 48 'Restableciendo permisos y activando herencia...'
    $x = Invoke-Tool $icacls ('"{0}" /reset{1} /c /q /L' -f $t, $tflag)
    Step-Check
    $st = Get-ToolStats $x.Output
    if ($st.Failed -gt 0) {
        $R.ResetFailed = $st.Failed
        Say ('Reset: {0} elementos no se pudieron restablecer.' -f $st.Failed) 'warn'
        foreach ($s in $st.Samples) { Say ('    ' + $s) 'warn' }
        $R.Warnings += 1
    }

    # ---- 4) control total explícito: tu usuario + Administradores + SYSTEM ----
    Prog 62 'Concediendo control total a tu usuario, Administradores y SYSTEM...'
    $grantSids = @((@($Ctx.GrantSids) + @('S-1-5-32-544', 'S-1-5-18')) | Select-Object -Unique)
    $ga = '"{0}" /grant:r' -f $t
    foreach ($sid in $grantSids) { $ga += (' *{0}:(OI)(CI)F' -f $sid) }
    if ($rec -and $R.ResetFailed -gt 0) { $ga += ' /t' }
    $ga += ' /c /q /L'
    $x = Invoke-Tool $icacls $ga
    Step-Check
    $st = Get-ToolStats $x.Output
    if ($st.Failed -gt 0) { Say ('Concesión de permisos: {0} elementos con error.' -f $st.Failed) 'warn'; $R.Warnings += 1 }

    # ---- 5) SID huérfanos heredados del padre: se rompe la herencia SOLO en esta carpeta ----
    Prog 72 'Buscando SID huérfanos heredados...'
    $rootDir = New-Object System.IO.DirectoryInfo($t)
    $ai = Get-AclInfo $rootDir
    if ($ai.Ok -and $ai.Orphans.Count -gt 0) {
        $R.OrphansFound = $ai.Orphans.Count
        Say ('SID huérfanos detectados en la carpeta: ' + ($ai.Orphans -join ', ')) 'warn'
        if (-not $ai.Protected) {
            Say 'Desactivando la herencia SOLO en esta carpeta (la carpeta padre no se toca)...' 'step'
            [void](Invoke-Tool $icacls ('"{0}" /inheritance:d /c /q /L' -f $t))
        }
        foreach ($sid in @($ai.Orphans)) { [void](Invoke-Tool $icacls ('"{0}" /remove *{1} /c /q /L' -f $t, $sid)) }
        Step-Check
        $ai2 = Get-AclInfo $rootDir
        if ($ai2.Ok) { $R.OrphansLeft = $ai2.Orphans.Count }
    }

    # ---- 6) verificación por muestreo de elementos internos ----
    Prog 78 'Verificando permisos internos (muestreo)...'
    $post = Scan-Folder -Root $t -Recurse $rec -CheckAcl $true -MaxAcl 4000
    Step-Check
    if ($post.Orphans.Count -gt 0) {
        Say ('Quedan SID huérfanos en elementos internos: ' + (@($post.Orphans.Keys) -join ', ') + '. Limpieza recursiva...') 'warn'
        foreach ($sid in @($post.Orphans.Keys)) { [void](Invoke-Tool $icacls ('"{0}" /remove *{1}{2} /c /q /L' -f $t, $sid, $tflag)) }
        Step-Check
        $post = Scan-Folder -Root $t -Recurse $rec -CheckAcl $true -MaxAcl 4000
        $R.OrphansLeft += $post.Orphans.Count
    }
    if ($post.AclDenied -gt 0) { Say ('{0} elementos de la muestra siguen sin poder leerse.' -f $post.AclDenied) 'warn'; $R.Warnings += 1 }

    # ---- 7) mostrar SOLO lo oculto por virus (Oculto + Sistema); respeta tus ocultos normales ----
    if ($unhide) {
        Prog 86 'Mostrando elementos Sistema+Oculto (típico del virus de acceso directo)...'
        $skip = @('desktop.ini', 'thumbs.db', 'ehthumbs.db', 'ehthumbs_vista.db', 'iconcache.db', '$recycle.bin', 'system volume information', 'recycler', 'recycled', 'pagefile.sys', 'hiberfil.sys', 'swapfile.sys')
        $cnt = 0
        foreach ($h in $scan.Hidden) {
            if (Cancelled) { break }
            $leaf = [System.IO.Path]::GetFileName($h.Path).ToLowerInvariant()
            if ($skip -contains $leaf) { continue }
            try {
                $a = [int][System.IO.File]::GetAttributes($h.Path)
                if (($a -band 6) -ne 6) { continue }
                $a = $a -band (-bnot 2)
                $keepSys = $false
                if ($h.IsDir -and (Test-Path -LiteralPath (Join-Path $h.Path 'desktop.ini'))) { $keepSys = $true }
                if (-not $keepSys) { $a = $a -band (-bnot 4) }
                [System.IO.File]::SetAttributes($h.Path, [System.IO.FileAttributes]$a)
                $cnt++
            } catch {}
        }
        $R.Unhidden = $cnt
        Say ('Elementos que vuelven a ser visibles: {0}' -f $cnt) 'ok'
    }

    # ---- 8) prueba real de escritura ----
    Prog 95 'Comprobando acceso de escritura...'
    $tf = Join-Path $t ('.sygmatch_test_' + [guid]::NewGuid().ToString('N'))
    try { [System.IO.File]::WriteAllText($tf, 'ok'); [System.IO.File]::Delete($tf); $R.WriteTest = $true } catch { $R.WriteTest = $false }

    $R.Ok = $true
    Prog 100 'Completado'
}
catch {
    $m = $_.Exception.Message
    if ($m -eq 'CANCELLED') { $R.Cancelled = $true; Say 'Operación cancelada. Puedes volver al estado original con "Restaurar copia".' 'warn' }
    elseif ($m -like 'ABORT:*') { $R.Message = $m.Substring(6); Say $R.Message 'err' }
    else { $R.Message = 'Error inesperado: ' + $m; Say $R.Message 'err' }
}
Done ([pscustomobject]$R)
'@

# ---------------------------------------------------------------- DIAGNOSTICO (solo lectura)
$script:OpDiag = @'
$t   = [string]$Ctx.Target
$rec = [bool]$Ctx.Recurse
$R = [ordered]@{ Ok = $false; Cancelled = $false; Message = ''; Lines = @(); NeedsRepair = $false }
$lines = New-Object System.Collections.ArrayList
try {
    Prog 3 'Validando carpeta...'
    $why = Get-ProtectedReason -Path $t
    if ($why) { throw "ABORT:$why" }
    Prog 6 'Analizando (solo lectura)...'
    $scan = Scan-Folder -Root $t -Recurse $rec -CheckAcl $true -MaxAcl 20000
    Step-Check
    $needs = $false
    [void]$lines.Add(@('info', ('Contenido: {0:N0} carpetas y {1:N0} archivos.' -f $scan.Dirs, $scan.Files)))

    $root = New-Object System.IO.DirectoryInfo($t)
    $ai = Get-AclInfo $root
    if ($ai.Ok) {
        $ownerTxt = 'desconocido'
        if ($ai.Owner) { $ownerTxt = Resolve-SidName $ai.Owner }
        if ($ai.OwnerOrphan) { [void]$lines.Add(@('warn', "Propietario de la carpeta: $ownerTxt (cuenta que ya no existe)")); $needs = $true }
        else { [void]$lines.Add(@('info', "Propietario de la carpeta: $ownerTxt")) }
        if ($ai.Protected) { [void]$lines.Add(@('info', 'La herencia de permisos está DESACTIVADA en esta carpeta.')) }
        else { [void]$lines.Add(@('info', 'La herencia de permisos está activada.')) }
        if ($ai.Orphans.Count -gt 0) { [void]$lines.Add(@('warn', ('La carpeta tiene {0} SID huérfano(s) en sus permisos.' -f $ai.Orphans.Count))); $needs = $true }
    }
    else { [void]$lines.Add(@('err', 'No se pueden leer los permisos de la propia carpeta (acceso denegado).')); $needs = $true }

    if ($scan.AclRead -gt 0) {
        [void]$lines.Add(@('info', ('Permisos revisados en {0:N0} elementos.' -f $scan.AclRead)))
        if ($scan.AclDenied -gt 0) { [void]$lines.Add(@('warn', ('{0:N0} elementos con permisos ilegibles (acceso denegado).' -f $scan.AclDenied))); $needs = $true }
        if ($scan.OwnerOrphan -gt 0) { [void]$lines.Add(@('warn', ('{0:N0} elementos con propietario que ya no existe.' -f $scan.OwnerOrphan))); $needs = $true }
        if ($scan.OwnerOther -gt 0) { [void]$lines.Add(@('warn', ('{0:N0} elementos con otro propietario distinto al esperado.' -f $scan.OwnerOther))); $needs = $true }
        foreach ($k in $scan.Orphans.Keys) { [void]$lines.Add(@('warn', ('SID huérfano {0}: presente en {1:N0} elementos.' -f $k, $scan.Orphans[$k]))); $needs = $true }
        if ($scan.AclDenied -eq 0 -and $scan.OwnerOrphan -eq 0 -and $scan.OwnerOther -eq 0 -and $scan.Orphans.Count -eq 0) { [void]$lines.Add(@('ok', 'Permisos y propietarios correctos en lo revisado.')) }
    }
    if ($scan.Unreadable -gt 0) { [void]$lines.Add(@('warn', ('{0:N0} carpetas no se pudieron abrir.' -f $scan.Unreadable))); $needs = $true }
    if ($scan.Hidden.Count -gt 0) {
        [void]$lines.Add(@('warn', ('{0:N0} elementos Sistema+Oculto (posible rastro del virus de acceso directo):' -f $scan.Hidden.Count)))
        foreach ($h in ($scan.Hidden | Select-Object -First 5)) { [void]$lines.Add(@('info', ('    ' + $h.Path))) }
    }
    if ($scan.DirLinks.Count -gt 0) {
        [void]$lines.Add(@('warn', ('{0} unión(es)/enlace(s) simbólico(s) a carpetas: el Nivel 1 NO se ejecutará en recursivo mientras existan.' -f $scan.DirLinks.Count)))
        foreach ($l in ($scan.DirLinks | Select-Object -First 5)) { [void]$lines.Add(@('info', ('    ' + $l))) }
    }
    $R.NeedsRepair = $needs
    $R.Ok = $true
    Prog 100 'Diagnóstico completado'
}
catch {
    $m = $_.Exception.Message
    if ($m -eq 'CANCELLED') { $R.Cancelled = $true; Say 'Diagnóstico cancelado.' 'warn' }
    elseif ($m -like 'ABORT:*') { $R.Message = $m.Substring(6); Say $R.Message 'err' }
    else { $R.Message = 'Error inesperado: ' + $m; Say $R.Message 'err' }
}
$R.Lines = @($lines)
Done ([pscustomobject]$R)
'@

# ---------------------------------------------------------------- RESTAURAR COPIA
$script:OpRestore = @'
$icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
$R = [ordered]@{ Ok = $false; Cancelled = $false; Message = ''; Processed = -1; Failed = -1 }
try {
    $why = Get-ProtectedReason -Path ([string]$Ctx.Target)
    if ($why) { throw "ABORT:$why" }
    if (-not (Test-Path -LiteralPath $Ctx.AclFile)) { throw 'ABORT:No se encuentra el archivo de copia de seguridad.' }
    if (-not (Test-Path -LiteralPath $Ctx.RestoreDir -PathType Container)) { throw 'ABORT:La carpeta de destino de la restauración no existe.' }
    Prog 15 'Restaurando permisos desde la copia...'
    $x = Invoke-Tool $icacls ('"{0}" /restore "{1}" /c /q /L' -f $Ctx.RestoreDir, $Ctx.AclFile)
    Step-Check
    $st = Get-ToolStats $x.Output
    $R.Processed = $st.Processed; $R.Failed = $st.Failed
    if ($st.Failed -gt 0) { foreach ($s in $st.Samples) { Say ('    ' + $s) 'warn' } }
    if ($x.ExitCode -eq 0 -or ($st.Processed -gt 0 -and $st.Failed -eq 0)) { $R.Ok = $true }
    else { $R.Message = 'icacls devolvió errores al restaurar (código ' + $x.ExitCode + ').' }
    Prog 100 'Restauración terminada'
}
catch {
    $m = $_.Exception.Message
    if ($m -eq 'CANCELLED') { $R.Cancelled = $true; Say 'Restauración cancelada.' 'warn' }
    elseif ($m -like 'ABORT:*') { $R.Message = $m.Substring(6); Say $R.Message 'err' }
    else { $R.Message = 'Error inesperado: ' + $m; Say $R.Message 'err' }
}
Done ([pscustomobject]$R)
'@

# ============================================================================
#  6) TEMAS, REGISTRO (LOG) Y DIALOGOS PROPIOS
# ============================================================================
$script:Themes = @{
    dark = @{
        IsDark = $true
        Bg = (RGB 14 16 26); Surface = (RGB 25 28 42); Border = (RGB 46 51 76)
        Text = (RGB 238 241 250); Sub = (RGB 140 149 178)
        Input = (RGB 20 22 35); LogBg = (RGB 10 11 19); SwOff = (RGB 70 76 104)
        LogText = (RGB 196 204 230); LogOk = (RGB 74 222 128); LogWarn = (RGB 251 191 36); LogErr = (RGB 248 113 113); LogStep = (RGB 167 139 250)
    }
    light = @{
        IsDark = $false
        Bg = (RGB 242 244 251); Surface = (RGB 255 255 255); Border = (RGB 222 226 240)
        Text = (RGB 24 28 45); Sub = (RGB 98 107 133)
        Input = (RGB 255 255 255); LogBg = (RGB 250 251 255); SwOff = (RGB 190 196 214)
        LogText = (RGB 52 62 92); LogOk = (RGB 21 128 61); LogWarn = (RGB 180 83 9); LogErr = (RGB 200 30 30); LogStep = (RGB 109 40 217)
    }
}
$script:Accent = @{
    diag = @((RGB 251 191 36), (RGB 249 115 22))
    n1   = @((RGB 167 139 250), (RGB 99 102 241))
    n2   = @((RGB 251 113 133), (RGB 225 29 72))
    n3   = @((RGB 45 212 191), (RGB 16 185 129))
    rest = @((RGB 56 189 248), (RGB 37 99 235))
    fold = @((RGB 232 121 249), (RGB 168 85 247))
}
$script:Violet = @((RGB 139 92 246), (RGB 79 70 229))

$themeName = [string](Get-Setting 'theme' '')
if ($themeName -ne 'dark' -and $themeName -ne 'light') {
    $themeName = 'dark'
    try {
        $v = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -ErrorAction Stop).AppsUseLightTheme
        if ($v -eq 1) { $themeName = 'light' }
    } catch {}
}
$script:Theme = $script:Themes[$themeName]

$script:LogLines = New-Object System.Collections.ArrayList
$script:txtLog = $null
$script:Worker = $null
$script:LastProg = ''
$script:KnownPrefixes = $null

function Write-LogLine([string]$Level, [string]$Line) {
    $rt = $script:txtLog
    if (-not $rt) { return }
    $t = $script:Theme
    $color = $t.LogText
    switch ($Level) { 'ok' { $color = $t.LogOk } 'warn' { $color = $t.LogWarn } 'err' { $color = $t.LogErr } 'step' { $color = $t.LogStep } }
    $rt.SelectionStart = $rt.TextLength
    $rt.SelectionLength = 0
    $rt.SelectionColor = $color
    $rt.AppendText($Line + "`r`n")
}

function Add-Log {
    param([string]$Message, [string]$Level = 'info')
    $line = '[{0}] {1}' -f (Get-Date).ToString('HH:mm:ss'), $Message
    [void]$script:LogLines.Add([pscustomobject]@{ Level = $Level; Line = $line })
    if ($script:LogLines.Count -gt 1500) { $script:LogLines.RemoveRange(0, 300); Rebuild-Log }
    else {
        Write-LogLine $Level $line
        if ($script:txtLog) { $script:txtLog.SelectionStart = $script:txtLog.TextLength; $script:txtLog.ScrollToCaret() }
    }
    try { Add-Content -LiteralPath $script:LogFile -Value ('{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.ToUpper(), $Message) -Encoding UTF8 } catch {}
}

function Rebuild-Log {
    if (-not $script:txtLog) { return }
    $script:txtLog.Clear()
    foreach ($l in $script:LogLines) { Write-LogLine $l.Level $l.Line }
    $script:txtLog.SelectionStart = $script:txtLog.TextLength
    $script:txtLog.ScrollToCaret()
}

function New-Label {
    param([string]$Text, [double]$X, [double]$Y, [double]$W, [double]$H, [double]$Size = 9, [string]$Style = 'Regular', [string]$FontName = 'Segoe UI')
    $l = New-Object System.Windows.Forms.Label
    $l.UseCompatibleTextRendering = $false
    $l.AutoSize = $false
    $l.Text = $Text
    $l.Location = PT $X $Y
    $l.Size = SZ $W $H
    $l.Font = [System.Drawing.Font]::new($FontName, [single]$Size, [System.Drawing.FontStyle]$Style)
    return $l
}

function Set-SecondaryButton($btn) {
    $t = $script:Theme
    $btn.BackColor = $t.Bg; $btn.FillA = $t.Surface; $btn.FillB = $t.Surface
    $btn.BorderColor = $t.Border; $btn.TextColor = $t.Text
    $btn.Invalidate()
}

function New-DialogButton {
    param([string]$Text, [double]$X, [double]$Y, [double]$W, [bool]$Primary, $Accent)
    $t = $script:Theme
    $b = New-Object Sygmatch.UI.RoundButton
    $b.Text = $Text
    $b.Location = PT $X $Y
    $b.Size = SZ $W 36
    $b.BackColor = $t.Bg
    if ($Primary) { $b.FillA = $Accent[0]; $b.FillB = $Accent[1]; $b.TextColor = [System.Drawing.Color]::White }
    else { Set-SecondaryButton $b }
    return $b
}

# Cuadro de mensaje con el tema de la aplicacion. Devuelve 'OK', 'Yes' o 'No'.
function Show-Dialog {
    param([string]$Title, [string]$Message, [string]$Buttons = 'OK', [string]$Icon = 'info', [string]$YesText = 'Sí', [string]$NoText = 'No')
    $t = $script:Theme
    $accent = (RGB 59 130 246)
    switch ($Icon) {
        'warn'     { $accent = (RGB 245 158 11) }
        'error'    { $accent = (RGB 239 68 68) }
        'ok'       { $accent = (RGB 34 197 94) }
        'question' { $accent = (RGB 139 92 246) }
    }
    $accent2 = [Sygmatch.UI.Gfx]::Lerp($accent, [System.Drawing.Color]::Black, 0.25)
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false; $dlg.MinimizeBox = $false; $dlg.ShowInTaskbar = $false
    $dlg.StartPosition = 'CenterParent'
    $dlg.BackColor = $t.Bg; $dlg.ForeColor = $t.Text
    $dlg.KeyPreview = $true
    if ($script:AppIcon) { $dlg.Icon = $script:AppIcon }
    $fw = 580; $textW = $fw - 28 - 26
    $msgFont = [System.Drawing.Font]::new('Segoe UI', [single]10)
    $flags = [System.Windows.Forms.TextFormatFlags]::WordBreak -bor [System.Windows.Forms.TextFormatFlags]::NoPadding
    $meas = [System.Windows.Forms.TextRenderer]::MeasureText($Message, $msgFont, [System.Drawing.Size]::new((px $textW), 100000), $flags)
    $mh = $meas.Height + (px 8)
    $maxH = px 330
    $y = 62
    $lblT = New-Label $Title 28 18 $textW 30 13 'Bold' 'Segoe UI Semibold'
    $lblT.ForeColor = $t.Text; $lblT.BackColor = $t.Bg
    $dlg.Controls.Add($lblT)
    if ($mh -gt $maxH) {
        $tb = New-Object System.Windows.Forms.TextBox
        $tb.Multiline = $true; $tb.ReadOnly = $true; $tb.ScrollBars = 'Vertical'; $tb.BorderStyle = 'None'
        $tb.Font = $msgFont; $tb.BackColor = $t.Bg; $tb.ForeColor = $t.Text
        $tb.Location = PT 28 $y; $tb.Size = [System.Drawing.Size]::new((px ($textW + 10)), $maxH)
        $tb.Text = $Message
        $dlg.Controls.Add($tb)
        $boxH = $maxH
    } else {
        $lm = New-Object System.Windows.Forms.Label
        $lm.UseCompatibleTextRendering = $false; $lm.AutoSize = $false
        $lm.Font = $msgFont; $lm.ForeColor = $t.Text; $lm.BackColor = $t.Bg
        $lm.Location = PT 28 $y; $lm.Size = [System.Drawing.Size]::new((px $textW), $mh)
        $lm.Text = $Message
        $dlg.Controls.Add($lm)
        $boxH = $mh
    }
    $btnY = [int](($y * $script:Scale + $boxH) / $script:Scale) + 20
    $strip = New-Object System.Windows.Forms.Panel
    $strip.BackColor = $accent; $strip.Location = PT 0 0
    $dlg.ClientSize = [System.Drawing.Size]::new((px $fw), (px ($btnY + 36 + 22)))
    $strip.Size = [System.Drawing.Size]::new((px 6), $dlg.ClientSize.Height)
    $dlg.Controls.Add($strip)

    $default = 'OK'
    if ($Buttons -eq 'YesNo') {
        $default = 'No'
        $bYes = New-DialogButton $YesText ($fw - 24 - 130) $btnY 130 $true @($accent, $accent2)
        $bNo  = New-DialogButton $NoText  ($fw - 24 - 130 - 10 - 120) $btnY 120 $false $null
        $bYes.add_Click({ $dlg.Tag = 'Yes'; $dlg.Close() }.GetNewClosure())
        $bNo.add_Click({ $dlg.Tag = 'No'; $dlg.Close() }.GetNewClosure())
        $dlg.Controls.Add($bYes); $dlg.Controls.Add($bNo)
    } else {
        $bOk = New-DialogButton 'Aceptar' ($fw - 24 - 130) $btnY 130 $true @($accent, $accent2)
        $bOk.add_Click({ $dlg.Tag = 'OK'; $dlg.Close() }.GetNewClosure())
        $dlg.Controls.Add($bOk)
    }
    $dlg.Tag = $default
    $dlg.add_KeyDown({
        param($sender, $ev)
        if ($ev.KeyCode -eq 'Escape') { $dlg.Tag = $default; $dlg.Close() }
        elseif ($ev.KeyCode -eq 'Return' -and $Buttons -ne 'YesNo') { $dlg.Tag = 'OK'; $dlg.Close() }
    }.GetNewClosure())
    $dlg.add_Shown({ param($sender, $ev) [Sygmatch.UI.Native]::SetDarkTitleBar($sender.Handle, [bool]$script:Theme.IsDark) })
    [void]$dlg.ShowDialog($script:Form)
    $res = [string]$dlg.Tag
    $dlg.Dispose()
    return $res
}

# Lista con casillas para que TU decidas que se elimina. Devuelve @{Ok; Indices}.
function Show-Checklist {
    param([string]$Title, [string]$Message, [object[]]$Items, [string]$OkText = 'Aplicar')
    $t = $script:Theme
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false; $dlg.MinimizeBox = $false; $dlg.ShowInTaskbar = $false
    $dlg.StartPosition = 'CenterParent'
    $dlg.BackColor = $t.Bg; $dlg.ForeColor = $t.Text
    if ($script:AppIcon) { $dlg.Icon = $script:AppIcon }
    $fw = 700; $textW = $fw - 28 - 26
    $dlg.ClientSize = [System.Drawing.Size]::new((px $fw), (px 470))
    $lblT = New-Label $Title 28 16 $textW 30 13 'Bold' 'Segoe UI Semibold'
    $lblT.ForeColor = $t.Text; $lblT.BackColor = $t.Bg
    $dlg.Controls.Add($lblT)
    $lblM = New-Label $Message 28 48 $textW 52 9.5
    $lblM.ForeColor = $t.Sub; $lblM.BackColor = $t.Bg
    $dlg.Controls.Add($lblM)
    $pnl = New-Object Sygmatch.UI.RoundedPanel
    $pnl.Location = PT 28 106; $pnl.Size = SZ ($fw - 56) 290
    $pnl.BackColor = $t.Bg; $pnl.Fill = $t.Surface; $pnl.Border = $t.Border
    $clb = New-Object System.Windows.Forms.CheckedListBox
    $clb.CheckOnClick = $true; $clb.BorderStyle = 'None'; $clb.IntegralHeight = $false
    $clb.HorizontalScrollbar = $true
    $clb.Font = [System.Drawing.Font]::new('Segoe UI', [single]9.5)
    $clb.BackColor = $t.Surface; $clb.ForeColor = $t.Text
    $clb.Location = PT 10 8; $clb.Size = SZ ($fw - 56 - 20) 274
    foreach ($it in $Items) { [void]$clb.Items.Add(('{0}   ›   {1}' -f $it.Text, $it.Detail), [bool]$it.Checked) }
    $pnl.Controls.Add($clb)
    $dlg.Controls.Add($pnl)
    $bAll  = New-DialogButton 'Todos' 28 410 90 $false $null
    $bNone = New-DialogButton 'Ninguno' 126 410 90 $false $null
    $bAll.add_Click({ for ($i = 0; $i -lt $clb.Items.Count; $i++) { $clb.SetItemChecked($i, $true) } }.GetNewClosure())
    $bNone.add_Click({ for ($i = 0; $i -lt $clb.Items.Count; $i++) { $clb.SetItemChecked($i, $false) } }.GetNewClosure())
    $bOk = New-DialogButton $OkText ($fw - 24 - 190) 410 190 $true $script:Violet
    $bCancel = New-DialogButton 'Cancelar' ($fw - 24 - 190 - 10 - 110) 410 110 $false $null
    $dlg.Tag = 'Cancel'
    $bOk.add_Click({ $dlg.Tag = 'Ok'; $dlg.Close() }.GetNewClosure())
    $bCancel.add_Click({ $dlg.Tag = 'Cancel'; $dlg.Close() }.GetNewClosure())
    foreach ($c in @($bAll, $bNone, $bOk, $bCancel)) { $dlg.Controls.Add($c) }
    $dlg.add_Shown({ param($sender, $ev)
        [Sygmatch.UI.Native]::SetDarkTitleBar($sender.Handle, [bool]$script:Theme.IsDark)
        [Sygmatch.UI.Native]::SetControlTheme($clb.Handle, [bool]$script:Theme.IsDark)
    }.GetNewClosure())
    [void]$dlg.ShowDialog($script:Form)
    $ok = ([string]$dlg.Tag -eq 'Ok')
    $idx = @()
    if ($ok) { foreach ($i in $clb.CheckedIndices) { $idx += [int]$i } }
    $dlg.Dispose()
    return [pscustomobject]@{ Ok = $ok; Indices = $idx }
}

# ============================================================================
#  7) IDENTIDAD DEL USUARIO Y GESTION DEL HILO DE TRABAJO
# ============================================================================
function Get-InteractiveUserSid {
    try {
        $u = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).UserName
        if ($u) { return (New-Object System.Security.Principal.NTAccount($u)).Translate([System.Security.Principal.SecurityIdentifier]).Value }
    } catch {}
    return $null
}

function Get-KnownSidPrefixes {
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    $add = { param($sid) if ($sid -and ("$sid" -match '^(S-1-5-21-\d+-\d+-\d+)-\d+$')) { [void]$set.Add($Matches[1]) } }
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        & $add $id.User.Value
        foreach ($g in $id.Groups) { & $add $g.Value }
    } catch {}
    try { foreach ($u in (Get-LocalUser -ErrorAction Stop)) { & $add $u.SID.Value } } catch {}
    try { foreach ($g in (Get-LocalGroup -ErrorAction Stop)) { & $add $g.SID.Value } } catch {}
    if ($set.Count -lt 2) {
        try { foreach ($u in (Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)) { & $add $u.SID } } catch {}
    }
    & $add (Get-InteractiveUserSid)
    return @($set)
}

function Get-WorkerParams([string]$Target) {
    if (-not $script:KnownPrefixes) { $script:KnownPrefixes = @(Get-KnownSidPrefixes) }
    $elev = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $inter = Get-InteractiveUserSid
    $owner = $elev
    if ($inter) { $owner = $inter }
    $grant = @($elev)
    if ($inter -and $inter -ne $elev) { $grant += $inter }
    $expected = @($grant) + @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    return @{
        Target = $Target; Recurse = [bool]$script:swRec.Checked; Unhide = [bool]$script:swHide.Checked
        BackupDir = $script:BackupDir; OwnerSid = $owner; GrantSids = $grant
        KnownPrefixes = $script:KnownPrefixes; ExpectedOwners = $expected
    }
}

function Set-Progress([int]$Pct, [string]$Text) {
    if ($Text) { $script:lblStatus.Text = $Text }
    if ($Pct -lt 0) { $script:progress.Marquee = $true }
    else { $script:progress.Marquee = $false; $script:progress.Value = $Pct }
}

function Set-Busy([bool]$Busy) {
    foreach ($k in @($script:Cards.Keys)) { $script:Cards[$k].Enabled = (-not $Busy) }
    $script:btnBrowse.Enabled = (-not $Busy)
    $script:txtPath.Enabled = (-not $Busy)
    $script:swRec.Enabled = (-not $Busy)
    $script:swHide.Enabled = (-not $Busy)
    $script:btnCancel.Visible = $Busy
    $script:btnCancel.Enabled = $true
    if (-not $Busy) { $script:progress.Marquee = $false; $script:progress.Value = 0 }
}

function Receive-WorkerMessages {
    $w = $script:Worker
    if (-not $w) { return }
    $item = $null
    $n = 0
    while ($n -lt 500 -and $w.Q.TryDequeue([ref]$item)) {
        $n++
        switch ($item.T) {
            'log'  { Add-Log $item.Text $item.Level }
            'prog' {
                Set-Progress $item.Pct $item.Text
                if ($item.Pct -ge 0 -and $item.Text -ne $script:LastProg) { $script:LastProg = $item.Text; Add-Log $item.Text 'step' }
            }
            'done' { $w.Result = $item.Result }
        }
    }
}

function Poll-Worker {
    $w = $script:Worker
    if (-not $w) { $script:pollTimer.Stop(); return }
    Receive-WorkerMessages
    if ($w.Handle.IsCompleted) {
        $script:pollTimer.Stop()
        Receive-WorkerMessages
        try { [void]$w.PS.EndInvoke($w.Handle) } catch { Add-Log ('Error en el proceso: ' + $_.Exception.Message) 'err' }
        try { foreach ($er in @($w.PS.Streams.Error | Select-Object -First 5)) { Add-Log ('[interno] ' + $er.ToString()) 'warn' } } catch {}
        try { $w.PS.Dispose(); $w.RS.Close(); $w.RS.Dispose() } catch {}
        $script:Worker = $null
        Set-Busy $false
        Set-Progress 0 'Listo'
        if ($w.OnDone) { try { & $w.OnDone $w.Result } catch { Add-Log ('Error: ' + $_.Exception.Message) 'err' } }
    }
}

function Start-Worker {
    param([string]$Body, [hashtable]$Params, [scriptblock]$OnDone)
    $q = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
    $state = [hashtable]::Synchronized(@{ Cancel = $false })
    $ctx = @{ Q = $q; State = $state }
    foreach ($k in $Params.Keys) { $ctx[$k] = $Params[$k] }
    $code = "param(`$Ctx)`r`n" + $script:WorkerPrelude + "`r`n" + $script:WorkerHeader + "`r`n" + $Body
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = [System.Threading.ApartmentState]::MTA
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($code).AddArgument($ctx)
    $script:LastProg = ''
    $script:Worker = @{ PS = $ps; RS = $rs; Q = $q; State = $state; Handle = $null; Result = $null; OnDone = $OnDone }
    Set-Busy $true
    Set-Progress -1 'Iniciando...'
    $script:Worker.Handle = $ps.BeginInvoke()
    $script:pollTimer.Start()
}

# ============================================================================
#  8) ACCIONES (Diagnostico, Nivel 1, Nivel 2, Nivel 3, Restaurar)
# ============================================================================
$script:ScriptExts = @('.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.bat', '.cmd', '.scr', '.pif')

function Get-TargetPath {
    $p = ([string]$script:txtPath.Text).Trim().Trim('"')
    if (-not $p) { [void](Show-Dialog 'Falta la carpeta' 'Escribe o selecciona primero la carpeta con el botón «Examinar».' 'OK' 'warn'); return $null }
    $p = [Environment]::ExpandEnvironmentVariables($p)
    $full = $null
    try { $full = [System.IO.Path]::GetFullPath($p) } catch { [void](Show-Dialog 'Ruta no válida' 'La ruta escrita no es válida.' 'OK' 'error'); return $null }
    if ($full.Length -gt 3) { $full = $full.TrimEnd('\') }
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { [void](Show-Dialog 'No existe' "La carpeta no existe:`r`n$full" 'OK' 'error'); return $null }
    return $full
}

function Open-GitHub {
    try { Start-Process -FilePath 'explorer.exe' -ArgumentList $script:GitHubUrl }
    catch { try { [void][System.Diagnostics.Process]::Start($script:GitHubUrl) } catch {} }
}

# ---------------------------------------------------------------- Diagnostico
function Invoke-Diagnose {
    $target = Get-TargetPath
    if (-not $target) { return }
    $why = Get-ProtectedReason -Path $target
    if ($why) { [void](Show-Dialog 'Carpeta bloqueada' $why 'OK' 'error'); return }
    Add-Log "Diagnóstico (solo lectura): $target" 'step'
    Start-Worker -Body $script:OpDiag -Params (Get-WorkerParams $target) -OnDone {
        param($r)
        if (-not $r -or $r.Cancelled) { return }
        if (-not $r.Ok) { [void](Show-Dialog 'Diagnóstico' ([string]$r.Message) 'OK' 'error'); return }
        $sb = New-Object System.Text.StringBuilder
        foreach ($l in $r.Lines) { Add-Log $l[1] $l[0]; [void]$sb.AppendLine(($l[1] -replace '^\s+', '  ')) }
        [void]$sb.AppendLine('')
        if ($r.NeedsRepair) {
            [void]$sb.AppendLine('Resultado: se detectaron problemas de permisos. Se recomienda ejecutar «Nivel 1 · Reparar carpeta».')
            [void](Show-Dialog 'Diagnóstico completado' $sb.ToString() 'OK' 'warn')
        } else {
            [void]$sb.AppendLine('Resultado: no se detectaron problemas de permisos en lo analizado.')
            [void](Show-Dialog 'Diagnóstico completado' $sb.ToString() 'OK' 'ok')
        }
    }
}

# ---------------------------------------------------------------- Nivel 1
function Invoke-Repair {
    $target = Get-TargetPath
    if (-not $target) { return }
    $why = Get-ProtectedReason -Path $target
    if ($why) { [void](Show-Dialog 'Carpeta bloqueada' $why 'OK' 'error'); return }
    $msg = "Se va a reparar esta carpeta:`r`n`r`n    $target`r`n`r`n" +
           "1. Copia de seguridad de los permisos actuales`r`n" +
           "2. Tomar posesión y asignarte como propietario`r`n" +
           "3. Restablecer permisos y activar la herencia`r`n" +
           "4. Control total para tu usuario, Administradores y SYSTEM`r`n" +
           "5. Quitar SID huérfanos de usuarios de un Windows anterior`r`n"
    if ($script:swHide.Checked) { $msg += "6. Mostrar elementos ocultos por virus (Sistema + Oculto)`r`n" }
    if (-not $script:swRec.Checked) { $msg += "`r`n(Solo la carpeta indicada: sin subcarpetas.)`r`n" }
    $msg += "`r`nNo se borra ningún archivo y la carpeta padre no se modifica. Puedes deshacerlo con «Restaurar copia».`r`n`r`n¿Continuar?"
    if ((Show-Dialog 'Confirmar reparación' $msg 'YesNo' 'question' 'Reparar' 'Cancelar') -ne 'Yes') { return }
    Add-Log "Nivel 1: reparando $target" 'step'
    Start-Worker -Body $script:OpRepair -Params (Get-WorkerParams $target) -OnDone {
        param($r)
        if (-not $r) { return }
        if ($r.Cancelled) { [void](Show-Dialog 'Operación cancelada' "La reparación se canceló.`r`nPuedes volver al estado original con «Restaurar copia»." 'OK' 'warn'); return }
        if (-not $r.Ok) { [void](Show-Dialog 'No se pudo reparar' ([string]$r.Message) 'OK' 'error'); return }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine(('Elementos procesados: {0:N0} carpetas y {1:N0} archivos.' -f $r.Dirs, $r.Files))
        [void]$sb.AppendLine('Copia de seguridad: ' + $r.Backup)
        if ($r.OrphansFound -gt 0) { [void]$sb.AppendLine(('SID huérfanos detectados en la carpeta: {0} (quedan: {1}).' -f $r.OrphansFound, $r.OrphansLeft)) }
        elseif ($r.OrphansLeft -gt 0) { [void]$sb.AppendLine(('SID huérfanos restantes en elementos internos: {0}.' -f $r.OrphansLeft)) }
        else { [void]$sb.AppendLine('SID huérfanos: ninguno pendiente.') }
        if ($script:swHide.Checked) { [void]$sb.AppendLine(('Elementos ocultos por virus que vuelven a verse: {0}.' -f $r.Unhidden)) }
        if ($r.WriteTest) { [void]$sb.AppendLine('Prueba de escritura: correcta.') } else { [void]$sb.AppendLine('Prueba de escritura: FALLÓ (revisa el registro).') }
        if ($r.Warnings -gt 0) { [void]$sb.AppendLine(("`r`nHubo {0} aviso(s): revisa el registro inferior para ver el detalle." -f $r.Warnings)) }
        $icon = 'ok'
        if ($r.Warnings -gt 0 -or -not $r.WriteTest -or $r.OrphansLeft -gt 0) { $icon = 'warn' }
        Add-Log 'Reparación finalizada.' 'ok'
        [void](Show-Dialog 'Reparación completada' $sb.ToString() 'OK' $icon)
    }
}

# ---------------------------------------------------------------- utilidades Nivel 2 / 3
function Get-FilesByExt {
    param([string]$Root, [bool]$Recurse, [string[]]$Exts, [int]$Max = 100000)
    $out = New-Object System.Collections.ArrayList
    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($Root)
    while ($stack.Count -gt 0 -and $out.Count -lt $Max) {
        $dir = $stack.Pop()
        $entries = $null
        try { $entries = (New-Object System.IO.DirectoryInfo($dir)).EnumerateFileSystemInfos() } catch { continue }
        try {
            foreach ($e in $entries) {
                $attr = [int]$e.Attributes
                $isDir = (($attr -band 16) -ne 0)
                if (($attr -band 1024) -ne 0) {
                    $lt = ''
                    try { $lt = [string]$e.LinkType } catch {}
                    if ($lt -eq 'Junction' -or $lt -eq 'SymbolicLink') { continue }
                }
                if ($isDir) {
                    if ($Recurse) {
                        $nm = $e.Name.ToLowerInvariant()
                        if ($nm -ne 'system volume information' -and $nm -ne '$recycle.bin') { $stack.Push($e.FullName) }
                    }
                } elseif ($Exts -contains $e.Extension.ToLowerInvariant()) { [void]$out.Add($e) }
            }
        } catch {}
    }
    return $out
}

function Test-SuspiciousLnk {
    param([string]$Target, [string]$Arguments)
    $leaf = ''
    try { $leaf = [System.IO.Path]::GetFileName($Target).ToLowerInvariant() } catch {}
    if (-not $leaf) { return $null }
    if (@('wscript.exe', 'cscript.exe', 'mshta.exe') -contains $leaf) {
        return [pscustomobject]@{ Reason = "ejecuta un script ($leaf $Arguments)"; Checked = $true }
    }
    if (@('cmd.exe', 'powershell.exe', 'pwsh.exe', 'rundll32.exe', 'regsvr32.exe') -contains $leaf) {
        if ($Arguments -match '(?i)\.(vbs|vbe|js|jse|wsf|wsh|hta|scr|pif)\b' -or $Arguments -match '(?i)\bstart\b.*\.exe' -or $Arguments -match '(?i)-(w|windowstyle)\s+hidden' -or $Arguments -match '(?i)-(e|enc|encodedcommand)\s') {
            return [pscustomobject]@{ Reason = "lanza comandos ocultos ($leaf $Arguments)"; Checked = $true }
        }
        if ($Arguments -match '(?i)\.(exe|bat|cmd|ps1)\b') {
            return [pscustomobject]@{ Reason = "lanza un programa o script ($leaf $Arguments)"; Checked = $false }
        }
    }
    return $null
}

function Move-ToQuarantine {
    param([string]$File, [string]$BatchDir)
    $leaf = [System.IO.Path]::GetFileName($File)
    $dest = Join-Path $BatchDir ('{0}_{1}.quarantined' -f ([guid]::NewGuid().ToString('N').Substring(0, 8)), (Get-SafeName $leaf))
    try { [System.IO.File]::SetAttributes($File, [System.IO.FileAttributes]::Normal) } catch {}
    Move-Item -LiteralPath $File -Destination $dest -Force -ErrorAction Stop
    Add-Content -LiteralPath (Join-Path $BatchDir 'manifest.txt') -Value ('{0}  <=  {1}' -f $dest, $File) -Encoding UTF8
    return $dest
}

# ---------------------------------------------------------------- Nivel 2
function Invoke-VirusScan {
    $target = Get-TargetPath
    if (-not $target) { return }
    $why = Get-ProtectedReason -Path $target -AllowDriveRoot $true
    if ($why) { [void](Show-Dialog 'Carpeta bloqueada' $why 'OK' 'error'); return }
    $isRoot = ($target.Length -le 3)
    $recurse = [bool]$script:swRec.Checked
    Add-Log "Nivel 2: buscando rastros del virus de acceso directo en $target ..." 'step'
    $cands = New-Object System.Collections.ArrayList
    $script:Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        try {
            $procs = @(Get-CimInstance Win32_Process -Filter "Name='wscript.exe' OR Name='cscript.exe'" -ErrorAction Stop)
            foreach ($p in $procs) {
                $cl = [string]$p.CommandLine
                if (-not $cl) { continue }
                $inTarget = ($cl.IndexOf($target, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
                if ($inTarget -or $cl -match '(?i)\\(temp|recycler|recycled)\\') {
                    [void]$cands.Add([pscustomobject]@{ Kind = 'proc'; Text = ('Proceso {0} (PID {1})' -f $p.Name, $p.ProcessId); Detail = $cl; Checked = $inTarget; Data = [int]$p.ProcessId })
                }
            }
        } catch {}

        $lnks = @(Get-FilesByExt -Root $target -Recurse $recurse -Exts @('.lnk'))
        if ($lnks.Count -gt 0) {
            $sh = New-Object -ComObject WScript.Shell
            try {
                foreach ($f in $lnks) {
                    $tp = ''; $ar = ''
                    try { $sc = $sh.CreateShortcut($f.FullName); $tp = [string]$sc.TargetPath; $ar = [string]$sc.Arguments } catch { continue }
                    $v = Test-SuspiciousLnk -Target $tp -Arguments $ar
                    if ($v) { [void]$cands.Add([pscustomobject]@{ Kind = 'file'; Text = ('Acceso directo ' + $f.FullName); Detail = $v.Reason; Checked = $v.Checked; Data = $f.FullName }) }
                }
            } finally { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($sh) }
        }

        foreach ($f in @(Get-ChildItem -LiteralPath $target -Force -File -ErrorAction SilentlyContinue)) {
            $ext = $f.Extension.ToLowerInvariant()
            $attr = [int]$f.Attributes
            $hid = (($attr -band 2) -ne 0); $sys = (($attr -band 4) -ne 0)
            if ($isRoot -and $f.Name -ieq 'autorun.inf') {
                [void]$cands.Add([pscustomobject]@{ Kind = 'file'; Text = ('autorun.inf ' + $f.FullName); Detail = 'archivo de ejecución automática de unidad'; Checked = $true; Data = $f.FullName })
            }
            elseif ($hid -and ($script:ScriptExts -contains $ext)) {
                [void]$cands.Add([pscustomobject]@{ Kind = 'file'; Text = ('Script oculto ' + $f.FullName); Detail = 'script con atributo oculto en la raíz'; Checked = $true; Data = $f.FullName })
            }
            elseif ($hid -and (@('.exe', '.com') -contains $ext)) {
                [void]$cands.Add([pscustomobject]@{ Kind = 'file'; Text = ('Ejecutable oculto ' + $f.FullName); Detail = $(if ($sys) { 'oculto + sistema (muy sospechoso)' } else { 'oculto (puede ser tuyo: revisa antes)' }); Checked = $sys; Data = $f.FullName })
            }
        }
    } finally { $script:Form.Cursor = [System.Windows.Forms.Cursors]::Default }

    if ($cands.Count -eq 0) {
        Add-Log 'Nivel 2: no se encontró nada sospechoso.' 'ok'
        [void](Show-Dialog 'Nivel 2' "No se encontraron accesos directos falsos, scripts ocultos ni procesos sospechosos en:`r`n$target`r`n`r`nSi tus carpetas siguen sin verse, ejecuta el Nivel 1 con «Mostrar ocultos de virus» activado." 'OK' 'ok')
        return
    }
    $sel = Show-Checklist -Title 'Elementos sospechosos' -Message "Marca lo que quieres neutralizar. Los archivos NO se borran: se mueven a cuarentena (recuperable). Los procesos se cierran." -Items @($cands) -OkText 'Neutralizar marcados'
    if (-not $sel.Ok -or $sel.Indices.Count -eq 0) { Add-Log 'Nivel 2: sin cambios.' 'info'; return }
    $batch = Join-Path $script:QuarDir (Get-Date -Format 'yyyyMMdd_HHmmss')
    [void](New-Item -ItemType Directory -Force -Path $batch)
    $killed = 0; $moved = 0; $failed = 0
    foreach ($i in $sel.Indices) { $c = $cands[$i]; if ($c.Kind -eq 'proc') {
        try { Stop-Process -Id $c.Data -Force -ErrorAction Stop; $killed++; Add-Log ('Proceso cerrado: PID ' + $c.Data) 'ok' } catch { $failed++; Add-Log ('No se pudo cerrar PID ' + $c.Data) 'warn' } } }
    foreach ($i in $sel.Indices) { $c = $cands[$i]; if ($c.Kind -eq 'file') {
        try { [void](Move-ToQuarantine -File $c.Data -BatchDir $batch); $moved++; Add-Log ('En cuarentena: ' + $c.Data) 'ok' } catch { $failed++; Add-Log ('No se pudo mover: ' + $c.Data + ' (' + $_.Exception.Message + ')') 'warn' } } }
    $res = "Procesos cerrados: $killed`r`nArchivos en cuarentena: $moved`r`nFallos: $failed`r`n`r`nCuarentena: $batch`r`n`r`nSi alguna carpeta sigue oculta, ejecuta ahora el Nivel 1 con «Mostrar ocultos de virus»."
    $ic = 'ok'; if ($failed -gt 0) { $ic = 'warn' }
    [void](Show-Dialog 'Nivel 2 completado' $res 'OK' $ic)
}

# ---------------------------------------------------------------- Nivel 3
function Invoke-DeepClean {
    $msg = "El Nivel 3 hace una limpieza más profunda:`r`n`r`n" +
           "1. Guarda una copia (.reg) de las claves que va a tocar`r`n" +
           "2. Vacía el historial MountPoints2 (Windows lo regenera solo)`r`n" +
           "3. Busca entradas de inicio automático sospechosas (scripts .vbs/.js, wscript, mshta, carpetas Temp) y te deja elegir cuáles quitar`r`n" +
           "4. Revisa Winlogon (Shell/Userinit) y solo te avisa, sin modificarlo`r`n`r`n¿Continuar?"
    if ((Show-Dialog 'Nivel 3 · Limpieza profunda' $msg 'YesNo' 'question' 'Continuar' 'Cancelar') -ne 'Yes') { return }
    $regDir = Join-Path $script:BackupDir ('Registro_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
    [void](New-Item -ItemType Directory -Force -Path $regDir)
    $regExe = Join-Path $env:SystemRoot 'System32\reg.exe'
    $keys = @(
        @{ N = 'MountPoints2'; K = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2'; Req = $true },
        @{ N = 'Run_HKCU'; K = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'; Req = $false },
        @{ N = 'RunOnce_HKCU'; K = 'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'; Req = $false },
        @{ N = 'Run_HKLM'; K = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run'; Req = $false },
        @{ N = 'RunOnce_HKLM'; K = 'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'; Req = $false },
        @{ N = 'Run_HKLM_WOW64'; K = 'HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Req = $false }
    )
    Add-Log 'Nivel 3: copia de seguridad del registro...' 'step'
    $script:Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        foreach ($k in $keys) {
            $file = Join-Path $regDir ($k.N + '.reg')
            [void](Invoke-Tool $regExe ('export "{0}" "{1}" /y' -f $k.K, $file))
            $ok = (Test-Path -LiteralPath $file)
            if ($ok) { Add-Log ('Copia de registro: ' + $file) 'ok' }
            elseif ($k.Req) { [void](Show-Dialog 'Nivel 3' "No se pudo crear la copia de seguridad del registro ($($k.N)). No se ha modificado nada." 'OK' 'error'); return }
        }

        $mp = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2'
        $removed = 0; $mpFailed = 0
        if (Test-Path -LiteralPath $mp) {
            foreach ($sub in @(Get-ChildItem -LiteralPath $mp -ErrorAction SilentlyContinue)) {
                try { Remove-Item -LiteralPath $sub.PSPath -Recurse -Force -ErrorAction Stop; $removed++ } catch { $mpFailed++ }
            }
        }
        Add-Log ('MountPoints2: {0} entradas eliminadas, {1} no se pudieron quitar.' -f $removed, $mpFailed) 'ok'

        $cands = New-Object System.Collections.ArrayList
        $runKeys = @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
        $psNames = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
        foreach ($rk in $runKeys) {
            if (-not (Test-Path -LiteralPath $rk)) { continue }
            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $rk -ErrorAction Stop } catch { continue }
            foreach ($pr in $props.PSObject.Properties) {
                if ($psNames -contains $pr.Name) { continue }
                $val = [string]$pr.Value
                if ($val -match '(?i)\.(vbs|vbe|js|jse|wsf|hta)\b' -or $val -match '(?i)\b(wscript|cscript|mshta)(\.exe)?\b' -or $val -match '(?i)\\(temp|recycler|recycled)\\') {
                    [void]$cands.Add([pscustomobject]@{ Kind = 'reg'; Text = ('Inicio automático «{0}»' -f $pr.Name); Detail = ($rk.Replace('Microsoft\Windows\CurrentVersion\', '') + ' → ' + $val); Checked = $true; Data = @{ Path = $rk; Name = $pr.Name } })
                }
            }
        }
        foreach ($sf in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
            if (-not $sf -or -not (Test-Path -LiteralPath $sf)) { continue }
            foreach ($f in @(Get-ChildItem -LiteralPath $sf -Force -File -ErrorAction SilentlyContinue)) {
                $ext = $f.Extension.ToLowerInvariant()
                if (@('.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta') -contains $ext) {
                    [void]$cands.Add([pscustomobject]@{ Kind = 'file'; Text = ('Script en Inicio: ' + $f.Name); Detail = $f.FullName; Checked = $true; Data = $f.FullName })
                }
                elseif ($ext -eq '.lnk') {
                    try {
                        $sh = New-Object -ComObject WScript.Shell
                        $sc = $sh.CreateShortcut($f.FullName)
                        $v = Test-SuspiciousLnk -Target ([string]$sc.TargetPath) -Arguments ([string]$sc.Arguments)
                        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($sh)
                        if ($v) { [void]$cands.Add([pscustomobject]@{ Kind = 'file'; Text = ('Acceso directo en Inicio: ' + $f.Name); Detail = $v.Reason; Checked = $v.Checked; Data = $f.FullName }) }
                    } catch {}
                }
            }
        }
    } finally { $script:Form.Cursor = [System.Windows.Forms.Cursors]::Default }

    $warnTxt = ''
    try {
        $wl = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
        if ($wl.Shell -and ([string]$wl.Shell).Trim() -ine 'explorer.exe') { $warnTxt += "Winlogon Shell no es el habitual: $($wl.Shell)`r`n" }
        if ($wl.Userinit -and (([string]$wl.Userinit).Trim().TrimEnd(',') -ine ($env:SystemRoot + '\system32\userinit.exe'))) { $warnTxt += "Winlogon Userinit no es el habitual: $($wl.Userinit)`r`n" }
    } catch {}
    if ($warnTxt) { Add-Log ('AVISO (solo informativo): ' + ($warnTxt -replace "`r`n", ' | ')) 'warn' }

    $applied = 0; $failed = 0
    if ($cands.Count -gt 0) {
        $sel = Show-Checklist -Title 'Inicio automático sospechoso' -Message 'Marca lo que quieres quitar. Las entradas del registro ya están guardadas en la copia .reg; los archivos van a cuarentena.' -Items @($cands) -OkText 'Quitar marcados'
        if ($sel.Ok -and $sel.Indices.Count -gt 0) {
            $batch = Join-Path $script:QuarDir (Get-Date -Format 'yyyyMMdd_HHmmss')
            [void](New-Item -ItemType Directory -Force -Path $batch)
            foreach ($i in $sel.Indices) {
                $c = $cands[$i]
                try {
                    if ($c.Kind -eq 'reg') { Remove-ItemProperty -LiteralPath $c.Data.Path -Name $c.Data.Name -Force -ErrorAction Stop }
                    else { [void](Move-ToQuarantine -File $c.Data -BatchDir $batch) }
                    $applied++; Add-Log ('Eliminado: ' + $c.Text) 'ok'
                } catch { $failed++; Add-Log ('No se pudo quitar: ' + $c.Text + ' (' + $_.Exception.Message + ')') 'warn' }
            }
        }
    }
    $res = "MountPoints2: $removed entradas limpiadas`r`nInicio automático sospechoso detectado: $($cands.Count)`r`nQuitado: $applied   Fallos: $failed`r`n`r`nCopia del registro:`r`n$regDir"
    if ($warnTxt) { $res += "`r`n`r`nAVISO (no se ha modificado):`r`n$warnTxt" }
    $ic = 'ok'; if ($failed -gt 0 -or $warnTxt) { $ic = 'warn' }
    [void](Show-Dialog 'Nivel 3 completado' $res 'OK' $ic)
}

# ---------------------------------------------------------------- Restaurar
function Invoke-Restore {
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Title = 'Selecciona la copia de permisos a restaurar'
    $ofd.InitialDirectory = $script:BackupDir
    $ofd.Filter = 'Copias de permisos (*.acl;*.txt)|*.acl;*.txt|Todos los archivos (*.*)|*.*'
    if ($ofd.ShowDialog($script:Form) -ne 'OK') { return }
    $file = $ofd.FileName
    $target = $null; $dir = $null
    $metaFile = [System.IO.Path]::ChangeExtension($file, 'json')
    if (Test-Path -LiteralPath $metaFile) {
        try { $m = Get-Content -LiteralPath $metaFile -Raw | ConvertFrom-Json; $target = [string]$m.Target; $dir = [string]$m.Parent } catch {}
    }
    if (-not $target) {
        $dir = Split-Path -Path $file -Parent
        $target = $dir
        Add-Log 'Copia sin metadatos (formato antiguo): se restaura sobre la carpeta que contiene el archivo.' 'warn'
    }
    $why = Get-ProtectedReason -Path $target
    if ($why) { [void](Show-Dialog 'Restauración bloqueada' $why 'OK' 'error'); return }
    $msg = "Se restaurarán los permisos guardados en:`r`n`r`n    $file`r`n`r`nCarpeta afectada:`r`n`r`n    $target`r`n`r`nEsto devuelve las listas de permisos (DACL) a como estaban cuando se hizo la copia. No restaura el propietario ni los atributos.`r`n`r`n¿Continuar?"
    if ((Show-Dialog 'Confirmar restauración' $msg 'YesNo' 'question' 'Restaurar' 'Cancelar') -ne 'Yes') { return }
    Add-Log "Restaurando permisos desde $file" 'step'
    $p = @{ Target = $target; RestoreDir = $dir; AclFile = $file; KnownPrefixes = @(); ExpectedOwners = @() }
    Start-Worker -Body $script:OpRestore -Params $p -OnDone {
        param($r)
        if (-not $r -or $r.Cancelled) { return }
        if ($r.Ok) { Add-Log 'Permisos restaurados.' 'ok'; [void](Show-Dialog 'Restauración completada' "Los permisos se restauraron correctamente.`r`nElementos procesados: $($r.Processed)" 'OK' 'ok') }
        else { [void](Show-Dialog 'Restauración con errores' ([string]$r.Message + "`r`nFallos: $($r.Failed). Revisa el registro inferior.") 'OK' 'warn') }
    }
}

function Invoke-CardAction([string]$Key) {
    if ($script:Worker) { return }
    switch ($Key) {
        'diag' { Invoke-Diagnose }
        'n1'   { Invoke-Repair }
        'n2'   { Invoke-VirusScan }
        'n3'   { Invoke-DeepClean }
        'rest' { Invoke-Restore }
        'fold' { try { Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f $script:DataDir) } catch {} }
    }
}

# ============================================================================
#  9) VENTANA PRINCIPAL
# ============================================================================
try { [System.Windows.Forms.Application]::SetUnhandledExceptionMode([System.Windows.Forms.UnhandledExceptionMode]::CatchException) } catch {}
[System.Windows.Forms.Application]::add_ThreadException({ param($sender, $ev) Add-Log ('Error: ' + $ev.Exception.Message) 'err' })

function New-AppIcon {
    try {
        $bmp = New-Object System.Drawing.Bitmap 64, 64
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'AntiAliasGridFit'
        $path = [Sygmatch.UI.Gfx]::RoundRect([System.Drawing.RectangleF]::new(2, 2, 60, 60), 15)
        $br = [System.Drawing.Drawing2D.LinearGradientBrush]::new([System.Drawing.Rectangle]::new(0, 0, 64, 64), (RGB 124 58 237), (RGB 236 72 153), [single]45)
        $g.FillPath($br, $path)
        $f = [System.Drawing.Font]::new('Segoe UI', [single]36, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
        $sf = New-Object System.Drawing.StringFormat
        $sf.Alignment = 'Center'; $sf.LineAlignment = 'Center'
        $g.DrawString('S', $f, [System.Drawing.Brushes]::White, [System.Drawing.RectangleF]::new(0, 2, 64, 64), $sf)
        $g.Dispose()
        return [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
    } catch { return $null }
}
$script:AppIcon = New-AppIcon

$ghB64 = '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'
$script:ghStream = [System.IO.MemoryStream]::new([Convert]::FromBase64String($ghB64))
$script:ghBmp = [System.Drawing.Bitmap]::new($script:ghStream)

$fw = 820
$wa = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$fh = [int][math]::Min(740, [math]::Floor($wa.Height / $script:Scale) - 70)
if ($fh -lt 620) { $fh = 620 }

$Form = New-Object System.Windows.Forms.Form
$script:Form = $Form
$Form.Text = ('{0} {1}' -f $script:AppName, $script:AppVer)
$Form.StartPosition = 'CenterScreen'
$Form.FormBorderStyle = 'FixedSingle'
$Form.MaximizeBox = $false
$Form.Font = [System.Drawing.Font]::new('Segoe UI', [single]9)
$Form.ClientSize = SZ $fw $fh
if ($script:AppIcon) { $Form.Icon = $script:AppIcon }
$Form.SuspendLayout()

$script:tip = New-Object System.Windows.Forms.ToolTip
$script:tip.InitialDelay = 400

# ---- cabecera ----
$script:header = New-Object Sygmatch.UI.GradientPanel
$script:header.Location = PT 0 0
$script:header.Size = SZ $fw 80
$script:header.Anchor = 'Top, Left, Right'
$lblTitle = New-Label $script:AppName 22 12 520 36 19 'Bold' 'Segoe UI Semibold'
$lblTitle.ForeColor = [System.Drawing.Color]::White; $lblTitle.BackColor = [System.Drawing.Color]::Transparent
$lblSub = New-Label 'Repara permisos, propietario y herencia de carpetas  ·  Windows 10 / 11' 25 48 560 22 9.5
$lblSub.ForeColor = (RGB 236 232 255); $lblSub.BackColor = [System.Drawing.Color]::Transparent
$script:btnGit = New-Object Sygmatch.UI.MaskButton
$script:btnGit.Mask = $script:ghBmp
$script:btnGit.Location = PT ($fw - 24 - 64 - 14 - 44) 18
$script:btnGit.Size = SZ 44 44
$script:btnGit.BackColor = [System.Drawing.Color]::Transparent
$script:btnGit.Anchor = 'Top, Right'
$script:btnGit.add_Click({ Open-GitHub })
$script:tip.SetToolTip($script:btnGit, 'Abrir github.com/Sygmatch')
$script:swTheme = New-Object Sygmatch.UI.ToggleSwitch
$script:swTheme.SunMoon = $true
$script:swTheme.OffColor = (RGB 99 179 237)
$script:swTheme.OnColor = (RGB 32 36 74)
$script:swTheme.Location = PT ($fw - 24 - 64) 24
$script:swTheme.Size = SZ 64 32
$script:swTheme.BackColor = [System.Drawing.Color]::Transparent
$script:swTheme.Anchor = 'Top, Right'
$script:tip.SetToolTip($script:swTheme, 'Cambiar entre modo claro (sol) y oscuro (luna)')
foreach ($hc in @($lblTitle, $lblSub, $script:btnGit, $script:swTheme)) { $script:header.Controls.Add($hc) }
$Form.Controls.Add($script:header)

# ---- ruta ----
$script:lblPath = New-Label 'CARPETA A REPARAR' 24 94 400 18 8.5 'Bold' 'Segoe UI Semibold'
$Form.Controls.Add($script:lblPath)
$script:pnlPath = New-Object Sygmatch.UI.RoundedPanel
$script:pnlPath.Location = PT 24 114
$script:pnlPath.Size = SZ ($fw - 48 - 132) 42
$script:pnlPath.Anchor = 'Top, Left, Right'
$script:txtPath = New-Object System.Windows.Forms.TextBox
$script:txtPath.BorderStyle = 'None'
$script:txtPath.Font = [System.Drawing.Font]::new('Segoe UI', [single]10.5)
$script:txtPath.Location = PT 14 10
$script:txtPath.Width = (px ($fw - 48 - 132 - 28))
$script:txtPath.Anchor = 'Top, Left, Right'
$script:pnlPath.Controls.Add($script:txtPath)
$Form.Controls.Add($script:pnlPath)
$script:btnBrowse = New-Object Sygmatch.UI.RoundButton
$script:btnBrowse.Text = 'Examinar...'
$script:btnBrowse.Location = PT ($fw - 24 - 122) 114
$script:btnBrowse.Size = SZ 122 42
$script:btnBrowse.FillA = $script:Violet[0]; $script:btnBrowse.FillB = (RGB 236 72 153)
$script:btnBrowse.Anchor = 'Top, Right'
$Form.Controls.Add($script:btnBrowse)

# ---- opciones ----
$script:swRec = New-Object Sygmatch.UI.ToggleSwitch
$script:swRec.Location = PT 24 168; $script:swRec.Size = SZ 44 24
$script:swRec.OnColor = (RGB 34 197 94)
$script:swRec.SetCheckedSilent($true)
$script:lblOpt1 = New-Label 'Incluir subcarpetas' 76 168 200 24 9.5
$script:lblOpt1.TextAlign = 'MiddleLeft'
$script:swHide = New-Object Sygmatch.UI.ToggleSwitch
$script:swHide.Location = PT 300 168; $script:swHide.Size = SZ 44 24
$script:swHide.OnColor = (RGB 245 158 11)
$script:swHide.SetCheckedSilent($true)
$script:lblOpt2 = New-Label 'Mostrar carpetas ocultas por virus (Sistema + Oculto)' 352 168 ($fw - 352 - 24) 24 9.5
$script:lblOpt2.TextAlign = 'MiddleLeft'
foreach ($oc in @($script:swRec, $script:lblOpt1, $script:swHide, $script:lblOpt2)) { $Form.Controls.Add($oc) }
$script:tip.SetToolTip($script:swRec, 'Aplica la operación también a todo el contenido de la carpeta (sin seguir enlaces).')
$script:tip.SetToolTip($script:swHide, 'Solo quita Oculto+Sistema a elementos típicos del virus de acceso directo. Tus archivos ocultos normales no se tocan.')

# ---- tarjetas ----
$script:Cards = @{}
$script:CardHelp = @{
    diag = "DIAGNÓSTICO (solo lectura)`r`n`r`nAnaliza la carpeta SIN modificar nada: propietario, herencia, SID huérfanos (cuentas de una instalación anterior), elementos con permisos ilegibles y elementos ocultos por virus.`r`n`r`nÚsalo primero para saber si realmente necesitas el Nivel 1."
    n1   = "NIVEL 1 · REPARAR CARPETA`r`n`r`nSoluciona los errores de «Acceso denegado» o de permisos tras reinstalar Windows.`r`n`r`n• Guarda una copia de seguridad de los permisos (obligatoria)`r`n• Toma posesión (takeown) y te asigna como propietario`r`n• Restablece permisos y activa la herencia (icacls /reset)`r`n• Da control total a tu usuario, Administradores y SYSTEM`r`n• Quita SID huérfanos reales (S-1-5-21-* que Windows no reconoce y que no son de este equipo)`r`n• Opcional: muestra elementos Sistema+Oculto dejados por virus`r`n`r`nSeguridad: bloquea carpetas del sistema, no sigue enlaces/uniones, no toca la carpeta padre y no borra archivos."
    n2   = "NIVEL 2 · VIRUS DE USB / ACCESO DIRECTO`r`n`r`nBusca accesos directos (.lnk) que lanzan scripts o comandos, scripts ocultos, ejecutables ocultos y autorun.inf, y procesos wscript/cscript sospechosos.`r`n`r`nTú eliges qué neutralizar. Los archivos NO se borran: van a cuarentena (carpeta Sygmatch\Quarantine) con un registro de su ubicación original."
    n3   = "NIVEL 3 · LIMPIEZA PROFUNDA`r`n`r`n• Guarda copias .reg de las claves que toca`r`n• Vacía MountPoints2 (historial de unidades; Windows lo regenera)`r`n• Detecta entradas de inicio automático sospechosas (scripts, wscript, mshta, Temp) y te deja elegir`r`n• Revisa Winlogon Shell/Userinit y solo te avisa si no son los habituales"
    rest = "RESTAURAR COPIA`r`n`r`nElige una copia de permisos guardada por el Nivel 1 y devuelve las listas de permisos (DACL) a como estaban. No restaura propietario ni atributos."
    fold = "COPIAS Y CUARENTENA`r`n`r`nAbre la carpeta %LOCALAPPDATA%\Sygmatch con:`r`n• Backups: copias de permisos y del registro`r`n• Quarantine: archivos neutralizados (recuperables)`r`n• Logs: registro diario de lo que hace la herramienta"
}
$cardDefs = @(
    @{ Key = 'diag'; Title = 'Diagnóstico (solo lectura)'; Desc = 'Analiza permisos, propietario, SID huérfanos y ocultos sin modificar nada.'; Glyph = [string][char]0xE721; Badge = '0' },
    @{ Key = 'n1';   Title = 'Nivel 1 · Reparar carpeta'; Desc = 'Propiedad, permisos y herencia, con copia de seguridad previa.'; Glyph = [string][char]0xE785; Badge = '1' },
    @{ Key = 'n2';   Title = 'Nivel 2 · Virus de USB'; Desc = 'Detecta accesos directos y scripts falsos y los envía a cuarentena.'; Glyph = [string][char]0xE7BA; Badge = '2' },
    @{ Key = 'n3';   Title = 'Nivel 3 · Limpieza profunda'; Desc = 'MountPoints2 e inicio automático sospechoso, con copia del registro.'; Glyph = [string][char]0xE713; Badge = '3' },
    @{ Key = 'rest'; Title = 'Restaurar copia'; Desc = 'Devuelve los permisos a como estaban desde una copia guardada.'; Glyph = [string][char]0xE777; Badge = 'R' },
    @{ Key = 'fold'; Title = 'Copias y cuarentena'; Desc = 'Abre la carpeta con copias de seguridad, cuarentena y registros.'; Glyph = [string][char]0xE838; Badge = 'F' }
)
$cw = [int](($fw - 48 - 12) / 2)
for ($ci = 0; $ci -lt $cardDefs.Count; $ci++) {
    $cd = $cardDefs[$ci]
    $ccol = $ci % 2
    $crow = [int][math]::Floor($ci / 2)
    $card = New-Object Sygmatch.UI.ActionCard
    $card.Title = $cd.Title; $card.Desc = $cd.Desc; $card.Glyph = $cd.Glyph; $card.Badge = $cd.Badge
    $card.AccentA = $script:Accent[$cd.Key][0]; $card.AccentB = $script:Accent[$cd.Key][1]
    $card.Location = PT (24 + $ccol * ($cw + 12)) (204 + $crow * 84)
    $card.Size = SZ $cw 76
    $card.Tag = $cd.Key
    $card.add_Click({ param($sender, $ev) Invoke-CardAction ([string]$sender.Tag) })
    $card.add_InfoClick({ param($sender, $ev) [void](Show-Dialog $sender.Title $script:CardHelp[[string]$sender.Tag] 'OK' 'info') })
    $script:tip.SetToolTip($card, $cd.Desc)
    $script:Cards[$cd.Key] = $card
    $Form.Controls.Add($card)
}

# ---- progreso ----
$script:progress = New-Object Sygmatch.UI.GradientProgress
$script:progress.Location = PT 24 462; $script:progress.Size = SZ ($fw - 48) 8
$script:progress.Anchor = 'Top, Left, Right'
$script:progress.ColorA = $script:Violet[0]; $script:progress.ColorB = (RGB 236 72 153)
$Form.Controls.Add($script:progress)
$script:lblStatus = New-Label 'Listo' 24 474 ($fw - 48 - 110) 22 9
$script:lblStatus.TextAlign = 'MiddleLeft'
$Form.Controls.Add($script:lblStatus)
$script:btnCancel = New-Object Sygmatch.UI.RoundButton
$script:btnCancel.Text = 'Cancelar'
$script:btnCancel.Location = PT ($fw - 24 - 100) 472
$script:btnCancel.Size = SZ 100 26
$script:btnCancel.FillA = (RGB 251 113 133); $script:btnCancel.FillB = (RGB 225 29 72)
$script:btnCancel.Anchor = 'Top, Right'
$script:btnCancel.Visible = $false
$Form.Controls.Add($script:btnCancel)

# ---- registro ----
$script:pnlLog = New-Object Sygmatch.UI.RoundedPanel
$script:pnlLog.Location = PT 24 504
$script:pnlLog.Size = SZ ($fw - 48) ($fh - 504 - 46)
$script:pnlLog.Anchor = 'Top, Bottom, Left, Right'
$script:pnlLog.Radius = 12
$script:txtLog = New-Object System.Windows.Forms.RichTextBox
$script:txtLog.ReadOnly = $true
$script:txtLog.BorderStyle = 'None'
$script:txtLog.Font = [System.Drawing.Font]::new('Consolas', [single]9)
$script:txtLog.DetectUrls = $false
$script:txtLog.HideSelection = $false
$script:txtLog.Location = PT 10 8
$script:txtLog.Size = [System.Drawing.Size]::new($script:pnlLog.Width - (px 20), $script:pnlLog.Height - (px 16))
$script:txtLog.Anchor = 'Top, Bottom, Left, Right'
$script:pnlLog.Controls.Add($script:txtLog)
$Form.Controls.Add($script:pnlLog)

# ---- pie ----
$script:lblFooter = New-Label ('v{0}  ·  Windows 10 / 11  ·  Modo administrador activo' -f $script:AppVer) 24 ($fh - 34) 420 22 8.5
$script:lblFooter.TextAlign = 'MiddleLeft'; $script:lblFooter.Anchor = 'Bottom, Left'
$Form.Controls.Add($script:lblFooter)
$script:btnClear = New-Object Sygmatch.UI.RoundButton
$script:btnClear.Text = 'Limpiar'; $script:btnClear.Font = [System.Drawing.Font]::new('Segoe UI Semibold', [single]8.5)
$script:btnClear.Location = PT ($fw - 24 - 84) ($fh - 38); $script:btnClear.Size = SZ 84 28; $script:btnClear.Anchor = 'Bottom, Right'
$script:btnCopy = New-Object Sygmatch.UI.RoundButton
$script:btnCopy.Text = 'Copiar registro'; $script:btnCopy.Font = [System.Drawing.Font]::new('Segoe UI Semibold', [single]8.5)
$script:btnCopy.Location = PT ($fw - 24 - 84 - 8 - 128) ($fh - 38); $script:btnCopy.Size = SZ 128 28; $script:btnCopy.Anchor = 'Bottom, Right'
$Form.Controls.Add($script:btnClear); $Form.Controls.Add($script:btnCopy)

# ============================================================================
#  10) TEMA, EVENTOS Y ARRANQUE
# ============================================================================
function Apply-Theme {
    $t = $script:Theme
    $dark = [bool]$t.IsDark
    $script:Form.BackColor = $t.Bg; $script:Form.ForeColor = $t.Text
    foreach ($c in @($script:lblPath, $script:lblStatus, $script:lblFooter)) { $c.BackColor = $t.Bg; $c.ForeColor = $t.Sub }
    foreach ($c in @($script:lblOpt1, $script:lblOpt2)) { $c.BackColor = $t.Bg; $c.ForeColor = $t.Text }
    $script:pnlPath.BackColor = $t.Bg; $script:pnlPath.Fill = $t.Input; $script:pnlPath.Border = $t.Border; $script:pnlPath.Invalidate()
    $script:txtPath.BackColor = $t.Input; $script:txtPath.ForeColor = $t.Text
    $script:pnlLog.BackColor = $t.Bg; $script:pnlLog.Fill = $t.LogBg; $script:pnlLog.Border = $t.Border; $script:pnlLog.Invalidate()
    $script:txtLog.BackColor = $t.LogBg; $script:txtLog.ForeColor = $t.LogText
    foreach ($sw in @($script:swRec, $script:swHide)) { $sw.BackColor = $t.Bg; $sw.OffColor = $t.SwOff; $sw.Invalidate() }
    foreach ($k in $script:Cards.Keys) {
        $cc = $script:Cards[$k]
        $cc.BackColor = $t.Bg; $cc.CardBack = $t.Surface; $cc.CardBorder = $t.Border; $cc.TitleColor = $t.Text; $cc.DescColor = $t.Sub
        $cc.Invalidate()
    }
    $script:progress.BackColor = $t.Bg; $script:progress.Track = $t.SwOff; $script:progress.Invalidate()
    foreach ($b in @($script:btnBrowse, $script:btnCancel)) { $b.BackColor = $t.Bg; $b.Invalidate() }
    Set-SecondaryButton $script:btnClear
    Set-SecondaryButton $script:btnCopy
    [Sygmatch.UI.Native]::SetControlTheme($script:txtLog.Handle, $dark)
    if ($script:Form.IsHandleCreated) { [Sygmatch.UI.Native]::SetDarkTitleBar($script:Form.Handle, $dark) }
    Rebuild-Log
}

$script:pollTimer = New-Object System.Windows.Forms.Timer
$script:pollTimer.Interval = 120
$script:pollTimer.add_Tick({ Poll-Worker })

$script:swTheme.SetCheckedSilent([bool]$script:Theme.IsDark)
$script:swTheme.add_CheckedChanged({
    $dark = [bool]$script:swTheme.Checked
    if ($dark) { $script:Theme = $script:Themes['dark'] } else { $script:Theme = $script:Themes['light'] }
    if ($dark) { Set-Setting 'theme' 'dark' } else { Set-Setting 'theme' 'light' }
    Apply-Theme
})

$script:btnBrowse.add_Click({
    $initial = [string]$script:txtPath.Text
    $sel = $null
    try { $sel = [Sygmatch.UI.Native]::PickFolder($script:Form.Handle, 'Selecciona la carpeta a reparar', $initial) }
    catch {
        $fb = New-Object System.Windows.Forms.FolderBrowserDialog
        $fb.Description = 'Selecciona la carpeta a reparar'
        if ($initial -and (Test-Path -LiteralPath $initial)) { $fb.SelectedPath = $initial }
        if ($fb.ShowDialog($script:Form) -eq 'OK') { $sel = $fb.SelectedPath }
    }
    if ($sel) { $script:txtPath.Text = $sel }
})

$script:btnCancel.add_Click({
    if ($script:Worker) {
        $script:Worker.State.Cancel = $true
        $script:btnCancel.Enabled = $false
        Add-Log 'Cancelando... (se detendrá al terminar el paso actual)' 'warn'
    }
})
$script:btnCopy.add_Click({ try { if ($script:txtLog.TextLength -gt 0) { [System.Windows.Forms.Clipboard]::SetText($script:txtLog.Text); Set-Progress 0 'Registro copiado al portapapeles' } } catch {} })
$script:btnClear.add_Click({ $script:LogLines.Clear(); $script:txtLog.Clear() })

$Form.add_FormClosing({
    param($sender, $ev)
    if ($script:Worker) {
        $r = Show-Dialog 'Operación en curso' 'Hay una operación en curso. ¿Quieres cancelarla y salir?' 'YesNo' 'warn' 'Cancelar y salir' 'Seguir'
        if ($r -ne 'Yes') { $ev.Cancel = $true; return }
        $script:Worker.State.Cancel = $true
        $deadline = (Get-Date).AddSeconds(4)
        while ($script:Worker -and -not $script:Worker.Handle.IsCompleted -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 100
            [System.Windows.Forms.Application]::DoEvents()
        }
    }
})

$startPath = $Path
if (-not $startPath) { $startPath = $PSScriptRoot }
if (-not $startPath) { $startPath = (Get-Location).Path }
$script:txtPath.Text = $startPath

$Form.add_Shown({
    Apply-Theme
    Add-Log ('{0} {1} listo. Windows {2}.' -f $script:AppName, $script:AppVer, [Environment]::OSVersion.Version) 'ok'
    Add-Log 'Consejo: empieza por «Diagnóstico» para ver qué le pasa a la carpeta sin modificar nada.' 'info'
    $why0 = Get-ProtectedReason -Path ([string]$script:txtPath.Text)
    if ($why0) { Add-Log ('La carpeta inicial no es reparable: ' + $why0 + ' Pulsa «Examinar» para elegir otra.') 'warn' }
    Add-Log ('Copias de seguridad en: ' + $script:BackupDir) 'info'
})

Apply-Theme
$Form.ResumeLayout($true)
[void]$Form.ShowDialog()

try { $script:pollTimer.Stop(); $script:pollTimer.Dispose() } catch {}
