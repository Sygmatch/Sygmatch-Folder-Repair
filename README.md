# Sygmatch Folder Repair 4.0

> Solución definitiva para el error "No tiene permisos" / "Acceso denegado" en carpetas después de reinstalar Windows.

**Sygmatch Folder Repair** es una herramienta gráfica portable para Windows 10/11 que repara de forma segura carpetas bloqueadas por SID huérfanos, propietarios antiguos, herencia rota y restos del virus de acceso directo en USB. Versión compilada lista para usar, sin necesidad de PowerShell.

[[Windows](https://img.shields.io/badge/Windows-10%2F11-0078D6?style=flat-square&logo=windows)](https://github.com/Sygmatch)
[[PowerShell](https://img.shields.io/badge/PowerShell-5.1-5391FE?style=flat-square&logo=powershell)](https://github.com/Sygmatch)
[[License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

---

## 🚀 ¿Qué hace?

El programa cuenta con 4 modos de operación principales:

### 1. Diagnóstico (Solo lectura - Recomendado para empezar)
Analiza la carpeta sin modificar nada. Detecta:
- SID huérfanos `S-1-5-21-*` (cuentas de instalaciones anteriores de Windows)
- Propietarios incorrectos o huérfanos
- Permisos ilegibles, denegados o con herencia rota
- Enlaces simbólicos / Junctions peligrosos dentro de la carpeta
- Archivos con atributos Sistema+Oculto (típico de virus de acceso directo en USB)
- Contadores de carpetas, archivos y elementos ilegibles

### 2. Reparación Completa
El modo principal. Realiza todo el proceso de forma segura:
- Toma posesión de la carpeta con `takeown.exe`
- Elimina **solo** SID huérfanos reales que Windows no puede resolver
- Restaura la herencia y otorga Acceso Total a `Administradores`, `SYSTEM` y al usuario actual con `icacls.exe`
- Desoculta archivos si se activa la opción
- Realiza una prueba de escritura final para confirmar que la carpeta ya es usable

### 3. Desocultar Archivos
Quita los atributos Sistema + Oculto a todos los archivos dentro de la carpeta. Ideal para USB infectados por el virus que oculta tus archivos y crea accesos directos `.lnk`.

### 4. Restaurar Copia de Seguridad
Restaura los permisos originales desde un backup automático creado antes de cualquier reparación.

## 🛡️ Sistema de Seguridad (Anti-Brick)

Esta herramienta está diseñada para **NO romper Windows**:

* **Elevación UAC automática:** Pide permisos de administrador automáticamente. Si no se acepta, no continúa.
* **Bloqueo de rutas críticas:** No permite reparar:
  - Raíces de unidad `C:\`, `D:\`, etc.
  - `C:\Windows`, `Program Files`, `Program Files (x86)`, `ProgramData`
  - `System Volume Information`, `$Recycle.Bin`, `$Windows.~BT`, `Recovery`, `PerfLogs`
  - Carpeta `Users` completa o perfiles completos `C:\Users\Nombre`
  - `AppData` y cualquier subcarpeta (contiene datos internos de programas)
  - Rutas de red UNC `\\servidor\carpeta`
  - La propia carpeta si es un Symlink o Junction
* **No sigue Symlinks:** Recorre las carpetas sin seguir enlaces simbólicos. Si encuentra un `DirLink` dentro, lo omite y te avisa.
* **Backup siempre primero:** Guarda la ACL completa con `icacls /save` en `%LOCALAPPDATA%\Sygmatch\Backups` ANTES de tocar nada.
* **Cuarentena, no borrado:** Los archivos sospechosos (accesos directos maliciosos) se mueven a `%LOCALAPPDATA%\Sygmatch\Quarantine` y son 100% recuperables.
* **Limpieza inteligente de SIDs:** Solo borra SIDs que cumplen 3 condiciones: es `S-1-5-21-*`, Windows no lo puede traducir a nombre, y su prefijo de dominio NO pertenece a tu equipo actual ni a tu dominio. Así evita borrar cuentas de dominio cuando estás sin conexión.
* **Operaciones cancelables y en segundo plano:** Todo el trabajo pesado corre en un `Runspace` separado para no congelar la UI.

## ✨ Interfaz

* GUI moderna hecha en WinForms + C# embebido (controles custom: `RoundedPanel`, `RoundButton`, `ActionCard`, `ToggleSwitch`, `Progress`)
* Tema claro/oscuro automático (detecta `AppsUseLightTheme` de Windows) y persistente en `settings.json`
* DPI-Aware, barra de progreso real, registro en tiempo real con colores y log diario
* Selector de carpeta nativo moderno `IFileOpenDialog` (no el viejo `FolderBrowserDialog`)
* Totalmente portable, no requiere instalación

## 📋 Requisitos

* Windows 10 / Windows 11 (x64)
* Permisos de Administrador
* No requiere PowerShell instalado (el .exe ya está compilado con PS 5.1 STA)

## ▶️ Modo de Uso

1. Descarga `Sygmatch_Folder_Repair V4.0.exe` desde **Releases**
2. Clic derecho > **Ejecutar como administrador** (si no lo haces, el programa te lo pedirá automáticamente)
3. Pulsa **Examinar** y selecciona la carpeta bloqueada
4. **Empieza siempre por Diagnóstico** para ver qué le pasa a la carpeta sin modificar nada
5. Si el diagnóstico confirma SIDs huérfanos o acceso denegado, ejecuta **Reparación Completa**
6. Revisa el registro inferior. Si todo sale OK, la carpeta ya será accesible

> **Tip:** Si tu USB fue infectado y ves solo accesos directos, usa el modo **Desocultar Archivos**.

## 📁 Ubicación de Archivos de Sygmatch

Todos los datos se guardan de forma segura en tu carpeta local, no en la carpeta del programa:

```
%LOCALAPPDATA%\Sygmatch\
├── Backups\        -> Copias de ACL con formato: 20250101_123000_MiCarpeta.txt
├── Quarantine\     -> Archivos .lnk sospechosos movidos (recuperables)
├── Logs\           -> Log diario: 20250101.log
└── settings.json   -> Guarda tu preferencia de tema (dark/light)
```
Ruta completa real: `C:\Users\TuUsuario\AppData\Local\Sygmatch`

Para abrirla rápido: presiona `Win + R`, escribe `%LOCALAPPDATA%\Sygmatch` y Enter.

## 🔧 Compilación

El .exe fue compilado desde `Sygmatch_Folder_Repair.ps1` con PS2EXE / Win-PS2EXE para garantizar compatibilidad con Windows PowerShell 5.1 en modo STA y con icono y manifiesto de administrador.

Si quieres compilarlo tú mismo:
```powershell
Invoke-PS2EXE -InputFile .\Sygmatch_Folder_Repair.ps1 -OutputFile "Sygmatch_Folder_Repair V4.0.exe" -STA -NoConsole -RequireAdmin -IconFile icon.ico -Title "Sygmatch Folder Repair"
```

## ⚖️ Licencia y Autor

Creado por **Sygmatch** - https://github.com/Sygmatch

Software gratuito para uso personal y profesional. Se proporciona "tal cual", sin garantías. Úsalo bajo tu propia responsabilidad. Siempre se crea un backup, pero se recomienda tener respaldo de datos importantes.

---
Si te sirvió, deja una ⭐ en el repo y compártelo.
