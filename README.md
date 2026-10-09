# Sygmatch Folder Repair 4.0

> Solución definitiva para el error "No tiene permisos" / "Acceso denegado" en carpetas después de reinstalar Windows.

Sygmatch Folder Repair es una herramienta gráfica para Windows 10/11 que repara de forma segura carpetas bloqueadas por SID huérfanos, propietarios antiguos, herencia rota y restos del virus de acceso directo en USB.

### 🚀 ¿Qué hace?

El script cuenta con 4 modos de operación:

**1. Diagnóstico (Solo lectura)**
Analiza la carpeta sin modificar nada. Detecta:
- SID huérfanos (cuentas de instalaciones anteriores de Windows)
- Propietarios incorrectos o huérfanos
- Permisos ilegibles o denegados
- Enlaces simbólicos/junctions peligrosos
- Archivos con atributos de sistema+oculto (típico de virus USB)

**2. Reparación Completa (Recomendado)**
- Toma posesión de la carpeta (takeown)
- Elimina solo SID huérfanos reales `S-1-5-21-*` que Windows no puede resolver
- Restaura la herencia y otorga acceso total a Administradores, SYSTEM y al usuario actual
- Opcionalmente desoculta archivos (virus de acceso directo)
- Prueba de escritura final para confirmar el éxito

**3. Desocultar Archivos**
Quita los atributos Sistema+Oculto a todos los archivos dentro de la carpeta. Ideal para USB infectados.

**4. Restaurar Copia de Seguridad**
Restaura los permisos originales desde un backup automático.

### 🛡️ Sistema de Seguridad (Anti-Brick)

Esta herramienta está diseñada para no romper Windows:

* **Elevación UAC automática:** Pide permisos de administrador y fuerza Windows PowerShell 5.1 en STA.
* **Bloqueo de rutas críticas:** No permite reparar `C:\`, `C:\Windows`, `Program Files`, `System Volume Information`, `$Recycle.Bin`, perfiles completos de usuario (`C:\Users\Nombre`) ni `AppData`.
* **No sigue Symlinks:** No sigue enlaces simbólicos ni junctions. Si encuentra uno, aborta para evitar bucles o borrar el sistema.
* **Backup siempre primero:** Guarda la ACL completa en `%AppData%\Sygmatch\FolderRepair\Backups` ANTES de tocar nada.
* **Cuarentena, no borrado:** Los archivos sospechosos (.lnk maliciosos, virus) se mueven a `Quarantine` y son recuperables.
* **Limpieza inteligente de SIDs:** Solo borra SIDs que son huérfanos reales y no pertenecen a tu equipo ni a tu dominio (evita borrar cuentas de dominio cuando estás offline).

### ✨ Interfaz

* GUI moderna hecha en WinForms + C# custom (RoundedPanel, RoundButton, ActionCard)
* Tema claro/oscuro automático (detecta el tema de Windows) y persistente
* DPI-Aware, con barra de progreso, registro en tiempo real y log diario
* Selector de carpeta nativo (IFileDialog) y operaciones en segundo plano cancelables

### 📋 Requisitos

* Windows 10 / Windows 11
* Windows PowerShell 5.1
* Permisos de Administrador

### ▶️ Uso

1. Clic sobre `Sygmatch_Folder_Repair V4.0.exe` 
2. Acepta el UAC
3. Selecciona la carpeta bloqueada
4. Empieza siempre por **Diagnóstico**
5. Luego ejecuta **Reparación Completa**

### 📁 Estructura de archivos
