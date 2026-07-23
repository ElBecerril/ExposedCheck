# ExposedCheck

```
    ______                                __________              __
   / ____/  ______  ____  ________  ____/ / ____/ /_  ___  _____/ /__
  / __/ | |/_/ __ \/ __ \/ ___/ _ \/ __  / /   / __ \/ _ \/ ___/ //_/
 / /____>  </ /_/ / /_/ (__  )  __/ /_/ / /___/ / / /  __/ /__/ ,<
/_____/_/|_/ .___/\____/____/\___/\__,_/\____/_/ /_/\___/\___/_/|_|
          /_/
                                                        by El_Becerril
```

Herramienta CLI para verificar si tus datos personales aparecen en brechas de seguridad conocidas. Consulta multiples APIs gratuitas, detecta perfiles duplicados, realiza busqueda inversa de imagenes y genera guias de remediacion.

## Uso responsable

ExposedCheck esta pensado para que verifiques **tu propia** exposicion de datos (o la de alguien que te dio autorizacion expresa), no para investigar o perfilar a terceros sin su consentimiento. En particular, el modo `--fingerprint` consulta endpoints internos de signup/recuperacion de varios servicios (Spotify, WordPress, Duolingo, GitHub, etc.) para saber si un email esta registrado ahi; usarlo contra emails ajenos sin autorizacion puede constituir doxing/stalking y violar los terminos de servicio de esas plataformas. La busqueda inversa de imagenes tambien sube el archivo a un host publico temporal (litterbox.catbox.moe, expira en 1h) — solo sube fotos que tengas derecho a compartir.

## Funcionalidades

- **Modo interactivo** - Menu guiado paso a paso, no requiere conocimiento tecnico
- **Verificacion de email** - Detecta en que brechas aparece tu correo, que datos fueron expuestos y el nivel de riesgo
- **Verificacion de username** - Busca tu nombre de usuario en bases de datos de brechas e infostealers
- **Verificacion de telefono** - Soporte opcional via BreachDirectory (RapidAPI)
- **Verificacion de password** - Comprueba si un password fue filtrado usando k-anonymity (nunca se envia el password completo)
- **Busqueda inversa de imagenes** - Sube tus fotos a Yandex, Google Lens y TinEye para detectar si alguien las usa sin autorizacion
- **Busqueda de perfiles duplicados** - Escanea 25+ plataformas para encontrar cuentas con tu username
- **Busqueda de email por username** - Extraccion OSINT desde GitHub/GitLab + verificacion en brechas
- **Fingerprint de email (OSINT completo)** - Analisis integral: dominio (MX/proveedor), Gravatar, brechas, infostealers, presencia en GitHub/GitLab, servicios registrados y perfiles asociados al username derivado
- **Reporte con nivel de riesgo** - Tablas con colores, alertas de infostealers y resumen visual
- **Guia de remediacion** - Pasos de accion, links de eliminacion de cuentas, plantilla GDPR Art. 17 y consejos anti-SIM swapping

## APIs utilizadas

| API | Email | Username | Password | API Key |
|-----|:-----:|:--------:|:--------:|:-------:|
| XposedOrNot | Si | - | Si | No |
| HIBP Pwned Passwords | - | - | Si | No |
| LeakCheck | Si | Si | - | No |
| Hudson Rock | Si | Si | - | No |
| BreachDirectory | - | - | - | Opcional (telefono) |
| GitHub API | Si (busqueda) | Si (commits) | - | No |
| GitLab API | - | Si (perfil) | - | No |
| Gravatar | Si (perfil) | - | - | No |

## Instalacion

```bash
git clone https://github.com/ElBecerril/ExposedCheck.git
cd ExposedCheck
./exposedcheck
```

El lanzador `./exposedcheck` (Linux/macOS) prepara todo la primera vez: crea el entorno
virtual `.venv`, instala las dependencias y genera el `.env`. Despues solo reinstala si
`requirements.txt` cambia. Acepta los mismos flags que `main.py`:

```bash
./exposedcheck -e correo@ejemplo.com
```

No activa el venv en tu shell: ejecuta con `.venv/bin/python`, asi que el entorno vive
solo mientras corre el programa.

<details>
<summary>Instalacion manual (o Windows)</summary>

```bash
python -m venv .venv
source .venv/bin/activate    # fish: source .venv/bin/activate.fish
                             # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```
</details>

Para verificacion de telefono (opcional), crea un archivo `.env` basado en `.env.example`:

```bash
cp .env.example .env
# Edita .env con tu API key de RapidAPI
```

## Uso

### Modo interactivo (recomendado)

Ejecuta sin argumentos y sigue el menu:

```bash
python main.py
```

```
  1 - Verificar email
  2 - Verificar nombre de usuario
  3 - Verificar numero de telefono
  4 - Verificar si un password esta filtrado
  5 - Busqueda inversa de imagenes (detectar uso de tus fotos)
  6 - Buscar perfiles duplicados en redes sociales
  7 - Verificacion completa (email + username + password)
  8 - Buscar email asociado a un username
  9 - Fingerprint de email (OSINT completo)
  0 - Salir
```

### Modo CLI (avanzado)

```bash
# Verificar email
python main.py -e correo@ejemplo.com

# Email + username
python main.py -e correo@ejemplo.com -u mi_usuario

# Email + verificar password (se pide de forma segura)
python main.py -e correo@ejemplo.com --check-password

# Todo: email + username + telefono
python main.py -e correo@ejemplo.com -u mi_usuario -t +521234567890

# Busqueda inversa de imagenes (abre pestanas en el navegador)
python main.py --reverse-image ./mis_fotos/
python main.py --reverse-image foto.jpg
python main.py --reverse-image https://url-de-imagen.jpg

# Busqueda inversa sin abrir navegador (solo muestra URLs completas)
python main.py --reverse-image ./mis_fotos/ --no-open

# Buscar perfiles duplicados en 25+ plataformas
python main.py --search-profiles mi_usuario

# Buscar email asociado a un username (OSINT + brechas)
python main.py --find-email mi_usuario

# Fingerprint OSINT completo de un email
python main.py --fingerprint correo@ejemplo.com

# Guardar los resultados en JSON y/o HTML (ademas de mostrarlos en consola)
python main.py -e correo@ejemplo.com -u mi_usuario --json resultado.json
python main.py --fingerprint correo@ejemplo.com --html reporte.html
```

`--json` y `--html` se pueden combinar y sirven para cualquier check. El
JSON incluye metadata (`tool`, `version`, `generated_at`) y un bloque
`results` por tipo de check. Los reportes de brechas traen el nivel de
riesgo calculado (`overall_risk`), incluido `"desconocido"` cuando ninguna
fuente respondio (no se confunde "sin brechas" con "no se pudo consultar").
El HTML es una pagina autocontenida (sin recursos externos) con el mismo
contenido y un badge de riesgo por seccion.

## Ejemplo de salida

```
    ______                                __________              __
   / ____/  ______  ____  ________  ____/ / ____/ /_  ___  _____/ /__
  / __/ | |/_/ __ \/ __ \/ ___/ _ \/ __  / /   / __ \/ _ \/ ___/ //_/
 / /____>  </ /_/ / /_/ (__  )  __/ /_/ / /___/ / / /  __/ /__/ ,<
/_____/_/|_/ .___/\____/____/\___/\__,_/\____/_/ /_/\___/\___/_/|_|
          /_/

  Verificador de Datos Filtrados en Brechas de Seguridad
  by El_Becerril

╔═════════════════════════ Resultado de Verificacion ═════════════════════════╗
║  Email: correo@ejemplo.com                                                  ║
║  Brechas encontradas: 8                                                     ║
║  !! RIESGO ALTO                                                             ║
╚═════════════════════════════════════════════════════════════════════════════╝

┌──────────────────┬───────┬──────────────────────────┬──────────┬─────────────┐
│ Brecha           │ Fecha │ Datos Expuestos          │  Riesgo  │ Fuente      │
├──────────────────┼───────┼──────────────────────────┼──────────┼─────────────┤
│ Naz.API          │ 2023  │ Email, Passwords         │ CRITICO  │ XposedOrNot │
│ Twitter-Scraped  │ 2021  │ Email, Telefono, Nombres │ CRITICO  │ XposedOrNot │
│ Adobe            │ 2013  │ Usernames, Passwords     │ CRITICO  │ XposedOrNot │
└──────────────────┴───────┴──────────────────────────┴──────────┴─────────────┘
```

## Estructura del proyecto

```
ExposedCheck/
  main.py                       # Punto de entrada (interactivo + CLI)
  config.py                     # Configuracion y constantes
  models.py                     # Modelos de datos
  requirements.txt              # Dependencias
  .env.example                  # Plantilla para API keys opcionales

  apis/                         # Proveedores de API
    base.py                     # Clase base abstracta
    xposedornot.py              # Email + password (SHA3 k-anonymity)
    hibp.py                     # Pwned Passwords (SHA-1 k-anonymity)
    leakcheck.py                # Email + username
    hudsonrock.py               # Infostealers/malware
    github_osint.py             # Extraccion de emails desde GitHub
    gitlab_osint.py             # Extraccion de emails desde GitLab
    email_generator.py          # Generacion y verificacion de candidatos

  checkers/                     # Orquestadores
    email_checker.py            # Verificacion de email
    username_checker.py         # Verificacion de username
    phone_checker.py            # Verificacion de telefono
    password_checker.py         # Verificacion de password
    image_checker.py            # Busqueda inversa de imagenes
    profile_checker.py          # Busqueda de perfiles duplicados
    email_finder.py             # Busqueda de email por username
    email_fingerprint.py        # Fingerprint OSINT completo de email

  reporting/                    # Reportes
    console_report.py           # Tablas y paneles con Rich
    remediation.py              # Guia GDPR, links, plantillas
```

## Dependencias

- [requests](https://pypi.org/project/requests/) - Cliente HTTP
- [rich](https://pypi.org/project/rich/) - Interfaz visual en terminal
- [python-dotenv](https://pypi.org/project/python-dotenv/) - Carga de variables de entorno
- [dnspython](https://pypi.org/project/dnspython/) - Resolucion MX para fingerprint (opcional, fallback a socket)

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

Cubren la logica de cobertura de fuentes (distinguir "sin brechas" de "no
se pudo consultar") y el parsing de respuestas de los password providers.
No tocan la red (los providers se mockean).

## Privacidad

- Los passwords se verifican usando **k-anonymity**: solo se envian los primeros caracteres del hash, nunca el password completo
- Las imagenes se suben a un hosting temporal que **expira en 1 hora**
- No se almacena ninguna informacion en servidores externos
- Todo se ejecuta localmente en tu maquina

## Licencia

MIT
