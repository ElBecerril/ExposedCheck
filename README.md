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

## Funcionalidades

- **Modo interactivo** - Menu guiado paso a paso, no requiere conocimiento tecnico
- **Verificacion de email** - Detecta en que brechas aparece tu correo, que datos fueron expuestos y el nivel de riesgo
- **Verificacion de username** - Busca tu nombre de usuario en bases de datos de brechas e infostealers
- **Verificacion de telefono** - Soporte opcional via BreachDirectory (RapidAPI)
- **Verificacion de password** - Comprueba si un password fue filtrado usando k-anonymity (nunca se envia el password completo)
- **Busqueda inversa de imagenes** - Sube tus fotos a Yandex, Google Lens y TinEye para detectar si alguien las usa sin autorizacion
- **Busqueda de perfiles duplicados** - Escanea 25+ plataformas para encontrar cuentas con tu username
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

## Instalacion

```bash
git clone https://github.com/ElBecerril/ExposedCheck.git
cd ExposedCheck
pip install -r requirements.txt
```

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
```

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

  checkers/                     # Orquestadores
    email_checker.py            # Verificacion de email
    username_checker.py         # Verificacion de username
    phone_checker.py            # Verificacion de telefono
    password_checker.py         # Verificacion de password
    image_checker.py            # Busqueda inversa de imagenes
    profile_checker.py          # Busqueda de perfiles duplicados

  reporting/                    # Reportes
    console_report.py           # Tablas y paneles con Rich
    remediation.py              # Guia GDPR, links, plantillas
```

## Dependencias

- [requests](https://pypi.org/project/requests/) - Cliente HTTP
- [rich](https://pypi.org/project/rich/) - Interfaz visual en terminal
- [python-dotenv](https://pypi.org/project/python-dotenv/) - Carga de variables de entorno

## Privacidad

- Los passwords se verifican usando **k-anonymity**: solo se envian los primeros caracteres del hash, nunca el password completo
- Las imagenes se suben a un hosting temporal que **expira en 1 hora**
- No se almacena ninguna informacion en servidores externos
- Todo se ejecuta localmente en tu maquina
