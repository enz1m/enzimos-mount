# enzimos-mount: mensajes que ven las personas (errores, nombres y notificaciones).

## Nombres y detalles

label-folder-on-host = { $folder } en { $host }
label-protocol-on-host = { $protocol } en { $host }
label-phone = Teléfono
label-camera = Cámara
label-ios-detail = iPhone o iPad
label-volume = Volumen
label-sized-volume = Volumen de { $size }
label-disk-image = Imagen de disco
label-optical-drive = Unidad óptica
size-bytes = { $count ->
    [one] { $count } byte
   *[other] { $count } bytes
}
number-decimal-separator = ,
keyring-item-title = Ubicación de red «{ $label }»
feature-phones = La compatibilidad con teléfonos
feature-share-browsing = La exploración de recursos compartidos

feature-sftp = La compatibilidad con SFTP
feature-webdav-ftp = La compatibilidad con WebDAV y FTP
## Notificaciones

notify-app-name = Dispositivos
notify-connected = { $device } conectado
notify-connected-phone = Desbloquéalo y elige «Transferencia de archivos» en sus ajustes USB para ver sus archivos.
notify-connected-ios = Desbloquéalo y toca «Confiar» si te lo pide; después ábrelo para ver sus fotos.
notify-connected-camera = Ábrela para ver sus fotos.
notify-disconnected = { $device } se desconectó
notify-disconnected-body = La conexión terminó inesperadamente. Sus archivos ya no están disponibles.
notify-attention = { $device } necesita tu atención
notify-attention-sign-in = Ábrelo en Archivos para iniciar sesión.
notify-attention-identity = Ábrelo en Archivos para comprobar la identidad del servidor.
notify-open-failed = No se pudo abrir { $device }
notify-trust = Confía en este ordenador desde { $device }
notify-trust-body = Desbloquea el iPhone y toca «Confiar». Sus fotos se abrirán en cuanto lo hagas.
notify-unplug = Ya puedes desconectar { $device }
notify-unplug-body = Sus archivos están cerrados.
notify-not-responding = { $device } no responde
notify-not-responding-body = Sus archivos no se pueden abrir hasta que vuelva a responder. Puedes desconectarlo.
notify-auto-failed = { $device } no se conectó
notify-auto-password = Necesita tu contraseña para conectarse automáticamente. Ábrelo en Archivos para iniciar sesión.
notify-auto-identity = Hay que confirmar la identidad del servidor. Ábrelo en Archivos para comprobarla.
action-open = Abrir
action-reconnect = Volver a conectar
action-try-again = Reintentar
action-disconnect = Desconectar

## Direcciones

uri-control-characters = La dirección contiene caracteres de control
uri-empty = Escribe la dirección de un servidor
uri-too-long = La dirección es demasiado larga
uri-not-valid = La dirección no es válida
uri-scheme = Usa smb://, sftp://, nfs://, dav://, davs://, ftp:// o ftps://
uri-password = No pongas la contraseña en la dirección; se te pedirá después
uri-query = La dirección no puede contener ? ni #
uri-no-host = La dirección no tiene nombre de servidor
uri-bad-host = El nombre del servidor no es válido
uri-bad-user = El nombre de usuario no es válido
uri-bad-path = La ruta de la carpeta no es válida
uri-bad-share = El nombre del recurso compartido no es válido

## Errores

error-system-service-missing = El servicio de montaje del sistema no está instalado
error-system-service-timeout = El servicio de montaje del sistema no respondió a tiempo
error-no-system-bus = El bus del sistema no está disponible
error-password-not-text = La contraseña no es un texto válido
error-password-line-break = La contraseña contiene un salto de línea o un carácter NUL
error-secret-not-memfd = El secreto debe ser un archivo de memoria sellado
error-secret-not-sealed = El archivo de memoria del secreto no está sellado
error-secret-too-large = El secreto es demasiado grande
error-keyring-store = El llavero no guardó la contraseña
error-invalid-field = La solicitud no es válida ({ $field })
error-item-busy = Otra operación sobre este elemento sigue en curso
error-no-such-item = Ese elemento no existe
error-no-such-location = Esa ubicación de red no existe
error-too-many-locations = Hay demasiadas ubicaciones de red
error-files-open = Todavía hay archivos abiertos en él; ciérralos e inténtalo de nuevo
error-busy-programs = Hay archivos abiertos en { $programs }. Ciérralos e inténtalo de nuevo, o desconéctalo de todos modos.
error-missing-helper = { $feature } ({ $helper }) no está instalada
error-helper-start = No se pudo iniciar el programa auxiliar: { $error }
error-helper-timeout = El dispositivo o el servidor no respondió a tiempo
error-cancelled = Cancelado

error-format-label = Ese nombre es demasiado largo o usa caracteres que este sistema de archivos no admite
error-not-formattable = Aquí solo se pueden formatear unidades extraíbles; usa Configuración para los discos internos
error-drive-busy = Todavía hay archivos abiertos en la unidad; ciérralos e inténtalo de nuevo
error-drive-not-allowed = No tienes permiso para cambiar esta unidad
error-drive-gone = La unidad ya no está
error-drive-timeout = La unidad no respondió a tiempo
error-udisks-missing = El servicio de unidades (UDisks2) no está disponible
error-udisks-timeout = El servicio de unidades no respondió
error-passphrase-refused = No se aceptó la frase de contraseña
error-unlock-first = Desbloquea primero la unidad
error-no-filesystem = La unidad desbloqueada no tiene sistema de archivos
error-no-disc = No hay ningún disco en la unidad
error-not-removable = Este volumen no está en una unidad extraíble
error-image-open = No se puede abrir la imagen: { $error }
error-not-image = No es un archivo de imagen de disco
error-image-no-filesystem = La imagen no tiene un sistema de archivos que este ordenador pueda leer

error-phone-no-files = El teléfono no ofrece sus archivos. Desbloquéalo y elige «Transferencia de archivos» en sus ajustes USB
error-phone-busy = Otro programa está usando el teléfono
error-phone-not-allowed = Esta cuenta no puede acceder a la conexión USB del teléfono
error-phone-locked = Desbloquea el teléfono y permite el acceso a los archivos; después inténtalo de nuevo
error-phone-failed = No se pudo abrir el teléfono: { $detail }
error-phone-gone = El teléfono ya no está conectado
error-iphone-trust = Desbloquea tu iPhone y toca «Confiar»; después inténtalo de nuevo
error-iphone-not-ready = El iPhone no está listo; desbloquéalo e inténtalo de nuevo
error-iphone-gone = El iPhone ya no está conectado
error-usbmuxd-missing = El servicio de conexión del iPhone (usbmuxd) no está en marcha
error-iphone-pair-failed = No se pudo vincular el iPhone: { $detail }
error-iphone-failed = No se pudo abrir el iPhone: { $detail }

error-login-refused = No se aceptó el nombre de usuario o la contraseña
error-server-no-answer = El servidor «{ $host }» no respondió
error-server-no-answer-unnamed = El servidor no respondió
error-server-not-found = No se encontró el servidor «{ $host }» en la red
error-server-timeout = El servidor no respondió a tiempo
error-certificate = El certificado del servidor no es de confianza
error-location-failed = No se pudo abrir la ubicación ({ $code }): { $detail }
error-sftp-failed = Falló la conexión SFTP
error-no-such-folder = La carpeta no existe en el servidor
error-not-sftp = Solo las ubicaciones SFTP tienen claves de servidor
error-host-key-moved = La clave del servidor ya no coincide con la que confirmaste
error-not-smb = Solo los servidores SMB tienen recursos compartidos
error-choose-share = Elige primero un recurso compartido
error-no-such-share = El servidor no tiene ningún recurso compartido llamado «{ $share }»
error-no-cifs = El núcleo de este sistema no tiene cliente SMB
error-smb1-only = «{ $host }» solo admite una versión de SMB antigua y menos segura (SMB1). Permítela para esta ubicación para conectarte.
error-share-failed = No se pudo montar el recurso compartido: { $detail }
error-nfs-missing = La compatibilidad con NFS no está instalada
error-export-refused = El servidor denegó el acceso a esta exportación
error-export-failed = No se pudo montar la exportación: { $detail }

error-unknown-user = Usuario desconocido
error-unknown-caller = La solicitud no procede de un programa conocido
error-authorization-timeout = Se agotó el tiempo de la autorización
error-authorization-failed = Falló la autorización: { $error }
error-not-allowed = No tienes permiso para montar aquí
error-registry = El servicio de montaje no puede leer su lista de montajes; consulta el registro del sistema
error-mount-table = No se puede leer la tabla de montajes del sistema; consulta el registro del sistema
error-too-many-pending = Se están preparando demasiadas conexiones a la vez; espera a que terminen
error-service-busy = El servicio de montaje está ocupado; inténtalo de nuevo dentro de un momento
error-too-many-mounts = Hay demasiados montajes abiertos
error-shutting-down = El servicio de montaje se está cerrando
error-worker-failed = Falló el auxiliar de montaje: { $detail }
error-not-your-mount = El servicio de montaje no hizo este montaje para ti
error-detach-failed = No se pudo separar el montaje
error-unmount-busy = Todavía hay archivos abiertos en él, o el servidor no responde; ciérralos o fuerza el desmontaje
error-unmount-failed = No se pudo desmontar: { $detail }
error-user-folder = El nombre de usuario no puede usarse como carpeta de medios
error-mount-folder = No se pudo crear la carpeta de montaje: { $error }
error-mount-folder-name = No se pudo elegir un nombre libre para la carpeta de montaje

error-startup-protocol = Solo las ubicaciones SMB y NFS se pueden montar al iniciar
error-startup-too-many = Hay demasiados recursos compartidos configurados para montarse al iniciar
error-startup-store = No se pudo guardar la contraseña: { $detail }
error-startup-decrypt = No se pudo descifrar la contraseña guardada

## Cloud drives

feature-cloud = La compatibilidad con unidades en la nube
cloud-signing-in-detail = Termina de iniciar sesión en tu navegador
notify-cloud-failed = No se añadió { $service }
error-cloud-denied = El inicio de sesión se canceló o se rechazó
error-cloud-unreachable = No se pudo contactar con el servicio; comprueba la conexión a internet
error-cloud-failed = No se pudo añadir la cuenta
error-cloud-timeout = El inicio de sesión no se terminó a tiempo
error-cloud-google-unavailable = Google Drive aún no está disponible en este ordenador
error-cloud-unavailable = { $service } no se puede añadir en este ordenador
error-cloud-server-invalid = Escribe la dirección de tu servidor Nextcloud, como cloud.ejemplo.com
error-cloud-server-https = Usa una dirección https:// para un servidor en internet
error-cloud-not-nextcloud = Ese servidor no respondió como un servidor Nextcloud
error-cloud-one-at-a-time = Termina primero el inicio de sesión que ya está abierto
