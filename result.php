 <?php

	$login = $_COOKIE['login'];
	$password = $_COOKIE['password'];
	$site = $_GET['site'];
	
	$getfile ='https://'.$site.'/robots.txt'; // пример URL
	$file_headers = @get_headers($getfile); // подготавливаем headers страницы

	if ($file_headers[0] == 'HTTP/1.1 404 Not Found') 
	{
		$robots = 'no';

	} else if ($file_headers[0] == 'HTTP/1.1 200 OK') 
	{
	   $robots = 'ok';
	}
	$getfile1 ='https://'.$site.'/sitemap.xml'; // пример URL
	$file_headers1 = @get_headers($getfile1); // подготавливаем headers страницы

	if ($file_headers1[0] == 'HTTP/1.1 404 Not Found') 
	{
		$sitemap = 'no';

	} else if ($file_headers1[0] == 'HTTP/1.1 200 OK') 
	{
	   $sitemap = 'ok';
	}




	$tags = get_meta_tags($website);

	

	//$generator = ( isset($tags['generator']) ) ? $tags['generator']: "Отсутствует";
	$h1 = ( isset($tags['h1']) ) ? $tags['h1']: "Отсутствует";
	$h2 = ( isset($tags['h2']) ) ? $tags['h2']: "Отсутствует";
	$h3 = ( isset($tags['h3']) ) ? $tags['h3']: "Отсутствует";
	$h4 = ( isset($tags['h4']) ) ? $tags['h4']: "Отсутствует";
	$h5 = ( isset($tags['h5']) ) ? $tags['h5']: "Отсутствует";

	$keywords = ( isset($tags['keywords']) ) ? $tags['keywords']: "Отсутствует";
	$description = ( isset($tags['description']) ) ? $tags['description']: "Отсутствует";

   



    


   
?>









 <!DOCTYPE html>
<html lang="zxx">
<head>
	<title>Zeuslab | SEO analysis result</title>
	<meta charset="UTF-8">
	<meta name="description" content="Real estate HTML Template">
	<meta name="keywords" content="real estate, html">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	
	<!-- Favicon -->
	<link href="img/favicon.ico" rel="shortcut icon"/>

	<!-- Google font -->
	<link href="https://fonts.googleapis.com/css?family=Lato:400,400i,700,700i,900%7cRoboto:400,400i,500,500i,700,700i&display=swap" rel="stylesheet">
	<link href="https://fonts.googleapis.com/css2?family=Commissioner&display=swap" rel="stylesheet">
 
	<!-- Stylesheets -->
	<link rel="stylesheet" href="css/bootstrap.min.css"/>
	<link rel="stylesheet" href="css/font-awesome.min.css"/>
	<link rel="stylesheet" href="css/slicknav.min.css"/>

	<!-- Main Stylesheets -->
	<link rel="stylesheet" href="css/style.css"/>


	<!--[if lt IE 9]>
		<script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
		<script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
	<![endif]-->

</head>
<body>
	<!-- Прелоадер -->
	<div id="preloder">
		<div class="loader"></div>
	</div>

	<!-- Хедер -->
	<header class="header-section">
		<a href="index.html" class="site-logo">
			<img class="logotip" src="img/logo.png" alt="">
		</a>
		<nav class="header-nav">
			<ul class="main-menu">
				<li><a href="index.html" class="active">Главная</a></li>
				<li><a href="about-us.html">О компании</a></li>
				<li><a href="#">Купить</a></li>
				<li><a href="#">О компании</a>
					<ul class="sub-menu">
						<li><a href="about-us.html">Отзывы</a></li>
						<li><a href="search-result.html">Сертификаты</a></li>
						<li><a href="single-property.html">Контакты</a></li>
					</ul>
				</li>
				<li><a href="news.html">Цены</a></li>
				<li><a href="contact.html">Акции</a></li>
			</ul>
			<div class="header-right">
				<div class="user-panel">
					<a href="#" onclick="openAuth()" class="login">Войти</a>
					<a href="#" onclick="openReg()" class="register">Зарегистрироваться</a>
				</div>
			</div>
		</nav>
	</header>
	<!-- Конец хедера -->

	<div class="result">
	<div class="container">
		<div class="result-title">
			
		</div>	
	</div>

	</div>
	<div class="result">
	<div class="container">
		<div class="result-title">
			
		</div>	
	</div>

	</div>

	<div class="result">
	<div class="container">
		<div class="result-title">
				
		</div>	
	</div>
	</div>
	<div class="result">
	<div class="container">
		<div class="result-title">
				<h1 class="result-text ct">Результаты анализа сайта <?php print_r($site); ?> </h1>
					<ul class="resultul">
						<h5 class="ct seg">Основные параметры</h5>
							<div class="row">
								<div class="col-lg-9 col-md-9 col-sm-6 col-10">	
									<li class="resultli ct">
										<img  width="40px" alt=""> Keywords
									</li>
									<li class="resultli ct">
										<img  width="40px" alt=""> Description
									</li>
									<li class="resultli ct">
										<img  width="40px" alt=""> Robots.txt
									</li>
									<li class="resultli ct">
										<img  width="40px" alt=""> Sitemap.xml
									</li>
								</div>
								<div class="col-lg-3 col-md-2 col-sm-2 col-2">
									<li class="resultli ct chi"> <?php print_r($keywords); ?> </li>
									<li class="resultli ct chi"><?php print_r($description); ?></li>
									<li class="resultli ct chi"> <?php print_r($robots); ?> </li>
									<li class="resultli ct chi"><?php print_r($sitemap); ?></li>
								</div>
								
					</div>
						
						
						
					</ul>
		</div>	
	</div>

	</div>
		<!-- Футер -->
	<footer class="footer-section">
		<div class="container">
			<div class="row text-white justify-content-center">
				<div class="col-lg-3 col-md-10 ">
					<div class="footer-widger">
						<div class="about-widget">
							<div class="aw-text">
								<img src="img/logo.png" alt="">
								<p>Созданно командой Zeuslab во время "Хакатона Вконтакте" как один из проектов</p>
								<a href="#" class="site-btn">Связаться</a>
							</div>
						</div>
					</div>
				</div>
				<div class="col-lg-2 col-md-3 col-sm-6">
					<div class="footer-widger">
						<h2>О компании</h2>
						<ul>
							<li><a href="#">О нас</a></li>
							<li><a href="#">Сервисы</a></li>
							<li><a href="#">Отзывы</a></li>	
						</ul>
					</div>
				</div>
				<div class="col-lg-2 col-md-3 col-sm-6">
					<div class="footer-widger">
						<h2>Контакты</h2>
						<ul>
							<li><a href="#">+7(999)444-33-22</a></li>
							<li><a href="#">Zeuslab@google.com</a></li>
							<li><a href="#">Ул.Пушкина 32</a></li>	
							<li><a href="#">Пн-Пт 8.00-20.00</a></li>	
						</ul>
					</div>
				</div>
				<div class="col-lg-2 col-md-3 col-sm-6">
					<div class="footer-widger">
						<h2>Мы в соц-сетях</h2>
						
							<a href="#"><img class="soc" src="img/vk.png" alt=""></a>
							<a href="#"><img class="soc" src="img/inst.png" alt=""></a>
							<a href="#"><img class="soc" src="img/youtube.png" alt=""></a>
						

					</div>
				</div>
				<div class="col-lg-2 col-md-3 col-sm-6">
					<div class="footer-widger">
						<h2>Мы принимаем</h2>
							<a href="#"><img class="acc" src="img/acc.png" alt=""></a>
					</div>
				</div>
			</div>




		</div>
<!-- Конец футера -->
		

	</footer>
	
		<div class="auth" id="auth-warp" style="top:-500px;">
			<div class="auth-warp authcon">
				<form class="login"  method="post" id="aut">
				<a href="#" onclick="closeAuth()" class="closeaut"><img class="clos" src="img/close.png"></a><br>
				<h2 class="auth-tex">Вход</h2>
				<br><input class="authel" type="text" name="login" placeholder="Логин" required>
				<br><input class="authel" type="password" name="password" placeholder="Пароль" required>
				<br><p for="horns" class="auth-tex"><input class="authel" type="checkbox" name="passrem">Запомнить пароль?</p>
				<br><a href="#" onclick="openReg()" class="authel auth-tex">Зарегистрироваиться</a><br>
				<br><input type="submit" class="site-btn authel" value="Войти">
				</form>
			</div>
		</div>
		<div class="auth" id="reg" style="top:-500px;">
			<div class="auth-warp authcon">
				<form class="login" method="post" id="regis">
				<a href="#" onclick="closeReg()" class="closeaut"><img class="clos" src="img/close.png"></a><br>
				<h2 class="auth-tex">Регистрация</h2>
				<br><input class="authel" type="text" name="login" placeholder="Логин" required>
				<br><input class="authel" type="text" name="email" placeholder="Почта" required>
				<br><input class="authel" type="text" name="number" placeholder="Номер телефона" required>
				<br><input class="authel" type="password" name="pass" placeholder="Пароль" required>
				<br><p for="horns" class="auth-tex"><input class="authel" type="checkbox" name="horns">Запомнить пароль?</p>
				<br><a href="#" onclick="openAuth()" class="authel auth-tex">Войти</a><br>
				<br><input type="submit"  class="site-btn authel" value="Зарегистрироваться">
				</form>
			</div>
		</div>
	<!-- Конец авторизации -->	
	
	<!--====== Javascripts & Jquery ======-->
	<script src="js/jquery-3.2.1.min.js"></script>
	<script src="js/bootstrap.min.js"></script>
	<script src="js/jquery.slicknav.min.js"></script>
	<script src="js/jquery.magnific-popup.min.js"></script>
	<script src="js/main.js"></script>
	<script src="js/script.js"></script>

	</body>
</html>
