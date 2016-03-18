<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="profile" href="http://gmpg.org/xfn/11">
<link rel="pingback" href="http://blog.ookcode.com/xmlrpc.php">

<title>Vincent Yao | 全栈工程师</title>
<link rel="alternate" type="application/rss+xml" title="Vincent Yao &raquo; Feed" href="http://blog.ookcode.com/feed/" />
<link rel="alternate" type="application/rss+xml" title="Vincent Yao &raquo; 评论Feed" href="http://blog.ookcode.com/comments/feed/" />
		<script type="text/javascript">
			window._wpemojiSettings = {"baseUrl":"http:\/\/s.w.org\/images\/core\/emoji\/72x72\/","ext":".png","source":{"concatemoji":"http:\/\/blog.ookcode.com\/wp-includes\/js\/wp-emoji-release.min.js?ver=4.3.3"}};
			!function(a,b,c){function d(a){var c=b.createElement("canvas"),d=c.getContext&&c.getContext("2d");return d&&d.fillText?(d.textBaseline="top",d.font="600 32px Arial","flag"===a?(d.fillText(String.fromCharCode(55356,56812,55356,56807),0,0),c.toDataURL().length>3e3):(d.fillText(String.fromCharCode(55357,56835),0,0),0!==d.getImageData(16,16,1,1).data[0])):!1}function e(a){var c=b.createElement("script");c.src=a,c.type="text/javascript",b.getElementsByTagName("head")[0].appendChild(c)}var f,g;c.supports={simple:d("simple"),flag:d("flag")},c.DOMReady=!1,c.readyCallback=function(){c.DOMReady=!0},c.supports.simple&&c.supports.flag||(g=function(){c.readyCallback()},b.addEventListener?(b.addEventListener("DOMContentLoaded",g,!1),a.addEventListener("load",g,!1)):(a.attachEvent("onload",g),b.attachEvent("onreadystatechange",function(){"complete"===b.readyState&&c.readyCallback()})),f=c.source||{},f.concatemoji?e(f.concatemoji):f.wpemoji&&f.twemoji&&(e(f.twemoji),e(f.wpemoji)))}(window,document,window._wpemojiSettings);
		</script>
		<style type="text/css">
img.wp-smiley,
img.emoji {
	display: inline !important;
	border: none !important;
	box-shadow: none !important;
	height: 1em !important;
	width: 1em !important;
	margin: 0 .07em !important;
	vertical-align: -0.1em !important;
	background: none !important;
	padding: 0 !important;
}
</style>
<link rel='stylesheet' id='oblique-bootstrap-css'  href='http://blog.ookcode.com/wp-content/themes/oblique/bootstrap/css/bootstrap.min.css?ver=1' type='text/css' media='all' />
<link rel='stylesheet' id='oblique-body-fonts-css'  href='//fonts.googleapis.com/css?family=Open+Sans%3A400italic%2C600italic%2C400%2C600&#038;ver=4.3.3' type='text/css' media='all' />
<link rel='stylesheet' id='oblique-headings-fonts-css'  href='//fonts.googleapis.com/css?family=Playfair+Display%3A400%2C700%2C400italic%2C700italic&#038;ver=4.3.3' type='text/css' media='all' />
<link rel='stylesheet' id='oblique-style-css'  href='http://blog.ookcode.com/wp-content/themes/oblique/style.css?ver=4.3.3' type='text/css' media='all' />
<style id='oblique-style-inline-css' type='text/css'>
.site-branding { padding:150px 0; }
@media only screen and (max-width: 1024px) { .site-branding { padding:100px 0; } }
.site-logo { max-width:200px; }
.svg-block { fill:#1c1c1c;}
.footer-svg.svg-block { fill:#17191B!important;}
.site-footer { background-color:#17191B;}
body { color:#50545C}
.site-title a, .site-title a:hover { color:#f9f9f9}
.site-description { color:#dddddd}
.entry-title, .entry-title a { color:#000}
.entry-meta, .entry-meta a, .entry-footer, .entry-footer a { color:#9d9d9d}
.widget-area { background-color:#17191B}
.widget-area, .widget-area a { color:#f9f9f9}
.social-navigation li a { color:#ffffff}

</style>
<link rel='stylesheet' id='oblique-font-awesome-css'  href='http://blog.ookcode.com/wp-content/themes/oblique/fonts/font-awesome.min.css?ver=4.3.3' type='text/css' media='all' />
<script type='text/javascript' src='http://blog.ookcode.com/wp-content/themes/oblique/js/imagesloaded.pkgd.min.js?ver=1'></script>
<script type='text/javascript' src='http://blog.ookcode.com/wp-includes/js/jquery/jquery.js?ver=1.11.3'></script>
<script type='text/javascript' src='http://blog.ookcode.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=1.2.1'></script>
<script type='text/javascript' src='http://blog.ookcode.com/wp-content/themes/oblique/js/scripts.js?ver=1'></script>
<script type='text/javascript' src='http://blog.ookcode.com/wp-includes/js/masonry.min.js?ver=3.1.2'></script>
<script type='text/javascript' src='http://blog.ookcode.com/wp-includes/js/jquery/jquery.masonry.min.js?ver=3.1.2'></script>
<script type='text/javascript' src='http://blog.ookcode.com/wp-content/themes/oblique/js/masonry-init.js?ver=1'></script>
<link rel="EditURI" type="application/rsd+xml" title="RSD" href="http://blog.ookcode.com/xmlrpc.php?rsd" />
<link rel="wlwmanifest" type="application/wlwmanifest+xml" href="http://blog.ookcode.com/wp-includes/wlwmanifest.xml" /> 
<meta name="generator" content="WordPress 4.3.3" />
<!--[if lt IE 9]>
<script src="http://blog.ookcode.com/wp-content/themes/oblique/js/html5shiv.js"></script>
<![endif]-->
	<style type="text/css">.recentcomments a{display:inline !important;padding:0 !important;margin:0 !important;}</style>
		<style type="text/css">
					.site-header {
					    background: url(http://blog.ookcode.com/wp-content/uploads/2015/12/cropped-fa15fa61ae9fed331bf9f75c739dbd7d.jpg) no-repeat;
					    background-position: center top;
					    background-attachment: fixed;
					    background-size: cover;
					}
		</style>
		<link rel="icon" href="http://blog.ookcode.com/wp-content/uploads/2015/12/cropped-fa15fa61ae9fed331bf9f75c739dbd7d1-32x32.jpg" sizes="32x32" />
<link rel="icon" href="http://blog.ookcode.com/wp-content/uploads/2015/12/cropped-fa15fa61ae9fed331bf9f75c739dbd7d1-192x192.jpg" sizes="192x192" />
<link rel="apple-touch-icon-precomposed" href="http://blog.ookcode.com/wp-content/uploads/2015/12/cropped-fa15fa61ae9fed331bf9f75c739dbd7d1-180x180.jpg">
<meta name="msapplication-TileImage" content="http://blog.ookcode.com/wp-content/uploads/2015/12/cropped-fa15fa61ae9fed331bf9f75c739dbd7d1-270x270.jpg">
</head>

<body class="home blog">
<div id="page" class="hfeed site">
	<a class="skip-link screen-reader-text" href="#content">Skip to content</a>

		<div class="sidebar-toggle">
			<i class="fa fa-bars"></i>
		</div>

	<div class="top-bar container">
					</div>

	<div class="svg-container nav-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1950 150">
		  <g transform="translate(0,-902.36218)"/>
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z" />
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
		  <path d="M 0,150 0,0 1925,0"/>
		</svg>
		</div>
	<header id="masthead" class="site-header" role="banner">
		<div class="overlay"></div>
		<div class="container">
			<div class="site-branding">
	        				<h1 class="site-title"><a href="http://blog.ookcode.com/" rel="home">Vincent Yao</a></h1>
				<h2 class="site-description">全栈工程师</h2>
	        			</div><!-- .site-branding -->
		</div>
		<div class="svg-container header-svg svg-block">
			
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1890 150">
			<g transform="translate(0,-902.36218)"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 1925,0 0,150 -1925,0"/>
		</svg>
			</div>		
	</header><!-- #masthead -->

	<div id="content" class="site-content">
		<div class="container content-wrapper">
	<div id="primary" class="content-area">
		<main id="main" class="site-main" role="main">

		
						<div id="ob-grid" class="grid-layout">
			
				
<article id="post-136" class="post-136 post type-post status-publish format-standard hentry category-c tag-c11 tag-stdthread tag-42 tag-43">
	<div class="svg-container post-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1950 150">
		  <g transform="translate(0,-902.36218)"/>
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z" />
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
		  <path d="M 0,150 0,0 1925,0"/>
		</svg>
		</div>	

		

		<div class="post-inner no-thumb">
			
		<header class="entry-header">
			<h1 class="entry-title"><a href="http://blog.ookcode.com/2016/01/29/c11%e4%b9%8b%e5%a4%9a%e7%ba%bf%e7%a8%8b/" rel="bookmark">C++11之多线程</a></h1>
						<div class="entry-meta">
				<span class="posted-on"><a href="http://blog.ookcode.com/2016/01/29/c11%e4%b9%8b%e5%a4%9a%e7%ba%bf%e7%a8%8b/" rel="bookmark"><time class="entry-date published updated" datetime="2016-01-29T17:45:05+00:00">2016.01.29</time></a></span><span class="byline"> <span class="author vcard"><a class="url fn n" href="http://blog.ookcode.com/author/vincent/">Vincent</a></span></span><span class="cat-link"><a href="http://blog.ookcode.com/category/c/">C++</a></span>			</div><!-- .entry-meta -->
					</header><!-- .entry-header -->

		<div class="entry-content">
			<p>C++11标准直接提供了并发编程的支持，这是C++新标准中非常重要的部[&#8230;]</p>

					</div><!-- .entry-content -->
	</div>
		<div class="read-more">
		<a href="http://blog.ookcode.com/2016/01/29/c11%e4%b9%8b%e5%a4%9a%e7%ba%bf%e7%a8%8b/">Continue reading &hellip;</a>
	</div>		
		<div class="svg-container post-bottom-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1890 150">
			<g transform="translate(0,-902.36218)"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 1925,0 0,150 -1925,0"/>
		</svg>
		</div>	
</article><!-- #post-## -->
			
				
<article id="post-117" class="post-117 post type-post status-publish format-standard hentry category-ios tag-appid tag-ios tag-provisioning-profiles tag-37">
	<div class="svg-container post-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1950 150">
		  <g transform="translate(0,-902.36218)"/>
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z" />
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
		  <path d="M 0,150 0,0 1925,0"/>
		</svg>
		</div>	

		

		<div class="post-inner no-thumb">
			
		<header class="entry-header">
			<h1 class="entry-title"><a href="http://blog.ookcode.com/2016/01/28/%e5%a6%82%e4%bd%95%e5%90%88%e7%90%86%e8%a7%84%e8%8c%83%e7%9a%84%e9%85%8d%e7%bd%aeios%e5%bc%80%e5%8f%91%e8%af%81%e4%b9%a6/" rel="bookmark">如何合理规范的配置iOS开发证书</a></h1>
						<div class="entry-meta">
				<span class="posted-on"><a href="http://blog.ookcode.com/2016/01/28/%e5%a6%82%e4%bd%95%e5%90%88%e7%90%86%e8%a7%84%e8%8c%83%e7%9a%84%e9%85%8d%e7%bd%aeios%e5%bc%80%e5%8f%91%e8%af%81%e4%b9%a6/" rel="bookmark"><time class="entry-date published" datetime="2016-01-28T16:07:12+00:00">2016.01.28</time><time class="updated" datetime="2016-01-28T16:12:12+00:00">2016.01.28</time></a></span><span class="byline"> <span class="author vcard"><a class="url fn n" href="http://blog.ookcode.com/author/vincent/">Vincent</a></span></span><span class="cat-link"><a href="http://blog.ookcode.com/category/ios/">iOS</a></span>			</div><!-- .entry-meta -->
					</header><!-- .entry-header -->

		<div class="entry-content">
			<p>目前很多公司开发证书配置的非常杂乱，多数依赖xcode自动生成，导致后[&#8230;]</p>

					</div><!-- .entry-content -->
	</div>
		<div class="read-more">
		<a href="http://blog.ookcode.com/2016/01/28/%e5%a6%82%e4%bd%95%e5%90%88%e7%90%86%e8%a7%84%e8%8c%83%e7%9a%84%e9%85%8d%e7%bd%aeios%e5%bc%80%e5%8f%91%e8%af%81%e4%b9%a6/">Continue reading &hellip;</a>
	</div>		
		<div class="svg-container post-bottom-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1890 150">
			<g transform="translate(0,-902.36218)"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 1925,0 0,150 -1925,0"/>
		</svg>
		</div>	
</article><!-- #post-## -->
			
				
<article id="post-109" class="post-109 post type-post status-publish format-standard hentry category-other tag-gpt tag-mbr tag-u tag-win10">
	<div class="svg-container post-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1950 150">
		  <g transform="translate(0,-902.36218)"/>
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z" />
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
		  <path d="M 0,150 0,0 1925,0"/>
		</svg>
		</div>	

		

		<div class="post-inner no-thumb">
			
		<header class="entry-header">
			<h1 class="entry-title"><a href="http://blog.ookcode.com/2016/01/27/windows10%e5%ae%89%e8%a3%85-%e8%a7%a3%e5%86%b3windows%e5%8f%aa%e8%83%bd%e5%ae%89%e8%a3%85%e5%88%b0gpt%e7%a3%81%e7%9b%98%e9%94%99%e8%af%af/" rel="bookmark">win10 U盘安装 &#8211; 解决windows只能安装到GPT磁盘错误</a></h1>
						<div class="entry-meta">
				<span class="posted-on"><a href="http://blog.ookcode.com/2016/01/27/windows10%e5%ae%89%e8%a3%85-%e8%a7%a3%e5%86%b3windows%e5%8f%aa%e8%83%bd%e5%ae%89%e8%a3%85%e5%88%b0gpt%e7%a3%81%e7%9b%98%e9%94%99%e8%af%af/" rel="bookmark"><time class="entry-date published" datetime="2016-01-27T11:07:57+00:00">2016.01.27</time><time class="updated" datetime="2016-01-27T11:11:39+00:00">2016.01.27</time></a></span><span class="byline"> <span class="author vcard"><a class="url fn n" href="http://blog.ookcode.com/author/vincent/">Vincent</a></span></span><span class="cat-link"><a href="http://blog.ookcode.com/category/other/">其他</a></span>			</div><!-- .entry-meta -->
					</header><!-- .entry-header -->

		<div class="entry-content">
			<p>准备工作： Windows 10 (Multiple Editions[&#8230;]</p>

					</div><!-- .entry-content -->
	</div>
		<div class="read-more">
		<a href="http://blog.ookcode.com/2016/01/27/windows10%e5%ae%89%e8%a3%85-%e8%a7%a3%e5%86%b3windows%e5%8f%aa%e8%83%bd%e5%ae%89%e8%a3%85%e5%88%b0gpt%e7%a3%81%e7%9b%98%e9%94%99%e8%af%af/">Continue reading &hellip;</a>
	</div>		
		<div class="svg-container post-bottom-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1890 150">
			<g transform="translate(0,-902.36218)"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 1925,0 0,150 -1925,0"/>
		</svg>
		</div>	
</article><!-- #post-## -->
			
				
<article id="post-99" class="post-99 post type-post status-publish format-standard hentry category-other tag-brew tag-linux tag-pip tag-python tag-yum">
	<div class="svg-container post-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1950 150">
		  <g transform="translate(0,-902.36218)"/>
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z" />
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
		  <path d="M 0,150 0,0 1925,0"/>
		</svg>
		</div>	

		

		<div class="post-inner no-thumb">
			
		<header class="entry-header">
			<h1 class="entry-title"><a href="http://blog.ookcode.com/2016/01/10/linux%e3%80%81mac%e3%80%81python%e5%8c%85%e7%ae%a1%e7%90%86%e5%b7%a5%e5%85%b7/" rel="bookmark">Linux、Mac、Python包管理工具</a></h1>
						<div class="entry-meta">
				<span class="posted-on"><a href="http://blog.ookcode.com/2016/01/10/linux%e3%80%81mac%e3%80%81python%e5%8c%85%e7%ae%a1%e7%90%86%e5%b7%a5%e5%85%b7/" rel="bookmark"><time class="entry-date published" datetime="2016-01-10T20:32:33+00:00">2016.01.10</time><time class="updated" datetime="2016-01-10T20:46:33+00:00">2016.01.10</time></a></span><span class="byline"> <span class="author vcard"><a class="url fn n" href="http://blog.ookcode.com/author/vincent/">Vincent</a></span></span><span class="cat-link"><a href="http://blog.ookcode.com/category/other/">其他</a></span>			</div><!-- .entry-meta -->
					</header><!-- .entry-header -->

		<div class="entry-content">
			<p>1、Linux 一般来说linux系统基本上分两大类：&nbsp; R[&#8230;]</p>

					</div><!-- .entry-content -->
	</div>
		<div class="read-more">
		<a href="http://blog.ookcode.com/2016/01/10/linux%e3%80%81mac%e3%80%81python%e5%8c%85%e7%ae%a1%e7%90%86%e5%b7%a5%e5%85%b7/">Continue reading &hellip;</a>
	</div>		
		<div class="svg-container post-bottom-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1890 150">
			<g transform="translate(0,-902.36218)"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 1925,0 0,150 -1925,0"/>
		</svg>
		</div>	
</article><!-- #post-## -->
			
				
<article id="post-97" class="post-97 post type-post status-publish format-standard hentry category-other tag-android tag-ios tag-privoxy tag-shadowsocks tag-ss">
	<div class="svg-container post-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1950 150">
		  <g transform="translate(0,-902.36218)"/>
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z" />
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
		  <path d="M 0,150 0,0 1925,0"/>
		</svg>
		</div>	

		

		<div class="post-inner no-thumb">
			
		<header class="entry-header">
			<h1 class="entry-title"><a href="http://blog.ookcode.com/2016/01/07/shadowsocks%e8%bd%achttp%e4%bb%a3%e7%90%86%e7%bb%99%e6%89%8b%e6%9c%ba%e5%b9%b3%e6%9d%bf/" rel="bookmark">shadowsocks转http代理给手机平板</a></h1>
						<div class="entry-meta">
				<span class="posted-on"><a href="http://blog.ookcode.com/2016/01/07/shadowsocks%e8%bd%achttp%e4%bb%a3%e7%90%86%e7%bb%99%e6%89%8b%e6%9c%ba%e5%b9%b3%e6%9d%bf/" rel="bookmark"><time class="entry-date published" datetime="2016-01-07T23:09:09+00:00">2016.01.07</time><time class="updated" datetime="2016-01-29T17:46:50+00:00">2016.01.29</time></a></span><span class="byline"> <span class="author vcard"><a class="url fn n" href="http://blog.ookcode.com/author/vincent/">Vincent</a></span></span><span class="cat-link"><a href="http://blog.ookcode.com/category/other/">其他</a></span>			</div><!-- .entry-meta -->
					</header><!-- .entry-header -->

		<div class="entry-content">
			<p>前提：shadowsocks属于socks5代理，默认端口号1080，[&#8230;]</p>

					</div><!-- .entry-content -->
	</div>
		<div class="read-more">
		<a href="http://blog.ookcode.com/2016/01/07/shadowsocks%e8%bd%achttp%e4%bb%a3%e7%90%86%e7%bb%99%e6%89%8b%e6%9c%ba%e5%b9%b3%e6%9d%bf/">Continue reading &hellip;</a>
	</div>		
		<div class="svg-container post-bottom-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1890 150">
			<g transform="translate(0,-902.36218)"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 1925,0 0,150 -1925,0"/>
		</svg>
		</div>	
</article><!-- #post-## -->
			
				
<article id="post-92" class="post-92 post type-post status-publish format-standard hentry category-other tag-25 tag-24 tag-17">
	<div class="svg-container post-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1950 150">
		  <g transform="translate(0,-902.36218)"/>
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z" />
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
		  <path d="M 0,150 0,0 1925,0"/>
		</svg>
		</div>	

		

		<div class="post-inner no-thumb">
			
		<header class="entry-header">
			<h1 class="entry-title"><a href="http://blog.ookcode.com/2015/12/30/%e7%a8%8b%e5%ba%8f%e5%91%98%e4%bb%80%e4%b9%88%e6%97%b6%e5%80%99%e8%af%a5%e8%80%83%e8%99%91%e8%be%9e%e8%81%8c%ef%bc%81/" rel="bookmark">程序员什么时候该考虑辞职！</a></h1>
						<div class="entry-meta">
				<span class="posted-on"><a href="http://blog.ookcode.com/2015/12/30/%e7%a8%8b%e5%ba%8f%e5%91%98%e4%bb%80%e4%b9%88%e6%97%b6%e5%80%99%e8%af%a5%e8%80%83%e8%99%91%e8%be%9e%e8%81%8c%ef%bc%81/" rel="bookmark"><time class="entry-date published" datetime="2015-12-30T20:25:30+00:00">2015.12.30</time><time class="updated" datetime="2016-01-10T20:42:04+00:00">2016.01.10</time></a></span><span class="byline"> <span class="author vcard"><a class="url fn n" href="http://blog.ookcode.com/author/vincent/">Vincent</a></span></span><span class="cat-link"><a href="http://blog.ookcode.com/category/other/">其他</a></span>			</div><!-- .entry-meta -->
					</header><!-- .entry-header -->

		<div class="entry-content">
			<p>本文转自：http://www.codeceo.com/article[&#8230;]</p>

					</div><!-- .entry-content -->
	</div>
		<div class="read-more">
		<a href="http://blog.ookcode.com/2015/12/30/%e7%a8%8b%e5%ba%8f%e5%91%98%e4%bb%80%e4%b9%88%e6%97%b6%e5%80%99%e8%af%a5%e8%80%83%e8%99%91%e8%be%9e%e8%81%8c%ef%bc%81/">Continue reading &hellip;</a>
	</div>		
		<div class="svg-container post-bottom-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1890 150">
			<g transform="translate(0,-902.36218)"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 1925,0 0,150 -1925,0"/>
		</svg>
		</div>	
</article><!-- #post-## -->
			
				
<article id="post-83" class="post-83 post type-post status-publish format-standard hentry category-ios tag-ios9 tag-url-scheme tag-23 tag-21">
	<div class="svg-container post-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1950 150">
		  <g transform="translate(0,-902.36218)"/>
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z" />
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
		  <path d="M 0,150 0,0 1925,0"/>
		</svg>
		</div>	

		

		<div class="post-inner no-thumb">
			
		<header class="entry-header">
			<h1 class="entry-title"><a href="http://blog.ookcode.com/2015/12/16/ios-9-%e5%b8%b8%e7%94%a8url-scheme/" rel="bookmark">iOS 9 常用Url Scheme</a></h1>
						<div class="entry-meta">
				<span class="posted-on"><a href="http://blog.ookcode.com/2015/12/16/ios-9-%e5%b8%b8%e7%94%a8url-scheme/" rel="bookmark"><time class="entry-date published" datetime="2015-12-16T17:31:11+00:00">2015.12.16</time><time class="updated" datetime="2015-12-16T18:32:43+00:00">2015.12.16</time></a></span><span class="byline"> <span class="author vcard"><a class="url fn n" href="http://blog.ookcode.com/author/vincent/">Vincent</a></span></span><span class="cat-link"><a href="http://blog.ookcode.com/category/ios/">iOS</a></span>			</div><!-- .entry-meta -->
					</header><!-- .entry-header -->

		<div class="entry-content">
			<p>iOS9的企业包分发不能像以前那样便利，安装完成需要到设置-&gt;通[&#8230;]</p>

					</div><!-- .entry-content -->
	</div>
		<div class="read-more">
		<a href="http://blog.ookcode.com/2015/12/16/ios-9-%e5%b8%b8%e7%94%a8url-scheme/">Continue reading &hellip;</a>
	</div>		
		<div class="svg-container post-bottom-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1890 150">
			<g transform="translate(0,-902.36218)"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 1925,0 0,150 -1925,0"/>
		</svg>
		</div>	
</article><!-- #post-## -->
			
				
<article id="post-72" class="post-72 post type-post status-publish format-standard hentry category-other tag-18 tag-16 tag-19 tag-17">
	<div class="svg-container post-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1950 150">
		  <g transform="translate(0,-902.36218)"/>
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z" />
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
		  <path d="M 0,150 0,0 1925,0"/>
		</svg>
		</div>	

		

		<div class="post-inner no-thumb">
			
		<header class="entry-header">
			<h1 class="entry-title"><a href="http://blog.ookcode.com/2015/11/10/%e7%a8%8b%e5%ba%8f%e5%91%98%e7%9a%84%e9%82%a3%e4%ba%9b%e4%ba%8b%e5%84%bf-%e7%9a%86%e5%a4%a7%e6%ac%a2%e5%96%9c%e7%9a%84%e5%8a%a0%e8%96%aa/" rel="bookmark">程序员的那些事儿 &#8212; 皆大欢喜的加薪</a></h1>
						<div class="entry-meta">
				<span class="posted-on"><a href="http://blog.ookcode.com/2015/11/10/%e7%a8%8b%e5%ba%8f%e5%91%98%e7%9a%84%e9%82%a3%e4%ba%9b%e4%ba%8b%e5%84%bf-%e7%9a%86%e5%a4%a7%e6%ac%a2%e5%96%9c%e7%9a%84%e5%8a%a0%e8%96%aa/" rel="bookmark"><time class="entry-date published" datetime="2015-11-10T09:21:32+00:00">2015.11.10</time><time class="updated" datetime="2015-12-16T17:13:23+00:00">2015.12.16</time></a></span><span class="byline"> <span class="author vcard"><a class="url fn n" href="http://blog.ookcode.com/author/vincent/">Vincent</a></span></span><span class="cat-link"><a href="http://blog.ookcode.com/category/other/">其他</a></span>			</div><!-- .entry-meta -->
					</header><!-- .entry-header -->

		<div class="entry-content">
			<p>本文转自：http://www.cnblogs.com/justnow[&#8230;]</p>

					</div><!-- .entry-content -->
	</div>
		<div class="read-more">
		<a href="http://blog.ookcode.com/2015/11/10/%e7%a8%8b%e5%ba%8f%e5%91%98%e7%9a%84%e9%82%a3%e4%ba%9b%e4%ba%8b%e5%84%bf-%e7%9a%86%e5%a4%a7%e6%ac%a2%e5%96%9c%e7%9a%84%e5%8a%a0%e8%96%aa/">Continue reading &hellip;</a>
	</div>		
		<div class="svg-container post-bottom-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1890 150">
			<g transform="translate(0,-902.36218)"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 1925,0 0,150 -1925,0"/>
		</svg>
		</div>	
</article><!-- #post-## -->
			
				
<article id="post-17" class="post-17 post type-post status-publish format-standard hentry category-other tag-10 tag-13 tag-12 tag-11 tag-14">
	<div class="svg-container post-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1950 150">
		  <g transform="translate(0,-902.36218)"/>
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z" />
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
		  <path d="M 0,150 0,0 1925,0"/>
		</svg>
		</div>	

		

		<div class="post-inner no-thumb">
			
		<header class="entry-header">
			<h1 class="entry-title"><a href="http://blog.ookcode.com/2015/09/21/%e7%99%be%e5%ba%a62016%e6%a0%a1%e5%9b%ad%e6%8b%9b%e8%81%98-%e7%a7%bb%e5%8a%a8%e8%bd%af%e4%bb%b6%e7%a0%94%e5%8f%91%e5%b7%a5%e7%a8%8b%e5%b8%88%e7%ac%94%e8%af%95%e9%a2%98/" rel="bookmark">百度2016校园招聘 &#8211; 移动软件研发工程师笔试题</a></h1>
						<div class="entry-meta">
				<span class="posted-on"><a href="http://blog.ookcode.com/2015/09/21/%e7%99%be%e5%ba%a62016%e6%a0%a1%e5%9b%ad%e6%8b%9b%e8%81%98-%e7%a7%bb%e5%8a%a8%e8%bd%af%e4%bb%b6%e7%a0%94%e5%8f%91%e5%b7%a5%e7%a8%8b%e5%b8%88%e7%ac%94%e8%af%95%e9%a2%98/" rel="bookmark"><time class="entry-date published" datetime="2015-09-21T21:52:19+00:00">2015.09.21</time><time class="updated" datetime="2016-01-10T20:43:17+00:00">2016.01.10</time></a></span><span class="byline"> <span class="author vcard"><a class="url fn n" href="http://blog.ookcode.com/author/vincent/">Vincent</a></span></span><span class="cat-link"><a href="http://blog.ookcode.com/category/other/">其他</a></span>			</div><!-- .entry-meta -->
					</header><!-- .entry-header -->

		<div class="entry-content">
			<p>题目类型 PART1:企业文化认知评测题 PART2:选择题 PART[&#8230;]</p>

					</div><!-- .entry-content -->
	</div>
		<div class="read-more">
		<a href="http://blog.ookcode.com/2015/09/21/%e7%99%be%e5%ba%a62016%e6%a0%a1%e5%9b%ad%e6%8b%9b%e8%81%98-%e7%a7%bb%e5%8a%a8%e8%bd%af%e4%bb%b6%e7%a0%94%e5%8f%91%e5%b7%a5%e7%a8%8b%e5%b8%88%e7%ac%94%e8%af%95%e9%a2%98/">Continue reading &hellip;</a>
	</div>		
		<div class="svg-container post-bottom-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1890 150">
			<g transform="translate(0,-902.36218)"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 1925,0 0,150 -1925,0"/>
		</svg>
		</div>	
</article><!-- #post-## -->
			
				
<article id="post-6" class="post-6 post type-post status-publish format-standard hentry category-ios tag-app tag-ipa">
	<div class="svg-container post-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1950 150">
		  <g transform="translate(0,-902.36218)"/>
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z" />
		  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
		  <path d="M 0,150 0,0 1925,0"/>
		</svg>
		</div>	

		

		<div class="post-inner no-thumb">
			
		<header class="entry-header">
			<h1 class="entry-title"><a href="http://blog.ookcode.com/2015/09/11/ipa%e5%8c%85%e9%87%8d%e7%ad%be%e5%90%8d%e6%ad%a5%e9%aa%a4/" rel="bookmark">ipa包重签名步骤</a></h1>
						<div class="entry-meta">
				<span class="posted-on"><a href="http://blog.ookcode.com/2015/09/11/ipa%e5%8c%85%e9%87%8d%e7%ad%be%e5%90%8d%e6%ad%a5%e9%aa%a4/" rel="bookmark"><time class="entry-date published" datetime="2015-09-11T20:23:58+00:00">2015.09.11</time><time class="updated" datetime="2015-12-16T18:34:09+00:00">2015.12.16</time></a></span><span class="byline"> <span class="author vcard"><a class="url fn n" href="http://blog.ookcode.com/author/vincent/">Vincent</a></span></span><span class="cat-link"><a href="http://blog.ookcode.com/category/ios/">iOS</a></span>			</div><!-- .entry-meta -->
					</header><!-- .entry-header -->

		<div class="entry-content">
			<p>&quot;用户会感激代码签名带来的好处&quot; &ndash; [&#8230;]</p>

					</div><!-- .entry-content -->
	</div>
		<div class="read-more">
		<a href="http://blog.ookcode.com/2015/09/11/ipa%e5%8c%85%e9%87%8d%e7%ad%be%e5%90%8d%e6%ad%a5%e9%aa%a4/">Continue reading &hellip;</a>
	</div>		
		<div class="svg-container post-bottom-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1890 150">
			<g transform="translate(0,-902.36218)"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 1925,0 0,150 -1925,0"/>
		</svg>
		</div>	
</article><!-- #post-## -->
						</div>

			
		
		</main><!-- #main -->
	</div><!-- #primary -->


<div id="secondary" class="widget-area" role="complementary">



	<nav id="site-navigation" class="main-navigation" role="navigation">
		<div class="menu"></div>
	</nav><!-- #site-navigation -->
	<nav class="sidebar-nav"></nav>



			<aside id="search-2" class="widget widget_search"><form role="search" method="get" class="search-form" action="http://blog.ookcode.com/">
				<label>
					<span class="screen-reader-text">搜索：</span>
					<input type="search" class="search-field" placeholder="搜索&hellip;" value="" name="s" title="搜索：" />
				</label>
				<input type="submit" class="search-submit" value="搜索" />
			</form></aside>		<aside id="recent-posts-2" class="widget widget_recent_entries">		<h3 class="widget-title">近期文章</h3>		<ul>
					<li>
				<a href="http://blog.ookcode.com/2016/01/29/c11%e4%b9%8b%e5%a4%9a%e7%ba%bf%e7%a8%8b/">C++11之多线程</a>
						</li>
					<li>
				<a href="http://blog.ookcode.com/2016/01/28/%e5%a6%82%e4%bd%95%e5%90%88%e7%90%86%e8%a7%84%e8%8c%83%e7%9a%84%e9%85%8d%e7%bd%aeios%e5%bc%80%e5%8f%91%e8%af%81%e4%b9%a6/">如何合理规范的配置iOS开发证书</a>
						</li>
					<li>
				<a href="http://blog.ookcode.com/2016/01/27/windows10%e5%ae%89%e8%a3%85-%e8%a7%a3%e5%86%b3windows%e5%8f%aa%e8%83%bd%e5%ae%89%e8%a3%85%e5%88%b0gpt%e7%a3%81%e7%9b%98%e9%94%99%e8%af%af/">win10 U盘安装 &#8211; 解决windows只能安装到GPT磁盘错误</a>
						</li>
					<li>
				<a href="http://blog.ookcode.com/2016/01/10/linux%e3%80%81mac%e3%80%81python%e5%8c%85%e7%ae%a1%e7%90%86%e5%b7%a5%e5%85%b7/">Linux、Mac、Python包管理工具</a>
						</li>
					<li>
				<a href="http://blog.ookcode.com/2016/01/07/shadowsocks%e8%bd%achttp%e4%bb%a3%e7%90%86%e7%bb%99%e6%89%8b%e6%9c%ba%e5%b9%b3%e6%9d%bf/">shadowsocks转http代理给手机平板</a>
						</li>
				</ul>
		</aside><aside id="recent-comments-2" class="widget widget_recent_comments"><h3 class="widget-title">近期评论</h3><ul id="recentcomments"><li class="recentcomments"><span class="comment-author-link">黄文</span>发表在《<a href="http://blog.ookcode.com/2015/09/11/ipa%e5%8c%85%e9%87%8d%e7%ad%be%e5%90%8d%e6%ad%a5%e9%aa%a4/#comment-4">ipa包重签名步骤</a>》</li><li class="recentcomments"><span class="comment-author-link"><a href='http://yuanoook.com' rel='external nofollow' class='url'>Rango</a></span>发表在《<a href="http://blog.ookcode.com/2015/11/10/%e7%a8%8b%e5%ba%8f%e5%91%98%e7%9a%84%e9%82%a3%e4%ba%9b%e4%ba%8b%e5%84%bf-%e7%9a%86%e5%a4%a7%e6%ac%a2%e5%96%9c%e7%9a%84%e5%8a%a0%e8%96%aa/#comment-2">程序员的那些事儿 &#8212; 皆大欢喜的加薪</a>》</li></ul></aside><aside id="linkcat-8" class="widget widget_links"><h3 class="widget-title">友链（不分先后）</h3>
	<ul class='xoxo blogroll'>
<li><a href="http://0x7c00.cn/" target="_blank">Breaker&#039;s Blog</a></li>
<li><a href="http://blog.eyrefree.org/" target="_blank">EyreFree&#039;s Blog</a></li>

	</ul>
</aside>
<aside id="categories-2" class="widget widget_categories"><h3 class="widget-title">分类目录</h3>		<ul>
	<li class="cat-item cat-item-40"><a href="http://blog.ookcode.com/category/c/" >C++</a>
</li>
	<li class="cat-item cat-item-3"><a href="http://blog.ookcode.com/category/ios/" >iOS</a>
</li>
	<li class="cat-item cat-item-15"><a href="http://blog.ookcode.com/category/other/" >其他</a>
</li>
		</ul>
</aside>	
</div><!-- #secondary -->

		</div>
	</div><!-- #content -->

	<div class="svg-container footer-svg svg-block">
		
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1890 150">
			<g transform="translate(0,-902.36218)"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 898.41609,-33.21176 0.01,0 -0.005,-0.009 -0.005,0.009 z"/>
			  <path d="m 1925,0 0,150 -1925,0"/>
		</svg>
		</div>
	<footer id="colophon" class="site-footer" role="contentinfo">
		<div class="site-info container">
			<a href="http://wordpress.org/" rel="nofollow">Proudly powered by WordPress</a><span class="sep"> | </span>Theme: <a href="http://themeisle.com/themes/oblique/" rel="nofollow">Oblique</a> by Themeisle.		</div><!-- .site-info -->
	</footer><!-- #colophon -->
</div><!-- #page -->

<script type='text/javascript' src='http://blog.ookcode.com/wp-content/themes/oblique/js/main.js?ver=4.3.3'></script>
<script type='text/javascript' src='http://blog.ookcode.com/wp-content/themes/oblique/js/navigation.js?ver=20120206'></script>
<script type='text/javascript' src='http://blog.ookcode.com/wp-content/themes/oblique/js/skip-link-focus-fix.js?ver=20130115'></script>

</body>
</html>
