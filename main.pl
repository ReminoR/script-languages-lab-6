# !/usr/bin/env perl
use strict;

my $filename = 'access.log';
open(my $file, '<', $filename) or die "Не удалось открыть '$filename' $!";

my $count = 0;
my $x = 0;
my %hash = ();
my @array;

while(my $line = <$file>) {

	if ($line =~ /^([^\s]+)\s-\s-\s\[([^\s]+)\s(\+\d+)\]\s"(\w*)?\s*([^"]+)"\s(\d+)\s(\d+)\s"([^\s]+)"\s"([^"]+)"/) {
		push @array, {
			"line" => $line,
			"ip" => $1,
			"date_time" => $2,
			"time_zone" => $3,
			"method" => $4,
			"request" => $5,
			"status" => $6,
			"size" => $7,
			"referrer" => $8,
			"user_agent" => $9,
			"score" => 0
		}
	}

}

#Blacklist и Whitelist сформированные службой безопасности
my @forein_black_list = ('185.25.151.159', '91.196.50.33', '74.208.71.103');
my @forein_white_list = ('195.101.2.195');

#Страницы нашего сайта
my @pages = (
	'http://mysite.fr/home_page',
	'http://mysite.fr/documents_share',
	'http://mysite.fr/document_share',
	'http://mysite.fr/file_server',
	'http://mysite.fr/administration',
	'http://mysite.fr/folder',
	'http://mysite.fr/search',
	'http://mysite.fr/searches',
	'http://mysite.fr/info',
	'http://mysite.fr/network',
	'http://mysite.fr/css',
	'http://mysite.fr/users_and_groups');


foreach my $item (@array) {
	#Method 'PROPFIND' не поддерживается нашим сайтом
	if ($$item{'method'} =~ 'PROPFIND') {
		$$item{'score'} += 1;
	}

	#Наш сайт не имеет API. Все попытки воспользоваться API блокируются
	if ($$item{'request'} =~ /^\/API/) {
		$$item{'score'} += 1;
	}

	# Если содержится одно из невалидных ключевых слов
	if ($$item{'request'} =~ /^\/Ringing.at.your.dorbell!|API|\/phpmyadmin|testproxy.php/) {
		$$item{'score'} += 1;
	}

	if ($$item{'user_agent'} =~ /^masscan|WEBDAV Client/) {
		$$item{'score'} += 1;
	}

	#Студенты выполняют лабораторную по скриптовым языкам, не будем их блокировать, пусть учатся :-)
	if ($$item{'user_agent'} =~ /^Python-urllib/) {
		$$item{'score'} = 0;
	}

	# Если запрашивается существующая страница сайта, то запрос легитимный
	foreach my $page (@pages) {
		if ( index($$item{'referrer'}, $page) != -1 ) {
			$$item{'score'} = 0;
		}
	}

	#Запретить все ip адреса из внешнего black-list
	foreach my $black_ip (@forein_black_list) {
		if ($$item{'ip'} =~ $black_ip) {
			$$item{'score'} += 5;
		}
	}

	#Разрешить все ip адреса из внешнего white-list
	foreach my $white_ip (@forein_white_list) {
		if ($$item{'ip'} =~ $white_ip) {
			$$item{'score'} = 0;
		}
	}

}

# сортировка по значению
print "Топ 50 нелегитимных запросов:\n";
my $count = 1;
foreach my $i (sort {$b->{score} <=> $a->{score}} @array) {
	print "$count) $$i{line} - $$i{score}\n";
	$count++;

	if ($count > 50) {
		last;
	}
}

close FILE;



#Заметки

# хэш таблица (ip - баллы)
# проверяем функцией

# признаки легитимности - белый лист, какого вида запросы с легитимного ip. Если есть известная страница, то легитимный
# признаки нелегитимности - юзер-агент, хост (если запрашивается страница, которой нет, то это нелегитимный), протокол PROPFIND, прокси, API )
# waf


# Открываем файл
# Анализируем каждую строчку по определенным критериям
# Есть ли в black-листе
# Есть ли в white-листе
# Содержит ли одно из ключевых слов
# Сколько символов длина строки
# Как часто происходит запрос, анализ времени запроса

# Если выводим ТОП-50 самых подозрительных запросов.




# – Если адрес находится в whiteliste, то никакие ограничения не действуют
# – Если находится в blackliste, то нет смысла проверять остальные условия.
# – Если слишком частые запросы, то добавляем балл
# – Если часто обращается к несуществующим страницам - 404 ответ
# – Обращения к закрытым скриптам 403
# – содержит одно из ключевых слов "testproxy", inging.at.your.dorbell!", wp-login.php, Python-urllib/2.7
# – длина запроса слишком маленькая
# – API
# – HEAD

# Если баллов 2-3, то добавляем в список подозрительных запросов
# Если баллов больше 4-5, то блокируем



# my $size = @array;
# for (my $i = 0; $i < $size; $i++) {
# 	# print "$i) " . $array[$i]{'line'}, "\n";
# 	# print "$i) " . $array[$i]{'ip'}, "\n";
# 	# print "$i) " . $array[$i]{'date_time'}, "\n";
# 	# print "$i) " . $array[$i]{'time_zone'}, "\n";
# 	# print "$i) " . $array[$i]{'method'}, "\n";
# 	# print "$i) " . $array[$i]{'request'}, "\n";
# 	# print "$i) " . $array[$i]{'status'}, "\n";
# 	# print "$i) " . $array[$i]{'size'}, "\n";
# 	# print "$i) " . $array[$i]{'referrer'}, "\n";
# 	# print "$i) " . $array[$i]{'user_agent'}, "\n";
# 	# print "$i) " . $array[$i]{'score'}, "\n";
# }
