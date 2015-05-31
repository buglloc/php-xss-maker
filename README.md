# XSS Maker

Пожалуй, поиск хранимых XSS самое не благодарное занятие. В этом может помочь данное расширение для PHP. Его суть заключается во вставке "XSS-маркеров" во все данные полученные из БД, на текущий момент поддерживает `mysql` и `mysqli`.
Иными словами его задача заменять строку полученную из БД:
```
Андрей Красичков
```
На
```
'"><img src=x onerror="alert('Андрей Красичков, go home');" />
```
Таким образом сразу же можно узнать что не правильно кодируется/эскейпится при выводе. Просто и наглядно, а благодаря такому низкому уровню - подходит практически для любых фреймворков, включая 1С-Битрикс.
По умолчанию заменяет любой _русский_ текст, ориентируясь на `internal_encoding`. Таким образом для `internal_encoding = UTF-8` он будет работать с любыми строками содержащими символы `[\xD0\xD1][\x80-\xBF]`, а для остальных - `[\xC0-\xFF]`.
Умеет включатся по триггеру в запросе, по аналогии с XDebug, достаточно в печеньки добавить `_XSS_MAKER=y` и на всех ваших хитах XSS Maker будет делать своё дело.

## Установка
```
mkdir ~/tmp && cd ~/tmp
git clone https://github.com/buglloc/php-xss-maker.git
cd php-xss-maker/
phpize
./configure
make
sudo make install
```

## Настройка
```
# Автостарт замены на каждом хите
xssmaker.autostart = On/Off
# Запуск по триггеру в $_REQUEST
xssmaker.use_autostart_trigger = On/Off
# Триггер используемый при use_autostart_trigger
xssmaker.autostart_trigger = _XSS_MAKER
# PCRE паттерн для поиска. Представляет любую желаемую вами регулярку которой проверяется подходит ли значение для замены
xssmaker.marker = '#_xss$#i'
# Паттерн для замены. Пока есть только две плейсхолдера $n (от name - имя поля) и $v (от value - значение)
xssmaker.xss = "'"><h1>$n|$v</h1>"
```

## Пример
Возьмем, например, 1С-Битрикс.
Тестовая страничка, содержащая не правильный вывод ФИО пользователя с ID 123 (`bHTMLSpec = false`):
```php
<?php
require_once($_SERVER["DOCUMENT_ROOT"] . "/bitrix/modules/main/include/prolog_before.php");
printf('User info: %s', CUser::FormatName(
    CSite::GetNameFormat(false),
    Bitrix\Main\UserTable::getByPrimary(123)->fetch(),
    true, false
));
?>
```
Делаем запрос:
```
$  http http://bus.my/test.php
HTTP/1.1 200 OK
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Connection: keep-alive
Content-Encoding: gzip
Content-Type: text/html; charset=UTF-8
Date: Sun, 31 May 2015 11:41:59 GMT
Expires: Thu, 19 Nov 1981 08:52:00 GMT
P3P: policyref="/bitrix/p3p.xml", CP="NON DSP COR CUR ADM DEV PSA PSD OUR UNR BUS UNI COM NAV INT DEM STA"
Pragma: no-cache
Server: nginx/1.8.0
Set-Cookie: PHPSESSID=g9gqm2iofc5686umn96md9t931; path=/; HttpOnly
Set-Cookie: BITRIX_SM_GUEST_ID=7; expires=Wed, 25-May-2016 11:41:59 GMT; Max-Age=31104000; path=/
Set-Cookie: BITRIX_SM_LAST_VISIT=31.05.2015+14%3A41%3A59; expires=Wed, 25-May-2016 11:41:59 GMT; Max-Age=31104000; path=/
Transfer-Encoding: chunked
X-Powered-By: PHP/5.6.9
X-Powered-CMS: Bitrix Site Manager (8e31e4c9436488ab7d6b8d0125a2553b)

User info: Андрей Красичков

```
Не плохо, теперь передаем триггер для XSS Maker'а, что бы он сделал своё дело:
```
$ http http://bus.my/test.php _XSS_MAKER==y
HTTP/1.1 200 OK
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Connection: keep-alive
Content-Encoding: gzip
Content-Type: text/html; charset=UTF-8
Date: Sun, 31 May 2015 11:42:11 GMT
Expires: Thu, 19 Nov 1981 08:52:00 GMT
P3P: policyref="/bitrix/p3p.xml", CP="NON DSP COR CUR ADM DEV PSA PSD OUR UNR BUS UNI COM NAV INT DEM STA"
Pragma: no-cache
Server: nginx/1.8.0
Set-Cookie: PHPSESSID=fv2ggfqrecs63aunccvjh42rc1; path=/; HttpOnly
Set-Cookie: BITRIX_SM_GUEST_ID=7; expires=Wed, 25-May-2016 11:42:11 GMT; Max-Age=31104000; path=/
Set-Cookie: BITRIX_SM_LAST_VISIT=31.05.2015+14%3A42%3A11; expires=Wed, 25-May-2016 11:42:11 GMT; Max-Age=31104000; path=/
Transfer-Encoding: chunked
X-Powered-By: PHP/5.6.9
X-Powered-CMS: Bitrix Site Manager (8e31e4c9436488ab7d6b8d0125a2553b)

User info: '"><h1>NAME|Андрей</h1> '"><h1>LAST_NAME|Красичков</h1>

```
И видим нашу проблему, исправляем и проверяем снова:
```
$ http http://bus.my/test.php _XSS_MAKER==y
HTTP/1.1 200 OK
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Connection: keep-alive
Content-Encoding: gzip
Content-Type: text/html; charset=UTF-8
Date: Sun, 31 May 2015 11:43:01 GMT
Expires: Thu, 19 Nov 1981 08:52:00 GMT
P3P: policyref="/bitrix/p3p.xml", CP="NON DSP COR CUR ADM DEV PSA PSD OUR UNR BUS UNI COM NAV INT DEM STA"
Pragma: no-cache
Server: nginx/1.8.0
Set-Cookie: PHPSESSID=h9osbhqfqdkf3g85qfdu3rksu6; path=/; HttpOnly
Set-Cookie: BITRIX_SM_GUEST_ID=7; expires=Wed, 25-May-2016 11:43:01 GMT; Max-Age=31104000; path=/
Set-Cookie: BITRIX_SM_LAST_VISIT=31.05.2015+14%3A43%3A01; expires=Wed, 25-May-2016 11:43:01 GMT; Max-Age=31104000; path=/
Transfer-Encoding: chunked
X-Powered-By: PHP/5.6.9
X-Powered-CMS: Bitrix Site Manager (8e31e4c9436488ab7d6b8d0125a2553b)

User info: '&quot;&gt;&lt;h1&gt;NAME|Андрей&lt;/h1&gt; '&quot;&gt;&lt;h1&gt;LAST_NAME|Красичков&lt;/h1&gt;


```

Отлично, теперь ФИО выводится корректно. Пример, конечно, упрощен, но главное ведь передать суть.