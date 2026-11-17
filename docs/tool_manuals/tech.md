# Tool manuals - tech

Stage `tech` of `reconkit`. Verified on the canonical Kali checkout
(`/home/kali/Desktop/reconkit`, Python 3.14.8) on **2026-11-16**. Every
`--help` block and every test block below is the tool's own raw output,
captured on that machine; nothing here is written from memory.

Authorized target used for the one safe test: **testfire.net** (already in
`scope.yaml`). One command per tool, no payloads, no brute force.

Tools from the `vulns` stage are deliberately absent - see
`docs/tool_manuals/README.md` ("Skipped").

| Tool | Kind | Tier | Mode | Phase | Adapter in this build |
|---|---|---|---|---|---|
| `httpx_tech` | binary | core | active | 3 | no |
| `whatweb` | binary | core | active | 3 | no |
| `wafw00f` | binary | core | active | 3 | no |
| `cdncheck` | binary | core | passive | 3 | no |
| `webanalyze` | binary | core | active | 3 | no |



---

## `httpx_tech`

- **Registry:** binary, core, active, phase 3, `stage: tech`
- **Adapter in this build:** none yet (phase 3, no adapter; `tools.yaml` has no `install` block - it reuses the `httpx` binary)
- **Official source used:** https://github.com/projectdiscovery/httpx
- **Installed on this box:** same binary as `httpx` (`/home/kali/.reconkit/bin/httpx`, v1.12.0)
- **Install command:** nothing to install - it is `httpx -td`
- **Multi-domain input:** **yes** - `-l, -list string`, same as `httpx`


#### Real test on testfire.net

Command:

```
httpx -u testfire.net -silent -sc -title -location -td -cdn -nc -duc
```


Output (raw, exit code 0):

```
https://testfire.net [200] [] [Altoro Mutual] [Apache Tomcat,Java]
```


#### Notes and errors hit

This is the `httpx` binary driving the `tech` stage; the technology column
in that same output is what the stage would store:

```
https://testfire.net [200] [] [Altoro Mutual] [Apache Tomcat,Java]
```

`-td` is what makes `tech` appear at all; without it the field is absent. A
`tech` adapter for this tool needs no separate install.


---

## `whatweb`

- **Registry:** binary, core, active, phase 3, `stage: tech`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/urbanadventurer/WhatWeb
- **Installed on this box:** `/usr/bin/whatweb`, `WhatWeb version 0.6.4`
- **Where it comes from:** Debian package `whatweb` - reference: docs/10_TOOL_SOURCES.md; reconkit does not install it
- **Multi-domain input:** **yes** - `--input-file=FILE, -i`

#### Real `--help` (raw, full)

Captured with `whatweb --help` (exit 0, wrote to stdout):

```
[1m[34m
.$$$     $.                                   .$$$     $.
$$$$     $$. .$$$  $$$ .$$$$$$.  .$$$$$$$$$$. $$$$     $$. .$$$$$$$. .$$$$$$.
$ $$     $$$ $ $$  $$$ $ $$$$$$. $$$$$ $$$$$$ $ $$     $$$ $ $$   $$ $ $$$$$$.
$ `$     $$$ $ `$  $$$ $ `$  $$$ $$' $ `$ `$$ $ `$     $$$ $ `$      $ `$  $$$'
$. $     $$$ $. $$$$$$ $. $$$$$$ `$  $. $  :' $. $     $$$ $. $$$$   $. $$$$$.
$::$  .  $$$ $::$  $$$ $::$  $$$     $::$     $::$  .  $$$ $::$      $::$  $$$$
$;;$ $$$ $$$ $;;$  $$$ $;;$  $$$     $;;$     $;;$ $$$ $$$ $;;$      $;;$  $$$$
$$$$$$ $$$$$ $$$$  $$$ $$$$  $$$     $$$$     $$$$$$ $$$$$ $$$$$$$$$ $$$$$$$$$'

[0m
WhatWeb - Next generation web scanner version 0.6.4.
Developed by Andrew Horton (urbanadventurer) and Brendan Coles (bcoles).
Homepage: https://morningstarsecurity.com/research/whatweb

Usage: whatweb [options] <URLs>

TARGET SELECTION:
  <TARGETs>			Enter URLs, hostnames, IP addresses, filenames or
  				IP ranges in CIDR, x.x.x-x, or x.x.x.x-x.x.x.x
  				format.
  --input-file=FILE, -i		Read targets from a file. You can pipe
				hostnames or URLs directly with -i /dev/stdin.

TARGET MODIFICATION:
  --url-prefix			Add a prefix to target URLs.
  --url-suffix			Add a suffix to target URLs.
  --url-pattern			Insert the targets into a URL.
				e.g. example.com/%insert%/robots.txt

AGGRESSION:
The aggression level controls the trade-off between speed/stealth and
reliability.
  --aggression, -a=LEVEL	Set the aggression level. Default: 1.
  1. Stealthy			Makes one HTTP request per target and also
  				follows redirects.
  3. Aggressive			If a level 1 plugin is matched, additional
  				requests will be made.
  4. Heavy			Makes a lot of HTTP requests per target. URLs
  				from all plugins are attempted.

HTTP OPTIONS:
  --user-agent, -U=AGENT	Identify as AGENT instead of WhatWeb/0.6.4.
  --header, -H			Add an HTTP header. eg "Foo:Bar". Specifying a
				default header will replace it. Specifying an
				empty value, e.g. "User-Agent:" will remove it.
  --follow-redirect=WHEN	Control when to follow redirects. WHEN may be
				`never', `http-only', `meta-only', `same-site',
				or `always'. Default: always.
  --max-redirects=NUM		Maximum number of redirects. Default: 10.

AUTHENTICATION:
  --user, -u=<user:password>	HTTP basic authentication.
  --cookie, -c=COOKIES		Use cookies, e.g. 'name=value; name2=value2'.
  --cookie-jar=FILE		Read cookies from a file and save cookies to the
				same file. Creates the file if it doesn't exist.
  --no-cookies			Disable automatic cookie handling (improves performance with high thread counts).

PROXY:
  --proxy			<hostname[:port]> Set proxy hostname and port.
				Default: 8080.
  --proxy-user			<username:password> Set proxy user and password.

PLUGINS:
  --list-plugins, -l		List all plugins.
  --info-plugins, -I=[SEARCH]	List all plugins with detailed information.
				Optionally search with keywords in a comma
				delimited list.
  --search-plugins=STRING	Search plugins for a keyword.
  --plugins, -p=LIST		Select plugins. LIST is a comma delimited set
				of selected plugins. Default is all.
				Each element can be a directory, file or plugin
				name and can optionally have a modifier, +/-.
				Examples: +/tmp/moo.rb,+/tmp/foo.rb
				title,md5,+./plugins-disabled/
				./plugins-disabled,-md5
				-p + is a shortcut for -p +plugins-disabled.
  --grep, -g=STRING|REGEXP	Search for STRING or a Regular Expression. Shows
				only the results that match.
				Examples: --grep "hello"
				--grep "/he[l]*o/"
  --custom-plugin=DEFINITION	Define a custom plugin named Custom-Plugin,
				Examples: ":text=>'powered by abc'"
				":version=>/powered[ ]?by ab[0-9]/"
				":ghdb=>'intitle:abc \"powered by abc\"'"
				":md5=>'8666257030b94d3bdb46e05945f60b42'"
				"{:text=>'powered by abc'}"
  --dorks=PLUGIN		List Google dorks for the selected plugin.

OUTPUT:
  --verbose, -v			Verbose output includes plugin descriptions.
				Use twice for debugging.
  --colour,--color=WHEN		control whether colour is used. WHEN may be
				`never', `always', or `auto'.
  --quiet, -q			Do not display brief logging to STDOUT.
  --no-errors			Suppress error messages.

LOGGING:
  --log-brief=FILE		Log brief, one-line output.
  --log-verbose=FILE		Log verbose output.
  --log-errors=FILE		Log errors.
  --log-xml=FILE		Log XML format.
  --log-json=FILE		Log JSON format.
  --log-sql=FILE		Log SQL INSERT statements.
  --log-sql-create=FILE		Create SQL database tables.
  --log-json-verbose=FILE	Log JSON Verbose format.
  --log-magictree=FILE		Log MagicTree XML format.
  --log-object=FILE		Log Ruby object inspection format.
  --log-mongo-database		Name of the MongoDB database.
  --log-mongo-collection	Name of the MongoDB collection.
				Default: whatweb.
  --log-mongo-host		MongoDB hostname or IP address.
				Default: 0.0.0.0.
  --log-mongo-username		MongoDB username. Default: nil.
  --log-mongo-password		MongoDB password. Default: nil.
  --log-elastic-index		Name of the index to store results. Default: whatweb
  --log-elastic-host		Host:port of the elastic http interface. Default: 127.0.0.1:9200

PERFORMANCE & STABILITY:
  --max-threads, -t		Number of simultaneous threads. Default: 25.
  --open-timeout		Time in seconds. Default: 15.
  --read-timeout		Time in seconds. Default: 30.
  --wait=SECONDS		Wait SECONDS between connections.
				This is useful when using a single thread.
  --output-sync			Force immediate output flushing for real-time
				monitoring (slower with high thread counts).
  --output-buffer-size=SIZE	Set output buffer size. 0=unbuffered,
				default=auto based on thread count.

HELP & MISCELLANEOUS:
  --short-help			Short usage help.
  --help, -h			Complete usage help.
  --debug			Raise errors in plugins.
  --version			Display version information.

EXAMPLE USAGE:
* Scan example.com.
  ./whatweb example.com

* Scan reddit.com slashdot.org with verbose plugin descriptions.
  ./whatweb -v reddit.com slashdot.org

* An aggressive scan of wired.com detects the exact version of WordPress.
  ./whatweb -a 3 www.wired.com

* Scan the local network quickly and suppress errors.
  whatweb --no-errors 192.168.0.0/24

* Scan the local network for https websites.
  whatweb --no-errors --url-prefix https:// 192.168.0.0/24

* Scan for crossdomain policies in the Alexa Top 1000.
  ./whatweb -i plugin-development/alexa-top-100.txt \
  --url-suffix /crossdomain.xml -p crossdomain_xml
```


#### Real test on testfire.net

Command:

```
whatweb --no-errors testfire.net
```


Output (raw, exit code 0):

```
[1m[34mhttp://testfire.net[0m [200 OK] [1mApache[0m, [1mCookies[0m[[0m[22mJSESSIONID[0m], [1mCountry[0m[[0m[22mUNITED STATES[0m][[1m[31mUS[0m], [1mHTTPServer[0m[[1m[36mApache-Coyote/1.1[0m], [1mHttpOnly[0m[[0m[22mJSESSIONID[0m], [1mIP[0m[[0m[22m65.61.137.117[0m], [1mJava[0m, [1mTitle[0m[[1m[33mAltoro Mutual[0m]
[1m[34mhttps://testfire.net[0m [200 OK] [1mApache[0m, [1mCookies[0m[[0m[22mJSESSIONID[0m], [1mCountry[0m[[0m[22mUNITED STATES[0m][[1m[31mUS[0m], [1mHTTPServer[0m[[1m[36mApache-Coyote/1.1[0m], [1mHttpOnly[0m[[0m[22mJSESSIONID[0m], [1mIP[0m[[0m[22m65.61.137.117[0m], [1mJava[0m, [1mTitle[0m[[1m[33mAltoro Mutual[0m]
```


#### Notes and errors hit

Output (exit 0, first line):

```
http://testfire.net [200 OK] Apache, Cookies[JSESSIONID], Country[UNITED STATES][US],
HTTPServer[Apache-Coyote/1.1], HttpOnly[JSESSIONID], IP[65.61.137.117], Java, Title[Altoro Mutual]
```

`-q` (quiet) suppresses the result line entirely - a future adapter must not use
it. `--no-errors` alone keeps the results. The output contains ANSI colour codes
when writing to a pipe unless `--color=never` is added, which a parser will need.


---

## `wafw00f`

- **Registry:** binary, core, active, phase 3, `stage: tech`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/EnableSecurity/wafw00f
- **Installed on this box:** `/usr/bin/wafw00f`, `WAFW00F : v2.4.2`
- **Where it comes from:** PyPI package `wafw00f` - reference: docs/10_TOOL_SOURCES.md; reconkit does not install it
- **Multi-domain input:** **yes** - `-i INPUT, --input-file=INPUT`

#### Real `--help` (raw, full)

Captured with `wafw00f -h` (exit 0, wrote to stdout):

```
Usage: wafw00f url1 [url2 [url3 ... ]]
example: wafw00f http://www.victim.org/

Options:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbosity, multiple -v options increase
                        verbosity
  -a, --findall         Find all WAFs which match the signatures, do not stop
                        testing on the first one
  -r, --noredirect      Do not follow redirections given by 3xx responses
  -t TEST, --test=TEST  Test for one specific WAF (use --list to get names,
                        quote names with spaces e.g. "AireeCDN (Airee)")
  -o OUTPUT, --output=OUTPUT
                        Write output to csv, json or text file depending on
                        file extension. For stdout, specify - as filename.
  -f FORMAT, --format=FORMAT
                        Force output format to csv, json or text.
  -i INPUT, --input-file=INPUT
                        Read targets from a file. Input format can be csv,
                        json or text. For csv and json, a `url` column name or
                        element is required.
  -l, --list            List all WAFs that WAFW00F is able to detect
  -p PROXY, --proxy=PROXY
                        Use an HTTP proxy to perform requests, examples:
                        http://hostname:8080, socks5://hostname:1080,
                        http://user:pass@hostname:8080
  -V, --version         Print out the current version of WafW00f and exit.
  -H HEADERS, --headers=HEADERS
                        Pass custom headers via a text file to overwrite the
                        default header set.
  -T TIMEOUT, --timeout=TIMEOUT
                        Set the timeout for the requests.
  --no-colors           Disable ANSI colors in output.
```


#### Real test on testfire.net

Command:

```
wafw00f testfire.net
```


Output (raw, exit code 0):

```

                [1;97m______
               [1;97m/      \
              [1;97m(  W00f! )
               [1;97m\  ____/
               [1;97m,,    [1;92m__            [1;93m404 Hack Not Found
           [1;96m|`-.__   [1;92m/ /                     [1;91m __     __
           [1;96m/"  _/  [1;92m/_/                       [1;91m\ \   / /
          [1;94m*===*    [1;92m/                          [1;91m\ \_/ /  [1;93m405 Not Allowed
         [1;96m/     )__//                           [1;91m\   /
    [1;96m/|  /     /---`                        [1;93m403 Forbidden
    [1;96m\\/`   \ |                                 [1;91m/ _ \
... (10 more lines, 22 total)
```


#### Notes and errors hit

Output (exit 0, the decision line):

```
~ WAFW00F : v2.4.2 ~
[-] No WAF detected by the generic detection
```

`-f json -o file` gives machine-readable output for an adapter. The tool sends a
handful of probe requests, so it belongs to the active side.


---

## `cdncheck`

- **Registry:** binary, core, passive, phase 3, `stage: tech`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/projectdiscovery/cdncheck
- **Installed on this box:** `/home/kali/.reconkit/bin/cdncheck`, `[INF] Current version: v1.4.0`
- **Where it comes from:** https://github.com/projectdiscovery/cdncheck/releases - reference: docs/10_TOOL_SOURCES.md; reconkit does not install it
- **Multi-domain input:** **yes** - `-i, -input string[]` (list of ip / dns)

#### Real `--help` (raw, full)

Captured with `cdncheck -h` (exit 0, wrote to stdout):

```
cdncheck is a tool for identifying the technology associated with dns / ip network addresses.

Usage:
  cdncheck [flags]

Flags:
INPUT:
   -i, -input string[]  list of ip / dns to process

DETECTION:
   -cdn    display only cdn in cli output
   -cloud  display only cloud in cli output
   -waf    display only waf in cli output

MATCHER:
   -mcdn, -match-cdn string[]      match host with specified cdn provider (yundun, aliyun, fastly, google, huawei, cafe24, cdnetworks, qrator, skbroadband, jiasule, tencent, arvancloud, cloudfront, gcore, gocache, lgtelecom, baidu, wangsu, kinx)
   -mcloud, -match-cloud string[]  match host with specified cloud provider (hostway, office365, oracle, zscaler, gabia, google, ktcloud, navercloud, nhncloud, arvancloud, aws, azure)
   -mwaf, -match-waf string[]      match host with specified waf provider (arvancloud, cloudflare, incapsula)

FILTER:
   -fcdn, -filter-cdn string[]      filter host with specified cdn provider (yundun, aliyun, fastly, google, huawei, cafe24, cdnetworks, qrator, skbroadband, jiasule, tencent, arvancloud, cloudfront, gcore, gocache, lgtelecom, baidu, wangsu, kinx)
   -fcloud, -filter-cloud string[]  filter host with specified cloud provider (hostway, office365, oracle, zscaler, gabia, google, ktcloud, navercloud, nhncloud, arvancloud, aws, azure)
   -fwaf, -filter-waf string[]      filter host with specified waf provider (arvancloud, cloudflare, incapsula)

OUTPUT:
   -resp               display technology name in cli output
   -o, -output string  write output in plain format to file
   -v, -verbose        display verbose output
   -j, -jsonl          write output in json(line) format
   -nc, -no-color      disable colors in cli output
   -version            display version of the project
   -silent             only display results in output

CONFIG:
   -r, -resolver string[]  list of resolvers to use (file or comma separated)
   -e, -exclude            exclude detected ip from output
   -retry int              maximum number of retries for dns resolution (must be at least 1) (default 2)
   -t, -threads int        number of concurrent threads to use (default 50)

UPDATE:
   -up, -update                 update cdncheck to latest version
   -duc, -disable-update-check  disable automatic cdncheck update check
```


#### Real test on testfire.net

Command:

```
cdncheck -i 104.16.0.1 -silent -nc -duc
```


Output (raw, exit code 0):

```
104.16.0.1
```


#### Notes and errors hit

Two results, both real:

- `cdncheck -i testfire.net -silent` printed **nothing** and exited 0: testfire.net
  is not fronted by a CDN/WAF, so there is nothing to report.
- A known Cloudflare address matches, which proves the tool works:

```
$ cdncheck -i 104.16.0.1 -silent -nc -duc
104.16.0.1
exit 0
```

This is a local range lookup - no packets to the target. `-silent` is required
for parseable output; without it the banner is the only thing on stdout.


---

## `webanalyze`

- **Registry:** binary, core, active, phase 3, `stage: tech`
- **Adapter in this build:** none yet (phase 3, no adapter)
- **Official source used:** https://github.com/rverton/webanalyze
- **Installed on this box:** `/home/kali/.reconkit/bin/webanalyze`, `v0.3.9`
- **Where it comes from:** github.com/rverton/webanalyze - reference: docs/10_TOOL_SOURCES.md; reconkit does not install it
- **Multi-domain input:** not verified - see the note; `-hosts` was not confirmed

#### Real `--help` (raw, full)

Captured with `webanalyze -h` (exit 0, wrote to stderr):

```
Usage of webanalyze:
  -apps string
    	technologies definition file (default "technologies.json")
  -crawl int
    	links to follow from the root page (default 0)
  -header value
    	custom HTTP request header, repeatable (e.g. 'User-Agent: webanalyze')
  -host string
    	single host to test
  -hosts string
    	filename with hosts, one host per line.
  -output string
    	output format (stdout|csv|json) (default "stdout")
  -redirect
    	follow http redirects (default false)
  -search
    	searches all urls with same base domain (i.e. example.com and sub.example.com) (default true)
  -silent
    	avoid printing header (default false)
  -update
    	update technologies file to current dir
  -worker int
    	number of worker (default 4)
```


#### Real test on testfire.net

Command:

```
webanalyze -host testfire.net
```


Output (raw, exit code 0):

```

http://testfire.net (0.6s):
    Java,  (Programming languages)
    Apache Tomcat,  (Web servers)
    Java,  (Programming languages)
--- stderr ---
 :: webanalyze        : v0.3.9
 :: workers           : 4
 :: technologies      : technologies.json
 :: crawl count       : 0
 :: search subdomains : true
 :: follow redirects  : false
```


#### Notes and errors hit

**First run fails; one documented preparation step fixes it.** (Recorded in
`tools.yaml` `notes:` and docs/09 since 2026-11-17. Measured again: the file
written by `-update` is 2,122,079 bytes and lands in the CWD, so it is one
update per working directory unless `-apps` is given.)

```
$ webanalyze -host testfire.net
2026/11/16 08:56:16 error: can not open apps file : could not find the technologies file: technologies.json
exit 1
```

After `webanalyze -update` (prints `app definition file updated`, exit 0):

```
$ webanalyze -host testfire.net
http://testfire.net (0.6s):
    Java,  (Programming languages)
    Apache Tomcat,  (Web servers)
    Java,  (Programming languages)
 :: webanalyze        : v0.3.9
```

A future adapter must run or require `-update` first, or every run fails.
The findings footer (`:: webanalyze : v0.3.9`) goes to stderr.

