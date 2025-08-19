# [![Send](https://github.com/OfficialV4NT/SecureSend/blob/main/assets/icon-64x64.png)](https://gitlab.com/timvisee/send/) Send

A fork of Mozilla's [Firefox-Send](https://github.com/mozilla/send). 
<br>
SecureSend is a simple, private end-to-end encrypted file sharing application. It ensures that your files are securely shared with the intended recipients without compromising privacy.

## Frequently Asked Questions (FAQ)

## How big of a file can I transfer with Send?

There is a 2GB file size limit built in to Send, but this may be changed by the
hoster. Send encrypts and decrypts the files in the browser which is great for
security but will tax your system resources.  In particular you can expect to
see your memory usage go up by at least the size of the file when the transfer
is processing.  You can see [the results of some
testing](https://github.com/mozilla/send/issues/170#issuecomment-314107793). For
the most reliable operation on common computers, it’s probably best to stay
under a few hundred megabytes.

## Why is my browser not supported?

We’re using the [Web Cryptography JavaScript API with the AES-GCM
algorithm](https://www.w3.org/TR/WebCryptoAPI/#aes-gcm) for our encryption.
Many browsers support this standard and should work fine, but some have not
implemented it yet (mobile browsers lag behind on this, in
particular).

## Why does Send require JavaScript?

Send uses JavaScript to:

- Encrypt and decrypt files locally on the client instead of the server.
- Render the user interface.
- Manage translations on the website into [various different languages](https://github.com/timvisee/send#localization).
- Collect data to help us improve Send in accordance with our [Terms & Privacy](https://send.firefox.com/legal).

Since Send is an open source project, you can see all of the cool ways we use JavaScript by [examining our code](https://github.com/timvisee/send/).

## How long are files available for?

Files are available to be downloaded for 24 hours, after which they are removed
from the server.  They are also removed immediately once the download limit is reached.

## Can a file be downloaded more than once?

Yes, once a file is submitted to Send you can select the download limit.


*Disclaimer: Send is an experiment and under active development.  The answers
here may change as we get feedback from you and the project matures.*

## DMCA Takedown Process Request

In cases of a DMCA notice, or other abuse yet to be determined, a file has to be removed from the service.

Files can be delisted and made inaccessible by removing their record from Redis.

Send share links contain the `id` of the file, for example `https://send.firefox.com/download/3d9d2bb9a1`

From a host with access to the Redis server run a `DEL` command with the file id.

For example:

```sh
redis-cli DEL 3d9d2bb9a1
```

Other redis-cli parameters like `-h` may also be required. See [redis-cli docs](https://redis.io/topics/rediscli) for more info.

The encrypted file resides on S3 as the same `id` under the bucket that the app was configured with as `S3_BUCKET`. The file can be managed if it has not already expired with the [AWS cli](https://docs.aws.amazon.com/cli/latest/reference/s3/index.html) or AWS web console.

## Localization

SecureSend is localized in over 50 languages. We use the [fluent](http://projectfluent.org/) library and store our translations in [FTL](http://projectfluent.org/fluent/guide/) files in `public/locales/`. `en-US` is our base language.

## Process

Strings are added or removed from [public/locales/en-US/send.ftl] as needed. Strings **MUST NOT** be *changed* after they've been commited and pushed to master. Changing a string requires creating a new ID with a new name (preferably descriptive instead of incremented) and deletion of the obsolete ID. It's often useful to add a comment above the string with info about how and where the string is used.

Once new strings are commited to master they are available for translators in Pontoon. All languages other than `en-US` should be edited via Pontoon. Translations get automatically commited to the github master branch.

### Activation

The development environment includes all locales in `public/locales` via the `L10N_DEV` environment variable. Production uses `package.json` as the list of locales to use. Once a locale has enough string coverage it should be added to `package.json`.

## Code

In `app/` we use the `state.translate()` function to translate strings to the best matching language base on the user's `Accept-Language` header. It's a wrapper around fluent's [FluentBundle.format](http://projectfluent.org/fluent.js/fluent/FluentBundle.html). It works the same for both server and client side rendering.

### Examples

```js
// simple string
const finishedString = state.translate('downloadFinish')
// with parameters
const progressString = state.translate('downloadingPageProgress', {
  filename: state.fileInfo.name,
  size: bytes(state.fileInfo.size)
})
```

## Developer

## Requirements

This document describes how to do a full deployment of Send on your own Linux server. You will need:

* A working (and ideally somewhat recent) installation of NodeJS and npm
* Git
* Apache webserver
* Optionally telnet, to be able to quickly check your installation

For example in Debian/Ubuntu systems:

```bash
sudo apt install git apache2 nodejs npm telnet
```

## Building

* We assume an already configured virtual-host on your webserver with an existing empty htdocs folder
* First, remove that htdocs folder - we will replace it with Send's version now
* git clone https://github.com/timvisee/send.git htdocs
* Make now sure you are NOT root but rather the user your webserver is serving files under (e.g. "su www-data" or whoever the owner of your htdocs folder is)
* npm install
* npm run build

## Running

To have a permanently running version of Send as a background process:

* Create a file `run.sh` with:

```bash
#!/bin/bash
nohup su www-data -c "npm run prod" 2>/dev/null &
```

* Execute the script:

```bash
chmod +x run.sh
./run.sh
```

Now the Send backend should be running on port 1443. You can check with:

```bash
telnet localhost 1443
```

## Reverse Proxy

Of course, we don't want to expose the service on port 1443. Instead we want our normal webserver to forward all requests to Send ("Reverse proxy").

# Apache webserver

* Enable Apache required modules:

```bash
sudo a2enmod headers
sudo a2enmod proxy
sudo a2enmod proxy_http
sudo a2enmod proxy_wstunnel
sudo a2enmod rewrite
```

* Edit your Apache virtual host configuration file, insert this:

```
# Enable rewrite engine
RewriteEngine on

# Make sure the original domain name is forwarded to Send
# Otherwise the generated URLs will be wrong
ProxyPreserveHost on

# Make sure the generated URL is https://
RequestHeader set X-Forwarded-Proto https

# If it's a normal file (e.g. PNG, CSS) just return it
RewriteCond %{REQUEST_FILENAME} -f
RewriteRule .* - [L]

# If it's a websocket connection, redirect it to a Send WS connection
RewriteCond %{HTTP:Upgrade} =websocket [NC]
RewriteRule /(.*) ws://127.0.0.1:1443/$1 [P,L]

# Otherwise redirect it to a normal HTTP connection
RewriteRule ^/(.*)$ http://127.0.0.1:1443/$1 [P,QSA]
ProxyPassReverse  "/" "http://127.0.0.1:1443"
```

* Test configuration and restart Apache:

```bash
sudo apache2ctl configtest
sudo systemctl restart apache2
```

## Environment Variables (Docker)

All the available config options and their defaults can be found here: https://github.com/timvisee/send/blob/master/server/config.js

Config options should be set as unquoted environment variables. Boolean options should be `true`/`false`, time/duration should be integers (seconds), and filesize values should be integers (bytes).

Config options expecting array values (e.g. `EXPIRE_TIMES_SECONDS`, `DOWNLOAD_COUNTS`) should be in unquoted CSV format. UI dropdowns will default to the first value in the CSV, e.g. `DOWNLOAD_COUNTS=5,1,10,100` will show four dropdown options, with `5` selected by the default.

#### Server Configuration

| Name     | Description |
|------------------|-------------|
| `BASE_URL`       | The HTTPS URL where traffic will be served (e.g. `https://send.firefox.com`)
| `DETECT_BASE_URL` | Autodetect the base URL using browser if `BASE_URL` is unset (defaults to `false`)
| `PORT`           | Port the server will listen on (defaults to `1443`)
| `NODE_ENV`       | Run in `development` mode (unsafe) or `production` mode (the default)
| `SEND_FOOTER_DMCA_URL` | A URL to a contact page for DMCA requests (empty / not shown by default)
| `SENTRY_CLIENT`, `SENTRY_DSN`  | Sentry Client ID and DSN for error tracking (optional, disabled by default)

*Note: more options can be found here: https://github.com/timvisee/send/blob/master/server/config.js*

#### Upload and Download Limits

Configure the limits for uploads and downloads. Long expiration times are risky on public servers as people may use you as free hosting for copyrighted content or malware (which is why Mozilla shut down their `send` service). It's advised to only expose your service on a LAN/intranet, password protect it with a proxy/gateway, or make sure to set `SEND_FOOTER_DMCA_URL` above so you can respond to takedown requests.

| Name    | Description |
|------------------|-------------|
| `MAX_FILE_SIZE` | Maximum upload file size in bytes (defaults to `2147483648` aka 2GB)
| `MAX_FILES_PER_ARCHIVE` | Maximum number of files per archive (defaults to `64`)
| `MAX_EXPIRE_SECONDS` | Maximum upload expiry time in seconds (defaults to `604800` aka 7 days)
| `MAX_DOWNLOADS` | Maximum number of downloads (defaults to `100`)
| `DOWNLOAD_COUNTS` | Download limit options to show in UI dropdown, e.g. `10,1,2,5,10,15,25,50,100,1000`
| `EXPIRE_TIMES_SECONDS` | Expire time options to show in UI dropdown, e.g. `3600,86400,604800,2592000,31536000`
| `DEFAULT_DOWNLOADS` | Default download limit in UI (defaults to `1`)
| `DEFAULT_EXPIRE_SECONDS` | Default expire time in UI (defaults to `86400`)

*Note: more options can be found here: https://github.com/timvisee/send/blob/master/server/config.js*

#### Storage Backend Options

Pick how you want to store uploaded files and set these config options accordingly:

- Local filesystem (the default): set `FILE_DIR` to the local path used inside the container for storage (or leave the default)
- S3-compatible object store: set `S3_BUCKET`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (and `S3_ENDPOINT` if using something other than AWS)
- Google Cloud Storage: set `GCS_BUCKET` to the name of a GCS bucket (auth should be set up using [Application Default Credentials](https://cloud.google.com/docs/authentication/production#auth-cloud-implicit-nodejs))

Redis is used as the metadata database for the backend and is required no matter which storage method you use.

| Name  | Description |
|------------------|-------------|
| `REDIS_HOST`, `REDIS_PORT`, `REDIS_USER`, `REDIS_PASSWORD`, `REDIS_DB` | Host name, port, and pass of the Redis server (defaults to `localhost`, `6379`, and no password)
| `FILE_DIR`       | Directory for storage inside the Docker container (defaults to `/uploads`)
| `S3_BUCKET`  | The S3 bucket name to use (only set if using S3 for storage)
| `S3_ENDPOINT` | An optional custom endpoint to use for S3 (defaults to AWS)
| `S3_USE_PATH_STYLE_ENDPOINT`| Whether to force [path style URLs](https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/Config.html#s3ForcePathStyle-property) for S3 objects (defaults to `false`)
| `AWS_ACCESS_KEY_ID` | S3 access key ID (only set if using S3 for storage)
| `AWS_SECRET_ACCESS_KEY` | S3 secret access key ID (only set if using S3 for storage)
| `GCS_BUCKET` | Google Cloud Storage bucket (only set if using GCP for storage)

*Note: more options can be found here: https://github.com/timvisee/send/blob/master/server/config.js*

## Branding

To change the look the colors aswell as some graphics can be changed via environment variables.  
See the table below for the variables and their default values.

| Name | Default | Description |
|---|---|---|
| UI_COLOR_PRIMARY | #0a84ff | The primary color |
| UI_COLOR_ACCENT | #003eaa | The accent color (eg. for hover-effects) |
| UI_CUSTOM_ASSETS_ANDROID_CHROME_192PX | | A custom icon for Android (192x192px) |
| UI_CUSTOM_ASSETS_ANDROID_CHROME_512PX | | A custom icon for Android (512x512px) |
| UI_CUSTOM_ASSETS_APPLE_TOUCH_ICON | | A custom icon for Apple |
| UI_CUSTOM_ASSETS_FAVICON_16PX | | A custom favicon (16x16px) |
| UI_CUSTOM_ASSETS_FAVICON_32PX | | A custom favicon (32x32px) |
| UI_CUSTOM_ASSETS_ICON | | A custom icon (Logo on the top-left of the UI) |
| UI_CUSTOM_ASSETS_SAFARI_PINNED_TAB | | A custom icon for Safari |
| UI_CUSTOM_ASSETS_FACEBOOK | | A custom header image for Facebook |
| UI_CUSTOM_ASSETS_TWITTER | | A custom header image for Twitter |
| UI_CUSTOM_ASSETS_WORDMARK | | A custom wordmark (Text next to the logo) |
| UI_CUSTOM_CSS | | Allows you to define a custom CSS file for custom styling |
| CUSTOM_FOOTER_TEXT | | Allows you to define a custom footer |
| CUSTOM_FOOTER_URL | | Allows you to define a custom URL in your footer |

Side note: If you define a custom URL and a custom footer, only the footer text will display, but will be hyperlinked to the URL.

### Automatic Installs (Docker)
```
https://github.com/OfficialV4NT/Watchtower
```

## Docker Deployment

Ensure [Docker Engine](https://docs.docker.com/engine/install/) and [Docker Compose](https://docs.docker.com/compose/install/) are installed before beginning.

Run send in production with docker-compose:
```
apt install git
git clone https://github.com/timvisee/send.git
cd send
nano docker-compose.yml
chmod 777 uploads
docker-compose pull
docker-compose up -d
```
Should be running at: http://localhost:1234

Run send in developer with docker-compose:
```
apt install git
git clone https://github.com/timvisee/send.git
cd send
nano docker-compose.yml
chmod 777 uploads
docker-compose up -d --build
```
Should be running at: http://localhost:1234

## Deployment with AWS S3

## AWS requirements

### Security groups (2)

* ALB:
  - inbound: allow traffic from anywhere on port 80 and 443
  - ountbound: allow traffic to the instance security group on port `8080`

* Instance:
  - inbound: allow SSH from your public IP or a bastion (changing the default SSH port is a good idea)
  - inbound: allow traffic from the ALB security group on port `8080`
  - ountbound: allow all traffic to anywhere

### Resources

* An S3 bucket (block all public access)

* A private EC2 instance running Ubuntu `20.04` (you can use the [Amazon EC2 AMI Locator](https://cloud-images.ubuntu.com/locator/ec2/) to find the latest)

  Attach an IAM role to the instance with the following inline policy:

  ```json
  {
      "Version": "2012-10-17",
      "Statement": [
          {
              "Action": [
                  "s3:ListAllMyBuckets"
              ],
              "Resource": [
                  "*"
              ],
              "Effect": "Allow"
          },
          {
              "Action": [
                  "s3:ListBucket",
                  "s3:GetBucketLocation",
                  "s3:ListBucketMultipartUploads"
              ],
              "Resource": [
                  "arn:aws:s3:::<s3_bucket_name>"
              ],
              "Effect": "Allow"
          },
          {
              "Action": [
                  "s3:GetObject",
                  "s3:GetObjectVersion",
                  "s3:ListMultipartUploadParts",
                  "s3:PutObject",
                  "s3:AbortMultipartUpload",
                  "s3:DeleteObject",
                  "s3:DeleteObjectVersion"
              ],
              "Resource": [
                  "arn:aws:s3:::<s3_bucket_name>/*"
              ],
              "Effect": "Allow"
          }
      ]
  }
  ```

* A public ALB:

  - Create a target group with the instance registered (HTTP on port `8080` and path `/`)
  - Configure HTTP (port 80) to redirect to HTTPS (port 443)
  - HTTPS (port 443) using the latest security policy and an ACM certificate like `send.mydomain.com`

* A Route53 public record, alias from `send.mydomain.com` to the ALB

## Software requirements

* Git
* NodeJS `15.x` LTS
* Local Redis server

### Prerequisite packages

```bash
sudo apt update
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common
```

### Add repositories

* NodeJS `15.x` LTS (checkout [package.json](../package.json)):

```bash
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource.gpg.key | sudo apt-key add -
echo 'deb [arch=amd64] https://deb.nodesource.com/node_15.x focal main' | sudo tee /etc/apt/sources.list.d/nodejs.list
```

* Git (latest)

```bash
sudo add-apt-repository ppa:git-core/ppa
```

* Redis (latest)

```bash
sudo add-apt-repository ppa:redislabs/redis
```

### Install required packages

```bash
sudo apt update
sudo apt install git nodejs redis-server telnet
```

### Redis server

#### Password (optional)

Generate a strong password:

```bash
makepasswd --chars=100
```

Edit Redis configuration file `/etc/redis/redis.conf`:

```bash
requirepass <redis_password>
```

_Note: documentation on securing Redis https://redis.io/topics/security_

#### Systemd

Enable and (re)start the Redis server service:

```bash
sudo systemctl enable redis-server
sudo systemctl restart redis-server
sudo systemctl status redis-server
```

## Website directory

Setup a directory for the data

```
sudo mkdir -pv /var/www/send
sudo chown www-data:www-data /var/www/send
sudo 750 /var/www/send
```

### NodeJS

Update npm:

```bash
sudo npm install -g npm
```

Checkout current NodeJS and npm versions:

```bash
node --version
npm --version
```

Clone repository, install JavaScript packages and compiles the assets:

```bash
sudo su -l www-data -s /bin/bash
cd /var/www/send
git clone https://gitlab.com/timvisee/send.git .
npm install
npm run build
exit
```

Create the file `/var/www/send/.env` used by Systemd with your environment variables
(checkout [config.js](../server/config.js) for more configuration environment variables):

```
BASE_URL='https://send.mydomain.com'
NODE_ENV='production'
PORT='8080'
REDIS_PASSWORD='<redis_password>'
S3_BUCKET='<s3_bucket_name>'
```

Lower files and folders permissions to user and group `www-data`:

```
sudo find /var/www/send -type d -exec chmod 750 {} \;
sudo find /var/www/send -type f -exec chmod 640 {} \;
sudo find -L /var/www/send/node_modules/.bin/ -exec chmod 750 {} \;
```

### Systemd

Create the file `/etc/systemd/system/send.service` with `root` user and `644` mode:

```
[Unit]
Description=Send
After=network.target
Requires=redis-server.service
Documentation=https://gitlab.com/timvisee/send

[Service]
Type=simple
ExecStart=/usr/bin/npm run prod
EnvironmentFile=/var/www/send/.env
WorkingDirectory=/var/www/send
User=www-data
Group=www-data
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

_Note: could be better tuner to secure the service by restricting system permissions,
check with `systemd-analyze security send`_

Enable and start the Send service, check logs:

```
sudo systemctl daemon-reload
sudo systemctl enable send
sudo systemctl start send
sudo systemctl status send
journalctl -fu send
```

## Reverse Proxy

## NGINX (Not Docker)

```
server {
  server_name changethis;

    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    ssl_certificate /etc/letsencrypt/live/changethis/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/changethis/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    add_header strict_sni on;
    add_header strict_sni_header on;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy upgrade-insecure-requests;
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options "DENY";
    add_header Clear-Site-Data "cookies";
    add_header Referrer-Policy "no-referrer";
    add_header Permissions-Policy "interest-cohort=(),accelerometer=(),ambient-light-sensor=(),autoplay=(),camera=(),encrypted-media=(),focus-without-user-activation=(),geolocation=(),gyroscope=(),magnetometer=(),microphone=(),midi=(),payment=(),picture-in-picture=(),speaker=(),sync-xhr=(),usb=(),vr=()";
    add_header Cross-Origin-Resource-Policy cross-origin;
    add_header Cross-Origin-Embedder-Policy require-corp;
    add_header Cross-Origin-Opener-Policy unsafe-none;
    resolver 1.1.1.1;
    
    ssl_trusted_certificate /etc/letsencrypt/live/changethis/chain.pem;
    ssl_stapling on;
    ssl_stapling_verify on;

    access_log /dev/null;
    error_log  /dev/null;

   location / {
   # Restoring original visitor IPs (https://www.cloudflare.com/ips-v4)
        # - IPv4
        set_real_ip_from 103.21.244.0/22;
        set_real_ip_from 103.22.200.0/22;
        set_real_ip_from 103.31.4.0/22;
        set_real_ip_from 104.16.0.0/13;
        set_real_ip_from 104.24.0.0/14;
        set_real_ip_from 108.162.192.0/18;
        set_real_ip_from 131.0.72.0/22;
        set_real_ip_from 141.101.64.0/18;
        set_real_ip_from 162.158.0.0/15;
        set_real_ip_from 172.64.0.0/13;
        set_real_ip_from 173.245.48.0/20;
        set_real_ip_from 188.114.96.0/20;
        set_real_ip_from 190.93.240.0/20;
        set_real_ip_from 197.234.240.0/22;
        set_real_ip_from 198.41.128.0/17;

        # - IPv6
        # Restoring original visitor IPs (https://www.cloudflare.com/ips-v6)
        set_real_ip_from 2400:cb00::/32;
        set_real_ip_from 2606:4700::/32;
        set_real_ip_from 2803:f800::/32;
        set_real_ip_from 2405:b500::/32;
        set_real_ip_from 2405:8100::/32;
        set_real_ip_from 2a06:98c0::/29;
        set_real_ip_from 2c0f:f248::/32;

        real_ip_header CF-Connecting-IP;
        real_ip_recursive on;
    
   proxy_pass http://localhost:1234;
   proxy_http_version 1.1;
   proxy_set_header Upgrade $http_upgrade;
   proxy_set_header Connection "Upgrade";
   proxy_set_header Host $host;
   proxy_set_header X-Real-IP $remote_addr;
   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
   proxy_set_header X-Forwarded-Proto $scheme;
   proxy_set_header Host $http_host;
   proxy_pass_header Authorization;
        }
}

server {
  listen 80;
  listen [::]:80;
  server_name changethis;
  return 301 https://changethis$request_uri;
  }
```

### Caddy

Contribute here for anyone that uses caddy, i have no experience in caddy except for nginx or maybe apache. Not even apache anymore, I mainly just use nginx. So for anyone who wants a caddy reverse proxy example just make a pull request.

### Other Reverse Proxies

Samething here, if there others that don't use nginx or caddy, contribute and make a pull request.

## Security Audits

Audit your public or private ```SecureSend Instance``` to make sure your service is hardened against cyberattacks.

- [Cloudflare Radar](https://radar.cloudflare.com/scan)
- [Internet.nl](https://internet.nl/site/)
- [HSTS Preload](https://hstspreload.org/)
- [SSL Labs](https://www.ssllabs.com/ssltest/analyze.html?d=)
- [Security Headers](https://securityheaders.com/?q=&hide=on&followRedirects=on)
- [pagespeed](https://pagespeed.web.dev/)
- [webbkoll](https://webbkoll.dataskydd.net/en)
- [ImmuniWeb](https://www.immuniweb.com/ssl/)
- [Mozilla.org](https://observatory.mozilla.org/)
- [report-uri.com](https://report-uri.com/home/tools)
- [check-your-website.server-daten.de](https://check-your-website.server-daten.de)
- [csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com/)
- [Hardenize](https://www.hardenize.com)
- [OpenWPM](https://github.com/openwpm/OpenWPM)
- [XSS.Report](https://xss.report)

```Make sure to not have any duplicates headers as some we already implemented inside the code```.

## Clients

- Web: [```send```](https://github.com/OfficialV4NT/SecureSend)
- Command-line: [```ffsend```](https://github.com/SecureSend/secure-ffsend)
- Android: [```Android```](#android)
- iOS: [```iOS```](#ios)
- Thunderbird: [```FileLink Provider for Send```](https://github.com/tdulcet/Thunderbird-Send)

#### Android

The android implementation is contained in the `android` directory,
and can be viewed locally for easy testing and editing by running `ANDROID=1 npm
start` and then visiting <http://localhost:8080>. CSS and image files are
located in the `android/app/src/main/assets` directory.

#### iOS

The ios implementation is contained in the `ios` directory,
and can be viewed locally for easy testing and editing by running `IOS=1 npm
start` and then visiting <http://localhost:8080>. CSS and image files are
located in the `ios/app/src/main/assets` directory.

## Automatic Delete Leak Files (Crontab)

# Delete leaked Send upload files older than 7 days (and a bit) every hour
0 * * * * find /usr/share/nginx/send/uploads/ -mmin +10130 -exec rm {} \;

# Uploads have their lifetime in days prefixed, so you can be a little bit smarter with cleaning up:
0 * * * * find /usr/share/nginx/send/uploads/ -name 7-\* -mmin +10130 -exec rm {} \;
0 * * * * find /usr/share/nginx/send/uploads/ -name 1-\* -mmin +1500 -exec rm {} \;

## Encryption

SecureSend uses 256-bit AES-GCM encryption via the [Web Crypto API](https://archive.is/BWjSu) to encrypt files in the browser before uploading them to the server. The code is in [app/keychain.js](https://github.com/V4NT-ORG/SecureSend/blob/main/app/keychain.js).

## Steps

### Uploading

1. A new secret key is generated with `crypto.getRandomValues`
2. The secret key is used to derive more keys via HKDF SHA-256
    - a series of encryption keys for the file, via [ECE](https://tools.ietf.org/html/rfc8188) (AES-GCM)
    - an encryption key for the file metadata (AES-GCM)
    - a signing key for request authentication (HMAC SHA-256)
3. The file and metadata are encrypted with their corresponding keys
4. The encrypted data and signing key are uploaded to the server
5. An owner token and the share url are returned by the server and stored in local storage
6. The secret key is appended to the share url as a [#fragment](https://en.wikipedia.org/wiki/Fragment_identifier) and presented to the UI

### Downloading

1. The browser loads the share url page, which includes an authentication nonce
2. The browser imports the secret key from the url fragment
3. The same 3 keys as above are derived
4. The browser signs the nonce with its signing key and requests the metadata
5. The encrypted metadata is decrypted and presented on the page
6. The browser makes another authenticated request to download the encrypted file
7. The browser downloads and decrypts the file
8. The file prompts the save dialog or automatically saves depending on the browser settings

### Passwords

A password may optionally be set to authenticate the download request. When a password is set the following steps occur.

#### Sender

1. The original signing key derived from the secret key is discarded
2. A new signing key is generated via PBKDF2 from the user entered password and the full share url (including secret key fragment)
3. The new key is sent to the server, authenticated by the owner token
4. The server stores the new key and marks the record as needing a password

#### Downloader

1. The browser loads the share url page, which includes an authentication nonce and indicator that the file requires a password
2. The user is prompted for the password and the signing key is derived
3. The browser requests the metadata using the key to sign the nonce
4. If the password was correct the metadata is returned, otherwise a 401

## Streams

# Web Streams

- API
  - https://developer.mozilla.org/en-US/docs/Web/API/Streams_API
- Reference Implementation
  - https://github.com/whatwg/streams/tree/master/reference-implementation
- Examples
  - https://github.com/mdn/dom-examples/tree/master/streams
- Polyfill
  - https://github.com/MattiasBuelens/web-streams-polyfill

# Encrypted Content Encoding

- Spec
  - https://trac.tools.ietf.org/html/rfc8188
- node.js implementation
  - https://github.com/web-push-libs/encrypted-content-encoding/tree/master/nodejs

# Other APIs

- Blobs
  - https://developer.mozilla.org/en-US/docs/Web/API/Blob
- ArrayBuffers, etc
  - https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer
  - https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array
- FileReader
  - https://developer.mozilla.org/en-US/docs/Web/API/FileReader

# Other

- node.js Buffer browser library
  - https://github.com/feross/buffer
- StreamSaver
  - https://github.com/jimmywarting/StreamSaver.js

## Instances

- [Instances](#instances)
- [Live Status](#live-status)
- [How to use](#how-to-use-cli)
- [Submit changes](#submit-changes)

This page does not give any promises or warranties with regard to instance
security and reliability.

Instance URL | Size<br>limit | Time<br>limit | DL<br>limit | Links/<br>Notes | Country | Version | Uptime<br>(90 days)
--- | ---: | ---: | ---: | --- | ---: | --- | ---
https://send.vis.ee | 2.5GiB | 3 days | 10 | [maintainer](https://github.com/timvisee), [contact](https://timvisee.com/contact) | Netherlands 🇳🇱 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.vis.ee/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794230691-8f60854620eb9d40dae7461e)
https://send.zcyph.cc | 10GiB | 7 days | 100 | [maintainer](https://github.com/zcyph), [contact](mailto:send@zcyph.cc) | Germany 🇩🇪 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.zcyph.cc/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794230695-ef83cfab5f4970c4487ad484)
https://send.ephemeral.land | 8GiB | 28 days | 1,000 | | Germany 🇩🇪 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.ephemeral.land/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794230698-d0fc0e9c893bdb81295c3ae2)
https://send.mni.li | 8GiB | 7 days | 25 | [contact](https://cryptpad.fr/form/#/2/form/view/gj2mDNekg5gf+AKPkTqLGY9W2Fa2rjceLFISeeLZa3Y/) | Germany 🇩🇪 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.mni.li/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794230704-256d7241d3fc3712ed74671c)
https://send.monks.tools | 5GiB | 7 days | 50 | | United States 🇺🇸 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.monks.tools/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794230706-152180f0f00c3516167167fd)
https://send.boblorange.net | 2.5GiB | 7 days | 100 | | Portugal 🇵🇹 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.boblorange.net/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794230709-6647754935bde8c9e48f74b0)
https://send.aurorabilisim.com | 2.5GiB | 7 days | 100 | [contact](https://www.aurorabilisim.com/iletisim/) | Turkey 🇹🇷 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.aurorabilisim.com/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794230712-50b203eb6aba33e7ed9f35a4)
https://send.artemislena.eu | 2.5GiB | 7 days | 100 | [contact](https://artemislena.eu/contact.html) | Germany 🇩🇪 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.artemislena.eu/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794230717-7d15b7ccd3aa5630bba41a8a)
https://send.datahoarder.dev | 1GiB | 1 day | 5 | [maintainer](https://github.com/whalehub), [contact](mailto:admin@datahoarder.dev) | Luxembourg 🇱🇺 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.datahoarder.dev/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794230721-b9f403d93360e8d40a50128d)
https://fileupload.ggc-project.de | 2.5GiB | 7 days | 100 | | Germany 🇩🇪 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://fileupload.ggc-project.de/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794230727-a652ecfbd4604f532e0ff48c)
https://drop.chapril.org | 1GiB | 5 days | 100 | [contact](https://www.chapril.org/contact.html) | Germany 🇩🇪 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://drop.chapril.org/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794230729-fd070e4aa8a6601035d9425a)
https://send.jeugdhulp.be | 50MiB | 10 days | 25 | [contact](https://www.jeugdhulp.be/contact) | France 🇫🇷 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.jeugdhulp.be/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794230732-350359a789fe5d02bdb5ad6d)
https://files.psu.ru | 16GiB | 7 days | 500 | no password | Russia 🇷🇺 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://files.psu.ru/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794230735-2d39e5d423d54366178406da)
https://send.portailpro.net | 10GiB | 30 days | 100 | | France 🇫🇷 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.portailpro.net/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794230737-577e6bfd57f73d339fd6554f)
https://transfer.acted.org | 5GiB | 14 days | 3,000 | | France 🇫🇷 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://transfer.acted.org/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794230739-463fdbc2d9c115069d8db1f1)
https://send.datenpost.app | 30GiB | 7 days | 3 | [contact](mailto:info@webality.de) | Germany 🇩🇪 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.datenpost.app/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794230691-8f60854620eb9d40dae7461e)
https://send.angelic.icu | 2.5GiB | 7 days | 50 | [contact](mailto:me@angelic.icu) | Romania 🇷🇴 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.angelic.icu/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794230747-a87dcbdff5b01eb9c5f92b6c)
https://s.opnxng.com | 2.5GiB | 7 days | 25 | [contact](https://about.opnxng.com/) | Singapore 🇸🇬 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://s.opnxng.com/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794398378-baf9f42c4a7e416bc51f5ba0)
https://send.whateveritworks.org | 10GiB | 7 days | 100 | [contact](https://www.whateveritworks.org/email) | Germany 🇩🇪 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.whateveritworks.org/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794407638-626e4c3452c6933ad106a402)
https://send.cyberjake.xyz | 10GiB | 30 days | 1000 | [contact](mailto:connect@cyberjake.xyz) | United States 🇺🇸 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.cyberjake.xyz/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794455795-2d6b721c8e5dfcc8dcdae877)
https://send.kokomo.cloud | 2.5GiB | 7 days | 100 | [maintainer](https://github.com/kokomo123), [contact](mailto:admin@kokomo.cloud) | United States 🇺🇸 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.kokomo.cloud/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794630156-5be85f191fc02e133c49732f)
https://send.adminforge.de | 8GiB | 7 days | 1,000 | | Germany 🇩🇪 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.adminforge.de/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794906532-6e73246019e2869040265ed5)
https://send.turingpoint.de | 2GiB | 7 days | 10 | | Germany 🇩🇪 | ![version](https://img.shields.io/badge/dynamic/json?label=version&query=version&url=https://send.turingpoint.de/__version__) | ![Uptime (90 days)](https://img.shields.io/uptimerobot/ratio/90/m794987552-6ad4b750a79fc8140bbf8c97)

Users can view the historic reliability of the Send instances on [this status page](https://stats.uptimerobot.com/5917xHMX01). Click each instance on that page for more details.

If you plan to host it publicly, please consider to add it to this list.

## How to Use ```CLI```
To use a specific instance from the command line with [ffsend][ffsend], provide
the `--host URL` flag while uploading.

```
# ffsend upload to custom host
ffsend upload --host https://send.vis.ee/ test.zip
```

## Submit changes

To submit changes to this list, please open a pull request or issue.

[send]: https://github.com/timvisee/send
[ffsend]: https://github.com/timvisee/ffsend

## Live Status

See Uptime Liability Send Instances: [here](https://github.com/tdulcet/send-instances-status)

## Acceptance Mobile

# Send V2 UX Mobile Acceptance and Spec Annotations

`Date Created: 8/20/2018`

## Acceptance Criteria

Adapted from [this spreadsheet](https://airtable.com/shrkcBPOLkvNFOrpp)

- [ ] It should look and feel of an Android App
- [ ] It should look and feel like the Send Web Client

### Main Screen
- [ ] It should clearly Indicate the name of the product
- [ ] If user has no existing Sends, it should make clear the primary benefits of the service (private, e2e encrypted, self-destructing file sharing)
- [ ] It should allow users to access the file picker to create Send links
- [ ] If the user has existing Sends, it should display a card-based list view of each [see Cards section below]

### Non-Authenticated Users
- [ ] It should make clear the benefits of a Firefox Account
- [ ] It should allow users to log into or create a Firefox account
- [ ] It should allow users to select and send multiple files in one URL
- [ ] It should limit the sendable file size to 1GB
- [ ] It should allow users to set an expiration time of 5 minutes, 1 hour, or 24 hours
- [ ] It should allow users to set a download count of 1 downloads

### Authenticated Users
- [ ] It should indicate that the user is signed in via Firefox Account
- [ ] It should allow the user to sign out
- [ ] It should allow users to select and send multiple files in one URL
- [ ] It should limit users to sending 2.5GB per Send
- [ ] It should allow users to extend Send times up to 1 Week
- [ ] It should allow users to extend Send download counts up to 100 times

### Cards
- [ ] It should display the name of the sent file/files
- [ ] It should display the time remaining before expiration
- [ ] It should display the number of downloads remaining before expiration
- [ ] It should have a button that lets the user copy the send link to their clipboard
- [ ] It should show a preview icon (not a thumbnail) that has some relationship to the file types or content being sent* (see 5.1 in spec)
- [ ] It should have an overflow (meatball) menu that when triggered, gives the user share or delete buttons
- [ ] While encrypting / pushing to server, it should display a progress meter and a cancel button
- [ ] For authenticated users, it should be expandable to display all files in a send (5.1.1)
- [ ] If user cancels Send, or Upload fails, it should display a warning in the card
- [ ] It should display expired Sends below current sends with their UI greyed out and an expiration warning for 24 hours after expiration
- [ ] It should remove expired cards from display after 24 hours
- [ ] It should let users permanently delete records expired sends
- [ ] It should display a visual indicator when a Send is password protected
- [ ] It should allow the user to share via a native Android share sheet
- [ ] It should allow me to create Send links through intents from other apps

### General/other
- [ ] It should allow users to set passwords to protect their Sends
- [ ] It should warn users when they are trying to upload files larger than their share limit

### Stretch
- [ ] It should allow users to use the photo gallery to create Send links
- [ ] It should allow users to use their camera to create Send links
- [ ] It should allow users to opt into notification when a share link expires
- [ ] It should allow users to opt into notifications when their link is downloaded

## Annotations on Mobile Spec
This document tracks differences between the UX spec for Send and the intended MVP.

[Spec Link](https://mozilla.invisionapp.com/share/GNN6KKOQ5XS)

* 1.1: Spec describes toolbar which may not be possible given the application framework we're using. In particular, issues with the spec include the color, logo and different font weights may be an issue.
* 1.2: Spec's treatment of FxA UI may be difficult to match. We should use the default OAuth implementation and re-evaluate UX once we see an implementation demo. Also, the landing page UI should display a log-in CTA directly and not require users click into the hamburger menu.
* 2.1: MVP will only include file picker. Signed in users will be able to select multiple files. File selection flow will be Android-native. Probably don't have the ability to add notifications as in the last screen on this page.
* 2.1: @fzzzy will provide screenshots of this flow for UX evaluation and comment.
* 3.1.4: The spec shows deleting the last item in an unshared set returning the user to the picker menu. Instead, it should return to the app home page.
* 3.1.5: Same as 3.1.5 notes. Both cases should show the warning dialog.
* 4.1: We may not be able to do a thumbnail here. Instead we should specify a set of icons to be displayed.
* 6.3: We're not going to allow cards to be edited. This page is deprecated.
* 6.4: Swiping cards to delete is stretched.
* 6.5: We're not 100% sure what happens on network connectivity errors, we should test this and adapt UX as necessary.
* 7.1: The last screen on this page depicts a network error notification on the selection screen. Instead the user should hit the send button, be taken back to the cards and display the card as in 5.1.2
* 7.3: May not be necessary...we can ask for permissions on install.
* 8.1: Notifications do not block launch

## Acceptance Web

# Send V2 UX Web Acceptance Criteria

## General

- [ ] It should match the spec provided.
- [ ] It should have a feedback button
- [ ] It should provide links to relevant legal documentation

### Non-Authenticated Users

- [ ] It should make clear the benefits of a Firefox Account
- [ ] It should allow users to log into or create a Firefox account
- [ ] It should allow users to select and send multiple files in one URL
- [ ] It should limit the sendable file size to 1GB
- [ ] It should allow users to set an expiration time of 5 minutes, 1 hour, or 24 hours
- [ ] It should allow users to set an download count of 1 downloads

### Authenticated Users

- [ ] It should indicate that the user is signed in via Firefox Account
- [ ] It should allow the user to sign out
- [ ] It should allow users to select and send multiple files in one URL
- [ ] It should limit users to sending 2.5GB per Send
- [ ] It should allow users to extend Send times up to 1 Week
- [ ] It should allow users to extend Send download counts up to 100 times

### Main Screen

- [ ] It should clearly indicate the name of the product
- [ ] If user has no existing Sends, it should make clear the primary benefits of the service (private, e2e encrypted, self-destructing file sharing)
- [ ] It should allow users to access the file picker to create Send links
- [ ] It should allow users to drag and drop files
- [ ] It should provide affordances to sign in to Send
- [ ] If the user has existing Sends, it should display a card-based list view of each

### Upload UI

- [ ] It should allow users to continue to add files to their upload up to a set limit
- [ ] It should allow users to set a password
- [ ] It should let users delete items from their upload bundle

### Uploading UI

- [ ] It should display an affordance to demonstrate the status of an upload

### Share UI

- [ ] It should provide a copiable URL to the bundle

### Download UI

- [ ] It should prompt the user for a password if one is required
- [ ] It should provide feedback for incorrect passwords
- [ ] It should provide a description of Send to make clear what this service is
- [ ] It should let the user see the files they are downloading
- [ ] It should let the user download their files

### Download Complete UI

- [ ] It should indicate that a download is complete
- [ ] It should provide a description of the Send service
- [ ] It should provide a link back to the upload UI

### Expiry UI

- [ ] It should provide a generic message indicating a share has expired
- [ ] It should allow the user to navigate back to the upload page

### In Memory DL Page

- [ ] It should show in case a user tries to download a large file on a suboptimal client
- [ ] It should suggest the user use Firefox
- [ ] It should let the user copy the download url

## CHANGELOGS

### v2.5.5 (2025/03/08 19:26 +00:00)

- Upgrade encryption from 128 to 256 GCM
- Fixed outdated dependencies
- Added Raspberry Pi ARMv8 Docker Support
- Fixed up the security policy
- Moved the wiki to the README.md again to make everything more organized and simple
- 

### v2.5.4 (2023/07/24 19:26 +00:00)
- Renamed LICENSE to LICENSE.md and Changed to AGPL-3.0
- Updated Dependencies
- Optimized code to understand
- Added example nginx.conf
- Harden docker-compose.yml
- Added SECURITY.md Policy
- Updated Nodejs & Optimized Dockerfile
- Optimzed README.md

### v2.5.1 (2018/03/12 19:26 +00:00)
- [#789](https://github.com/mozilla/send/pull/789) Fixed #775 : Made text not-selectable (@RCMainak)

### v2.5.0 (2018/03/08 19:31 +00:00)
- [#782](https://github.com/mozilla/send/pull/782) updated docs (@dannycoates)
- [#781](https://github.com/mozilla/send/pull/781) Don't translate URL-safe chars, b64 is doing it for us (@timvisee)
- [#779](https://github.com/mozilla/send/pull/779) implemented crypto polyfills for ms edge (@dannycoates)

### v2.4.1 (2018/02/28 17:05 +00:00)
- [#777](https://github.com/mozilla/send/pull/777) use a separate circle in the progress svg for indefinite progress (@dannycoates)

### v2.4.0 (2018/02/27 01:55 +00:00)
- [#769](https://github.com/mozilla/send/pull/769) removed unsafe-inline styles via svgo-loader (@dannycoates)
- [#767](https://github.com/mozilla/send/pull/767) added coverage artifact to circleci (@dannycoates)
- [#766](https://github.com/mozilla/send/pull/766) Some frontend unit tests [WIP] (@dannycoates)
- [#761](https://github.com/mozilla/send/pull/761) added maxPasswordLength and passwordError messages (@dannycoates)
- [#764](https://github.com/mozilla/send/pull/764) added indefinite progress mode (@dannycoates)
- [#760](https://github.com/mozilla/send/pull/760) refactored css: phase 1 (@dannycoates)
- [#759](https://github.com/mozilla/send/pull/759) Switch en-US FTL file to new syntax (@flodolo)
- [#758](https://github.com/mozilla/send/pull/758) refactored server (@dannycoates)
- [#757](https://github.com/mozilla/send/pull/757) Update to fluent 0.4.3 (@stasm)

### v2.3.0 (2018/02/01 23:27 +00:00)
- [#536](https://github.com/mozilla/send/pull/536) use redis expire event to delete stored data immediately (@ehuggett)
- [#744](https://github.com/mozilla/send/pull/744) Gradient experiment (@dannycoates)
- [#739](https://github.com/mozilla/send/pull/739) added /api/info/:id route (@dannycoates)
- [#737](https://github.com/mozilla/send/pull/737) big refactor (@dannycoates)
- [#722](https://github.com/mozilla/send/pull/722) Add localization note to 'Time' and 'Downloads' string (@flodolo)
- [#721](https://github.com/mozilla/send/pull/721) show download Limits on page; Fixes #661 (@shikhar-scs)
- [#694](https://github.com/mozilla/send/pull/694) Passwords can now be changed (#687) (@himanish-star)
- [#702](https://github.com/mozilla/send/pull/702) Restricted the banner from showing on unsupported browsers (@himanish-star)
- [#701](https://github.com/mozilla/send/pull/701) improved popup for mobile display; Fixes #699 (@shikhar-scs)
- [#683](https://github.com/mozilla/send/pull/683) API changes to accommodate 3rd party clients (@ehuggett)
- [#698](https://github.com/mozilla/send/pull/698) Popup for delete button attached (@himanish-star)
- [#695](https://github.com/mozilla/send/pull/695) Show Warning, Cancel and Redirect on size > 2GB ; fixes #578 (@shikhar-scs)
- [#684](https://github.com/mozilla/send/pull/684) delete btn popup attached (@himanish-star)
- [#686](https://github.com/mozilla/send/pull/686) Hide password while Typing and after Entering: Fixes #670 (@shikhar-scs)
- [#679](https://github.com/mozilla/send/pull/679) changed font to sans sherif: Solves #676 (@shikhar-scs)
- [#693](https://github.com/mozilla/send/pull/693) README: Fix query link for "good first bugs" (@jspam)
- [#685](https://github.com/mozilla/send/pull/685) checkbox now has a hover effect: fixes #635 (@himanish-star)
- [#668](https://github.com/mozilla/send/pull/668) Add possibility to bind to a specific IP address (@TwizzyDizzy)
- [#682](https://github.com/mozilla/send/pull/682) [Docs] - README.md - minor spelling fixes (@tmm2018)
- [#672](https://github.com/mozilla/send/pull/672) Use EXPIRE_SECONDS to calculate file ttl for static content (@derektamsen)
- [#680](https://github.com/mozilla/send/pull/680) adjusted line height of label : fixes #609 (@himanish-star)

### v2.2.2 (2017/12/19 18:06 +00:00)
- [#667](https://github.com/mozilla/send/pull/667) Make develop the default NODE_ENV (@claudijd)

### v2.2.1 (2017/12/08 18:00 +00:00)
- [#665](https://github.com/mozilla/send/pull/665) stop drag target from flickering when dragging over children (@ericawright)

### v2.2.0 (2017/12/06 23:57 +00:00)
- [#654](https://github.com/mozilla/send/pull/654) Multiple download UI (@dannycoates)
- [#650](https://github.com/mozilla/send/pull/650) #634: overwrite appearance of password submit input (@ovlb)
- [#649](https://github.com/mozilla/send/pull/649) #609 share interface: align text in input and button (@ovlb)

### v2.1.2 (2017/11/16 19:03 +00:00)
- [#645](https://github.com/mozilla/send/pull/645) Remove the leak of the password into the console (@laurentj)

### v2.1.0 (2017/11/15 03:07 +00:00)
- [#641](https://github.com/mozilla/send/pull/641) Added experiment for firefox download promo (@dannycoates)
- [#640](https://github.com/mozilla/send/pull/640) use fluent-langneg for subtag support (@dannycoates)
- [#639](https://github.com/mozilla/send/pull/639) wrap number localization in try/catch (@dannycoates)

### v2.0.0 (2017/11/08 05:31 +00:00)
- [#633](https://github.com/mozilla/send/pull/633) Keyboard navigation/visual feedback regression (@ehuggett)
- [#632](https://github.com/mozilla/send/pull/632) display the 'add password' button only when the input field isn't empty (@dannycoates)
- [#626](https://github.com/mozilla/send/pull/626) Partial fix for #623 (@ehuggett)
- [#624](https://github.com/mozilla/send/pull/624) set a default MIME type in file metadata (@ehuggett)
- [#612](https://github.com/mozilla/send/pull/612) Password UI nits (@dannycoates, @ericawright)
- [#617](https://github.com/mozilla/send/pull/617) allow drag and drop if navigating from shared page (@ericawright)
- [#608](https://github.com/mozilla/send/pull/608) disable copying link when password not completed (@ericawright)
- [#605](https://github.com/mozilla/send/pull/605) align the "Password" and "Copy to clipboard" fields. (@ericawright)
- [#582](https://github.com/mozilla/send/pull/582) Add optional password to the download url (@dannycoates)

### v1.2.4 (2017/10/10 17:34 +00:00)
- [#583](https://github.com/mozilla/send/pull/583) Promote the beefy UI to default (@dannycoates)
- [#581](https://github.com/mozilla/send/pull/581) introducing ToC to README.md (@tmm2018)
- [#579](https://github.com/mozilla/send/pull/579) Hide cancel button when upload reaches 100% (@ericawright)
- [#580](https://github.com/mozilla/send/pull/580) Change Favicon in to look better in a variety of cases (@ericawright)
- [#571](https://github.com/mozilla/send/pull/571) Centre logo (@ehuggett)
- [#574](https://github.com/mozilla/send/pull/574) Make upload button focusable (accessibility/tab navigation) (@ehuggett)

### v1.2.0 (2017/09/12 22:42 +00:00)
- [#559](https://github.com/mozilla/send/pull/559) added first A/B experiment (@dannycoates)
- [#542](https://github.com/mozilla/send/pull/542) fix docker link typo (@ehuggett)
- [#541](https://github.com/mozilla/send/pull/541) removed .title and .alt attributes from ftl (@dannycoates)
- [#537](https://github.com/mozilla/send/pull/537) a few changes to make A/B testing easier (@dannycoates)
- [#533](https://github.com/mozilla/send/pull/533) minor UI fixes (@youwenliang)
- [#531](https://github.com/mozilla/send/pull/531) Add CHANGELOG script (@pdehaan)
- [#535](https://github.com/mozilla/send/pull/535) Fixed minimum NodeJS version in README (@LuFlo)
- [#528](https://github.com/mozilla/send/pull/528) adding separators to README (@tmm2018)

### v1.1.1 (2017/08/17 01:29 +00:00)
- [#516](https://github.com/mozilla/send/pull/516) cache assets (@dannycoates)
- [#520](https://github.com/mozilla/send/pull/520) fix drag & drop (@dannycoates)
- [#515](https://github.com/mozilla/send/pull/515) removed jquery from upload.js (@dannycoates)
- [#514](https://github.com/mozilla/send/pull/514) use async and removed jquery from download.js (@dannycoates)
- [#513](https://github.com/mozilla/send/pull/513) use svg for progress (@dannycoates)
- [#510](https://github.com/mozilla/send/pull/510) added precommit hook for format (@dannycoates)
- [#502](https://github.com/mozilla/send/pull/502) extracted filelist into its own file (@dannycoates)
- [#428](https://github.com/mozilla/send/pull/428) add twitter and open graph cards (@dannycoates, @johngruen)
- [#506](https://github.com/mozilla/send/pull/506) 404 page (@varghesethomase)
- [#508](https://github.com/mozilla/send/pull/508) fixes 478 (@abhinadduri)
- [#504](https://github.com/mozilla/send/pull/504) fix japanese browse button (@johngruen)
- [#503](https://github.com/mozilla/send/pull/503) Added editorconfig (@skystar-p)
- [#499](https://github.com/mozilla/send/pull/499) use import/export in the frontend code (@dannycoates)
- [#500](https://github.com/mozilla/send/pull/500) fixed build:css on windows (@dannycoates)
- [#481](https://github.com/mozilla/send/pull/481) Cater for mobile and desktop (@pdehaan, @hubdotcom)
- [#493](https://github.com/mozilla/send/pull/493) added webpack-dev-middleware (@dannycoates)
- [#491](https://github.com/mozilla/send/pull/491) added missing exit event cases (@dannycoates)
- [#492](https://github.com/mozilla/send/pull/492) make the site mostly work when cookies (localStorage) are disabled (@dannycoates)
- [#490](https://github.com/mozilla/send/pull/490) set the mime type in the download blob (@dannycoates)
- [#485](https://github.com/mozilla/send/pull/485) added progress to tab title when not in focus (@dannycoates)
- [#474](https://github.com/mozilla/send/pull/474) Fixing bug #438 by adding role attribute to anchor tags and alt attribute images (@varghesethomase)
- [#480](https://github.com/mozilla/send/pull/480) Increase font weight to 500 on <button>s and <label>s (@pdehaan)
- [#419](https://github.com/mozilla/send/pull/419) Add autoprefixer and cssnano support (@pdehaan)

### v1.1.0 (2017/08/08 03:59 +00:00)
- [#473](https://github.com/mozilla/send/pull/473) Sort contributors alphabetically to prevent churn (@pdehaan)
- [#472](https://github.com/mozilla/send/pull/472) removed references to checksums in frontend tests (@abhinadduri)
- [#470](https://github.com/mozilla/send/pull/470) removed the file sha256 hash (@dannycoates)
- [#469](https://github.com/mozilla/send/pull/469) Increase mimimum node version to 8.2.0 (@ehuggett)
- [#468](https://github.com/mozilla/send/pull/468) attach delete-file handler only after upload (@dannycoates)
- [#466](https://github.com/mozilla/send/pull/466) added webpack (@dannycoates)
- [#427](https://github.com/mozilla/send/pull/427) Extended system font list fixes:#408 (@gautamkrishnar)
- [#448](https://github.com/mozilla/send/pull/448) Migrate width attribute to CSS (Fixes #436) (@nskins)
- [#457](https://github.com/mozilla/send/pull/457) factored out progress into progress.js (@dannycoates)
- [#452](https://github.com/mozilla/send/pull/452) refactored metrics (@dannycoates)
- [#455](https://github.com/mozilla/send/pull/455) Add a few missing strings from es-CL and tr locales (@pdehaan)
- [#444](https://github.com/mozilla/send/pull/444) Chain jQuery calls, do not use events alias and store selectors (@Johann-S)
- [#416](https://github.com/mozilla/send/pull/416) WIP: use webcrypto-liner to support Safari 10 (@dannycoates)
- [#451](https://github.com/mozilla/send/pull/451) Add rel noopener noreferrer to target='_blank' anchor elements (Fixes #439) (@boopeshmahendran)
- [#449](https://github.com/mozilla/send/pull/449) Add X-UA-Compatible meta tag (@kenrick95)
- [#433](https://github.com/mozilla/send/pull/433) Prevent download button from being clicked multiple times (@pdehaan)
- [#432](https://github.com/mozilla/send/pull/432) Add contributors script (@pdehaan)
- [#409](https://github.com/mozilla/send/pull/409) Handle copy clipboard disabled (@Johann-S)

### v1.0.4 (2017/08/03 23:05 +00:00)
- [#418](https://github.com/mozilla/send/pull/418) _blank all footer links (@dannycoates)
- [#386](https://github.com/mozilla/send/pull/386) fix percentage view on mobile layout (@ariestiyansyah)
- [#414](https://github.com/mozilla/send/pull/414) Add link to FAQ in unsupported view (@pdehaan)
- [#415](https://github.com/mozilla/send/pull/415) Only include Fira CSS on /unsupported/* route (@pdehaan)
- [#412](https://github.com/mozilla/send/pull/412) throw key errors before download begins (@dannycoates)
- [#404](https://github.com/mozilla/send/pull/404) Use async function instead of promise (#325) (@weihanglo)
- [#406](https://github.com/mozilla/send/pull/406) Add noscript tag (@pdehaan)
- [#325](https://github.com/mozilla/send/pull/325) Use async function instead of promise (#325) (@weihanglo)
- [#325](https://github.com/mozilla/send/pull/325) Use async function instead of promise (#325) (@weihanglo)

### v1.0.3 (2017/08/02 23:59 +00:00)
- [#402](https://github.com/mozilla/send/pull/402) filter the hash from error reports (@dannycoates)
- [#400](https://github.com/mozilla/send/pull/400) fix link that breaks download by opening in new tab (@johngruen)
- [#369](https://github.com/mozilla/send/pull/369) Add ESLint no-alert shame rule (@pdehaan)
- [#396](https://github.com/mozilla/send/pull/396) add babel-polyfill (@dannycoates)
- [#394](https://github.com/mozilla/send/pull/394) catch JSON.parse errors of storage metadata (@dannycoates)
- [#367](https://github.com/mozilla/send/pull/367) Generate production locales using 'compare-locales' (@pdehaan)
- [#392](https://github.com/mozilla/send/pull/392) Adjust hover behavior on send-logo (#382)
 Fixes: #382. (@weihanglo)
- [#382](https://github.com/mozilla/send/pull/382) Adjust hover behavior on send-logo (#382) (@weihanglo)
- [#382](https://github.com/mozilla/send/pull/382) Adjust hover behavior on send-logo (#382) (@weihanglo)
- [#380](https://github.com/mozilla/send/pull/380) Add Pontoon URL to README (@pdehaan)

### v1.0.2 (2017/07/31 18:58 +00:00)
- [#365](https://github.com/mozilla/send/pull/365) revert the IE fix to fix footer on chrome (@dannycoates)

### v1.0.1 (2017/07/31 17:28 +00:00)
- [#353](https://github.com/mozilla/send/pull/353) redirect ie to /unsupported (@abhinadduri, @dannycoates)
- [#360](https://github.com/mozilla/send/pull/360) Fix some linting nits (@pdehaan)
- [#362](https://github.com/mozilla/send/pull/362) Adjusts category of unsupported event (fixes #350). (@chuckharmston)
- [#355](https://github.com/mozilla/send/pull/355) Make order of uploaded files in list consistent (@pdehaan)
- [#356](https://github.com/mozilla/send/pull/356) Get rid of console.log statements (@pdehaan)
- [#358](https://github.com/mozilla/send/pull/358) Fix some missing .title attributes in dev-only locales (@pdehaan)
- [#354](https://github.com/mozilla/send/pull/354) Remove /en-US/ from cookies link in footer (@pdehaan)
- [#339](https://github.com/mozilla/send/pull/339) Show error page on firefox v49 and below (@ericawright, @abhinadduri)
- [#346](https://github.com/mozilla/send/pull/346) Add docs/CODEOWNERS file (@pdehaan)
- [#345](https://github.com/mozilla/send/pull/345) wrap long file names (@dnarcese)
- [#344](https://github.com/mozilla/send/pull/344) don't wrap file list headers (@dnarcese)
- [#327](https://github.com/mozilla/send/pull/327) Modify popup delete dialog (@youwenliang)
- [#341](https://github.com/mozilla/send/pull/341) center percentage text on all browser versions (@dnarcese)
- [#340](https://github.com/mozilla/send/pull/340) Remove duplicate entities in localized FTL files (@flodolo)
- [#337](https://github.com/mozilla/send/pull/337) support v 50 and 51 by not allowing const in loops (@ericawright)
- [#338](https://github.com/mozilla/send/pull/338) Remove duplicated strings in en-US, fix nn-NO file (@flodolo)
- [#336](https://github.com/mozilla/send/pull/336) German(de): Fixed missing value for deleteFileButton (#336) (@flodolo)
- [#334](https://github.com/mozilla/send/pull/334) fix functionality on firefox 50 and 51 (@dnarcese)

### v1.0.0 (2017/07/26 19:08 +00:00)
- [#323](https://github.com/mozilla/send/pull/323) disable upload/download notifications (@dannycoates)
- [#322](https://github.com/mozilla/send/pull/322) fix feedback button jump (@dnarcese)
- [#320](https://github.com/mozilla/send/pull/320) fix German footer (@dnarcese)

### v0.2.2 (2017/07/26 04:50 +00:00)
- [#314](https://github.com/mozilla/send/pull/314) added L10N_DEV environment variable for making all languages available (@dannycoates)
- [#313](https://github.com/mozilla/send/pull/313) removing timeout limit for front end tests (@abhinadduri)
- [#311](https://github.com/mozilla/send/pull/311) expired ids should reject instead of returning null (@dannycoates)
- [#302](https://github.com/mozilla/send/pull/302) UX Refine WIP (@youwenliang)
- [#310](https://github.com/mozilla/send/pull/310) if the download card is pressed, the expired card shows up properly (@abhinadduri)
- [#269](https://github.com/mozilla/send/pull/269) refactored ftl file (@abhinadduri)
- [#291](https://github.com/mozilla/send/pull/291) added legal page (@dannycoates)
- [#307](https://github.com/mozilla/send/pull/307) don't show error page on upload cancel (@dnarcese)
- [#299](https://github.com/mozilla/send/pull/299) use CIRCLE_TAG as version.json version if present (@dannycoates)

### v0.2.1 (2017/07/24 23:34 +00:00)
- [#296](https://github.com/mozilla/send/pull/296) restyle delete popup (@dnarcese)
- [#295](https://github.com/mozilla/send/pull/295) renamed environment variables to remove P2P_ prefix (@dannycoates)
- [#294](https://github.com/mozilla/send/pull/294) dealing with invalid drag and drops (@abhinadduri)
- [#297](https://github.com/mozilla/send/pull/297) added environment variable for expire time (@dannycoates)
- [#292](https://github.com/mozilla/send/pull/292) Fixes289 (@abhinadduri)
- [#288](https://github.com/mozilla/send/pull/288) fix: Don`t allow upload when not on the upload page. (@ericawright)
- [#285](https://github.com/mozilla/send/pull/285) added messages for processing phases (@dannycoates)
- [#267](https://github.com/mozilla/send/pull/267) make site responsive and add feedback link (@johngruen)
- [#286](https://github.com/mozilla/send/pull/286) Update download progress bar color (@pdehaan)
- [#281](https://github.com/mozilla/send/pull/281) Stop ESLint from linting the /public/ directory (@pdehaan)
- [#280](https://github.com/mozilla/send/pull/280) created /unsupported page and added gcmCompliant to /download page (@dannycoates)
- [#279](https://github.com/mozilla/send/pull/279) create separate js bundles for upload/download pages (@dannycoates)
- [#268](https://github.com/mozilla/send/pull/268) Testpilot ga (@abhinadduri)

### v0.2.0 (2017/07/21 19:27 +00:00)
- [#266](https://github.com/mozilla/send/pull/266) abort uploads over maxfilesize (@dannycoates)
- [#264](https://github.com/mozilla/send/pull/264) Remove duplicate custom metric. (@chuckharmston)
- [#259](https://github.com/mozilla/send/pull/259) add alert when uploading multiple files (@dnarcese)
- [#262](https://github.com/mozilla/send/pull/262) sync download progress bar with percentage (@dnarcese)
- [#258](https://github.com/mozilla/send/pull/258) better sync percent with progress bar (@dnarcese)
- [#257](https://github.com/mozilla/send/pull/257) add a dynamic js script for page config (@dannycoates)
- [#256](https://github.com/mozilla/send/pull/256) add file size limit message (@dnarcese)
- [#253](https://github.com/mozilla/send/pull/253) Add favicon.ico version of the Send logo (@pdehaan)
- [#254](https://github.com/mozilla/send/pull/254) Add nsp check to circle ci (@pdehaan)
- [#245](https://github.com/mozilla/send/pull/245) Localization (@abhinadduri)
- [#252](https://github.com/mozilla/send/pull/252) only allow drag and drop on upload page (@dnarcese)
- [#250](https://github.com/mozilla/send/pull/250) make footer not overlap (@dnarcese)
- [#251](https://github.com/mozilla/send/pull/251) minify all images (@ericawright)
- [#249](https://github.com/mozilla/send/pull/249) change how the file upload box expands (@dnarcese)
- [#246](https://github.com/mozilla/send/pull/246) remove P2P references.  Fixes #224 (@clouserw)
- [#242](https://github.com/mozilla/send/pull/242) Make only icons clickable in file list (@dnarcese)
- [#236](https://github.com/mozilla/send/pull/236) add FAQ. Fixes #186 (@clouserw)
- [#235](https://github.com/mozilla/send/pull/235) allow send another file link to open in new tab (@dnarcese)
- [#234](https://github.com/mozilla/send/pull/234) fix download svg (@dnarcese)
- [#232](https://github.com/mozilla/send/pull/232) escape filename in the ui (@dannycoates)
- [#226](https://github.com/mozilla/send/pull/226) added functionality to cancel uploads (@abhinadduri)
- [#231](https://github.com/mozilla/send/pull/231) move head and html tags to main template (@dnarcese)
- [#228](https://github.com/mozilla/send/pull/228) add send logo (@dnarcese)
- [#229](https://github.com/mozilla/send/pull/229) change learn more and github links (@dnarcese)
- [#201](https://github.com/mozilla/send/pull/201) Adds metrics documentation (closes #5). (@chuckharmston)
- [#223](https://github.com/mozilla/send/pull/223) change size of send another file links (@dnarcese)
- [#222](https://github.com/mozilla/send/pull/222) add footer (@dnarcese)
- [#197](https://github.com/mozilla/send/pull/197) fixes issues 195 and 192 (@abhinadduri)
- [#204](https://github.com/mozilla/send/pull/204) added HSTS header (@dannycoates)
- [#193](https://github.com/mozilla/send/pull/193) Frontend tests (@abhinadduri)
- [#191](https://github.com/mozilla/send/pull/191) New ui! (@dnarcese)

### v0.1.4 (2017/07/12 18:21 +00:00)
- [#189](https://github.com/mozilla/send/pull/189) Add CSP directives (@dannycoates)
- [#188](https://github.com/mozilla/send/pull/188) fixes delete button error (@abhinadduri)
- [#185](https://github.com/mozilla/send/pull/185) added loading, hashing, and encrypting events for uploader; decryptin… (@abhinadduri)
- [#183](https://github.com/mozilla/send/pull/183) rename to 'Send' (@dannycoates)
- [#184](https://github.com/mozilla/send/pull/184) Server tests (@abhinadduri)
- [#178](https://github.com/mozilla/send/pull/178) fixed issues in branch title (@abhinadduri)
- [#177](https://github.com/mozilla/send/pull/177) Gcm compliance (@abhinadduri)
- [#106](https://github.com/mozilla/send/pull/106) Gcm (@abhinadduri, @dannycoates)
- [#168](https://github.com/mozilla/send/pull/168) Show error page if upload fails (@dnarcese)
- [#148](https://github.com/mozilla/send/pull/148) WIP: Add basic contribute.json (@pdehaan)
- [#162](https://github.com/mozilla/send/pull/162) Fix dev server URL in README.md file (@pdehaan)
- [#167](https://github.com/mozilla/send/pull/167) build docker image with new name (@relud)
- [#164](https://github.com/mozilla/send/pull/164) Add word wraps to table (@dnarcese)
- [#149](https://github.com/mozilla/send/pull/149) Add robots.txt (@pdehaan)
- [#161](https://github.com/mozilla/send/pull/161) Hide table header on empty list (@dnarcese)
- [#154](https://github.com/mozilla/send/pull/154) Remove expired uploads (@dnarcese)
- [#146](https://github.com/mozilla/send/pull/146) Update README with some more details (@pdehaan)

### v0.1.2 (2017/06/24 03:38 +00:00)
- [#138](https://github.com/mozilla/send/pull/138) remove notLocalHost (@dannycoates)

### v0.1.0 (2017/06/24 01:24 +00:00)
- [#137](https://github.com/mozilla/send/pull/137) refactored docker build (@dannycoates)
- [#132](https://github.com/mozilla/send/pull/132) Add /__version__ route (@pdehaan)
- [#135](https://github.com/mozilla/send/pull/135) make dockerfile more dockerflowy (@dannycoates)
- [#134](https://github.com/mozilla/send/pull/134) Load previous uploads (@dannycoates, @dnarcese)
- [#131](https://github.com/mozilla/send/pull/131) added __heartbeat__ (@dannycoates)
- [#133](https://github.com/mozilla/send/pull/133) Add LICENSE file (@pdehaan)
- [#130](https://github.com/mozilla/send/pull/130) added sentry to server code (@abhinadduri)
- [#124](https://github.com/mozilla/send/pull/124) Remove unused [dev]dependencies (@pdehaan)
- [#119](https://github.com/mozilla/send/pull/119) Move cross-env to a dep (@pdehaan)
- [#123](https://github.com/mozilla/send/pull/123) removed bitly integration (@abhinadduri)
- [#122](https://github.com/mozilla/send/pull/122) fix docker build (@dannycoates)
- [#121](https://github.com/mozilla/send/pull/121) added docker service to circle.yml (@dannycoates)
- [#120](https://github.com/mozilla/send/pull/120) added sentry (@abhinadduri)
- [#118](https://github.com/mozilla/send/pull/118) change docker image name and add builds for tags (@relud)
- [#116](https://github.com/mozilla/send/pull/116) add /__lbheartbeat__ endpoint (@relud)
- [#79](https://github.com/mozilla/send/pull/79) Optimize/minimize bundle.js for production (@pdehaan)
- [#104](https://github.com/mozilla/send/pull/104) Fix a bunch of ESLint and HTMLLint errors (@pdehaan)
- [#105](https://github.com/mozilla/send/pull/105) Progress bars (@dnarcese)
- [#111](https://github.com/mozilla/send/pull/111) added in anonmyized ip google analytics (@abhinadduri)
- [#110](https://github.com/mozilla/send/pull/110) added notifications (@abhinadduri)
- [#103](https://github.com/mozilla/send/pull/103) added Dockerfile (@dannycoates)
- [#100](https://github.com/mozilla/send/pull/100) Added Helmet Middleware (@abhinadduri)
- [#99](https://github.com/mozilla/send/pull/99) Testing (@abhinadduri)
- [#77](https://github.com/mozilla/send/pull/77) Fix the linter errors (@pdehaan)
- [#54](https://github.com/mozilla/send/pull/54) Adding basic ESLint config (@pdehaan)
- [#71](https://github.com/mozilla/send/pull/71) Drag & drop (@dnarcese)
- [#72](https://github.com/mozilla/send/pull/72) Logging (@abhinadduri, @dannycoates)
- [#45](https://github.com/mozilla/send/pull/45) S3 integration (@abhinadduri, @dannycoates)
- [#46](https://github.com/mozilla/send/pull/46) Download page and share link UI (@dnarcese)
- [#41](https://github.com/mozilla/send/pull/41) Added upload page and file list UI (@dnarcese)
- [#40](https://github.com/mozilla/send/pull/40) Tweak the package.json file (@pdehaan)
- [#43](https://github.com/mozilla/send/pull/43) added return (@abhinadduri)
- [#42](https://github.com/mozilla/send/pull/42) changed to handle 404 during download, also removing progress listene… (@abhinadduri)
- [#39](https://github.com/mozilla/send/pull/39) Refactor riff (@abhinadduri, @dannycoates)
- [#36](https://github.com/mozilla/send/pull/36) added prettier for js formatting (@dannycoates)
- [#28](https://github.com/mozilla/send/pull/28) Added a UI for the uploader end, made stylistic changes, implemented deleting (@abhinadduri)
- [#25](https://github.com/mozilla/send/pull/25) Changed naming for some pages, no longer stores files by name on server (@abhinadduri)
- [#17](https://github.com/mozilla/send/pull/17) changed from using input fields for keys to getting from url (#17) (@abhinadduri)

## Experiments

# A/B experiment testing

We're using Google Analytics Experiments for A/B testing.

## Creating an experiment

Navigate to the Behavior > Experiments section of Google Analytics and click the "Create experiment" button.

The "Objective for this experiment" is the most complicated part. See the "Promo click (Goal ID 4 / Goal Set 1)" for an example.

In step 2 add as many variants as you plan to test. The urls are not important since we aren't using their js library to choose the variants. The name will show up in the report so choose good ones. "Original page" becomes variant 0 and each variant increments by one. We'll use the numbers in our `app/experiments.js` code.

Step 3 contains some script that we'll ignore. The important thing here is the **Experiment ID**. This is the value we need to name our experiment in `app/experiments.js`. Save the changes so far and wait until the code containing the experiment has been deployed to production **before** starting the experiment.

## Experiment code

Code for experiments live in [app/experiments.js](../app/experiments.js). There's an `experiments` object that contains the logic for deciding whether an experiment should run, which variant to use, and what to do. Each object needs to have these functions:

### `eligible` function

This function returns a boolean of whether this experiment should be active for this session. Any data available to the page can be used determine the result.

### `variant` function

This function returns which experimental group this session is placed in. The variant values need to match the values set up in Google Analytics, usually 0 thru N-1. This value is usually picked at random based on what percentage of each variant is desired.

### `run` function

This function gets the `variant` value chosen by the variant function and the `state` and `emitter` objects from the app. This function can do anything needed to change the app based on the experiment. A common pattern is to set or change a value on `state` that will be picked up by other parts of the app, like ui templates, to change how it looks or behaves.

### Example

Here's a full example of the experiment object:

```js
const experiments = {
  S9wqVl2SQ4ab2yZtqDI3Dw: { // The Experiment ID from Google Analytics
    id: 'S9wqVl2SQ4ab2yZtqDI3Dw',
    run: function(variant, state, emitter) {
      switch (variant) {
        case 1:
          state.promo = 'blue';
          break;
        case 2:
          state.promo = 'pink';
          break;
        default:
          state.promo = 'grey';
      }
      emitter.emit('render');
    },
    eligible: function() {
      return (
        !/firefox|fxios/i.test(navigator.userAgent) &&
        document.querySelector('html').lang === 'en-US'
      );
    },
    variant: function(state) {
      const n = this.luckyNumber(state);
      if (n < 0.33) {
        return 0;
      }
      return n < 0.66 ? 1 : 2;
    },
    luckyNumber: function(state) {
      return luckyNumber(
        `${this.id}:${state.storage.get('testpilot_ga__cid')}`
      );
    }
  }
};
```

## Reporting results

All metrics pings will include the variant and experiment id, but it's usually important to trigger a specific event to be counted as the experiment goal (the "Objective for this experiment" part from setup). Use an 'experiment' event to do this. For example:

```js
emit('experiment', { cd3: 'promo' });
```

where `emit` is the app emitter function passed to the [route handler](https://github.com/choojs/choo#approuteroutename-handlerstate-emit)

The second argument can be an object with any additional parameters. It  usually includes a custom dimension that we chose to filter on while creating the experiment in Google Analytics.

## Credits

- The original project by Mozilla can be found [mozilla-send](https://github.com/mozilla/send).

- This maintain fork made by me [Jeyso215](https://github.com/Jeyso215) is to make sure it has no security issues and to keep it maintain as long as i feel i have the interest in this project.

- The [```branch-mozilla-master```](https://gitlab.com/timvisee/send/-/tree/mozilla-master) branch holds the `master` branch
as left by Mozilla.

- The [```branch-send-v3```](https://gitlab.com/timvisee/send/-/tree/send-v3) branch holds the commit tree of Mozilla's last
publicly hosted version, which this fork is based on.

- The [```branch-send-v4```](https://gitlab.com/timvisee/send/-/tree/send-v4) branch holds the commit tree of Mozilla's last
experimental version which was still a work in progress (featuring file
reporting, download tokens, trust warnings and FxA changes), this has
selectively been merged into this fork.
