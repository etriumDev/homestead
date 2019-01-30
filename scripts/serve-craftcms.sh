#!/usr/bin/env bash

declare -A params=$6       # Create an associative array
declare -A headers=$9      # Create an associative array
declare -A rewrites=${10}  # Create an associative array
paramsTXT=""
if [ -n "$6" ]; then
   for element in "${!params[@]}"
   do
      paramsTXT="${paramsTXT}
      fastcgi_param ${element} ${params[$element]};"
   done
fi
headersTXT=""
if [ -n "$9" ]; then
   for element in "${!headers[@]}"
   do
      headersTXT="${headersTXT}
      add_header ${element} ${headers[$element]};"
   done
fi
rewritesTXT=""
if [ -n "${10}" ]; then
   for element in "${!rewrites[@]}"
   do
      rewritesTXT="${rewritesTXT}
      location ~ ${element} { if (!-f \$request_filename) { return 301 ${rewrites[$element]}; } }"
   done
fi

if [ "$7" = "true" ] && [ "$5" = "7.2" ]
then configureZray="
location /ZendServer {
        try_files \$uri \$uri/ /ZendServer/index.php?\$args;
}
"
else configureZray=""
fi

block="map \$http_user_agent \$limit_bots {
     default 0;
     ~*(AhrefsBot|Baiduspider|PaperLiBot) 1;
 }

# redirect http to https
server {
    listen ${3:-80};

    server_name .$1;
    root \"$2\";
    return 301 https://$1\$request_uri;
}

# Cannonical domain rewrite to remove www., etc. An SSL certificate is required to do the redirect
#server {
#     Listen for both IPv4 & IPv6 requests on port 443 with http2 enabled
#    listen ${4:-443} ssl http2;

#    server_name *.$1;
#    ssl_certificate     /etc/nginx/ssl/$1.crt;
#    ssl_certificate_key /etc/nginx/ssl/$1.key;
#    return 301 https://$1$request_uri;
#}

# Primary virtual host server block
server {
    # Listen for both IPv4 & IPv6 requests on port 443 with http2 enabled
    listen ${4:-443} ssl http2;

    # General virtual host settings
    server_name .$1;
    root \"$2\";
    index index.html index.htm index.php;
    charset utf-8;

    # Enable server-side includes as per: http://nginx.org/en/docs/http/ngx_http_ssi_module.html
    ssi on;

    # Disable limits on the maximum allowed size of the client request body
    client_max_body_size 0;

    # Ban certain bots from crawling the site
    if (\$limit_bots = 1) {
        return 403;
    }

    # 404 error handler
    error_page 404 /index.php?\$query_string;

    # 301 Redirect URLs with trailing /'s as per https://webmasters.googleblog.com/2010/04/to-slash-or-not-to-slash.html
    rewrite ^/(.*)/$ /\$1 permanent;

    # Change // -> / for all URLs, so it works for our php location block, too
    merge_slashes off;
    rewrite (.*)//+(.*) \$1/\$2 permanent;

    # For WordPress bots/users
    location ~ ^/(wp-login|wp-admin|wp-config|wp-content|wp-includes|(.*)\.exe) {
        return 301 https://wordpress.com/wp-login.php;
    }

    # Handle Do Not Track as per https://www.eff.org/dnt-policy
    location /.well-known/dnt-policy.txt {
        try_files /dnt-policy.txt /index.php?p=/dnt-policy.txt;
    }

    # Access and error logging
    access_log off;
    error_log  /var/log/nginx/$1-error.log error;
    # If you want error logging to go to SYSLOG (for services like Papertrailapp.com), uncomment the following:
    #error_log syslog:server=unix:/dev/log,facility=local7,tag=nginx,severity=error;

    # Don't send the nginx version number in error pages and Server header
    server_tokens off;

    # Load configuration files from nginx-partials
    include /etc/nginx/nginx-partials/*.conf;

    # Root directory location handler
    location / {
        try_files \$uri/index.html \$uri \$uri/ /index.php?\$query_string;
    }

    # Localized sites, hat tip to Johannes -- https://gist.github.com/johanneslamers/f6d2bc0d7435dca130fc

    # If you are creating a localized site as per: https://craftcms.com/docs/localization-guide
    # the directives here will help you handle the locale redirection so that requests will
    # be routed through the appropriate index.php wherein you set the CRAFT_LOCALE

    # Enable this by un-commenting it, and changing the language codes as appropriate
    # Add a new location @XXrewrites and location /XX/ block for each language that
    # you need to support

    #location @enrewrites {
    #    rewrite ^/en/(.*)$ /en/index.php?p=\$1? last;
    #}
    #
    #location /en/ {
    #    try_files \$uri \$uri/ @enrewrites;
    #}

    # Craft-specific location handlers to ensure AdminCP requests route through index.php
    # If you change your cpTrigger, change it here as well
    location ^~ /admin {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    location ^~ /cpresources {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    # php-fpm configuration
    location ~ [^/]\.php(/|$) {
        try_files \$uri \$uri/ /index.php?\$query_string;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/var/run/php/php$5-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;

        # Don't allow browser caching of dynamically generated content
        add_header Last-Modified \$date_gmt;
        add_header Cache-Control \"no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0\";
        if_modified_since off;
        expires off;
        etag off;

        # See https://github.com/nystudio107/craft-multi-environment or https://github.com/nystudio107/craft3-multi-environment
        # Remove if you don't plan to use server-set ENV variables
        $paramsTXT
        fastcgi_param CRAFTENV_CRAFT_ENVIRONMENT \"dev\";
        fastcgi_param CRAFTENV_DB_DRIVER \"mysql\";
        fastcgi_param CRAFTENV_DB_SERVER \"localhost\";
        fastcgi_param CRAFTENV_DB_USER \"homestead\";
        fastcgi_param CRAFTENV_DB_PASSWORD \"secret\";
        fastcgi_param CRAFTENV_SITE_URL \"https:\\\\$1\";
        fastcgi_param CRAFTENV_BASE_URL \"https:\\\\$1\";
        fastcgi_param CRAFTENV_BASE_PATH \"$2\";

        fastcgi_intercept_errors off;
        fastcgi_buffer_size 16k;
        fastcgi_buffers 4 16k;
        fastcgi_connect_timeout 300;
        fastcgi_send_timeout 300;
        fastcgi_read_timeout 300;
    }

    # SSL/TLS configuration, with TLSv1.0 disabled because it is insecure; note that IE 8, 9 & 10 support
    # TLSv1.1, but it's not enabled by default clients using those browsers will not be able to connect
    ssl_certificate     /etc/nginx/ssl/$1.crt;
    ssl_certificate_key /etc/nginx/ssl/$1.key;
    ssl_protocols TLSv1.2 TLSv1.1;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDH+AESGCM:ECDH+AES256:ECDH+AES128:DH+3DES:!ADH:!AECDH:!MD5';
    ssl_buffer_size 4k;
    ssl_session_timeout 4h;
    ssl_session_cache shared:SSL:40m;


    # Disable reading of Apache .htaccess files
    location ~ /\.ht {
        deny all;
    }

    # Built-in filename-based cache busting
    location ~* (.+)\.(?:\d+)\.(js|css|png|jpg|jpeg|gif|webp)$ {
        etag off;
        expires 1M;
        access_log off;
        add_header Cache-Control \"public\";
        try_files \$uri \$1.\$2;
    }


    # Security headers via https://securityheaders.io
    add_header Strict-Transport-Security \"max-age=15768000; includeSubDomains; preload\";
    add_header X-Frame-Options \"SAMEORIGIN\";
    add_header X-XSS-Protection \"1; mode=block\";
    add_header X-Content-Type-Options \"nosniff\";
    add_header Referrer-Policy \"no-referrer-when-downgrade\";

    # Misc settings
    sendfile off;
}
"

echo "$block" > "/etc/nginx/sites-available/$1"
ln -fs "/etc/nginx/sites-available/$1" "/etc/nginx/sites-enabled/$1"
#echo "127.0.0.1 $1" >> /etc/hosts
