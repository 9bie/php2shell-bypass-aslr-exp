FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive
ARG PHP_PKG_VERSION=8.5.4-0ubuntu1.3
ARG TARGETARCH

COPY php-pin.pref /etc/apt/preferences.d/php-pin

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apache2 \
        ca-certificates \
        curl \
        gdb \
        libapache2-mod-php8.5 \
        php8.5-cli \
        procps \
        python3 \
    && rm -rf /var/lib/apt/lists/*

# Ubuntu's current package includes the security fix. Keep the vulnerable
# packaging revision explicitly for the local reproduction.
RUN mkdir -p /tmp/php-debs \
    && curl -fsSL -o /tmp/php-debs/php8.5-common.deb \
       "https://launchpad.net/ubuntu/+archive/primary/+files/php8.5-common_${PHP_PKG_VERSION}_${TARGETARCH}.deb" \
    && curl -fsSL -o /tmp/php-debs/php8.5-cli.deb \
       "https://launchpad.net/ubuntu/+archive/primary/+files/php8.5-cli_${PHP_PKG_VERSION}_${TARGETARCH}.deb" \
    && curl -fsSL -o /tmp/php-debs/php8.5-readline.deb \
       "https://launchpad.net/ubuntu/+archive/primary/+files/php8.5-readline_${PHP_PKG_VERSION}_${TARGETARCH}.deb" \
    && curl -fsSL -o /tmp/php-debs/libapache2-mod-php8.5.deb \
       "https://launchpad.net/ubuntu/+archive/primary/+files/libapache2-mod-php8.5_${PHP_PKG_VERSION}_${TARGETARCH}.deb" \
    && dpkg -i --force-downgrade \
       /tmp/php-debs/php8.5-common.deb \
       /tmp/php-debs/php8.5-cli.deb \
       /tmp/php-debs/php8.5-readline.deb \
       /tmp/php-debs/libapache2-mod-php8.5.deb \
    && apt-mark hold php8.5-common php8.5-cli php8.5-readline libapache2-mod-php8.5 \
    && rm -rf /tmp/php-debs

COPY poc.ini /etc/php/8.5/apache2/conf.d/99-poc.ini
COPY mpm_prefork.conf /etc/apache2/mods-available/mpm_prefork.conf
COPY webroot/ /var/www/html/
COPY start-apache /usr/local/bin/start-apache

RUN chmod 0755 /usr/local/bin/start-apache \
    && a2dismod mpm_event mpm_worker \
    && a2enmod mpm_prefork php8.5

EXPOSE 80
CMD ["/usr/local/bin/start-apache"]
