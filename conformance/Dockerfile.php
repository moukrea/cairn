FROM php:8.4-cli-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iptables libgmp-dev libsodium-dev unzip \
    && docker-php-ext-install gmp \
    && pecl install sodium 2>/dev/null || true \
    && docker-php-ext-enable sodium 2>/dev/null || true \
    && rm -rf /var/lib/apt/lists/*

# Install Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app

# Copy composer files for dependency caching
COPY packages/php/cairn-p2p/composer.json ./
RUN composer install --no-dev --no-scripts --no-autoloader 2>/dev/null || true

# Copy the PHP source
COPY packages/php/cairn-p2p/ ./
RUN composer require symfony/yaml:^6.0 --no-interaction 2>/dev/null || true
RUN composer dump-autoload --optimize 2>/dev/null || true

# Copy the conformance runner and network shaper
COPY conformance/network-shaper.sh /usr/local/bin/network-shaper
COPY conformance/runners/php-runner.php /usr/local/bin/cairn-conformance-runner.php

RUN printf '#!/bin/sh\nexec php /usr/local/bin/cairn-conformance-runner.php "$@"\n' > /usr/local/bin/cairn-conformance-runner && \
    chmod +x /usr/local/bin/network-shaper /usr/local/bin/cairn-conformance-runner

WORKDIR /conformance
COPY conformance/tests/ tests/
COPY conformance/fixtures/ fixtures/
COPY conformance/vectors/ vectors/

ENTRYPOINT ["php", "/usr/local/bin/cairn-conformance-runner.php"]
