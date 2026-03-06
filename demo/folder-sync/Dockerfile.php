# cairn-folder-sync: P2P folder sync demo (PHP)
# Build from repo root: docker build -f demo/folder-sync/Dockerfile.php -t cairn-demo-folder-sync-php .

FROM php:8.3-cli-bookworm
WORKDIR /app

# Install composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Copy local cairn-p2p package
COPY packages/php/cairn-p2p /app/packages/php/cairn-p2p

# Copy demo files
COPY demo/folder-sync/php /app/demo/folder-sync/php

# Install dependencies
WORKDIR /app/demo/folder-sync/php
RUN composer install --no-interaction --no-dev 2>/dev/null || true

RUN useradd -r -s /bin/false cairn
USER cairn
ENTRYPOINT ["php", "cairn_sync.php"]
