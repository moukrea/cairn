# cairn-chat: P2P messaging demo (PHP)
# Build from repo root: docker build -f demo/messaging/Dockerfile.php -t cairn-demo-messaging-php .

FROM php:8.3-cli-bookworm
WORKDIR /app

# Install composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Copy local cairn-p2p package
COPY packages/php/cairn-p2p /app/packages/php/cairn-p2p

# Copy demo files
COPY demo/messaging/php /app/demo/messaging/php

# Install dependencies
WORKDIR /app/demo/messaging/php
RUN composer install --no-interaction --no-dev 2>/dev/null || true

RUN useradd -r -s /bin/false cairn
USER cairn
ENTRYPOINT ["php", "cairn_chat.php"]
