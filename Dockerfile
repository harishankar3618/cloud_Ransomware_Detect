# Use official PHP image with Apache
FROM php:8.2-apache

# Install system dependencies and PHP extensions
RUN apt-get update && apt-get install -y \
    git zip unzip libpng-dev libjpeg-dev libfreetype6-dev libonig-dev libxml2-dev \
    && docker-php-ext-install pdo_mysql mbstring exif pcntl bcmath gd

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Copy existing application code
COPY . /var/www/html

# Set working directory
WORKDIR /var/www/html

# Install Composer
COPY --from=composer:2.6 /usr/bin/composer /usr/bin/composer

# Install Laravel dependencies
RUN composer install --no-dev --optimize-autoloader

# Copy Apache config (for Laravel routing)
RUN echo '<Directory /var/www/html/public>\n\
    AllowOverride All\n\
</Directory>' > /etc/apache2/conf-available/laravel.conf && \
    a2enconf laravel

# Set permissions for Laravel storage & cache
RUN chown -R www-data:www-data /var/www/html/storage /var/www/html/bootstrap/cache

# Expose port
EXPOSE 80

# Start Apache
CMD ["apache2-foreground"]
