<?php
/**
 * Plugin Name: WLN Cloudflare Worker Static Assets
 * Description: Route public WordPress static assets through Cloudflare Worker.
 */

if (!defined('ABSPATH')) {
    exit;
}

function wln_worker_rewrite_static_asset_url($url) {
    if (!is_string($url) || $url === '') {
        return $url;
    }

    $decoded = html_entity_decode(
        $url,
        ENT_QUOTES | ENT_HTML5,
        'UTF-8'
    );

    $parts = wp_parse_url($decoded);

    if (
        !is_array($parts) ||
        empty($parts['host']) ||
        empty($parts['path'])
    ) {
        return $url;
    }

    if (
        strtolower($parts['host']) !==
        'we-love-network.duckdns.org'
    ) {
        return $url;
    }

    if (!preg_match(
        '~^/(?:wp-content|wp-includes)/~i',
        $parts['path']
    )) {
        return $url;
    }

    if (!preg_match(
        '~\.(?:css|js|mjs|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf|eot)$~i',
        $parts['path']
    )) {
        return $url;
    }

    $worker_url =
        'https://we-love-network-cache.67160256.workers.dev'
        . $parts['path'];

    if (isset($parts['query'])) {
        $worker_url .= '?' . $parts['query'];
    }

    if (isset($parts['fragment'])) {
        $worker_url .= '#' . $parts['fragment'];
    }

    return esc_url($worker_url);
}

function wln_worker_rewrite_static_assets_in_html($html) {
    $pattern =
        '~https://we-love-network\.duckdns\.org/(?:wp-content|wp-includes)/[^"\'<>\s,()]+~i';

    $result = preg_replace_callback(
        $pattern,
        function ($matches) {
            return wln_worker_rewrite_static_asset_url(
                $matches[0]
            );
        },
        $html
    );

    return is_string($result) ? $result : $html;
}

add_action('template_redirect', function () {
    // Do not rewrite the WordPress admin or logged-in pages.
    if (
        is_admin() ||
        is_user_logged_in() ||
        is_feed() ||
        is_preview() ||
        (defined('REST_REQUEST') && REST_REQUEST)
    ) {
        return;
    }

    ob_start('wln_worker_rewrite_static_assets_in_html');
}, 0);
