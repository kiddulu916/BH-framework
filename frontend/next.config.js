/** @type {import('next').NextConfig} */
const nextConfig = {
  // Environment variables
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL,
    NEXT_PUBLIC_WS_URL: process.env.NEXT_PUBLIC_WS_URL,
  },
  
  // Development settings
  reactStrictMode: true,
<<<<<<< HEAD:frontend/next.config.js
  
=======
    
>>>>>>> 104107464cb0d6c74457d543e9bf7f7cb883603f:frontend/next.config.mjs
  // CORS headers for development
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Access-Control-Allow-Origin',
            value: '*',
          },
        ],
      },
    ];
  },
  
  // Webpack configuration for development
  webpack: (config, { dev, isServer }) => {
    if (dev && !isServer) {
      // Enable hot reloading
      config.watchOptions = {
        poll: 1000,
        aggregateTimeout: 300,
      };
    }
    return config;
  },
};

module.exports = nextConfig; 