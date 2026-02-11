# VM2: React Landing Page
# Repository: https://github.com/sujoyduttajad/Landing-Page-React
# Build steps: npm install -> npm run build -> serve the build/ directory with nginx
FROM node:16-alpine AS build
WORKDIR /app
RUN apk add --no-cache git
RUN git clone https://github.com/sujoyduttajad/Landing-Page-React.git .
RUN npm install
RUN npm run build

# Serve static files with nginx (sinh access log chi tiết)
FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html

# Custom nginx config to produce more detailed access logs
RUN echo 'server { \
    listen 80; \
    server_name localhost; \
    access_log /dev/stdout combined; \
    error_log /dev/stderr warn; \
    location / { \
        root /usr/share/nginx/html; \
        index index.html; \
        try_files $uri $uri/ /index.html; \
    } \
}' > /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
